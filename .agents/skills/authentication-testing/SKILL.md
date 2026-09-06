---
name: Authentication & Session Testing
description: Reach protected functionality without valid credentials and take over accounts via JWT forgery, MFA bypass, OAuth flaws, session fixation, and password-reset abuse.
tags: [web, auth, session, jwt, oauth, mfa, owasp-a07]
recommended_tools: [jwt_analyzer, http_request, http_repeater, http_intruder, hydra_attack]
vuln_classes: [auth_bypass, jwt]
domain: web
phase: exploitation
---
# Authentication & Session Testing

Authentication bugs are mostly **manual** — craft exact requests with `http_request`, read the raw
response, and compare against an authenticated baseline. Map the full auth surface first: login,
register, logout, password reset/change, email change, MFA enrolment + verification, OAuth/SSO
callbacks, "remember me", and any pre-auth → post-auth transition. `auth_bypass` is confirmed when
you reach protected functionality (a page/action/data that requires login) **without valid auth**.

## JWT (`jwt_analyzer`, then forge with `http_request`)
Where: `Authorization: Bearer`, cookies, `id_token`/`access_token` in OAuth responses. Decode header+claims.
1. **alg=none** — set header `{"alg":"none","typ":"JWT"}`, keep/modify claims (`"role":"admin"`,
   `"sub":"1"`), drop the signature but **keep the trailing dot**: `base64url(header).base64url(payload).`
   Replay. Acceptance = forgery.
2. **RS256 → HS256 confusion** — fetch the public key (`/.well-known/jwks.json`, cert, or PEM).
   Switch header `alg` to `HS256` and sign the token using the **public key bytes as the HMAC secret**.
   If accepted, the server verifies an RS256 token with an HMAC routine = full forgery.
3. **Weak HMAC secret** — `jwt_analyzer` cracks the secret (wordlist). On hit, mint arbitrary claims.
4. **Claim tampering / no verification** — flip `role`, `user_id`, `email`, `is_admin`; resend with the
   ORIGINAL signature. If accepted, signature is not checked. Also test `kid` path traversal/SQLi and
   `jku`/`x5u` pointing to an attacker-controlled JWKS.
Proof: the decoded forged token + the request bearing it + a response returning another principal's
data or admin functionality (jwt → auth_bypass chain).

## MFA / 2FA bypass (`http_request`, OTP brute via `http_intruder`)
After password but before MFA, the server usually issues a "pre-MFA" cookie/token. Attack the gap:
1. **Direct post-MFA URL** — with the pre-MFA cookie, request `/dashboard`, `/account`, or the
   post-login API directly, skipping `/mfa`. Success = bypass.
2. **Response tampering** — intercept the verify response (`{"success":false}`/`401`); rewrite to
   `{"success":true}`/`200` and forward. Client-trusted result = bypass.
3. **OTP brute force** — no rate limit on `POST /verify-otp {"otp":FUZZ}`: `http_intruder` over
   `000000`–`999999`, filter the failure status/length (HITL-gate volume). Also try the OTP **after
   its expiry window** and **reusing a consumed OTP** after re-login (not invalidated).
4. **Backup codes** — 6–8 digit codes (1–10M space) often lack throttling; brute or test reuse/
   predictable regeneration.
5. **"Remember device" misuse** — complete MFA, capture the trust cookie, replay from a new
   IP/User-Agent. If MFA skips, trust isn't bound to device.
Proof: the request sequence reaching authenticated state with no valid second factor (auth_bypass).

## OAuth / OIDC (`http_request`)
1. **redirect_uri** — substitute attacker domain; bypass weak validators with `@`
   (`https://legit.com@evil.com`), `//evil.com`, double-encoding (`%252f%252fevil.com`), suffix/prefix
   (`legit.com.evil.com`, `evil.com/legit.com`), or open-redirect chaining. Leaked `code`/`token` = ATO.
2. **state** — drop/fix the `state` param; if the callback still completes, OAuth-CSRF → attacker code
   bound to victim session.
3. **PKCE** — start auth without PKCE; a `302` (not error) means PKCE unenforced → stolen code is exchangeable.
4. **Pre-account-takeover** — register the victim's email at the IdP/app before they do; on their SSO
   login the accounts merge under your control.
Proof: the callback/token-exchange request + evidence the attacker controls the victim session (auth_bypass).

## Session management & password reset (`http_request`)
- **Session fixation** — capture the session id pre-login; if it is **unchanged after login**, set it on a
  victim and ride their session. Also verify logout invalidates the id **server-side** (replay post-logout).
- **Cookie flags** — missing `HttpOnly`/`Secure`/`SameSite`; token in URL; excessive lifetime.
- **Reset poisoning** — `POST /forgot-password` with `Host: attacker.com` or `X-Forwarded-Host:
  attacker.com`; if the emailed link points to your host you own the token → ATO.
- **Reset token flaws** — predictable/sequential/timestamp tokens (request several, diff them); no expiry
  (reuse after hours); reuse after a newer token issued; leak via `Referer` to third-party scripts.
- **Email change with no re-auth** — `PUT /api/user/email {"new_email":"attacker@..."}` without current
  password = ATO primitive.

## Credential attacks (HITL-gated)
`hydra_attack`/`http_intruder` low-volume for default creds, missing lockout, and user enumeration
(differing response body/status/timing for valid vs invalid usernames on login/register/reset).

## Chaining
JWT/source leak (Spring `/actuator/env`, `__NEXT_DATA__`, JS bundles) → signing key → forge admin →
auth_bypass; open redirect → OAuth code theft → ATO; reset poisoning → MFA reset → full takeover.

## Evidence & safety
Capture the exact request(s) and raw response proving you reached protected functionality or another
account without valid auth. Use throwaway/engagement accounts; HITL-gate any brute force; never lock
out real users. CWE-287 (auth) / CWE-384 (fixation) / CWE-345 (JWT verification) / CWE-613 (session).


<!-- Ingested from reference frameworks (skill-ingestion) -->
## Password-reset takeover patterns
```
Param-swap:    request reset for victim@example.com, intercept and change email/user param to attacker@example.com
               while keeping victim's token/context. Win = victim's reset link delivered to/usable by attacker.
Host-header poison: POST /reset with  Host: attacker.tld  (or X-Forwarded-Host: attacker.tld) vs legit host.
               Win = poison host appears in the reset link/body ONLY when the override header is sent.
```
Proof signal: reset link/token for victim's account is usable by or sent to attacker; or attacker-controlled host reflected in reset link only under header override.

## Session hijack / fixation
```
curl -b "sessionid=STOLEN_VALUE" https://target/api/profile
// Playwright: await page.context().addCookies([{name:'sessionid',value:'STOLEN',domain:'target',path:'/'}]);
```
Fixation: capture pre-login session ID and post-login session ID for the SAME browser context — if they are identical, the session is not rotated on auth (fixation). Proof signal: protected page (/profile, /dashboard) renders as the victim user.

## nOAuth / OIDC attribute-hijack identity confusion
Verify the app keys identity on the immutable `sub` claim, NOT on mutable/user-controllable claims (`email`, `preferred_username`, `name`). If keyed on `email`: attacker stands up their own OAuth/OIDC tenant, sets a matching email, and lands on the victim account. Also check: signature + pinned algs enforced, `iss`/`aud`/`exp` validated, PKCE required for public clients, no silent account creation without a verified link, exact redirect-URI allowlist (no open redirect in `redirect_uri`).
Proof signal: logging in via attacker-controlled IdP with the victim's email/attribute lands on the victim's account.

## Broken-auth checklist -> attack mapping (per endpoint)
```
rate-limit/CAPTCHA/lockout absent  -> credential stuffing / password spraying (200s with no throttle = proof)
generic error messages absent      -> account enumeration (distinct "user not found" vs "bad password")
session ID in URL / no HttpOnly+Secure+SameSite -> session hijack
single-use short-TTL reset tokens absent -> reset-token guess/replay
```

## Modern techniques & real-world CVEs (via recon-skills)

### SAML signature bypass & parser-differential (XSW)
SAML SP implementations are a top-paying auth-bypass class. Capture a valid `SAMLResponse`
(POST body / `Set-Cookie`), base64-decode, inspect the XML, then attack the signature layer.

- **Signature stripping** — remove the `<ds:Signature>` element entirely and replay. If the SP
  accepts the unsigned assertion, it never enforced signing (`wantAssertionsSigned: false` default).
  ```python
  import base64, re
  saml_xml = base64.b64decode("BASE64_FROM_CAPTURE").decode()
  stripped = re.sub(r'<ds:Signature.*?</ds:Signature>', '', saml_xml, flags=re.DOTALL)
  print(base64.b64encode(stripped.encode()).decode())
  ```
- **Parser-differential XSW (GitHub Enterprise CVE-2025-25291/25292)** — inject a sibling
  `<Assertion>` so the signature-checker (e.g. REXML) and the business-logic reader (e.g. Nokogiri)
  resolve *different* nodes for the same XPath. Signature validates the benign node; the SP consumes
  your attacker-controlled `<NameID>admin@target</NameID>`. Root cause: two XML parsers disagree.
  Also **CVE-2024-4985** (GHE encrypted-assertion branch skips signature verification, provision
  arbitrary `site_admin`, CVSS 10.0) and **samlify CVE-2025-47949**.
- **XML comment / namespace injection (Slack, ruby-saml class)** — split the signed `NameID` with a
  comment or namespace prefix so the signed bytes differ from the evaluated identity:
  ```xml
  <NameID>attacker@evil.com<!---->victim@company.com</NameID>
  <NameID xmlns:evil="http://evil.com">victim@company.com</NameID>
  ```
- **Audience / freshness not validated (Slack confused-deputy 2017)** — replay an old, differently-
  audienced signed assertion (e.g. a GitHub-signed one) at the target ACS; if `Audience`/`NotOnOrAfter`
  aren't checked, you log in as the asserted subject.
- **Domain-binding bypass via control chars (H1 #2101076, 2024)** — append a trailing `\r`, space, or
  unicode control char to an email during SAML-enforced signup; the domain check normalises it away
  while the identity write keeps it → join a restricted org.
- CWE-347 (improper signature verification). Verify `iss`/`aud`/`exp`, pinned algs, and that a single
  parser handles both verification and consumption.

### JWT audience confusion (Argo CD CVE-2023-22482)
Beyond alg=none / key-confusion: test whether the server enforces the `aud` claim, not just the
signature. Present a validly-signed token minted by the same issuer but for a *different* audience
(e.g. `kubernetes`); if the API accepts it as a bearer, signature-trust was extended across audiences.
Also **8x8/Jitsi H1 #1210502** (RS256→HS256 confusion, Prosody admits attacker to moderator room).

### Legacy-protocol matrix — native-cred bypass of branded/SSO login
When a target has a custom branded login (`customlogin.aspx`, `/auth/signin`) or SSO on the UI,
**probe the platform's legacy/native auth endpoint in parallel**. These frequently outlive the UI's
protections and accept native credentials with no rate limit, MFA, or CAPTCHA. Generalises the
WordPress XMLRPC pattern (Uber H1 #138869, OneLogin plugin left `@@@nopass@@@` accounts brute-able
via `xmlrpc.php`).

| Tech | Legacy endpoint(s) | Bypass surface |
|---|---|---|
| WordPress | `/xmlrpc.php` (`system.listMethods`, `wp.getUsersBlogs`, `system.multicall`) | Native creds; bypasses SSO/MFA/IP-allow on `wp-login.php`. `multicall` batches 100s of cred pairs per request → rate-limit bypass |
| WordPress REST | `/wp-json/wp/v2/users`, `/?rest_route=/wp/v2/users` | Anonymous user enumeration |
| SharePoint | `/_vti_bin/Authentication.asmx` (SOAP `Login`), `/_api/contextinfo` | Native Forms-auth cred, FedAuth cookie, no rate limit — canonical SP equivalent of XMLRPC |
| Atlassian Jira/Confluence | `/rest/auth/1/session`, `/rest/api/2/myself` | Native creds accepted even under Crowd/Access SSO |
| Drupal | `/user/login?_format=json`, `/jsonapi/` | JSON POST accepts native passwords, separate from SSO |
| Joomla | `/administrator/index.php?option=com_login` | Native admin creds independent of front-site SSO |
| Exchange/OWA | `/EWS/Exchange.asmx`, `/Autodiscover/Autodiscover.xml` | NTLM/Basic bypasses OWA MFA/IP-allow (CVE-2020-0688 / CVE-2021-26855 surface) |
| Tomcat / WebLogic / Jenkins | `/manager/html`, `/console/login/LoginForm.jsp`, `/script` | Native realm creds independent of front auth |
| Spring Boot | `/actuator/*`, `/management/*` | Anonymously enumerable actuators leak signing keys/env |

Procedure: fingerprint tech → probe the legacy endpoint anonymously (not 403/404) → confirm it takes
native-cred format with differential success/fail responses → burst 10 requests at one user to prove
no lockout/throttle → report by chain-to-ATO impact (unlimited anon brute endpoint = Critical).

### Function-level access control (broken authorization)
Auth bypass gets you *in*; missing per-function checks let an authenticated low-priv user reach
privileged functions. **Sibling-function rule:** if 9 endpoints under a path enforce auth middleware,
the 10th that doesn't is the bug — admin route families are highest-yield.
```
/api/admin/users   -> authenticate + authorize('admin')
/api/admin/export  -> often MISSING middleware
/api/admin/delete  -> often MISSING middleware
```
Enumerate every privileged endpoint (admin/export/delete/reset/impersonate, GraphQL admin ops) and
replay each from a regular session and with no session. A 200 (or a differential vs the 403 its
siblings return) is broken function-level access control. Real: HackerOne TrustHub `POST /graphql`
`TrustHubQuery` op had no authz check → any user reads all vendors' data (CVSS 8.7).

### Duende BFF / proxy token-confusion (2024-2026 .NET surface)
- **YARP `UserOrClient` privilege escalation** — a route marked `TokenType.UserOrClient` falls back to
  the *client-credentials* (M2M) token when unauthenticated. That service token often has broader scope
  (`api.admin`) than any user token. Hit the route with **no cookies** → BFF proxies with the admin-scope
  M2M token attached downstream → unauthenticated priv-esc. Adjacent **CVE-2024-51987** in
  `Duende.AccessTokenManagement.OpenIdConnect` (wrong token used after refresh) confirms the family.
- **Cookie-domain wildcard fixation** — `Domain=.example.com` drops `__Host-` protection; a taken-over
  sibling subdomain writes `Set-Cookie: .AspNetCore.Cookies=<attacker>; Domain=.example.com`. With
  `SlidingExpiration=true` + large `ExpireTimeSpan`, cron-poll `GET /bff/user -H 'X-CSRF: 1'` every 6h
  to keep the session alive indefinitely → persistent ATO.
- **`/bff/user` claim disclosure** — returns the full session claim set (sub, sid, email, tenant, role,
  employee ID); gated only by cookie + `X-CSRF: 1`. Also an auth-state oracle when
  `AnonymousSessionResponse=Response200`. Recon for the YARP class above.

### MFA bypass — modern patterns
- **OAuth device-code flow (RFC 8628)** — the device grant has no interactive user-agent, so the IdP
  often never enforces MFA. Detect via `.well-known/oauth-authorization-server` →
  `device_authorization_endpoint`. Azure: `POST /<tenant>/oauth2/v2.0/devicecode`, phish the `user_code`
  to the victim, poll `/token` with `device_code`; the returned token may carry no MFA. Azure device
  codes are tenant-agnostic → cross-tenant ATO.
- **SP-side `amr`/`acr` not checked** — SP-initiated SSO grants access when the IdP issues an assertion
  without an MFA claim. Decode the ID token, check `amr` contains `mfa` and `acr`/`AuthnContextClassRef`
  matches the expected MFA class; if the SP accepts tokens lacking it, MFA is bypassed.
- **OTP race (TOCTOU)** — fire **30+** parallel submissions of the same OTP via an HTTP/2 single-packet
  attack (Turbo Intruder `Engine.BURP2`, `concurrentConnections=1`) before the server marks it used;
  2-5 requests resolve sequentially and false-negative. Race confirmed if >1 success.
- **Biometric replay** — capture a `biometric_verified:true` / signed match token, wait, replay in a new
  session; accepted without nonce/`jti`/device-binding = bypass.

### Session hardening — refresh-token rotation & DBSC
- **Refresh-token reuse-detection (OAuth Security BCP)** — rotate RT1→RT2, then replay the old RT1. If
  RT1 still mints tokens, or RT2 survives the RT1 replay, the server lacks *family* revocation → a leaked
  refresh token is a permanent credential surviving password change. No rotation at all (RT1==RT2) is a
  long-lived stealable credential.
- **Single-logout / IdP-session linkage** — log out at the IdP only, replay the app session cookie; still
  200 with user data = app session outlives the IdP session.
- **DBSC downgrade** — if responses carry `Sec-Session-Registration`/`Sec-Session-Id`, strip the device-
  bound proof header and replay the plain cookie; acceptance = device-binding is advisory, not enforced.
- **SameSite=Lax sibling-subdomain CSRF (Argo CD CVE-2024-22424)** — a Lax cookie is sent on top-level
  cross-site navigations from a sibling subdomain; when Lax is the only CSRF defence, this reaches state.

### Rate-limit classification (avoid false "no rate limit")
A `401` with no `429` is NOT "no rate limiting". Classify against four states before concluding:
hard lockout, soft IP-throttle, CAPTCHA-injection, and **silent shadow-throttle** (all requests return
200/401 but submissions are dropped — the genuinely-correct value stops authenticating). Shadow-throttle
detector: seed the *real* OTP for your test account at a known position in the brute set; if it no longer
authenticates under load, the endpoint is silently throttling. Then bypass per-IP limits by rotating
`X-Forwarded-For`/`X-Real-IP`/`CF-Connecting-IP`/`True-Client-IP` (and comma-joined chains) every request;
prove the bypass by toggling rotation off and showing the `429` returns. Instagram-2019 reset-OTP class:
6-digit code + no per-source limit + IP rotation made 10^6 tractable. Justify severity with the
reachability math (throughput × code-lifetime vs keyspace), not a 101-code probe.

### Gate 0 validation (before any report)
1. What can the attacker DO now — authenticate as another user, or without valid creds, or elevate to
   admin? (Username enumeration or a 401-vs-403 differential alone is not auth bypass.)
2. What does the victim LOSE — a concrete asset (specific account ATO, all admin functions, cross-tenant
   data)? Abstract "control bypass" is insufficient.
3. Reproducible in 10 minutes from a fresh browser/session? Prove takeover of test account B from
   attacker A's session; OOB-confirm any blind token-leak step (Collaborator reads the real email).
