---
name: Triage and Validation
description: Finding-validation and evidence-hygiene gate run BEFORE any report — 7-question kill gate, pre-submission gates, chain requirements, CVSS 3.1 scoring, PoC capture and redaction discipline.
tags: [reporting, triage, validation, cvss, evidence, poc]
recommended_tools: [http_request, http_repeater, http_intruder, curl, python3, jq]
vuln_classes: []
domain: general
phase: reporting
provenance: {source: uphiago/recon-skills, paths: [redteam/triage-validation/SKILL.md, redteam/evidence-hygiene/SKILL.md]}
---

# Triage & Validation

Run this gate BEFORE writing any report. One wrong answer = kill **the finding** (not the engagement) and move on to the next test class. Killing a finding via the gate means *that finding* doesn't get submitted; every other test class is still pending.

> N/A hurts your validity ratio. Informative is neutral. Only submit what passes all seven questions with proof captured and redacted.

The reporting phase has two halves:
1. **Validate** — does this finding survive the 7-question kill gate and the pre-submission gates?
2. **Evidence hygiene** — capture proof of impact, then redact secrets and PII before attaching.

---

## PART 1 — THE 7-QUESTION KILL GATE

Ask IN ORDER. One wrong answer = STOP immediately.

### Q1: Can an attacker use this RIGHT NOW, step by step?

Complete this template:
```
1. Setup:   I need [own account / another user's ID / no account]
2. Request: [exact HTTP method, URL, headers, body — copy-paste ready]
3. Result:  I can [read / modify / delete] [exact data shown in response]
4. Impact:  The real-world consequence is [ATO / PII read / money stolen]
5. Cost:    Time: [X minutes], Capital: [$0 / $X subscription required]
```
If you CANNOT write step 2 as a real HTTP request → KILL IT.

### Q2: Is the impact on the program's accepted-impact list?

Common tiers:
- **Critical**: any-user ATO without interaction, RCE, SQLi with data exfil, admin auth bypass
- **High**: mass PII exfil, privilege escalation, internal SSRF with data, stored XSS all users
- **Medium**: IDOR on specific-user non-critical data, XSS on sensitive page requiring click
- **Low**: non-sensitive info disclosure, clickjacking with PoC

If your bug maps to a listed exclusion → KILL IT.

### Q3: Is the root cause in an in-scope asset?
- Vulnerable domain is on the in-scope list (not `*.internal.target.com`)
- Production asset, not staging/dev unless explicitly in scope
- Not a third-party service the company merely uses (Stripe, Salesforce, Google Auth)

Out of scope → KILL IT.

### Q4: Does it require privileged access an attacker can't realistically get?
- "Admin can do X" = centralization risk = KILL IT (on 99% of programs)
- "Non-admin can do X that only admin should do" = valid
- "Requires physical access / MFA device" = usually invalid
- "Requires compromised victim account to work" = questionable, low severity at best

### Q5: Is this already known or accepted behavior?

Search:
1. Program's HackerOne/Bugcrowd disclosed reports: Ctrl+F endpoint + bug class
2. GitHub issues on target repo: `is:issue label:security ENDPOINT_NAME`
3. Changelog / CHANGELOG.md
4. API / design docs — is it documented as intended?

Acknowledged / design decision → KILL IT.

### Q6: Can you prove impact beyond "technically possible"?
- XSS → actual cookie theft or session hijack, not just `alert(1)` / `alert(document.domain)`
- SSRF → hit an internal endpoint that returns data, not just a DNS ping
- SQLi → actual data exfil from a real table, not just an error message
- IDOR → actual other-user data in the response, not just a `200` status code

If you can only show "technically possible" → DOWNGRADE severity, not kill.

### Q7: Is this a known-invalid bug class?

Check the NEVER SUBMIT list. On the list without a chain → KILL IT.

---

## PART 2 — PRE-SUBMISSION GATES

Run in sequence. ALL must PASS.

### Gate 0: Reality check (30 seconds)
```
[ ] Bug is REAL — confirmed with actual HTTP requests, not code reading alone
[ ] Bug is IN SCOPE — checked the program scope page explicitly
[ ] Reproducible from scratch — can reproduce from a fresh session
[ ] Evidence ready — screenshot, response body, or video
```

### Gate 1: Impact validation (2 minutes)
```
[ ] Can answer "what can the attacker DO that they couldn't before?"
[ ] Answer is more than "see non-sensitive data" (unless the program pays for info disclosure)
[ ] Real victim: another user's data, the company's data, financial loss
[ ] Not relying on the victim doing something unlikely
```

### Gate 2: Deduplication (5 minutes)
```
[ ] Searched HackerOne Hacktivity for program + similar title/endpoint
[ ] Searched GitHub issues for the target repo
[ ] Read the 5 most recent disclosed reports for this program
[ ] Not a known issue in their changelog or public docs
[ ] Google: "TARGET_NAME ENDPOINT_NAME bug bounty"
```

### Gate 3: Report quality (10 minutes)
```
[ ] Title: [Bug Class] in [Endpoint] allows [actor] to [impact]
[ ] Steps to Reproduce: copy-pasteable HTTP request
[ ] Evidence: screenshot/video of actual impact (not just a 200 status)
[ ] Severity: matches CVSS 3.1 score AND the program's severity definitions
[ ] Remediation: 1-2 sentences of concrete fix
[ ] NEVER used "could potentially" or "may allow"
```

---

## PART 3 — NEVER SUBMIT LIST

Submitting these destroys your validity ratio.
```
Missing CSP / HSTS / security headers
Missing SPF / DKIM / DMARC
GraphQL introspection alone (no auth bypass / IDOR demonstrated)
Banner / version disclosure without a working CVE exploit
Clickjacking on non-sensitive pages (no sensitive-action PoC)
Tabnabbing
CSV injection (no actual code execution shown)
CORS wildcard (*) without credential-exfil PoC
Logout CSRF
Self-XSS (only exploits own account)
Open redirect alone (no ATO or OAuth-theft chain)
OAuth client_secret in mobile app (known, expected)
SSRF DNS callback only (no internal service access or data)
Host header injection alone (no password-reset poisoning PoC)
Rate limit on non-critical forms (search, contact, Cloudflare-fronted login)
Session not invalidated on logout / concurrent sessions
Internal IP in error message
Mixed content / SSL weak ciphers
Missing HttpOnly / Secure cookie flags alone
Broken external links / autocomplete on password fields
Pre-account takeover (only under very specific conditions)
```

---

## PART 4 — CONDITIONALLY VALID: CHAIN REQUIRED

Build the chain first, prove it end-to-end, THEN report.

| Standalone Finding | Chain Required | Valid Result |
|---|---|---|
| Open redirect | + OAuth `redirect_uri` → auth code theft | ATO (Critical) |
| Clickjacking | + sensitive action + working PoC | Medium |
| CORS wildcard | + credentialed request exfils user PII | High |
| CSRF | + sensitive action (transfer funds, change email, delete account) | High |
| Rate-limit bypass | + OTP/reset-token brute force succeeds | Medium/High |
| SSRF DNS-only | + internal service access + data returned | Medium |
| Host header injection | + password-reset email uses injected host | High |
| Prompt injection | + reads other user's data (IDOR) | High |
| S3 bucket listing | + JS bundles contain API keys / OAuth secrets | Medium/High |
| Self-XSS | + CSRF to trigger it on the victim | Medium |
| Subdomain takeover | + OAuth `redirect_uri` registered at that subdomain | Critical |
| GraphQL introspection | + auth-bypass mutation or IDOR on `node()` | High |

---

## PART 5 — CVSS 3.1 QUICK REFERENCE

| Finding | Score | Severity | Vector |
|---|---|---|---|
| IDOR read PII, any user, auth required | 6.5 | Medium | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N |
| IDOR write/delete, any user | 7.5 | High | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N |
| Auth bypass → admin panel | 9.8 | Critical | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| Stored XSS → cookie theft | 8.5 | High | AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N |
| SQLi → full DB dump | 9.1 | Critical | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N |
| SSRF → cloud metadata | 9.1 | Critical | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N |
| Race → double spend | 7.5 | High | AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N |
| GraphQL auth bypass | 8.1 | High | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N |
| JWT `none` algorithm | 9.1 | Critical | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |

> Stored XSS UI is a judgment call. NVD/FIRST frequently score it UI:R (dropping the row above to ~7.6). If your triager expects UI:R, defend the choice or re-score before copying the number into a report.

**Metric quick guide:** AV:N = internet-exploitable · AC:L = no timing/race · PR:N = no login / PR:L = free account / PR:H = admin · UI:N = no victim action / UI:R = victim must click · C/I:H = reads/modifies all data, L = some · A:H = crashes service · S:C = affects browser/OS/cloud beyond the app, else S:U.

---

## PART 6 — KILL-FAST & PRE-SEVERITY GATES

**Kill-fast rules:**
1. **5-minute rule** — can't fill Q1's template in 5 minutes → move on.
2. **Precondition count** — more than 2 simultaneous preconditions → kill.
3. **Impact test** — "what does the attacker walk away with?" Nothing tangible → kill.
4. **Admin bypass** — "admin can do X" is never a bug → kill immediately.
5. **Design-doc test** — documented behavior → kill immediately.
6. **Rabbit-hole signal** — 30+ min on Q6 with no reproducible PoC → kill.

**Pre-severity gate — before labelling anything Critical/High, answer each as a one-liner:**
1. Have I validated the FULL chain to attacker-attainable impact, or only one primitive in the middle? A primitive confirmed at layer N ≠ exploitable.
2. What does the attacker walk away with, in one concrete sentence? "RCE on the front-end web server" is concrete; "could lead to RCE" is High at best, often Medium.
3. Have I personally reproduced the full chain end-to-end at least twice (once at discovery, once for the PoC)?
4. Is there an inheritance gate, signature check, audience check, or other validation step still gating the chain? If yes, it is not Critical — document as "primitive present" at lower severity until bypassed.
5. Has the program rejected this severity class before?

> Lesson: JWT `alg:none` was labelled Critical on a confirmed signature-bypass primitive at the audience layer. Later testing showed the issuer-trust check still rejected unsigned tokens — the ATO chain never completed and the finding was retracted. The pre-severity gate would have killed the Critical label pre-submission. Critical means impact-demonstrated, not impact-inferable.

---

## PART 7 — RETRACTION DISCIPLINE

When a claimed finding fails reproduction, never silently drop it — append a retraction entry. Self-retractions read "the researcher validates their own work"; a triager retraction reads "the researcher submitted noise" and is platform-tracked against your validity rate.

```markdown
### Retracted: <finding name>
- Original signal: <what looked like a bug>
- Disproving evidence: <reproduction step + observation that disproves it>
- Why it looked like a bug: <root cause of the false positive>
- Retraction date: <YYYY-MM-DD>
```

Common false-positive shapes to watch for:
- **URL echo dressed as reflection** — payload appears because the response IS the URL. Q1 kills it.
- **Word collision dressed as marker hit** — canary matched a CSS class, not your injection. Q1 kills it.
- **Server policy mistaken for a state oracle** — `download.aspx?file=foo.config` always returns "blocked" regardless of file existence; that's a deny-list, not an oracle. Q6 kills it.
- **200 OK without leak** — status differs from a 403 baseline but the body is byte-identical. Body-diff + Q6 kill it.
- **Single-sample timing leak** — one 1527 ms request vs ~700 ms control collapsed to 685–716 ms across n=80 interleaved samples. Statistical-sample rule kills it.

---

## PART 8 — EVIDENCE HYGIENE (PoC CAPTURE & REDACTION)

Core principle: bug-bounty evidence exists to convince a triager. Live cookies, real-user PII, and useless internal IDs should not be in it.

### 8.1 Two categories of sensitive data

| Category | Examples | Treatment |
|---|---|---|
| **Your-account secrets** | Session cookies, OAuth/refresh tokens, API keys | Always redact, even in private attachments. |
| **Other users' PII** | Real names, emails, phones, addresses, faces, correlatable account IDs | Redact unless demonstrating cross-account impact; even then mask faces and minimize. |
| **Triager-useful metadata** | Trace IDs (`x-datadog-trace-id`), request IDs, timestamps, YOUR test UID/email, GraphQL op names, response shapes | Leave visible — helps correlation and reproduction. |
| **Test-account passwords** | Throwaway password on a test account | OK in screenshots if you rotate immediately after submission so the shown value is dead. |

### 8.2 Cookie redaction protocol

**Mask:** the session cookie value (`authn`, `session`, `sid`, `__Secure-id`, name varies), session-bound `csrf-token`, `Authorization` (Bearer/JWT), and any session-bearing `Cookie` / `Set-Cookie` header values.

**Safe to leave:** Cloudflare cookies (`__cf_bm`, `_cfuvid`), analytics (`_ga`, `ajs_anonymous_id`), trace IDs, server/framework headers, your test account email/UID.

**Methods (ranked):**
- **A — Don't capture them.** For Console PoCs use `credentials: 'include'` so the browser sends cookies and your code never echoes them; screenshot the Console, never the Network Headers panel. For repeater PoCs, drag the request panel divider down to hide the request before capturing.
- **B — Black-bar** the value in an image editor (Preview annotate on macOS; Snip & Sketch / Paint.NET on Windows). Or pre-redact via Burp Match-and-Replace.
- **C — Find/replace in raw text** for HAR / transcripts (see 8.4).

**Pre-screenshot checklist:**
```
[ ] Network Headers panel collapsed / out of frame
[ ] Request panel hidden behind the divider
[ ] No "Copy as cURL" output visible
[ ] Application → Storage → Cookies tab closed
[ ] URL bar shows no session token in the query string
```
**After capturing:** open at full resolution; search visible text for the cookie NAME and the first 6 chars of its VALUE; if present, redact. Match the redaction discipline of prior screenshots in the same engagement.

### 8.3 PII black-bar protocol

**Mask (other-user data):** first/last name, email local part (domain OK if non-identifying), phone (last 7 digits), address below city, DoB year, government IDs entirely, faces, correlatable account IDs.

**Leave visible (proves the bug, not the user):** the JSON key name and field shape, YOUR attacker-session UID/email (proves cross-account), the endpoint URL/method, the trace ID.

Worked IDOR body:
```json
// Bad — leaks victim PII
{"contact":{"first_name":"Nadene","email":"nadene.afton@example.com","phone":"+1-555-867-5309"}}
// Good — proves the bug, masks the PII
{"contact":{"first_name":"<REDACTED — real first name>","email":"<REDACTED>@example.com","phone":"<REDACTED>"}}
```
In the report body, state the redaction explicitly and offer the unredacted version privately on request — it signals discipline and gives the triager a verification path.

### 8.4 HAR sanitization

Export: DevTools → Network → right-click → "Save all as HAR with content." Then strip sensitive headers with `jq`:
```bash
sanitize_har() {
  jq '
    .log.entries |= map(
      (.request.headers  |= map(if .name|ascii_downcase|IN("cookie","authorization","x-csrf-token") then .value="<REDACTED>" else . end)) |
      (.response.headers |= map(if .name|ascii_downcase|IN("set-cookie") then .value="<REDACTED>" else . end)) |
      (.request.cookies  |= map(.value="<REDACTED>")) |
      (.response.cookies |= map(.value="<REDACTED>"))
    )
  ' "$1" > "${1%.har}.sanitized.har"
}
```
Verify before attaching — if this prints a real value, the filter missed a field:
```bash
grep -i 'authn\|"cookie"\|authorization' exported.sanitized.har | head -20
```
For cross-account HARs, additionally `gsub` victim-PII substrings out of `.response.content.text`.

### 8.5 Burp screenshot hygiene
- **Repeater:** drag the request-panel divider down (or delete the Cookie header from the pane; it doesn't touch the original) and capture only the response panel showing the JSON/HTML that proves the bug.
- **Intruder (rate-limit / brute force):** the Results table is the strongest evidence. Drag the divider down so only the table shows; capture `Request#`, `Payload`, `Status`, `Length`. Never include the request/response sub-panels — they hold the cookie.
- **Proxy HTTP history:** almost never the right screenshot — use Repeater instead.

### 8.6 Console PoC patterns
```js
fetch('/api/endpoint', {
  method: 'POST',
  headers: {'content-type':'application/json'},
  credentials: 'include',              // cookies sent automatically, never in your code
  body: JSON.stringify({ /* payload */ })
}).then(r=>r.json()).then(j=>console.log("LABEL:", JSON.stringify(j)))
```
- Clear the console between multi-step calls (`Ctrl+L` / `Cmd+K`) so each screenshot shows one call and one response.
- For long responses, log only `Object.keys(j.data)` plus the critical fields, not the whole object.
- Type `allow pasting` once per session BEFORE any running-PoC screenshot, or the anti-self-XSS warning appears in the capture.

### 8.7 State-change PoC capture order

Canonical 5-screenshot pattern (e.g. password change without step-up), captured in one sitting without reloading:
1. **Pre-state** — `verify_password("current") → true`
2. **The bug** — `update_password(...)` succeeds without step-up (the key screenshot)
3. **Post-state negative** — `verify_password("old") → false`
4. **Post-state positive** — `verify_password("new") → true`
5. **Out-of-band** — inbox showing whether a notification email fired

Filenames: `{finding#}-step{n}-{description}.png`, e.g. `04-step2-update-password-no-stepup.png`. Reference each by filename in the report body.

### 8.8 Post-submission hygiene
- Rotate the test account: log out, log back in (kills any shown cookie), change the password (kills any shown password).
- Keep unredacted artifacts local; if the triager needs them, share only via the platform's private attachment thread — never email.
- Don't discuss the finding publicly until the program says you can. Sweep `~/Downloads` and research folders quarterly for stale HARs/screenshots.

### 8.9 Public-output OPSEC

When publishing anything public (README, blog, dashboard), NEVER include target company/domain names tied to vuln details, real person names or emails, internal IPs/hostnames/AD domains, or raw credentials. Replace with sector labels (`e-commerce site` not `wines.com`), ranges (`several users` not `11`), and pattern descriptions (`CORS credential reflection on WP REST API` not the target name). Grep before pushing:
```bash
grep -E '[a-z]+\.(com|io|app)' *.md
grep -E '[a-zA-Z.+-]+@[a-zA-Z-]+\.[a-zA-Z.]+' *.md
grep -E '10\.|172\.1[6-9]\.|192\.168\.' *.md
```

---

## Anti-patterns that lose money
```
Writing a report before confirming the bug exists (most common)
Submitting theoretical impact without proof
Chaining two separate bugs into one report (two separate payouts lost)
Reporting B as "similar to A" — fresh Gate 0 for every bug
Overclaiming severity — triagers trust you less next time
Under-describing impact — triager doesn't see why it matters
```

CWE anchors for severity write-ups: CWE-639 (IDOR), CWE-79 (XSS), CWE-89 (SQLi), CWE-918 (SSRF), CWE-287 (auth bypass), CWE-347 (JWT signature), CWE-200 (info disclosure).
