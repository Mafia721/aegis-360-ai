---
name: Bug Bounty Methodology
description: Master orchestrator for offensive engagements — 5-phase non-linear hunting workflow, attacker mindset, escalation ladders, and finding-correctness discipline gates that keep results out of the N/A pile.
tags: [methodology, recon, mindset, workflow, escalation, validation]
recommended_tools: [http_request, http_repeater, http_intruder, httpx_probe, nuclei_scan, subfinder_scan, katana_crawl, gau_discovery, waybackurls_discovery, arjun_parameter_discovery, paramspider_discovery, ffuf_scan, dalfox_xss_scan, sqlmap, wafw00f_scan, trufflehog, curl, python3, jq]
vuln_classes: []
domain: general
phase: recon
provenance: {source: uphiago/recon-skills, paths: [redteam/bb-methodology/SKILL.md, redteam/redteam-mindset/SKILL.md]}
---

# Bug Bounty Methodology: Workflow + Mindset

Master orchestrator for hunting sessions. Combines the 5-phase non-linear workflow with the attacker mindset and the finding-correctness discipline that separates confirmed impact from artefacts. Use this at the START of any session, when switching targets, or whenever you feel lost about what to do next.

---

## PART 0: MODE CONFIRMATION (Before Anything Else)

Confirm the engagement type before deciding what counts as a finding. The same target produces a different report shape depending on the mode. Getting this wrong is the single biggest waste of time in the workflow — answer it explicitly before Phase 0 and write it as the first line of your hunt notes.

| Engagement type | What counts as a finding | What gets rejected |
|---|---|---|
| **Bug bounty** (H1 / Bugcrowd / Intigriti / VDP) | Impact-demonstrated bugs ONLY. Full chain to attacker-attainable harm. | Hygiene alone (EoL software, permissive CSP, stack traces, info disclosure without impact, "best practice" nits) |
| **Red team** (external client) | Hygiene + recon + IoCs + defensive-state observations are ALL deliverables | Nothing — even "no finding here" is a positive defensive observation |
| **Pentest** (signed SoW / WAPT) | Depends on SoW. Usually accepts hygiene + impact + recon | Out-of-scope assets, unsigned testing |
| **Internal audit** | Compliance-mapped findings (PCI / ISO / NIST / GDPR) | Findings without a control mapping |

**Reading mixed scope language:** `in-scope`/`out-of-scope`/`safe harbor` → bug-bounty discipline (validation-heavy, OOB-required, no exfil). `kill chain`/`objectives`/`adversary emulation`/`assume breach` → red-team (stealth, persistence, lateral movement valid). `compliance`/`PCI`/`HIPAA`/`remediation timeline` → WAPT (coverage-driven, all findings count regardless of exploitability). When language is mixed, **default to bug-bounty discipline** (strictest) until the client confirms otherwise — the reverse (assuming red-team latitude on a WAPT) gets findings retracted at delivery.

---

## PART 1: MINDSET (How to Think)

Hunting is not "find a bug" — it is "prove an attack scenario." Think like an attacker with a specific goal, not a scanner looking for patterns.

**Daily discipline — Define, Select, Execute (before touching any tool):**
1. **Define:** "Today I target [feature/domain] to achieve [C/I/A/ATO/RCE]."
2. **Select:** Choose 1-2 vuln classes (IDOR, race condition, SSRF, etc.).
3. **Execute:** Focus ONLY on selected techniques. No wandering.

**5 ultimate goals (pick one per session):** Confidentiality (steal data), Integrity (modify data), Availability (app-level DoS only), Account Takeover, RCE.

### Question trust boundaries
- Frontend control disabled? Send the request directly via `http_repeater`.
- `user_role=user` cookie? Change to `admin`.
- `price=1000` in POST? Change to `1`.
- `<script>` blocked? Try `<img onerror=...>`.

### Reverse-engineer developer psychology
- Feature A has auth checks → similar feature B (newly added) probably doesn't.
- Complex flows (coupon + points + refund) → edge cases have bugs.
- `/api/v2/user` exists → does `/api/v1/user` still work with weaker auth?

### What-If experiments
- Skip checkout → hit `/checkout/success` directly.
- Skip 2FA → navigate to `/dashboard`.
- Send the coupon request 10x simultaneously → race condition?
- Replace `guid=f8a2...` with `id=100` on a sibling endpoint → IDOR?

### Multi-perspective angles
| Perspective | What to check |
|------------|---------------|
| Horizontal (same role) | User A's token + User B's ID → IDOR |
| Vertical (different role) | Regular user → `/admin/deleteUser` |
| Data flow (proxy view) | Hidden params in JSON: `debug=false`, `discount_rate` |
| Time/State | Race conditions, post-delete session reuse |
| Client environment | Mobile UA → legacy API with weaker auth |
| Business impact | "What's the $ damage if this breaks?" |

### Tactical anomaly detection
- **Naming anomaly:** `userId` everywhere but suddenly `user_id` → different dev, weaker security.
- **Error diff:** same 403 but different JSON structure → different backend systems.
- **Environment diff:** prod vs dev/staging → debug headers, CSP disabled.
- **Version diff:** JS file before/after update → new endpoints, removed params.
- **Supply chain:** check framework/library versions for known CVEs.
- **Third-party integration:** Stripe/Auth0/Intercom → webhook signature missing?

### Anti-patterns (stop doing these)
- **Program hopping:** stick with one target minimum 2 weeks / 30 hours.
- **Tool-only hunting:** automation finds duplicates; manual testing finds unique bugs.
- **Rabbit hole:** max 45 min per parameter. Set a timer. If stuck, move on.
- **No goal:** "just looking around" = wasted time. Always Define first.

---

## PART 2: WORKFLOW (What to Do)

The 5 phases are **non-linear**. Move freely between them. When stuck, return to a previous phase (new API found at Phase 3 → back to Phase 2; WAF blocks at Phase 4 → origin IP from Phase 1).

```
RECON → MAP → FIND → PROVE → REPORT
  ^_______________|______|         (stuck anywhere → go back)
```

**Route selection — Wide or Deep?** Wide (recon sweep) for a new program, first day, wildcard scope `*.target.com`, or a scope update. Deep (focused testing) for a main webapp you've been on >3 days or an interesting subdomain you just found.

**Phase priority shifts by engagement type** (the phases are not equal-weight):

| Engagement | Recon | Hunt | Validate+Report |
|---|---|---|---|
| SaaS bug-bounty (defined scope) | 10% | 70% | 20% |
| External red-team (wide scope) | 40% | 30% | 30% |
| WAPT (asset list provided) | 0% | 60% | 40% |
| Enterprise on-prem (single product) | 5% | 50% | 45% |

If you're spending 50% of a SaaS bug-bounty in recon, you're procrastinating on the hunt. If you're spending 10% of an external red-team on recon, you've lost — the attack-surface map IS the deliverable there.

### Phase 1: RECON
**Goal:** maximize attack surface; find what others missed.
- **Wide:** subdomain enum (`subfinder_scan`) → DNS resolution → HTTP probing (`httpx_probe`) → port scan (`nmap_scan`) → tech detect (`whatweb_scan`/`wappalyzer_scan`).
- **Deep:** Google Dorks → JS file download → hidden param discovery → API mapping.
- **URLs:** archive first (`gau_discovery` + `waybackurls_discovery` — forgotten endpoints) → active crawl (`katana_crawl` — JS-rendered) → deduplicate.
- **JS/secrets:** extract URLs and API keys from bundles, then verify keys actually work with `trufflehog` (`--only-verified` to kill false positives).
- **Scan:** `nuclei_scan` CVE tags first → then subdomain-takeover tags (act immediately).

| What you find | Next action |
|--------------|-------------|
| Live subdomains with tech stack | Phase 2 |
| Known software (WordPress, Jira) | Check CVEs + defaults immediately |
| Cloud resources (S3, Firebase) | Test permissions (read/write/list) |
| Nothing after 5 min on a host | Skip, next host (5-minute rule) |

### Phase 2: MAPPING & ANALYSIS
**Goal:** understand the app like its developer does.
- Map all endpoints (proxy sitemap + JS analysis).
- Identify the auth model (cookie, JWT, OAuth, SAML).
- Find business-critical flows (payment, registration, password reset, data export).
- Download/analyze JS for hidden routes, secrets, logic.
- Identify roles and permissions (user, admin, API keys).
- Brute hidden params (`arjun_parameter_discovery` + `paramspider_discovery` + cache-header mining).
- Note "weird" behaviors (naming/error/timing anomalies).

### Phase 3: VULNERABILITY DISCOVERY
**Goal:** find the bug. Error-based first, then blind. Route by input type:

```
ID parameter (user_id, order_id)  → IDOR checklist
Search/filter/sort field          → SQLi / NoSQLi probing (sqlmap)
URL input / webhook / PDF gen     → SSRF checklist
Text reflected in page            → XSS DOM/reflected (dalfox_xss_scan)
File upload                       → SVG XSS, web shell, path traversal
Price/quantity/coupon             → business logic, race conditions
Login / 2FA / password reset      → auth bypass
Profile update API                → mass assignment
Template / wiki editor            → SSTI
Nothing obvious                   → fuzz (ffuf_scan), error-based probing
```

**Error vs Blind decision ladder:**
1. Error-based first — send `'`, `"`, `{{7*7}}`, `${7*7}`; watch for 500s and stack traces.
2. No error? Time-based (`SLEEP(10)`, `; sleep 10;`); watch response time.
3. No time diff? OOB (`curl attacker.com`, interactsh); watch for DNS callback.
4. Still nothing? Boolean (`AND 1=1` vs `AND 1=0`); watch content-length diff.

### Phase 4: PROVE & ESCALATE
**Goal:** prove maximum business impact. Turn Low into Critical.

```
XSS
  ├ Can steal cookie/token?  → session hijack → ATO
  ├ Cookie HttpOnly?         → force email change via XHR → ATO
  └ Self-XSS only?           → find CSRF to trigger it
IDOR
  ├ Read PII?                → automate scraping, show scale
  ├ Change password/email?   → direct ATO
  └ UUID only?               → find UUID leak source, retry
SSRF
  ├ DNS only?                → DON'T REPORT alone. Try cloud metadata
  ├ Reach 169.254.169.254?   → extract IAM keys → cloud/RCE
  └ Internal port scan?      → find Redis/K8s → RCE
SQLi
  ├ Error-based?             → extract passwords/tokens
  ├ INTO OUTFILE?            → web shell → RCE
  └ Blind?                   → boolean/time extraction
Open Redirect
  ├ OAuth flow?              → token theft → ATO
  └ javascript: scheme?      → XSS
Blocked by defense           → bypass (WAF/CSP/proxy/sanitizer/2FA), then retry
Low-impact, can't escalate   → find connector gadget for a chain
```

After proving impact: Can it work with 0-1 clicks? Does it affect all users or one role? What's the business $ impact?

### Phase 5: VALIDATE & REPORT
**Goal:** get paid; make the triager's job easy. Run the validation gate (PART 4) before writing. Any fail → KILL the finding, don't waste time.

Report format: platform-specific (H1/Bugcrowd/Intigriti/Immunefi). Title = `[Bug class] in [endpoint] allows [role] to [impact]`. Impact-first summary (sentence 1 = what the attacker CAN do). Exact HTTP requests in Steps to Reproduce. Under 600 words. CVSS 3.1 that matches actual impact.

**After submission:** while waiting for triage, try to escalate further; if a fix deploys, re-test for bypass (an incomplete patch is a new bug).

---

## PART 3: NAVIGATION, TIMING & RED-TEAM AGGRESSION

### 20-minute rotation clock
Every 20 minutes: "Am I making progress?" Yes → continue. No → rotate: endpoint → subdomain → vuln class → target. Same target 2+ weeks with no findings → consider switching program.

### When to break the methodology
If you find a Critical in the first 30 minutes of recon, **stop reconning, validate the Critical fully, report it, then return to recon.** A confirmed Critical paying out within 24h is worth more than a comprehensive asset list you'll never chain. Conversely, if a candidate won't reproduce on a second account after 4+ hours, it's dead — document the retraction and move on.

### DO NOT STOP — the primary directive (red-team / full-engagement modes)
Discipline rules answer "is this signal actually a finding?" — they never answer "should I send the next probe?" That answer is always **yes** unless scope is exhausted or the user said stop. "Stop at PoC" means stop **escalating** class X, not stop **testing** classes Y and Z. Coverage discipline and finding-correctness discipline are orthogonal axes — you need both on full.

**Self-throttling anti-patterns — flag if you catch yourself:**
- Asking "want me to continue?" after the user already chose a full-engagement mode. Authorization at engagement start covers the whole engagement; a mid-loop question is a stall, not a check.
- Stopping at the first class returning 401/403. There are 12+ auth-bypass classes (header tricks, method tampering, param pollution, JSON parser confusion, race on session create, mass-assignment on optional fields, X-Forwarded-Host in SAML callback, `alg=none` JWT, audience confusion, scope-claim manipulation, refresh-token replay, device-code flow). Run them all per surface.
- "Interesting constant token, not chased." A constant hash/ID across varying responses is a lead — GET it, decode it, pass it back.
- Reading `robots.txt` and NOT reading the `Disallow` lines. Every Disallow is a developer-curated probe target. Same for `sitemap.xml`.
- Treating a soft-404 as "noted." A 37 KB body inside a 404 is leaking a real page — read, grep, diff it against the home page.
- "OpenAPI exposed → logged" with only some endpoints probed. The spec is the attack-surface map handed to you: every endpoint × every relevant class.
- Skill-gap-as-stop-condition. No dedicated playbook for a discovered tech stack → run the vendor's public check matrix manually now; log the gap separately.

### Sister-app / A→B signal recognition
When you confirm a vuln on app A, sibling apps B, C, D on the same host likely share the code template. Identify shared infrastructure (same IP, LB, TLS cert, headers, cookie name, login-form HTML) and shared code template (same fields, error messages, framework version), then sweep all siblings with the **same** payload immediately. Document as a class vulnerability in the shared handler, and recommend a class-fix, not a single-app patch.

### Blocker decision trees (persistence beats elegance)
A blocker is **data, not a stop sign** — the next move is another vector to the same goal, not "documented as not vulnerable."
- **WAF:** slower pace → encode payload (URL/hex/base64/mixed case) → different injection context (cookie/header/JSON) → different HTTP verb → different content-type (multipart, `application/json`) → host-level bypass (`X-Forwarded-Host`, `X-Original-URL`) → probe origin server directly (find via certificate transparency). Fingerprint first with `wafw00f_scan`.
- **Rate limit:** IP rotation (multiple cloud regions) → UA rotation → slower pace + jitter → distribute across TLS sessions.
- **Captcha:** omit field (required?) → empty value → reuse value across submits (session-bound?) → OCR with preprocessing → trained-model OCR → paid solving service → audio captcha (weaker). A real attacker will invest the $5.
- **Slow timing exfil:** different injection point → `BENCHMARK`/`GET_LOCK` oracle → error-based extraction → OOB DNS callback → cloud VM in the target's region → run the dumper unattended overnight, deliver partials.

### Real-time IR observation is a finding
If a defense disappears mid-test (client SOC patched), capture timestamps before/after, document as a positive operational finding ("detected + mitigated within X min"), verify mitigation depth (WAF rule = bypassable vs code fix = real), and remember the original PoC still stands — patching does not erase the finding.

---

## PART 4: METHODOLOGY DISCIPLINE (False-Positive Prevention)

These are quality gates on finding correctness, not effort throttles. Most retracted findings come from these recurring process bugs. Each has a hard rule.

### Marker Discipline
The marker string you inject MUST be unique and unmistakable.
- Random alphanumeric, **8+ chars**, no English words, no protocol keywords.
- **NEVER** use `test`, `marker`, `evil`, `attacker`, `payload`, `javascript`, `script`, `AAAA`, your domain, or anything that could appear naturally in the target's HTML/JS/errors.
- Good: `cpmark987abc`, `x4hd2k9pq`, a Collaborator subdomain prefix, `__ZZ_MARKER_<random>_ZZ__`.
- Before claiming reflection, search the **baseline** (no-marker) response for the marker. If it appears naturally, change it — this single check catches ~80% of false-positive reflections.
- Marker Discipline is about WHICH payloads (synthetic, identifiable, recoverable) — never HOW MANY. A hardened target needs MORE marker-discipline probes, not fewer.

*Real case:* `X-Forwarded-Proto: javascript` appeared to reflect into SharePoint pages — but the word `javascript` occurs naturally in SP help-link hrefs (`href="javascript:HelpWindowKey(...)"`). False positive from a non-unique marker.

### Body-Diff Rule
A bypass claim requires a response **body** differential, not just a status code.
- 200 OK with byte-identical body to baseline is NOT a bypass.
- Always diff side-by-side: `diff <(curl ... baseline) <(curl ... bypass)`.
- Status-code-only claims (e.g., "Host header X gave 200 instead of 403") are the most common rejected-as-N/A category.

*Real case:* `Host: target.example:80@evil.example.com` returned 200 instead of 403 — but the body was byte-identical (8341 bytes both). The AWS ELB normalised the Host, dropping `@evil`. Not a bypass.

### Statistical-Sample Rule (timing claims)
Single outliers are NOT signal — network jitter routinely produces 2× outliers.
- Minimum **n ≥ 10 interleaved trials per group** (control + test, randomised order, not back-to-back).
- Compute mean, median, σ per group. A signal requires the suspect group's mean **≥ 2σ above** control's mean.

*Real case:* A single probe showed `Administrator` at 1527 ms vs ~700 ms control on a login endpoint — looked like user-enum. n=80 interleaved trials collapsed every group to mean 685-716 ms, σ 25-74 ms. The 1527 ms was jitter. Retracted.

### Shell-Loop Ban (>5 iterations)
For any iteration running more than 5 times, use `python3` (with try/except per iteration), not shell for-loops. Shell array expansion fails silently on edge cases and can produce zero iterations with no error, so output looks complete while every test was skipped. Loops of ≤5 hardcoded items in shell are fine. Always count results — if you expected 100 probes and got <50 lines, the loop ate something.

### Multi-tool reproduction bar (Critical / High only)
Before labeling a finding Critical or High, reproduce it via **two independent tools** (different stacks, different HTTP libraries) — e.g., `curl` + `http_repeater`, or `python3` requests + a raw socket. Cross-tool consistency rules out tool-artefact findings (a curl-only timing differential that vanishes under Python `requests` was an artefact). Reproduction commands in the report MUST be paste-into-shell ready; if the curl version needs special flags, include a Python alternative.

### Cross-validate every finding via 2+ techniques
| Vuln class | Primary | Cross-check |
|---|---|---|
| Time-based blind SQLi | SLEEP() differential | 3+ distinct SLEEP payloads |
| Boolean blind SQLi | Body-size differential | Different boolean comparisons |
| Error-based SQLi | Error reflection | UPDATEXML + EXTRACTVALUE both |
| RCE | Command output reflection | OOB callback (DNS) |
| LFI | File content reflection | Different paths/encodings |
| SSRF | Internal-only response | OOB callback (DNS) |
| Auth bypass | Logged-in landing page | Session cookie persistence on next request |

---

## Legitimate stop conditions

Only stop when: every in-scope asset has been **actively probed** (not just discovered) for top vuln classes; every confirmed vuln validated via 2+ techniques and swept on sister apps; every blocker attempted via 2+ alternative vectors; the engagement window has expired with deliverables documented; or the client explicitly directed you to stop.

NOT legitimate: "I'm tired," "the first attempt didn't work," "defenses are working" (on class X — says nothing about Y, Z), "I documented it" (documenting a gap is not running the test), "volume is high" (the only volume question is whether each request is well-tagged), or "the tool isn't installed" (most engagement tools install in under 5 minutes).
