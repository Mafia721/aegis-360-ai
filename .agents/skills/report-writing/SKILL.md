---
name: Professional Report Writing
description: Produce a consulting-grade penetration test report grounded strictly in collected evidence.
tags: [reporting, documentation]
recommended_tools: []
domain: reporting
phase: reporting
---
# Professional Report Writing

Goal: a clear, defensible report a client or program can act on.

## Structure
- Executive summary (business-readable risk narrative)
- Scope, methodology (OWASP WSTG / MITRE ATT&CK as relevant), limitations
- Coverage matrix (tested vs untested categories)
- Findings: each with severity, confidence, reproduction, evidence, impact, remediation, references (CWE/CVSS)
- Remediation roadmap (immediate / short / long term)

## Rules
- Never fabricate evidence, requests, responses, or exploitation results.
- If something was not tested, say so explicitly.
- Severity reflects realistic attacker impact, not scanner defaults.
- Deduplicate findings; separate confirmed issues from informational observations.


<!-- Ingested from reference frameworks (skill-ingestion) -->
## Deterministic proof-level rubric (gate EXPLOITED on Level 3+)
Attach a level to every finding; when uncertain, round down.
```
L1  Injection point / sink confirmed (errors, timing delta, response variation)
L2  Query/structure manipulated (boolean blind works, UNION/ORDER BY column count, JS injected but filtered)
L3  Concrete impact proven (data extracted, JS executes in browser, OOB callback received) -> EXPLOITED bar
L4  Critical impact (admin creds dumped, RCE shell, account takeover, session hijack)
```
Hard rule: a finding is EXPLOITED only at L3+ with evidence reproducible from the report alone. `Reflected != executed`; `theory != impact`; `both return 200` is auto-rejected.

## Twin-request / differential proof requirement
Every finding must carry a 3-gate confirmation: (1) benign baseline/control request, (2) attack request, (3) a MEASURABLE diff — data the baseline can't access, distinct error, timing delta >=200ms (or ~5s for SQLi time-based), OOB callback, or invariant-violating state change. 'Both responses identical' = auto-reject. For authz, require disjoint evidence: low-priv actor succeeds AND true non-permitted actor gets 401/403 on the identical request.

## Bypass-exhaustion gate before FALSE POSITIVE
A finding may only be marked FALSE POSITIVE after >=3 distinct documented bypass techniques across vectors (encoding, obfuscation, second-order, blind) have failed, escalated manual -> scripted. List the techniques that failed. Ask: is the blocker a SECURITY control designed to stop this (=> honest FALSE POSITIVE) or an EXTERNAL operational constraint (=> POTENTIAL/blocked)? WAF/CSP blocking is an obstacle to bypass, not proof of safety.

## Vulnerability chaining / severity boost
Correlate individually low/medium findings into critical paths and upgrade severity automatically:
```
SSRF -> cloud metadata -> AWS keys -> lateral movement      => Critical
SQLi + IDOR                                                  => Account Takeover (Critical)
SQLi + directory listing                                     => full DB dump (Critical)
open redirect + OAuth redirect_uri                           => token theft / takeover
```

## Per-finding evidence block (reproducible-from-doc)
Record: exact request (method/path/headers/body), the control twin, the observed differential, the proof signal matched (e.g. `uid=0(root)`, `root:x:0:0:`, OAST hit id), proof level, and severity. Bind blind/OOB payloads to a per-finding correlation id so async callbacks map back to the exact probe.

---

## Modern techniques & real-world CVEs (via recon-skills)

The body above is optimized for bug-bounty **platform** submissions (one finding per report, triager audience). External **red-team / enterprise-client deliverables** are a different artifact: multi-finding DOCX/PDF, CISO + board audience, SOW-scoped. This section adds that format plus writing disciplines not covered above. Pick the format by engagement mode — do not mix them.

### Client-deliverable 6-section finding format

For enterprise deliverables, each finding follows Subject / Observations / Description / Impact / Recommendation / PoC — not the H1 Summary/Steps/Impact/Fix flow.

```markdown
## Finding F##: <descriptive title>

**Severity:** Critical / High / Medium / Low / Informational
**Status:** Confirmed / Confirmed; patched mid-engagement / Suspected (1 signal)
**CVSS 3.1:** <score> (<vector>)
**Affected Asset:** <URL / IP / app name>

### 1. Subject
<One-line, plain-English, jargon-free statement of the issue.>

### 2. Observations
<Bulleted concrete facts observed during testing — no interpretation yet. Past tense.>

### 3. Description
<2-4 paragraphs: WHY the observations indicate a vuln, what the underlying flaw is. Present tense for the flaw ("The application does not validate...").>

### 4. Impact
<Concrete attacker outcomes tied to business — money, data, reputation, regulatory. NOT generic CIA triad.>

### 5. Recommendation
<Specific, actionable, imperative. Name the patch/config/code fix — never "implement best practices".>

### 6. Proof of Concept
<Numbered steps, exact HTTP requests/curl, payloads, tool versions, screenshot ref.>
```

### The Status field (red-team-specific, absent from bug-bounty flow)

Bug-bounty reports have no notion of engagement-window state; red-team deliverables do. Use one of:

- **Confirmed** — reproduced multiple times, full PoC.
- **Confirmed; patched mid-engagement** — was reproducible, client patched during the test window. **Still ship it** with timestamps showing when it broke. A finding that stops reproducing is almost always a client patch, not a false positive — do not retract it.
- **Confirmed; partially reproducible** — works under specific conditions.
- **Suspected (1 signal)** — single indicator, not confirmed (rare — usually drop).
- **Out-of-band** — from passive recon, not actively tested.

### Findings bug-bounty rejects but red-team ships

The client paid to know these; do not silently drop them (mark Informational/Medium with stakeholder relevance):

- Information disclosure that aids attack mapping (framework debug toolbars leaking routes, version banners on appliances).
- User enumeration via response differentials (e.g. 302-vs-404, timing).
- Pre-existing security state (accounts already locked by an external attacker; weak password policy).
- Defensive observations (SOC patched the injection within 30 min — evidence of working detection — is a *positive* finding).
- Sister-app pattern issues (same vulnerable code template across N apps → multiplied blast radius).

Recon notes (subdomains, open ports, fingerprints) go in a **Recon / Attack Surface appendix**, never the findings list — a finding must have an attacker-attainable outcome.

### Document-level structure

```
1. Executive Summary (1 page, non-technical): scope/dates, risk heat-map, top-3 strategic recs
2. Engagement Details: scope, methodology (align to PTES / OSSTMM), tools+versions, timeline, team
3. Risk Summary Table (F# | Title | Severity | Status)
4. Findings (one ## per finding, Critical first)
5. Attack Surface / Recon Appendix (subdomains, ports, tech, breach-corpus creds — count+sample only, redacted)
6. Indicators of Compromise (source IPs, User-Agents, test accounts, files uploaded) — lets the SOC correlate
7. Cleanup Statement (what was created, what was removed, outstanding client-action items)
8. Appendices (raw output, screenshot index, full target list)
```

### Audience translation — one Impact, three altitudes

Start the Impact paragraph with the business outcome, then descend into technical detail so it serves every reader:

| Framing | Example (hardcoded JWT key in mobile APK) |
|---|---|
| Board | "A leaked secret in our mobile app lets attackers impersonate users." |
| CISO | "Anyone with the customer-facing app can read any customer's invoice." |
| Technical | "JWT signing key extracted from the APK enables forging admin tokens." |

### Regulatory / quantified impact anchoring

Replace CIA-triad boilerplate with breach-scale numbers and the specific regulation, which drives client urgency:

```
BAD:  "Loss of confidentiality and integrity of customer data."
GOOD: "Read access to 247,000 customer records incl. national-ID cards, addresses,
       tax numbers. India DPDPA Section 33 mandates 72-hour breach disclosure to the DPB."
```
Common anchors: GDPR Art. 33/34 (72h notification, EU), India DPDPA §33, US state breach laws, PCI-DSS for cardholder data. Cite the article/section, not just the acronym.

### DOCX generation pipeline (markdown to DOCX with embedded screenshots)

```bash
# Prereq: pandoc
pandoc REPORT_FINAL.md \
  -o REPORT_FINAL.docx \
  --resource-path=engagement_log/poc \
  --reference-doc=templates/reference.docx \
  --toc --toc-depth=2 \
  --highlight-style=tango

# Verify embedded image / structure counts match the MD
python3 -c "
from docx import Document
d = Document('REPORT_FINAL.docx')
imgs = [r for r in d.part.rels.values() if 'image' in r.target_ref]
print('images:', len(imgs), 'paragraphs:', len(d.paragraphs),
      'headings:', sum(1 for p in d.paragraphs if p.style.name.startswith('Heading')))
"
```

Screenshot naming: `screenshots/F<NN>_<descriptive>.png`, zero-padded finding number, letter suffixes for variants (`F02a`, `F02b`). Keep reusable boilerplate (executive_summary.md, methodology.md, cleanup_statement.md, reference.docx, cover.docx) in a `templates/` dir and clone per engagement rather than rewriting.

### Pre-delivery checklist (client deliverable)

```
[ ] Every finding has all 6 sections populated (no "TBD")
[ ] Every finding has >=1 screenshot or HTTP-level evidence
[ ] Every PoC redacts client PII (emails, phone, IDs masked)
[ ] Every screenshot path in the MD resolves; DOCX image count == MD reference count
[ ] Findings in severity order (Critical first)
[ ] Exec summary counts/themes match final findings
[ ] Cleanup statement lists what was created and removed
[ ] IoC section lets the SOC reconstruct testing activity
[ ] Tool versions noted in methodology; client/product names spell-checked
[ ] Status field correct on every finding (esp. patched-mid-engagement)
```

### Anti-patterns (calibration)

- Do NOT pad a 3-finding engagement into a 50-page report — page-padding erodes credibility.
- Do NOT use one severity for everything — calibrate against the business definition, not CVSS alone (a CVSS-Medium touching a regulated dataset can be Critical for the client).
- Do NOT copy OWASP Top-10 boilerplate into Description sections.
- Do NOT ship findings without a PoC — they read as speculative.
- The hedge ban applies identically here: "could potentially" / "it might be possible" get findings marked N/A. Prove it end-to-end on a test account, or downgrade the severity claim to what you actually demonstrated.
