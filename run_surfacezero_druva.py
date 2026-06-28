#!/usr/bin/env python3
"""
SurfaceZero Engagement Runner — support.druva.com
Dispatches the full pre-login attack-surface assessment prompt to
DeepSeek V4 Pro via OpenRouter, streams/collects the response, and
writes the report to pentest_reports/.
"""

import os
import sys
import time
from pathlib import Path
from dotenv import load_dotenv
from openai import OpenAI

# ── Load environment ──────────────────────────────────────────────────────────
load_dotenv(Path(__file__).parent / ".env")

OPENROUTER_API_KEY = os.environ["OPENROUTER_API_KEY"]
OPENROUTER_BASE_URL = os.environ.get("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
MODEL = os.environ.get("DEEPSEEK_V4_PRO_MODEL", "deepseek/deepseek-v4-pro")

# ── Recon intelligence gathered via SurfaceZero passive scan ─────────────────
RECON_EVIDENCE = """
=== PHASE 1 RAW EVIDENCE (collected via SurfaceZero passive scan) ===

TARGET: support.druva.com
PLATFORM: Salesforce Experience Cloud (Force.com Sites / Communities)
EVIDENCE OF PLATFORM:
  - robots.txt comment: "# default robots.txt for sfdc communities sites / For use by salesforce.com"
  - URL pattern: /s/ prefix = LWC Experience Cloud routing
  - CustomLoginPage = custom Visualforce login page
  - DRC_ prefix on all custom objects/pages = Salesforce custom namespace ("Druva Resource Center/Community")
  - /services/data/ endpoint returns full Salesforce API version array (unauthenticated)

SALESFORCE API DISCLOSURE (UNAUTHENTICATED):
  - Endpoint: GET https://support.druva.com/services/data/
  - Response: 34 API version objects, v31.0 (Summer '14) through v67.0 (Summer '26)
  - This confirms Salesforce org is on the latest release (API v67.0)

ROBOTS.TXT (verbatim):
  User-agent: *
  Allow: /
  Disallow: */secur/forgotpassword.jsp?*
  Sitemap: https://support.druva.com/s/sitemap.xml

SITEMAP URLS (from sitemap-view-1.xml, 11 entries):
  https://support.druva.com/s/contactsupport
  https://support.druva.com/s/
  https://support.druva.com/s/drc-announcementdetail
  https://support.druva.com/s/drc-announcementpage
  https://support.druva.com/s/druvacloudstatus
  https://support.druva.com/s/drc-discussiondetail
  https://support.druva.com/s/DiscussionsForums
  https://support.druva.com/s/drc-casedetail
  https://support.druva.com/s/drc-posttocommunity
  https://support.druva.com/s/SubmitNewCase
  https://support.druva.com/s/drc-viewmorecases

LOGIN PAGE OBSERVATIONS:
  - URL: https://support.druva.com/CustomLoginPage
  - Druva logo: /resource/1561367442000/Druva_Icons/images/Loginlogo.png
    (timestamp 1561367442000 = June 24, 2019 — static resource upload date)
  - "Forgot Password?" link → ./ResetPassword
  - "New User" link → href="#" (JavaScript-driven, resolves to /DRC_RegisterNewUser)
  - Privacy acknowledgment: "Druva's Privacy Policy ... sharing with third parties"
  - No CAPTCHA detected on login page or reset page
  - No X-Frame-Options or CSP meta tags detected in rendered HTML
  - Form action URL not captured (dynamically rendered via LWC/Aura)

REGISTRATION:
  - Path: https://support.druva.com/DRC_RegisterNewUser (custom VF page)
  - /SelfRegister → 404 (default SFDC path not in use)
  - /s/register → 404
  - Fields visible on DRC_RegisterNewUser: Email (*required), Phone (*required),
    Timezone dropdown (*required), Notification Preferences multi-picklist
    (inSync Cloud, inSync Gov Cloud, Phoenix Cloud, Phoenix Gov Cloud,
    Event Notification, Software Release, CloudRanger)
  - NO CAPTCHA detected on registration page
  - Post-registration: email sent with password assignment link
    (registration creates account before email verification — password set after)
  - Self-registration is OPEN (no invite gate observed)

OAUTH / SSO ENDPOINT:
  - GET /services/oauth2/authorize?response_type=code&client_id=PROBE&redirect_uri=...
    → HTTP 400 (endpoint is ACTIVE, not 404; processes and validates request)
  - Confirms OAuth/Connected App infrastructure is configured on this Salesforce org

OPEN REDIRECT CANDIDATE (startURL parameter):
  - Login page accepts: /CustomLoginPage?startURL=https://example.com
  - Page renders normally (login form shown); no client-side redirect pre-auth
  - Post-auth redirect behaviour not verifiable without authentication
  - Observed startURL patterns in search-indexed URLs:
      /CustomLoginPage?startURL=/DRC_AnnouncementDetail?annId%3Da1e3t000004UD79AAG
      /CustomLoginPage?startURL=/DruvaCloudStatus
      /CustomLoginPage?locale=us
  - Salesforce record IDs exposed in startURL-indexed pages:
      a1e3t000004UD79AAG, a1e380000047DaAAAU, a1e3t000008YWzPAAW, a1e3t000004vHZUAA2
    (object key prefix 'a1e' = custom DRC_ object; not an org ID leak by itself)

FORGOT PASSWORD / ACCOUNT ENUMERATION:
  - Reset page: /ResetPassword
  - Only a username/email field visible
  - No CAPTCHA detected
  - Error message behavior: NOT CONFIRMED (could not force error without submitting
    real email values)
  - Risk: standard Salesforce community reset pages historically return
    distinct responses for valid vs invalid usernames (enumeration risk)

PARTNER & ADJACENT SUBDOMAIN MAP (from crt.sh CT logs):
  - support.druva.com           — this target (Salesforce Experience Cloud)
  - partnersocial.druva.com     — Drupal CMS, SAML SSO via partnerportal.druva.com
  - partneracademy.druva.com    — HTTP 403 (IP-restricted or hard-blocked)
  - logindstg.druva.com         — staging login instance (responds, minimal content)
  - stgfederal.druva.com        — staging federal instance (resolves, empty response)
  - dev-cloudranger-login.druva.com — dev CloudRanger login
  - stage-cloudranger-login.druva.com — staging CloudRanger login
  - federal.druva.com           — federal tenant
  - au-login.druva.com          — Australia region login
  - login.druva.com             — primary Druva platform login (separate from support portal)
  - security.druva.com          — security subdomain
  - developer.druva.com         — developer portal

PARTNER PORTAL SSO FINDING:
  - partnersocial.druva.com → HTTP 302 → partnerportal.druva.com/auth/saml2/idp/sso.ashx
  - IdP: partnerportal.druva.com (ASP.NET / .ashx extension — IIS-based)
  - RelayState: https://partnersocial.druva.com/reseller/socialmedia/reviewpost/
  - Separate auth stack from the Salesforce Experience Cloud at support.druva.com
  - SAML AuthnRequest encoded in redirect (base64+deflate standard SAML SP-initiated flow)

THIRD-PARTY SCRIPTS / ANALYTICS:
  - No third-party analytics, chat widgets, or CDN URLs detected in pre-auth rendered HTML
  - (Dynamic JS content may load additional third-party scripts post-auth)

AURA / LWC PRE-AUTH ACCESS:
  - GET /aura?... → redirected to login page (not pre-auth accessible)
  - /s/sfsites/auraFW/javascript/.../aura_prod.js → 404

SOURCE MAPS:
  - No //# sourceMappingURL references detected in accessible pre-auth HTML
  - Full JS bundle content not retrievable without browser execution context

AUTHENTICATED CONTENT AUTH-GATING:
  - /DRC_AnnouncementDetail?annId=a1e380000047DaAAAU → redirected to login
    (authenticated content is properly gated)
  - All /s/ LWC routes not tested for pre-auth access
"""

# ── Full engagement prompt ────────────────────────────────────────────────────
SYSTEM_PROMPT = """\
You are a senior Red Team operator and application security assessor. You have been \
given passive reconnaissance evidence collected during a SurfaceZero-style pre-login \
attack-surface assessment of support.druva.com (Salesforce Experience Cloud). \
Your task is to produce the complete, structured security assessment report covering \
all three phases: RECON findings synthesis, VULNERABILITY ASSESSMENT (configuration-level, \
non-exploit), and ATTACK CHAIN MAPPING (MITRE ATT&CK + STRIDE + Kill Chain). \
Do NOT describe exploit code, working PoC, or actual payload execution. \
Describe attack paths narratively to enable defensive prioritisation only.
"""

USER_PROMPT = f"""\
You are a senior Red team operator and application security assessor performing an authorized,
pre-login attack-surface assessment of a Salesforce Experience Cloud (Community) login portal
at support.druva.com. This is a SurfaceZero-style engagement:
RECON -> VULNERABILITY ASSESSMENT -> ATTACK CHAIN MAPPING ONLY.

SCOPE:
- Target: support.druva.com (Salesforce Experience Cloud / Force.com Sites)
- In-scope: CustomLoginPage and pre-login surface (login, registration, forgot password,
  SSO/social login options, error pages, static resources)
- Out of scope: exploitation, payload injection, brute force, multi-tenant data access

ENGAGEMENT CONSTRAINTS:
- No SQLi/XSS/SSRF/template injection payloads
- No automated brute force or credential stuffing
- No access to other tenants' data
- No CAPTCHA bypass, no DoS-style traffic
- Attack chains are described narratively ONLY — no working PoC

Below is the complete passive reconnaissance evidence collected during Phase 1.
Use this evidence to produce the full assessment report.

{RECON_EVIDENCE}

---

OUTPUT FORMAT REQUIRED:

## 1. Executive Summary
(3-5 bullets, business-risk framed for a non-technical stakeholder)

## 2. Recon Findings (Phase 1)
(Structured list, each finding with: Finding ID, Category, Description, Evidence Reference, Severity indicator)

## 3. Vulnerability Assessment (Phase 2)
(For each finding: Finding ID, Title, Category, CVSS v3.1 Base Score [estimated, no PoC],
CVSS Vector, Severity [Critical/High/Medium/Low/Informational], Description,
Evidence, Label: "Configuration Observation" unless non-destructively confirmed)

## 4. Attack Chain Table (Phase 3)
Produce a Markdown table with columns:
| Finding ID | STRIDE Category | ATT&CK Technique (ID) | Kill Chain Stage | Plausible Chain (narrative — no PoC) | Likelihood | Impact | Mitigation |

Include chains for:
- Open redirect on startURL → post-auth phishing lure
- Account enumeration via reset-page response variance → targeted credential stuffing
- No CAPTCHA on login/register → automated account creation / credential stuffing
- Missing/weak frame-ancestors (if applicable) → clickjacking on login/register
- API version disclosure → Salesforce org fingerprinting → adjacent attack surface
- Open self-registration → unauthorized community access / spam account creation
- SAML IdP (partnerportal.druva.com) adjacent attack surface
- Static resource timestamp leak → org configuration reconnaissance
- Staging/dev subdomain cluster → weaker-control lateral pivot

## 5. Recommendations
(Mapped to each finding ID, prioritised P1/P2/P3, with specific Salesforce
Experience Cloud configuration guidance where applicable)

## 6. Scope & Limitations Statement
(Standard engagement scope disclaimer)
"""

# ── Call DeepSeek V4 Pro via OpenRouter ──────────────────────────────────────
def main():
    client = OpenAI(api_key=OPENROUTER_API_KEY, base_url=OPENROUTER_BASE_URL)

    print(f"[*] Dispatching SurfaceZero assessment to {MODEL} via OpenRouter...")
    print(f"[*] Target: support.druva.com")
    print(f"[*] Prompt size: {len(USER_PROMPT):,} chars")
    print("-" * 72)

    start = time.time()

    response = client.chat.completions.create(
        model=MODEL,
        max_tokens=8192,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": USER_PROMPT},
        ],
    )

    elapsed = time.time() - start
    report = response.choices[0].message.content

    print(f"[+] Response received in {elapsed:.1f}s ({len(report):,} chars)")
    print(f"[+] Model: {response.model}")
    print(f"[+] Usage: {response.usage}")
    print("=" * 72)
    print(report)
    print("=" * 72)

    # Save report
    out_dir = Path(__file__).parent / "pentest_reports"
    out_dir.mkdir(exist_ok=True)
    out_path = out_dir / "surfacezero-druva-support-prelogin.md"
    out_path.write_text(report, encoding="utf-8")
    print(f"\n[+] Report saved to: {out_path}")


if __name__ == "__main__":
    main()
