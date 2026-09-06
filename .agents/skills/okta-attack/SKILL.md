---
name: Okta IdP Assessment
description: Assess Okta-as-IdP tenants — tenant discovery, disciplined user enumeration, authentication/factor flow analysis, MFA-fatigue and redirect_uri risks, and post-compromise admin API surface.
tags: [okta, idp, sso, mfa, identity, enumeration]
recommended_tools: [curl, jq, python3, httpx_probe]
vuln_classes: []
domain: cloud
phase: exploitation
provenance: {source: uphiago/recon-skills, paths: [redteam/okta-attack/SKILL.md]}
---
# Okta IdP Assessment

Many enterprises use Okta as their identity provider. It has distinct endpoints, rate-limiting, and factor
flows from Entra ID. Goal: confirm the tenant, enumerate identities and factors **without triggering lockout**,
and identify auth-flow weaknesses (weak factors, redirect_uri tampering, MFA fatigue) — all within the
engagement's rules of engagement.

## When to use
Recon shows `<tenant>.okta.com`, `<tenant>.okta-emea.com`, `<tenant>.oktapreview.com`, a corporate login that
redirects to Okta, or DNS CNAMEs pointing at Okta.

## Tenant discovery
```
# Direct: tenant slug often matches the brand
curl -s -o /dev/null -w '%{http_code}' https://BRAND.okta.com/
# DNS: CNAMEs to okta
dig +short login.corp.example.com
# App flow: follow a corporate app login redirect → <tenant>.okta.com confirms the tenant
```

## User enumeration (disciplined — counts as auth attempts)
- **`/api/v1/authn` differential:** a single probe per user returns different status/JSON for valid vs invalid
  users on some configs. Probe **one** user to establish the differential; do NOT spray here.
- **Well-known metadata:** `/.well-known/openid-configuration`, `/oauth2/default/.well-known/...` for endpoints,
  supported factors, and policies.
Feed confirmed usernames to a **lockout-aware** spray (see authentication-testing) — respect the org's
`maxAttempts`/lockout policy; low-and-slow, and stop on the first sign of lockout.

## Authentication & factor flow analysis
- **Enumerate factors** offered for an account (`/api/v1/authn/factors`): SMS/Voice (weak), Okta Verify push,
  FastPass, WebAuthn (strong). Flag reliance on phishable factors.
- **MFA push fatigue:** if push is enabled, note whether number-matching is enforced; unbounded push prompts
  are a real risk (report as a policy finding — do not actually spam a real user).
- **SMS/Voice fallback bypass:** whether a user can downgrade from a strong factor to SMS.

## OIDC / redirect_uri
Inspect the OIDC apps' `redirect_uri` validation: open/loose matching (wildcards, path-append, subdomain)
enables auth-code/token theft. Test per the oauth-security skill's redirect_uri matrix.

## Post-compromise admin surface (only with a legitimately obtained admin session)
Okta admin APIs (`/api/v1/users`, `/api/v1/apps`, `/api/v1/logs`) expose the full identity graph and app
assignments. Enumerate read-only to scope blast radius; do not create backdoor users/factors outside an
explicitly authorized objective.

## Validation gate
- User enum: the concrete differential (status/body) distinguishing valid vs invalid, from a single probe.
- Weak-factor/redirect finding: the exact configuration evidence (factor list, redirect_uri accepted).
- Never report enumeration from an untested assumption; never trigger real lockouts or push-spam a real user.

## Remediation (attach to findings)
Enforce phishing-resistant factors (WebAuthn/FastPass with number-matching); disable SMS/Voice fallback;
strict exact-match `redirect_uri`; ProfileEnumeration protection + tight lockout/rate policies; monitor
`/api/v1/logs` for spray/fatigue patterns.
