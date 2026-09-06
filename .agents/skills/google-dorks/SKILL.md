---
name: Google Dorks for Exposed Configs & Secrets
description: High-precision Google/GitHub dork catalog to surface exposed .env files, credentials, API keys, and configs during passive recon before active scanning.
tags: [recon, osint, google-dorks, secrets, info-disclosure]
recommended_tools: [curl, python3, jq, httpx_probe, gau_discovery, waybackurls_discovery, trufflehog, gitleaks]
vuln_classes: [info_disclosure]
domain: recon
phase: recon
provenance: {source: uphiago/recon-skills, paths: [meta/google-dorks-catalog/SKILL.md]}
---

# Google Dorks for Exposed Configs & Secrets

Search-engine and code-search reconnaissance to surface leaked credentials, API keys,
private keys, and misconfigured configuration files that a target has inadvertently
indexed. This is passive/OSINT recon: no packets hit the target's application until you
validate a candidate hit. CWE-200 (Exposure of Sensitive Information), CWE-540
(Information Exposure Through Source Code), CWE-312 (Cleartext Storage).

## When to Use

- During passive reconnaissance on every in-scope target, before any active scanning.
- After passive subdomain enumeration (crt.sh / CT logs, `subfinder`) to fold newly
  discovered hostnames into `site:` queries.
- Any time you need a fast, low-noise signal of where secrets may already be public.

Substitute `$target` with the apex domain (e.g. `example.com`). Run each query for the
apex and for high-value subdomains discovered in enumeration.

## Ordered Methodology

1. Enumerate the domain surface (subdomains, indexed hostnames).
2. Run the critical-file dork ladder below against each host.
3. Run service-specific key dorks (AWS / Firebase / Supabase / Stripe / etc.).
4. Pivot to GitHub/GitLab code search for the org and its domains.
5. Validate every candidate hit deterministically (Gate 0) before reporting.
6. Chain confirmed secrets into the relevant attack (cloud, DB, auth bypass, IDOR).

## High-Precision Google Dorks

### Critical Exposed Files & Inline Secrets

```
site:$target "APP_KEY"
site:$target "DB_PASSWORD"
site:$target "-----BEGIN RSA PRIVATE KEY-----"
site:$target "-----BEGIN OPENSSH PRIVATE KEY-----"
site:$target filetype:env
site:$target inurl:git/config
site:$target intitle:"index of" ".env"
site:$target intitle:"index of" "backup"
site:$target "api_key" OR "apikey" OR "secret_key"
site:$target "firebase" "apiKey"
site:$target "supabase" "anon" "key"
site:$target inurl:"/.env" "DB_PASSWORD"
site:$target "client_secret" "redirect_uris" extension:json
site:$target "private_key" "client_email" extension:json
```

### Exposed Configuration Files (all sensitive extensions)

```
site:$target ext:log | ext:txt | ext:conf | ext:cnf | ext:ini | ext:env | ext:sh | ext:bak | ext:backup | ext:swp | ext:old | ext:~ | ext:git | ext:svn | ext:htpasswd | ext:htaccess | ext:json
```

What each extension tends to leak:

- `log` -- tokens, SQL queries, emails, stack traces in plaintext.
- `txt`/`conf`/`cnf`/`ini` -- server configs, DB hosts, connection details.
- `env` -- environment variables with live credentials.
- `sh` -- deploy/cron scripts with hardcoded passwords.
- `bak`/`backup`/`swp`/`old`/`~` -- backup copies of source or config (e.g. `.env.bak`,
  `config.php.old`, editor swap files) that bypass server-side handlers and serve as text.
- `git`/`svn` -- exposed VCS metadata; pivot to full source reconstruction.
- `htpasswd`/`htaccess` -- access-control rules and password hashes.
- `json` -- service-account keys, Firebase/Supabase configs, SDK credentials.

### Service-Specific Key Dorks

```
# Supabase
site:$target "supabase.co" "anon_key" OR "SUPABASE_ANON_KEY"

# Firebase admin SDK service account
site:$target "firebase-adminsdk" "private_key_id" extension:json

# AWS access keys (strip out example/test noise)
site:$target "AKIA" filetype:env NOT example NOT test

# SendGrid
site:$target "SG." filetype:env NOT example

# MongoDB connection strings
site:$target "mongodb+srv://" "password"

# PostgreSQL connection strings
site:$target "postgresql://" "password" ext:env

# JWT signing secrets
site:$target "JWT_SECRET" OR "jwt_secret" filetype:env

# OpenAI API keys
site:$target "sk-" filetype:env OR filetype:txt

# GitHub tokens (personal / OAuth / user-to-server)
site:$target "ghp_" OR "gho_" OR "ghu_"
```

Key-prefix reference for building further dorks and for grepping results: `AKIA` (AWS
access key), `ASIA` (AWS temporary), `AIza` (Google API), `ghp_`/`gho_`/`ghu_`/`ghs_`
(GitHub), `sk-`/`sk-proj-` (OpenAI), `xoxb-`/`xoxp-` (Slack), `SG.` (SendGrid), `SK`
(Twilio), `sk_live_`/`pk_live_`/`rk_live_` (Stripe), `glpat-` (GitLab PAT).

## GitHub / GitLab Code Search

Code search almost always beats web dorks for live secrets. With an authenticated
GitHub token you get 5000 req/hr and full code-search coverage.

```python
import requests

headers = {"Authorization": "token GH_TOKEN", "Accept": "application/vnd.github+json"}
base = "https://api.github.com/search/code"

queries = {
    # GCP/Firebase service-account keys -- historically ~1 in 30 hits is a live key
    "sa_keys":  '"type": "service_account" "private_key" "project_id"',
    # .env files carrying real credentials (filter template/example noise)
    "dotenv":   'DB_PASSWORD DB_HOST APP_KEY filename:.env NOT example NOT your NOT test',
    # Supabase project URL + anon/service key pairs
    "supabase": 'supabase.co SUPABASE_URL SUPABASE_ANON_KEY NOT example NOT your',
    # AWS keys committed to .env
    "aws":      'AKIA filename:.env NOT example NOT your',
    # SendGrid
    "sendgrid": 'SG. filename:.env NOT example',
    # MongoDB Atlas connection strings
    "mongo":    'mongodb+srv:// password filename:.env',
}

for name, q in queries.items():
    r = requests.get(base, headers=headers, params={"q": q, "per_page": 30})
    for item in r.json().get("items", []):
        print(name, item["repository"]["full_name"], item["html_url"])
```

Scope-tighten by adding `org:$org`, `user:$user`, or the target's email domain to each
query. For GitLab use `https://gitlab.com/api/v4/search?scope=blobs&search=...`.

Complementary tooling once you have candidate repos or a checkout:

- `trufflehog git https://github.com/$org/$repo --only-verified` -- verifies live keys.
- `gitleaks detect --source . --report-format json` -- fast regex/entropy secret scan.
- `gau_discovery` / `waybackurls_discovery` -- pull historical URLs from Wayback/CommonCrawl;
  grep the result for `.env`, `.bak`, `config`, `backup`, `.git` paths that Google never
  indexed but archives retained.

## Certificate SAN Discovery (subdomain pivot)

TLS certificates often list hostnames that never surface in CT-log search UIs. Pull SANs
directly and feed them back into your `site:` dorks.

```bash
openssl s_client -connect $target:443 -servername $target </dev/null 2>/dev/null | \
  openssl x509 -noout -ext subjectAltName | grep -oP 'DNS:[^,]+' | cut -d: -f2 | sort -u
```

Real-world case (MPF Argentina): an SSO certificate exposed `fiscales.gob.ar`,
`fiscales.gov.ar`, and `mpf.gov.ar` -- hostnames absent from conventional CT search but
present in the cert's SAN list, each an additional dork target.

## Gate 0 -- Deterministic Validation

Never report a dork hit as a finding on the strength of the search snippet alone. Search
caches go stale and index example/template files. Confirm the secret is served live and,
where possible, that it authenticates.

```bash
# 1. The file is actually served (not a 404 / stale cache). Inspect, do not exfiltrate more
#    than needed to prove exposure.
curl -sk "https://$target/.env" | head -20
curl -skI "https://$target/.git/config"   # expect 200 + text/plain-ish body

# 2. Confirm the exposed value is a real secret, not a placeholder.
#    Reject values matching: example, changeme, your-key-here, xxxx, <...>, dummy, test.

# 3. Where safe and in-scope, prove the credential authenticates:
aws sts get-caller-identity          # AWS keys (exported into env first)
curl -s "https://$PROJECT.supabase.co/rest/v1/?apikey=$KEY" -H "apikey: $KEY"  # Supabase
```

A finding is Gate 0-passed only when the file/secret is served live AND the value is
non-placeholder (ideally shown to authenticate). Record the exact URL, HTTP status, the
secret type/prefix (never the full secret in reports -- redact), and the validation command.

## Chaining Confirmed Secrets

- AWS/GCP/Azure keys -> enumerate the cloud account (IAM, S3/GCS buckets, secrets manager).
- DB connection strings (Mongo/Postgres/MySQL) -> direct DB access, data exfiltration.
- `JWT_SECRET` -> forge/sign tokens for `auth_bypass` and privilege escalation.
- `APP_KEY` (Laravel) -> decrypt cookies/sessions; historically chains to RCE via
  deserialization when the app decrypts attacker-controlled cookies.
- Firebase/Supabase service keys -> bypass row-level security, read/write arbitrary records (IDOR at scale).
- `.git`/`.svn` exposure -> reconstruct source, hunt for further hardcoded secrets and logic flaws.

## Pitfalls & Rate Limits

| Issue | Mitigation |
|-------|------------|
| Google rate-limits/CAPTCHAs bulk dorking | Space queries out, rotate egress IP, avoid tight loops. |
| GitHub search API throttling | Use an authenticated token (5000 req/hr) over anonymous. |
| False positives from example/template repos | Append `NOT example NOT test NOT your` and reject placeholder values at Gate 0. |
| Stale search-engine cache | Always re-fetch the live URL (Gate 0) before reporting. |
| Scope creep | Only act on hostnames/keys that fall inside the engagement's authorized scope. |
