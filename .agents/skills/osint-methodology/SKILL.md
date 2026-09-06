---
name: OSINT Methodology (External Red-Team Edition)
description: End-to-end OSINT recon playbook — 5-stage pipeline, asset-graph discipline, confidence gates, identity-fabric mapping, breach correlation, origin/WAF bypass, vuln prioritization, supply-chain recon.
tags: [recon, osint, attack-surface, asset-discovery, identity-fabric, supply-chain]
recommended_tools: [subfinder_scan, httpx_probe, katana_crawl, gau_discovery, waybackurls_discovery, nuclei_scan, nmap_scan, wafw00f_scan, whatweb_scan, trufflehog, gitleaks, curl, jq, python3, execute_command]
vuln_classes: []
domain: recon
phase: recon
provenance: {source: uphiago/recon-skills, paths: [redteam/osint-methodology/SKILL.md, redteam/offensive-osint/SKILL.md, redteam/supply-chain-attack-recon/SKILL.md]}
---

# OSINT Methodology — External Red-Team Edition

Reconnaissance-only playbook for authorized external assessments (red team, in-scope bug bounty, ASM). Maps an org's external attack surface end-to-end: seeds -> assets -> exposure -> attack paths. Exploitation, post-exploitation, and blue-team work are out of scope.

## Authorization & always-on guardrails

Only assets the operator owns or has written authorization to assess. If authorization is unclear, ask once ("is this a target you own or have written authorization to assess?"), then proceed. Regardless of authorization:

- Never weaken auth, rate limits, banners, or scope-enforcing controls on the target.
- No destructive probes (line-rate masscan, fuzzing, brute-force, true SYN scans on prod) outside an explicit DEEP/`--aggressive` mode.
- Never paste real PII, valid creds, session tokens, or API keys into cloud LLMs — use local models for sensitive analysis.
- Never act against assets outside documented scope, even if "obviously related" (subsidiaries, vendors, employee personal accounts).

## Confidence gates (attach to every assertion)

| Level | Meaning | Example |
|---|---|---|
| TENTATIVE | Indirect, unverified | snippet-only dork, inferred email pattern, single passive source, favicon-hash overlap |
| FIRM | Directly observed, uncorroborated | subdomain resolves, HEAD-confirmed bucket, CT-log cert, Shodan banner |
| CONFIRMED | Multiple corroborations OR direct verification | live-validated token (read-only `/me` 200), breach+CT+DNS agree, listable bucket with object retrieval |

**Rule of three for attribution:** 3 independent weak signals OR 1 strong + 1 weak before asserting linkage. Never single-source attribute. Default posture: never claim CONFIRMED without explicit corroboration — when in doubt, downgrade.

**Upgrade paths (per asset type):** subdomain TENTATIVE->FIRM when >=2 passive sources agree or DNS resolves; FIRM->CONFIRMED when it serves a banner. Bucket FIRM when HEAD returns 200/301/403; CONFIRMED when GET lists/retrieves objects. Credential FIRM when a read-only validator (`/me`, `auth.test`, `sts:GetCallerIdentity`, `/user`) succeeds; CONFIRMED with documented scope + account ID.

## Evidence hygiene

Per artifact: **URL + UTC timestamp + SHA-256 + tool version + run_id**. Screenshot PNG (lossless), raw HTTP capped at 2 KiB/side, JSONL run log one event per line. Evidence read-only, separate from working copies. Prefer durable citations (CVE, vendor advisory, ATT&CK ID, RFC); archive ephemeral sources (archive.today, Wayback SavePageNow) before citing. Always UTC — local time creates correlation bugs.

## The 5-stage pipeline

Stages are sequential; modules within a stage run concurrently.

1. **Seed discovery** — WHOIS/RDAP, ASN enumeration (HE BGP Toolkit, RIPEstat, BGPView), DNS records (A/AAAA/MX/TXT/NS/SOA/CAA), CT history (crt.sh, Censys).
2. **Asset expansion** — passive subdomain enum first (crt.sh, VT, OTX, Shodan) then permutation/bruteforce; cloud bucket permutation; typosquat generation (dnstwist); Wayback CDX archive paths; mobile app discovery; LinkedIn employee enum -> email pattern.
3. **Enrichment** — port/service detection (Shodan InternetDB free, then nmap if authorized); TLS handshakes (cert chain, JARM, favicon mmh3); web tech + WAF/CDN inference (`whatweb_scan`, `wafw00f_scan`); origin discovery; security-header audit; bulk screenshots; email harvest + SPF/DMARC/DKIM/BIMI/MTA-STS audit; GitHub code-search dorking; JS deep analysis; SSO/IdP fingerprinting; API/auth-map discovery.
4. **Exposure analysis** — `nuclei_scan` misconfig sweep; TLS deep audit (sslyze/testssl.sh); breach x identity correlation; targeted misconfig probes (`.git/config`, `.env`, `/actuator/env`, `/actuator/heapdump`, `_cat/indices`, `/manager/html`); CVE x EPSS x KEV prioritization.
5. **Reporting** — per-finding risk scoring; asset-graph export; client exec summary + technical report; reproduction package (run_id + tool versions + raw evidence).

### Priority order (highest signal density first)

Breaches (infostealer logs -> valid corp SSO creds) > GitHub secret dorks > `nuclei_scan` misconfig sweep > cloud buckets > ports (Shodan InternetDB first) > email OSINT > web tech/WAF/screenshots > Wayback > DNS+email-security > certificates > ASN/reverse-DNS > WHOIS > typosquat > security headers.

**Abort early** after Stage 1 if scope is wrong, after Stage 2 if attack surface is below threshold, or during any stage on the detection signs below.

## Asset-graph discipline

Every discovery is a **typed asset** in a graph, not a free-floating string. Each asset carries `type`, `key` (typed prefix, e.g. `sub:api.example.com`), `value`, `sources[]` (all confirming sources, deduped), `confidence`, `first_seen`/`last_seen` (UTC), `attrs{}`. Dedup by key, not value (`sub:api.example.com` != `webapp:https://api.example.com/`; link with a `BELONGS_TO_HOST` edge). Late-bind cross-module data via JSON sidecars — don't block module B on module A.

**Triage by what an asset enables.** WebApp priority: auth hostnames (`auth.`/`login.`/`sso.`/`idp.`) > admin paths > dev/staging (lower defenses, often dump prod data) > API hosts > customer-facing > marketing. Email priority: exec (`ceo@`/`cfo@`/`cto@`/`ciso@`) > IT/security/helpdesk > dev/engineer > sales/marketing/hr/finance > generic role accounts. Repo priority: recently-pushed > stale; names with `prod`/`internal`/`private`/`secret` escalate to HIGH despite being public.

## Severity rubric

- **CRITICAL** — pre-auth RCE, live-validated broad-scope credential, listable prod bucket, exposed `.git`/`.env`/`/actuator/env`/`/actuator/heapdump`, open Firebase RTDB, open Elasticsearch/Redis/Docker/etcd/kubelet/K8s-anon, `android:debuggable=true` on prod, >=10 employees breached + tenant identified (SSO_EXPOSURE), KEV-listed vendor CVE (Citrix/F5/Pulse).
- **HIGH** — public secret in repo, sourcemap `.js.map` exposed, open GraphQL introspection on prod, subdomain takeover possible, reflected CORS + credentials, verb tampering (hidden DELETE/PATCH), missing HSTS on auth/login/SSO/admin, exposed Jenkins/Tomcat-Manager/phpMyAdmin, DMARC `p=none` on sending domain, mobile WebView JS bridge / sensitive deep-link.
- **MEDIUM** — missing HSTS/CSP, `/server-status`, internal IP/K8s DNS leaked in JS, wildcard CORS on user-tied API, Slack webhook leaked, permissive SPF (`+all`), `android:allowBackup=true`, `android:usesCleartextTraffic=true`.
- **LOW/INFO** — missing `X-Frame-Options`/`X-Content-Type-Options`, `.DS_Store`, Stripe test key, cert pinning absent, BIMI unconfigured, `/.well-known/security.txt`, DNSSEC not enabled, private locked-down bucket.

**Escalation rules:** HSTS-missing-on-auth-path MED->HIGH; wildcard CORS+credentials MED->HIGH; API interest-score >=70 -> HIGH; >=10 employees breached -> CRITICAL; vendor version matches KEV -> CRITICAL.

## Identity-fabric mapping

Compromise the identity fabric and you skip individual apps. Probe `auth.`/`login.`/`sso.`/`idp.`/`iam.`/`identity.`/`accounts.`/`oauth.` prefixes, plus `{host}/.well-known/openid-configuration` on every alive host.

- **Entra** — `login.microsoftonline.com/{domain}/.well-known/openid-configuration` `issuer` field carries the tenant GUID. `getuserrealm.srf?login=<user>@<domain>` returns `Managed`/`Federated`/`Unknown` (low detectability). `GetCredentialType` POST for user-enum (medium; cap ~20/tenant).
- **Okta** — `<slug>.okta.com/.well-known/openid-configuration`; `/api/v1/authn` 400-vs-401 for user-enum (deep-mode only).
- **ADFS** — `/adfs/idpinitiatedsignon.aspx` 200 = present; `/adfs/Services/Trust/mex` for SOAP metadata.
- **SAML** — probe `/saml/metadata`, `/FederationMetadata/2007-06/FederationMetadata.xml`, `/simplesaml/saml2/idp/metadata.php`.
- **M365 deep** — `<stem>.sharepoint.com` / `<stem>-my.sharepoint.com` / `<stem>-admin.sharepoint.com`; Teams external federation (soft attack surface for vishing/from-IT pretexts); `device_authorization_endpoint` on `common` = device-code-phishing target (MEDIUM). SharePoint HEAD 200 = tenant exists, **not** anonymous access.

Each IdP becomes a `Service` asset with `attrs.product`/`tenant_id`/`discovery_endpoint`. Correlate with breach data in Stage 4: any compromised user under a discovered tenant = SSO_EXPOSURE (CRITICAL).

## Breach x identity correlation

Highest-ROI single technique — run on every engagement. Sources: **Hudson Rock Cavalier** (free, infostealer corpus, very high signal for corp SSO), HIBP, DeHashed, IntelX, local corpus. Domain-level severity: >=10 employees CRITICAL, 1-9 HIGH, >=1 end-user MEDIUM, 0 named accounts INFO. Treat stealer logs as PII: encrypt at rest, SHA-256 every artifact, never paste plaintext passwords into cloud LLMs, redact passwords in client reports (offer a separate encrypted credential bundle).

## JavaScript deep analysis

For every alive webapp scrape its JS — modern frontends leak there.

- **Sourcemaps (HIGH info-disclosure):** regex `//[#@]\s*sourceMappingURL=`, or fetch `<bundle>.map`. Parse `sources[]` (repo structure) and `sourcesContent[]` (full original source — run the secret catalog over it).
- **Secrets:** run the pattern catalog (AWS, GCP, GitHub PAT, Stripe, Slack, JWT, private keys, Anthropic/OpenAI/HuggingFace, Cloudflare, DigitalOcean, npm, PyPI, Docker Hub) over every JS body.
- **Endpoints:** each extracted endpoint -> asset -> API classifier.
- **Internal-host leakage (MEDIUM):** RFC1918, internal DNS suffixes, K8s service DNS.
- **Next.js:** `_buildManifest.js` enumerates every page route.

Budget: 40 webapps default (120 `--deep`), 40 JS files/webapp, 2 MiB/file cap, 10s per-file timeout.

## API & auth-map

Discover via Swagger/OpenAPI 28-path wordlist, GraphQL 13-path wordlist (POST standard introspection; fall back to field-suggestion enumeration when introspection is disabled), Postman public workspace search, and JS/mobile-extracted endpoints. Classify each: `OPTIONS` -> `Allow` header (verb tampering); unauth GET 200 vs 401 (auth required); `Origin: https://attacker.example` reflection (CORS); trigger errors for stack-trace/ORM schema leaks.

**Interest score (0-100):** unauth write +40, open GraphQL introspection +35, verb-tampering bypass +30, reflected CORS+creds +25, sensitive keyword in path +20, schema leak in error +20, API key in URL +15, wildcard CORS +10, missing rate-limit +10. Score >=90 CRITICAL, 70-89 HIGH, 50-69 MED. For >=70 attach an `attack_path_hint` (e.g. unauth POST -> "try IDOR + privilege escalation; check whether numeric IDs are guessable").

## Cloud & mobile surface

**Buckets:** permutate root domain + subdomain stems + brand name across S3/GCS/Azure templates. HEAD first (200/301 exists, 403 exists-private, 404 skip); if exists, GET root — listable = CRITICAL, readable-not-listable = HIGH, ACL private = INFO. Extract AWS account-ID from S3 region/error responses (`arn:aws:...:([0-9]{12}):`).

**Mobile:** discover Android (google-play-scraper) + iOS (iTunes Search API). Ownership confidence (0-100): package reverse-DNS match +40, dev email @target +25, dev website = target +20; threshold >=70 for deep analysis. Static-analyze APK manifest/resources/dex; `android:debuggable=true` CRITICAL, deep-link/WebView-JS-bridge HIGH. Firebase RTDB canonical probe: GET `https://{project}.firebaseio.com/.json` — JSON tree returned = CRITICAL.

## WAF/CDN bypass & origin discovery

The CDN is hard; the origin is often softly defended. Six techniques:

1. **DNS history pivot** — SecurityTrails / Validin / Censys for an IP that resolved 1-5 years ago and is **not** in the current CDN's published ranges.
2. **Cert SAN pivot** — crt.sh `?q=%.<target>&exclude=expired`; the non-CDN cert often points to origin via CN/SAN (`cero` correlates IPs whose certs include the hostname).
3. **Favicon mmh3 + JARM clustering** — Shodan `http.favicon.hash:<hash>` / `ssl.jarm:<hash>`; non-CDN IPs are origin candidates.
4. **Direct Host-header probe** — `curl -sk -H "Host: target.example.com" https://<candidate-IP>/`; matching content = origin.
5. **Auxiliary-subdomain exception** — `mail.`/`ftp.`/`cpanel.`/`webmail.`/`direct.`/`origin.`/`dev.`/`staging.` often skip the CDN.
6. **Error/header leakage** — 502/504 confirms origin exists; `X-Cache`/`X-Backend-Server`/`Server` headers can leak through.

Confidence: DNS-history alone TENTATIVE; Host-header content match FIRM; Host-header + cert SAN + favicon all matching CONFIRMED.

## Vulnerability prioritization (CVE / EPSS / KEV)

A `nuclei_scan` can return 100+ CVEs. Score each: CISA KEV +50 (proven exploited, treat as immediate), EPSS >=0.7 +30 (0.3-0.69 +15), Metasploit module +25, public POC +15, unauth +20, network-vector +15, CVSS >=9.0 +15. Tiers: >=100 P0 (validate now), 70-99 P1, 40-69 P2, <40 P3.

**Validation discipline:** a validation is a single read-only proof (version-banner check, static-page fetch confirming the vulnerable component) — never run the actual exploit unless RoE explicitly permits. CVE-less findings (sourcemap, open GraphQL, public bucket) are scored by independent interest/severity — don't gate on CVE availability.

## Supply-chain recon

Recon and identification ONLY — publishing typosquat/dep-confusion packages is EXTERNAL-OFFENSIVE and needs explicit written sign-off (blast radius spans the whole ecosystem).

**Attack surface:** public GitHub org -> workflow secret-exfil; internal package names in JS/APK bundles -> dependency confusion; Docker images on public registries -> secrets in layers; SBOM/lockfiles -> known-vuln chaining; `.npmrc`/`pip.conf` -> internal registry URL disclosure; external deps -> typosquat candidates.

```bash
# GitHub org discovery
gh search users --owner-affiliations=organization --query "$TARGET" --limit 10
gh repo list "$ORG" --limit 100 --json name | jq -r '.[].name' | grep -iE "internal|infra|deploy|config|secret|sdk"

# Internal package-name discovery from JS bundles
curl -sk https://target.com/main.js | grep -oE '@[a-z-]+/[a-z-]+' | sort -u

# Dependency-confusion check (404 = unclaimed = CANDIDATE, not confirmed exploitable)
curl -sI "https://registry.npmjs.org/@target-internal/utils" | head -1   # npm
curl -sI "https://pypi.org/project/target_utils/" | head -1              # pypi

# GitHub Actions injection scan (per repo .github/workflows/)
grep -E 'pull_request_target' wf.yml                                     # runs secrets on fork PRs
grep -E '\$\{\{ ?github\.event\.(pull_request|head_ref)' wf.yml          # script injection
grep -E 'uses: *[^ ]+/[^ ]+@(v?[0-9.]+|main|master|latest)\b' wf.yml | grep -v '@[0-9a-f]\{40\}'  # mutable tag

# Docker layer secret mining
docker save "$ORG/$img:latest" -o /tmp/image.tar && mkdir -p /tmp/img && tar -xf /tmp/image.tar -C /tmp/img
trufflehog filesystem /tmp/img --no-update

# SBOM / known-vuln chaining
gh api "repos/$ORG/$REPO/releases" --jq '.[] | .assets[] | select(.name|test("sbom|cyclonedx|spdx";"i")) | .browser_download_url'
curl -s "https://api.osv.dev/v1/query" -d '{"package":{"name":"lodash","ecosystem":"npm"},"version":"4.17.10"}'
```

**Severity calibration:** "name unclaimed" alone is INFORMATIONAL — a deliverable dep-confusion finding needs proof the build resolves from public registries (insecure `.npmrc` without `@scope:registry=` mapping) AND the package is actually in `package.json`. `pull_request_target` + checkout of PR head + repo secrets = CRITICAL. Unpinned third-party action (`@v1`/`@main` vs `@<40-char-sha>`) = HIGH (repointable — see tj-actions/changed-files below).

**Tooling:** `trufflehog`, `gitleaks`, `osv-scanner`, `actionlint`, `semgrep` (supply-chain rules), Confused (dep-confusion), `packj`.

**Real-world CVEs / cases:** Alex Birsan dependency-confusion (2021, $130K+, JS-bundle internal-scope leakage is the canonical path); tj-actions/changed-files (CVE-2025-30066, ~23K repos, mutable-tag repoint dumped CI secrets — highest-yield current vector); Codecov bash-uploader (2021, `curl|bash` in CI = blast radius); XZ Utils (CVE-2024-3094, multi-year maintainer social-engineering — watch for high-trust grants to low-history accounts + obfuscated test fixtures); ua-parser-js / event-stream (npm maintainer-account compromise); Log4Shell (CVE-2021-44228, SBOM mining earns its keep); MOVEit (CVE-2023-34362, edge file-transfer products — fingerprint by title/favicon early); SolarWinds/SUNBURST (2020, code-signing does NOT save you). Recurring pattern: pinning to mutable references (`curl|bash`, `@v35` tags, `^1.0.0` semver) is the repeated failure.

## Detection-aware probing (back off before you trip an active response)

**Signs (increasing severity):** 429/`Retry-After`/`X-RateLimit-Remaining: 0` -> captcha interstitial -> explicit WAF page (Cloudflare/Akamai/Imperva/F5/AWS WAF) -> status drift (previously-200 now 403 only from your IP) -> banner/timing change -> honeypot bait (`/admin/db_dump.sql`, `.env` with non-validating creds) -> direct contact.

**Back-off ladder:** slow down (halve concurrency, 2-10s jitter) -> switch endpoints -> switch persona (UA + TLS fingerprint) -> switch egress IP -> pause 1-24h -> **document and consult the engagement lead** (mandatory once you hit a confirmed WAF block, status drift, or direct contact). Never send more aggressive payloads to "outsmart" a confirmed block, and never switch IPs to evade an explicit block-list — that crosses into evasion and may breach RoE.

**Detectability tagging:** tag every op Low (passive Shodan/CT/Wayback/passive-DNS, HEAD on public buckets, OIDC metadata), Medium (user-enum, PMAK validation, `sts:GetCallerIdentity`, Swagger/GraphQL probes), or High (active port scans, full `nuclei_scan` on prod, subdomain brute at scale, SMTP `RCPT TO` enum, web fuzzing). Passive by default; active only when authorized, in-window, and with the operator aware of resulting log volume.

## Common failure modes

Single-source attribution; trusting vendor labels as ground truth; assuming favicon-hash = ownership; treating snippet-only dorks as confirmed; pasting real PII/creds into cloud LLMs; attribution by IP geolocation; ignoring CT-log lag (absence != doesn't exist); trusting `whoami` from a discovered API (could be a honeypot); letting the asset graph carry untyped strings; skipping the scope check; forgetting UTC; continuing to probe after a WAF block; confusing "name unclaimed" with "exploitable dependency confusion."

## Chaining notes

- Origin/subdomain discoveries with stale CNAMEs -> subdomain-takeover validation.
- Listable buckets / `/actuator/env` / open Firebase -> cloud-misconfig exploitation.
- Entra/Okta fingerprint -> matched IdP-attack skill for active enumeration.
- Internal package names in JS -> supply-chain dep-confusion candidate list.
- CI-runner supply-chain RCE -> env-var extraction (AWS keys, `GITHUB_TOKEN`) -> cloud-IAM enumeration.

CWE references: CWE-200 (info exposure), CWE-522 (insufficiently protected credentials), CWE-1104 (unmaintained third-party components), CWE-829 (inclusion of functionality from untrusted control sphere — dependency confusion), CWE-16 (misconfiguration).
