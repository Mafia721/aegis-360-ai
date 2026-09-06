---
name: WordPress Attack & Plugin CVE Hunting
description: Assess WordPress targets end-to-end — fingerprint, user enumeration, XML-RPC abuse, REST API exposure, vulnerable-plugin CVE hunting, and credentialed foothold-to-RCE chains.
tags: [wordpress, cms, plugin-cve, xmlrpc, rest-api, exploitation]
recommended_tools: [wpscan, httpx_probe, nuclei_scan, ffuf_scan, curl, python3, http_request, jq]
vuln_classes: []
domain: web
phase: exploitation
provenance: {source: uphiago/recon-skills, paths: [redteam/hunt-wordpress/SKILL.md, recon/wp-mass-recon/SKILL.md, recon/wordpress-plugin-hunt/SKILL.md, recon/wp-plugin-rest-auth-bypass/SKILL.md, recon/xmlrpc-exploitation/SKILL.md, recon/cors-credential-wordpress/SKILL.md, redteam/wp-plugin-cve-hunt/SKILL.md, chains/wordpress-full-compromise/SKILL.md]}
---
# WordPress Attack & Plugin CVE Hunting

WordPress on shared hosting without a WAF is one of the most common real-world weak points. The
core is usually patched; the vulnerabilities live in **plugins/themes** and in **misconfiguration**
(open registration, exposed `wp-config.php` backups, debug logs, XML-RPC). Goal: fingerprint the
exact plugin/version set, map it to known CVEs, and prove impact.

## When to use
Recon shows any of: `/wp-content/`, `/wp-json/`, `/xmlrpc.php`, `<meta name="generator" content="WordPress">`,
`X-Powered-By` with WP, WooCommerce API endpoints, or `wp-login.php`.

## Phase 1 — Fingerprint
```
httpx_probe on target                         # title/tech/server
curl -s TARGET/?p=1 | grep -i 'generator'      # core version (generator tag)
curl -s TARGET/readme.html | grep -i version   # core version (often left in place)
curl -s TARGET/wp-json/ | jq '.namespaces'     # REST namespaces reveal active plugins
curl -s TARGET/ | grep -oE 'wp-content/plugins/[^/]+' | sort -u   # plugins referenced in HTML
curl -s TARGET/ | grep -oE 'wp-content/themes/[^/]+' | sort -u
wpscan --url TARGET --enumerate vp,vt,u,cb,dbe --plugins-detection aggressive
```
Note the exact plugin **slug + version** for each — that is what maps to a CVE. On multisite / subdirectory
installs, check each subdir separately (plugin sets differ).

## Phase 2 — User enumeration
```
curl -s 'TARGET/wp-json/wp/v2/users' | jq '.[].slug'   # REST user list (if not filtered)
curl -s 'TARGET/?author=1' -I | grep -i location        # author archive → username in redirect
curl -s TARGET/wp-sitemap-users-1.xml                    # Yoast/core user sitemap
```
Usernames feed a **disciplined** password spray (respect lockout; see authentication-testing skill).

## Phase 3 — XML-RPC abuse (`/xmlrpc.php`)
- **Method discovery:** `system.listMethods` — if `pingback.ping` / `wp.getUsersBlogs` are present:
- **Credential brute amplification:** `system.multicall` batches many `wp.getUsersBlogs` logins in one
  request (bypasses per-request throttling). Prove the amplification, then report — do not mass-brute.
- **Pingback SSRF/port-scan:** `pingback.ping` with an internal `sourceUri` → server-side request to
  attacker-chosen host (see ssrf-testing for the OOB proof pattern).
Remediation reference: disable XML-RPC or restrict `system.multicall`/`pingback`.

## Phase 4 — REST API & misconfiguration
- **Open registration:** `wp-login.php?action=register` or `settings.default_role` via REST → self-serve
  low-priv account (foothold for authenticated plugin CVEs).
- **CORS credential reflect:** send `Origin: https://evil.tld` to `/wp-json/...` with credentials; if the
  response reflects the origin with `Access-Control-Allow-Credentials: true`, cross-origin auth theft.
- **Application Passwords** (`/wp-json/wp/v2/users/me/application-passwords`) abuse on a compromised session.
- **Exposed sensitive files:** `wp-config.php~`, `wp-config.php.bak`, `.wp-config.php.swp`, `/wp-content/debug.log`
  (leaks paths, queries, sometimes creds). Use ffuf with a WP-backup wordlist.

## Phase 5 — Plugin/theme CVE hunting → RCE
1. For each `slug@version`, search the WPScan/Wordfence/CVE databases for known issues (auth bypass, SQLi,
   arbitrary file upload, LFI, unauth RCE). High-signal historical examples: ElementsKit, RevSlider,
   WP Download Manager, Gravity Forms, File Manager.
2. Confirm the version is in the vulnerable range (readme.txt of the plugin usually states the version).
3. Reproduce the specific CVE PoC against the target **once** to prove exploitability; capture request/response.

## Foothold-to-RCE chain (authenticated)
Admin/editor session → **Theme/Plugin editor** (`/wp-admin/theme-editor.php`) to write PHP into a theme file,
or upload a malicious plugin zip (`/wp-admin/plugin-install.php`) → web-shell → `id`. Only where the
engagement authorizes code execution. Record the exact steps as the impact proof.

## Validation gate (before filing)
- Plugin/theme finding: name the **CVE or the concrete flaw**, the confirmed vulnerable version, and a
  reproduced request/response. "Old version installed" alone is informational, not a confirmed finding.
- XML-RPC/SSRF: show the OOB callback or the differential proving the server made the request.
- Never report a version-only guess as exploited.

## Remediation (attach to findings)
Update/remove the vulnerable plugin; disable XML-RPC or restrict methods; filter `wp-json` user endpoints;
remove config backups/debug logs from the web root; disable file editing (`DISALLOW_FILE_EDIT`); enforce
strong-auth on wp-admin; put the site behind a WAF.
