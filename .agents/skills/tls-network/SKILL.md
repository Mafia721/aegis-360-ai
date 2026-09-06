---
name: TLS/SSL & DNS Network Enumeration
description: Enumerate and triage TLS/SSL and DNS posture (certs, ciphers, HSTS, AXFR, SPF/DKIM/DMARC, dangling records, mTLS bypass) plus JA3/JA4 fingerprint evasion to reach blocked hosts.
tags: [network, tls, dns, enumeration, fingerprint, email-security]
recommended_tools: [nmap_scan, httpx_probe, subfinder_scan, curl, python3, execute_command, http_request, http_repeater]
vuln_classes: []
domain: network
phase: enumeration
provenance: {source: uphiago/recon-skills, paths: [redteam/hunt-tls-network/SKILL.md, recon/tls-fingerprint-impersonation/SKILL.md, recon/http2-header-impersonation/SKILL.md]}
---

# TLS/SSL & DNS Network Enumeration

Enumerate the transport-layer and DNS posture of a target: certificate chain, offered
ciphers/protocols, HSTS, DNS zone transfer, email authentication (SPF/DKIM/DMARC),
dangling records, and mTLS edge trust. This skill is opinionated about **which findings
actually pay** versus which are best-practice noise, and it includes a TLS/HTTP2
fingerprint-impersonation phase for when the target blocks non-browser clients before you
can even enumerate it.

## Reality Check (Read First)

Most raw findings in this class are **Info/Low and routinely rejected** as "missing-hardening."
Before treating anything here as a finding, ask:

1. **Is there a real victim and a real action?** "Missing HSTS" is not a vulnerability — a
   *demonstrated session-cookie capture from a victim you MitM'd* is. "Missing CAA" is never
   demonstrable.
2. **Is it in scope?** Email-auth (SPF/DMARC), missing security headers, weak TLS without an
   exploit, and CAA are commonly listed out of scope. Read scope first.

**What actually pays (in order):**
- **Dangling-CNAME / dangling-A subdomain takeover** — you control content on a `target.com`
  subdomain. Real impact.
- **Spoofable DMARC proven by delivered-to-inbox email** — not "p=none exists" but a real mail
  from `ceo@target.com` landing in a real inbox.
- **DNS AXFR returning internal hosts** — full internal hostname/IP map, often Medium.
- **mTLS / client-cert bypass on an internal service** — reaching authenticated-only
  functionality = auth bypass, High.
- **Exploited TLS weakness with a working decrypt/MitM PoC** — almost never achievable remotely
  against a patched 2024+ stack; see Phase 1 caveats.

**What does NOT pay (do not report standalone):** missing CAA, missing HSTS with no MitM PoC,
missing security headers alone, weak-cipher *support* without an exploit, self-signed cert on a
non-prod host, TLS 1.0/1.1 *enabled* without a downgrade victim.

---

## Phase 0 — Reach the Target (Fingerprint Evasion)

If `curl`/`httpx_probe` returns 403/blocked even with a correct User-Agent, the edge
(Cloudflare, Akamai, F5) is likely fingerprinting your **TLS ClientHello (JA3/JA4)** or
**HTTP/2 setup**, not your headers. Spoof a real browser at the transport level before
concluding the host is down or enumerating further.

```bash
# Quick test: does a browser TLS fingerprint change the verdict?
curl -sk https://target.com | head -1        # e.g. 403
python3 -c "
from impit import Impit                        # pip install impit (patched rustls, PyO3)
c = Impit.builder().with_fingerprint('chrome142').build()
print(c.get('https://target.com').status_code) # 200 => TLS/HTTP2 fingerprinting was the blocker
"
```

Pick the profile that matches the surface you are probing:

| Profile | Use case | Key differentiator |
|---|---|---|
| `chrome142` | Modern desktop / default | Post-quantum KEX (X25519MLKEM768), GREASE |
| `chrome100` | Legacy | Older ciphers, no GREASE key exchange |
| `firefox144` | Firefox | `:path` before `:authority`, FFDHE groups, SHA-1 sigs |
| `ios18` | iOS mobile API | 3DES ciphers, duplicate sig alg, no session tickets |
| `okhttp4` | Android app API | BoringSSL, no GREASE/ECH, TLS 1.2+ |

```python
from impit import Impit
client = (
    Impit.builder()
    .with_fingerprint("chrome142")
    .with_ignore_tls_errors(True)   # self-signed certs during recon
    .with_http3()
    .with_fallback_to_vanilla(False) # keep True OFF if stealth matters — vanilla leaks real JA3
    .build()
)
r = client.get("https://target.com/api/endpoint")
```

**HTTP/2 layer.** Even with correct TLS, a mismatched HTTP/2 SETTINGS frame or pseudo-header
order gets flagged. `curl` cannot spoof SETTINGS frames — use impit for HTTP/2 targets, or the
manual header block below for HTTP/1.1.

| Browser | Stream Window | Pseudo-Header Order |
|---|---|---|
| Chrome | 6,291,456 | `:method :authority :scheme :path` |
| Firefox | 131,072 | `:method :path :authority :scheme` |
| Safari iOS | 2,097,152 | `:method :scheme :authority :path` |
| OkHttp | 16,777,216 | `:method :path :authority :scheme` |

```bash
# Chrome 142 header profile for curl/httpx on HTTP/1.1 targets (must match the TLS fingerprint)
curl -sk "https://target.com" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36" \
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7" \
  -H "Accept-Language: en-US,en;q=0.9" \
  -H "Accept-Encoding: gzip, deflate, br, zstd" \
  -H "sec-ch-ua: \"Chromium\";v=\"142\", \"Google Chrome\";v=\"142\", \"Not?A_Brand\";v=\"99\"" \
  -H "sec-ch-ua-mobile: ?0" -H "sec-ch-ua-platform: \"Windows\"" \
  -H "sec-fetch-dest: document" -H "sec-fetch-mode: navigate" -H "sec-fetch-site: none" \
  -H "sec-fetch-user: ?1" -H "Upgrade-Insecure-Requests: 1" -H "Priority: u=0, i"
```

**Evasion pitfalls:**
- Test with plain `curl` first — if it works, fingerprinting is not the blocker; don't add complexity.
- The TLS fingerprint **must match the User-Agent**. Chrome TLS + Firefox UA is itself a tell.
- `sec-ch-ua` is version-specific and must match the UA; mobile headers over a desktop TLS
  fingerprint are flagged.
- Validate the spoof: hit `https://www.howsmyssl.com/`, `https://tls.peet.ws/api/all`, or the
  Cloudflare `cf-ja4` response header and confirm it reports the intended browser; verify the
  403→200 flip against vanilla curl.

---

## Phase 1 — TLS/SSL Audit

```bash
# Comprehensive TLS test
testssl.sh --fast target.com 2>/dev/null | grep -E "CRITICAL|HIGH|MEDIUM|OK|NOT" | head -30
python3 -m sslyze target.com --json_out /tmp/sslyze.json 2>/dev/null

# nmap ssl-enum-ciphers grades every offered protocol/cipher
nmap -sV --script ssl-enum-ciphers -p 443 target.com

# Certificate expiry, subject, issuer, SAN list
echo | openssl s_client -connect target.com:443 -servername target.com 2>/dev/null | \
  openssl x509 -noout -dates -subject -issuer -ext subjectAltName 2>/dev/null

# Protocol downgrade surface — are TLS 1.0/1.1 still negotiable?
openssl s_client -connect target.com:443 -tls1   2>/dev/null | grep -E "Protocol|Cipher"
openssl s_client -connect target.com:443 -tls1_1 2>/dev/null | grep -E "Protocol|Cipher"
```

**Accuracy / triage notes — do not over-claim TLS bugs:**

- **Offered ≠ exploitable.** A successful handshake means the cipher/protocol is *negotiated*.
  That is a hardening finding, not a demonstrated decrypt. Without a PoC it is Info/Low and often OOS.
- **SWEET32 (CVE-2016-2183)** — 3DES birthday attack; needs a long-lived session, on-path
  attacker, and hundreds of GB of same-key traffic. Un-demonstrable in practice; report only 3DES
  *support*, expect Low/Info.
- **POODLE (CVE-2014-3566)** — SSLv3 CBC padding oracle. Needs **SSLv3 actually enabled**
  (`testssl.sh --poodle` / `nmap --script ssl-poodle`). Modern OpenSSL 3.x dropped `-ssl3`; if
  SSLv3 won't negotiate there is no POODLE.
- **FREAK (CVE-2015-0204)** / **DROWN (CVE-2016-0800)** — require export-grade RSA / a shared
  SSLv2 endpoint. Prove the precondition present (`testssl.sh --drown`, `nmap --script sslv2-drown`
  across the cert's SAN list) before claiming it.
- **Heartbleed (CVE-2014-0160)** — a genuinely unpatched OpenSSL 1.0.1 leaking memory *is*
  High/Critical **with a captured dump** containing keys/cookies. Verify with `testssl.sh
  --heartbleed`; the rare TLS bug worth a full report.

---

## Phase 2 — HSTS & Security Headers

```bash
# HSTS on apex + critical subdomains (login/auth/api/pay)
curl -sI "https://target.com/" | grep -i "strict-transport-security"
for sub in login auth api account pay www; do
  H=$(curl -sI "https://$sub.target.com/" 2>/dev/null | grep -i "strict-transport-security")
  [ -z "$H" ] && echo "[!] MISSING HSTS: $sub.target.com" || echo "[OK] $sub: $H"
done

# HTTP should redirect to HTTPS immediately
curl -sI "http://target.com/" | grep -i "location"
# HSTS preload status
curl -s "https://hstspreload.org/api/v2/status?domain=target.com" | jq . 2>/dev/null

# Security header sweep
HEADERS=$(curl -sI "https://target.com/")
for H in "Strict-Transport-Security" "Content-Security-Policy" "X-Frame-Options" \
         "X-Content-Type-Options" "Referrer-Policy" "Permissions-Policy"; do
  echo "$HEADERS" | grep -qi "$H" && echo "[OK] $H" || echo "[MISSING] $H"
done
```

Missing headers/HSTS are **Info-tier** absent a working MitM/downgrade PoC that captures a
victim cookie over plaintext. Do not file standalone.

---

## Phase 3 — DNS Zone Transfer (AXFR)

```bash
dig NS target.com +short
for NS in $(dig NS target.com +short); do
  echo "=== AXFR from $NS ==="
  dig AXFR target.com @$NS 2>/dev/null | grep -v "^;" | head -30
done
nmap -sn --script dns-zone-transfer --script-args dns-zone-transfer.domain=target.com \
  $(dig NS target.com +short | head -1)
# Success => full internal hostname/IP map: internal IPs, staging, admin, CI/CD hosts.
```

A successful AXFR returning internal hosts is concrete recon value, typically **Medium**. Ship
the full transcript.

---

## Phase 4 — Email Security (SPF/DKIM/DMARC)

```bash
dig TXT target.com +short | grep "v=spf1"
dig TXT _dmarc.target.com +short
for sel in default google mail k1 selector1 selector2 s1 s2 dkim; do
  R=$(dig TXT $sel._domainkey.target.com +short 2>/dev/null)
  [ -n "$R" ] && echo "DKIM selector: $sel -> $R"
done

# Spoofability heuristic (PROOF is the swaks test below, not this)
SPF=$(dig +short TXT target.com | tr -d '"' | grep -i "v=spf1")
DMARC=$(dig +short TXT _dmarc.target.com | tr -d '"' | grep -i "v=DMARC1")
echo "$SPF" | grep -Eq '[+ ]all($|[^-~?])' && echo "[CRITICAL] SPF passes all senders (+all)"
if [ -z "$DMARC" ]; then
  echo "[INFO] No DMARC policy published"
else
  echo "$DMARC" | grep -qi "p=none" && echo "  p=none: monitors only, does NOT block spoofing"
  echo "$DMARC" | grep -qiE "p=(quarantine|reject)" && echo "  enforcing: spoofing likely blocked"
fi
```

> Always capture `dig` output into a variable and test `[ -z "$VAR" ]`. The old
> `dig ... | wc -c | grep '^1$'` idiom misfires on empty output and is unreliable.

### Spoofability is a RECEIVER decision, not a record-reading exercise

`p=none` (or absent) means the **sending domain** published no enforcement — but the **receiving**
provider (Gmail, M365, the program's MX) may still junk or reject your spoof via SPF, ARC, or
heuristics. The only proof that survives triage is a message you delivered to a real inbox.

```bash
# PROOF: send a spoofed mail, confirm INBOX delivery (tester account you own; check MX first)
dig MX target.com +short
swaks --to your-tester@gmail.com \
      --from "CEO <ceo@target.com>" \
      --header "Subject: [TEST] DMARC spoof PoC for target.com" \
      --body "Authorized bug-bounty test. Spoofed from-domain: target.com" \
      --server <smtp-relay-you-control-or-localhost>
```

**Confirmation gate — valid only if you show:** (1) landed in **Inbox** not Spam (screenshot the
folder); (2) raw `Authentication-Results:` showing `dmarc=none|fail` AND still **delivered** (a
bounce or Spam landing is NOT a finding); (3) visible `From:` shows `@target.com` (header-from
spoof, the one that matters for phishing). Severity **Medium at best**, often OOS.

---

## Phase 5 — Certificate Transparency (Subdomain Discovery)

```bash
# CT logs surface every SAN ever issued — feeds the dangling-record hunt below
curl -s "https://crt.sh/?q=%25.target.com&output=json" | \
  jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > ct-subdomains.txt
subfinder_scan -d target.com -all -silent >> ct-subdomains.txt
sort -u ct-subdomains.txt -o ct-subdomains.txt
echo "[+] CT/subfinder subdomains: $(wc -l < ct-subdomains.txt)"
# New entries = recently issued certs = new services to investigate
```

---

## Phase 6 — Dangling Records → Subdomain Takeover (the finding that pays)

Highest-impact item here. A CNAME/A record pointing at a deprovisioned third-party resource
(S3, Azure CDN/App Service, GitHub Pages, Heroku, Fastly) lets you claim it and serve content
from `*.target.com`.

```bash
while read sub; do
  CNAME=$(dig +short CNAME "$sub" | head -1)
  [ -z "$CNAME" ] && continue
  CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "https://$sub/" 2>/dev/null)
  echo "$sub -> $CNAME  [http $CODE]"
done < ct-subdomains.txt | tee cname-map.txt
# Then confirm the provider fingerprint string in the body:
#   "NoSuchBucket" / "The specified bucket does not exist" (S3),
#   "There isn't a GitHub Pages site here", "Fastly error: unknown domain",
#   Azure "Web App - Unavailable", "no such app" (Heroku).
```

**Validation gate — a takeover claim requires you to actually claim it:**
1. Confirm the dangling target is **unregistered/claimable** (the bucket name is free, the Heroku
   app doesn't exist). The error fingerprint alone is necessary but NOT sufficient.
2. **Register the resource yourself** and serve a unique canary at `https://$sub/<random>.txt`.
   Screenshot it served over the victim subdomain with valid TLS.
3. Tear it down immediately after PoC.

Impact: cookie-scope theft (`.target.com` cookies), OAuth `redirect_uri`/CORS-trust abuse,
phishing on a trusted origin. Typically **High** (Critical at an OAuth/SSO redirect or shared
session cookie). CWE-350 / trust-of-untrusted-DNS.

---

## Phase 7 — CAA Records (recon signal only — NOT a finding)

```bash
dig CAA target.com +short
dig CAA "*.target.com" +short
```

**Do NOT report "missing CAA" as a vulnerability** — it is the most common false positive here.
A missing CAA record does not let an attacker obtain a certificate; issuance still requires
passing Domain Control Validation. Fraudulent issuance needs CA compromise/social-engineering,
which is OOS for essentially every program. **Where CAA recon IS useful (intel only):**
`issue`/`issuewild` values reveal which CA the org uses (letsencrypt, digicert, amazon), hinting
at ACME automation and where a *real* takeover (Phase 6) could let you mint a valid cert via DCV.

---

## Phase 8 — mTLS / Edge-Trust Bypass

```bash
# Does the endpoint require a client cert? Try without one.
curl -sk "https://target.com/internal/api" | head -5

# Some apps skip mTLS on health/metrics paths
for path in /health /ping /status /metrics /api/health; do
  echo "$path: $(curl -sk -o /dev/null -w "%{http_code}" "https://target.com$path")"
done

# Header-injection bypass: nginx/HAProxy/Envoy terminate mTLS at the edge and forward the verdict
# as a header the backend trusts. If the edge does NOT strip client-supplied copies, spoof a
# verified client. Try the real header names per proxy:
for combo in \
  "X-SSL-Client-Verify: SUCCESS|X-SSL-Client-S-DN: CN=admin" \
  "ssl-client-verify: SUCCESS|ssl-client-subject-dn: CN=admin" \
  "X-Client-Verify: SUCCESS|X-Client-DN: CN=admin,O=target" \
  "X-Forwarded-Client-Cert: By=spiffe://x;Hash=0;Subject=\"CN=admin\""; do
  H1="${combo%%|*}"; H2="${combo##*|}"
  echo "== $H1 / $H2 =="
  curl -sk "https://target.com/internal/api" -H "$H1" -H "$H2" -o /dev/null -w "%{http_code}\n"
done
```

**Validation — this is a real auth bypass, so prove access, not a status code:**
- A `200` may be a generic page. Confirm you reached **authenticated-only functionality** (an
  admin-only object, an internal-only body impossible without the cert).
- A `403`→`200` flip with the spoofed header is meaningful; `200` both with and without means the
  path was never protected (no finding).
- Health/metrics paths are only a finding if they expose **sensitive data** (internal IPs, build
  secrets, Prometheus topology). Capture the request/response pair in `http_repeater` so the
  spoofed-header → privileged-response mapping is unambiguous.

---

## Chain / Severity Table (calibrated to what triage accepts — do not inflate)

| Finding | Realistic standalone severity | Raises it |
|---|---|---|
| Dangling-CNAME takeover (claimed + canary served) | **High** | Critical at OAuth `redirect_uri`/SSO or shared `.target.com` cookies |
| mTLS / client-cert bypass to authed functionality | **High** | Must show privileged data/action, not just 200 |
| AXFR returning internal hosts/IPs | **Medium** | Pairs with internal-service findings |
| Spoofable DMARC delivered-to-inbox (PoC headers) | **Medium** | Often OOS — `p=none` from `dig` alone = Info, do not file |
| Heartbleed / live memory leak with captured secrets | **High–Critical** | Only with an actual dump |
| Missing HSTS on auth subdomain | **Low / Info** | Only with a working downgrade-capture PoC |
| Weak cipher support (RC4/3DES/SWEET32), no decrypt PoC | **Info / Low** | Hardening only, frequently OOS |
| Missing CAA | **Info (do not file)** | Absence does not enable issuance |

---

## Validation Summary

Each finding ships with proof, never `dig`/header output alone:

- **Takeover:** you registered the dangling resource and served a unique canary over
  `https://sub.target.com/` with valid TLS. Screenshot + canary string. Tear down after.
- **mTLS bypass:** spoofed client-verify header returns *privileged* data the cert-required path
  otherwise denies. `http_repeater` request/response pair.
- **AXFR:** zone transfer returns internal hostnames/IPs from an authoritative NS. Full transcript.
- **DMARC spoof:** swaks mail with `From: @target.com` **delivered to a real Inbox** (not Spam),
  raw `Authentication-Results` attached.
- **HSTS/headers:** only reportable with a working downgrade PoC capturing a victim cookie.

**Pre-submission scope gate:** before filing ANY item, confirm the program does not list it OOS
(email-auth, missing-headers, weak-TLS-without-exploit, CAA are commonly OOS). Quote the in-scope
line in your report.
