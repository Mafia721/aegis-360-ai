# Aegis-360 AI — Full Automated Web App Pentest Guide

> **Authorized use only.** All capabilities are for legal penetration testing engagements,
> bug bounty programs, CTF competitions, and security research only.

---

## Table of Contents

1. [Starting the Stack](#1-starting-the-stack)
2. [Method 1 — CLI Chat (aegis360chat.py)](#2-method-1--cli-chat-aegis360chatpy--fastest)
3. [Method 2 — Direct Flask API](#3-method-2--direct-flask-api-scriptable--curl)
4. [Method 3 — Orchestrator (Phased, Multi-Model)](#4-method-3--orchestrator-phased-multi-model)
5. [Method 4 — Claude Desktop / Claude Code (MCP)](#5-method-4--via-claude-desktop--claude-code-mcp)
6. [Full Automated Pipeline — Single Command](#6-full-automated-pipeline--single-command)
7. [Model Routing Cheat Sheet](#7-model-routing-cheat-sheet)
8. [Tool Categories Reference](#8-tool-categories-reference)
9. [AI-Powered Tools Reference](#9-ai-powered-tools-reference)
10. [Built-in Methodology Guides](#10-built-in-methodology-guides)
11. [Reporting Tools](#11-reporting-tools)
12. [Architecture Overview](#12-architecture-overview)
13. [Summary Numbers](#13-summary-numbers)

---

## 1. Starting the Stack

```bash
# 1. Activate environment and start the backend
cd /home/kali/aegis-360-ai-master
source aegis-360-env/bin/activate
python3 aegis_360_server.py

# 2. In a second terminal — launch the real-time monitor
./pentest_monitor.sh --with-server

# 3. Verify server is alive
curl http://127.0.0.1:8888/health
```

---

## 2. Method 1 — CLI Chat (`aegis360chat.py`) — Fastest

```bash
source aegis-360-env/bin/activate
python3 aegis360chat.py
```

### One-liner flags (non-interactive)

```bash
# Full recon on a target (subfinder + nmap + httpx + katana + nuclei)
python3 aegis360chat.py --recon target.com

# Full vulnerability scan (nuclei + nikto + gobuster + dalfox + ffuf + sqlmap)
python3 aegis360chat.py --vuln https://target.com

# Full autonomous agent — describe the task, it chains tools automatically
python3 aegis360chat.py --agent "perform full pentest on https://target.com"

# Ask a specific question
python3 aegis360chat.py --ask "what XSS payloads bypass Cloudflare WAF"

# Lock to a specific model
python3 aegis360chat.py --model deepseek --recon target.com
python3 aegis360chat.py --model claude  --agent "exploit SQLi on https://target.com/login"

# Increase max agent iterations (default 10)
python3 aegis360chat.py --recon target.com --max-iter 20

# List all available models and their status
python3 aegis360chat.py --list
```

### Full CLI help

```
usage: aegis360chat.py [-h] [--model MODEL] [--list] [--ask QUESTION]
                        [--agent TASK] [--recon TARGET] [--vuln TARGET]
                        [--max-iter N]

options:
  -h, --help        show this help message and exit
  --model MODEL     auto (default) | deepseek | llama33 | llama4 | qwen3 | gptoss | fast | claude | all
  --list            list available models and their status
  --ask QUESTION    one-shot question (non-interactive)
  --agent TASK      run autonomous ReAct agent on TASK
  --recon TARGET    recon agent: subfinder + nmap + httpx + katana + nuclei
  --vuln  TARGET    vuln agent: nuclei + nikto + gobuster + dalfox + ffuf + sqlmap
  --max-iter N      agent max iterations (default 10)
```

### Interactive mode slash commands

Once inside `python3 aegis360chat.py`:

```
/recon   target.com                         # recon agent (DeepSeek V4 Pro)
/vuln    https://target.com                 # vuln agent  (DeepSeek V4 Pro)
/exploit https://target.com SQLi in /login  # exploit agent (Claude Sonnet)
/agent   perform full web app pentest on https://target.com
```

---

## 3. Method 2 — Direct Flask API (scriptable / curl)

The server at `http://127.0.0.1:8888` exposes 300+ endpoints. Key ones for web app pentesting:

```bash
TARGET="https://target.com"

# ── PHASE 1: RECON ─────────────────────────────────────────────────────────────

# Subdomain enumeration
curl -s -X POST http://127.0.0.1:8888/api/tools/subfinder \
  -H "Content-Type: application/json" \
  -d '{"domain":"target.com","threads":50}'

# Port scan
curl -s -X POST http://127.0.0.1:8888/api/tools/nmap \
  -H "Content-Type: application/json" \
  -d '{"target":"target.com","flags":"-sV -sC -p- --min-rate 5000"}'

# Bulk HTTP probe all subdomains
curl -s -X POST http://127.0.0.1:8888/api/tools/httpx \
  -H "Content-Type: application/json" \
  -d '{"targets":"target.com","flags":"-status-code -title -tech-detect -follow-redirects"}'

# Web crawl
curl -s -X POST http://127.0.0.1:8888/api/tools/katana \
  -H "Content-Type: application/json" \
  -d '{"url":"'$TARGET'","depth":3,"headless":true}'

# Historical URLs
curl -s -X POST http://127.0.0.1:8888/api/tools/gau \
  -H "Content-Type: application/json" \
  -d '{"domain":"target.com"}'

# WAF detection
curl -s -X POST http://127.0.0.1:8888/api/tools/wafw00f \
  -H "Content-Type: application/json" \
  -d '{"url":"'$TARGET'"}'

# ── PHASE 2: ENUMERATION ───────────────────────────────────────────────────────

# Directory brute-force (ffuf)
curl -s -X POST http://127.0.0.1:8888/api/tools/ffuf \
  -H "Content-Type: application/json" \
  -d '{"url":"'$TARGET'/FUZZ","wordlist":"/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt","threads":100}'

# Directory brute-force (gobuster)
curl -s -X POST http://127.0.0.1:8888/api/tools/gobuster \
  -H "Content-Type: application/json" \
  -d '{"url":"'$TARGET'","wordlist":"/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt","threads":50}'

# Parameter discovery
curl -s -X POST http://127.0.0.1:8888/api/tools/arjun \
  -H "Content-Type: application/json" \
  -d '{"url":"'$TARGET'/api/endpoint","method":"GET"}'

# ── PHASE 3: VULNERABILITY SCANNING ───────────────────────────────────────────

# Nuclei full template scan
curl -s -X POST http://127.0.0.1:8888/api/tools/nuclei \
  -H "Content-Type: application/json" \
  -d '{"target":"'$TARGET'","templates":"cves,exposures,misconfiguration,takeovers,vulnerabilities","severity":"critical,high,medium"}'

# Nikto web server scan
curl -s -X POST http://127.0.0.1:8888/api/tools/nikto \
  -H "Content-Type: application/json" \
  -d '{"target":"'$TARGET'"}'

# WPScan (if WordPress)
curl -s -X POST http://127.0.0.1:8888/api/tools/wpscan \
  -H "Content-Type: application/json" \
  -d '{"url":"'$TARGET'","enumerate":"vp,u,ap"}'

# ── PHASE 4: EXPLOITATION ──────────────────────────────────────────────────────

# SQL injection
curl -s -X POST http://127.0.0.1:8888/api/tools/sqlmap \
  -H "Content-Type: application/json" \
  -d '{"url":"'$TARGET'/login","data":"user=test&pass=test","flags":"--batch --level 5 --risk 3 --dbs"}'

# XSS scanning
curl -s -X POST http://127.0.0.1:8888/api/tools/dalfox \
  -H "Content-Type: application/json" \
  -d '{"url":"'$TARGET'","flags":"--silence --no-spinner"}'

# Path traversal
curl -s -X POST http://127.0.0.1:8888/api/tools/dotdotpwn \
  -H "Content-Type: application/json" \
  -d '{"target":"target.com","protocol":"http","depth":8}'

# API harvesting — OWASP API Top 10 (13 attack modules)
curl -s -X POST http://127.0.0.1:8888/api/tools/apiharvester \
  -H "Content-Type: application/json" \
  -d '{"target":"'$TARGET'","modules":"all"}'

# ── PHASE 5: AI-POWERED FULL PIPELINE ─────────────────────────────────────────

# Let the autonomous agent chain tools automatically
curl -s -X POST http://127.0.0.1:8888/api/agent/run \
  -H "Content-Type: application/json" \
  -d '{"task":"perform full web application penetration test on '$TARGET'","max_iterations":15}'

# AI-generated attack suite tailored to target
curl -s -X POST http://127.0.0.1:8888/api/tools/ai_generate_attack_suite \
  -H "Content-Type: application/json" \
  -d '{"target":"'$TARGET'","scope":"full web app"}'
```

---

## 4. Method 3 — Orchestrator (Phased, Multi-Model)

The orchestrator enforces strict model separation with a validation gate before exploitation:

```bash
source aegis-360-env/bin/activate
python3 aegis_360_orchestrator.py --target https://target.com --scope web
```

### Phase breakdown

| Phase | Model | Tools / Actions |
|---|---|---|
| RECON | DeepSeek V4 Pro | subfinder, nmap, httpx, katana, gau |
| ENUMERATION | DeepSeek V4 Pro | ffuf, gobuster, arjun, paramspider |
| VULN_ANALYSIS | DeepSeek V4 Pro | nuclei, nikto, dalfox, sqlmap |
| VALIDATION_GATE | — | human / AI confirms scope before proceeding |
| EXPLOITATION | Claude Sonnet 4.6 | payload generation, PoC, exploit chains |
| REPORTING | Claude Sonnet 4.6 | structured report with CVSS, PoC, remediation |

> **PhaseViolationError** is raised if Claude API is invoked during RECON, ENUMERATION,
> VULNERABILITY_ANALYSIS, or VALIDATION_GATE phases. All handoffs are timestamped and logged.

---

## 5. Method 4 — Via Claude Desktop / Claude Code (MCP)

With the server running, talk to Claude naturally — it calls MCP tools automatically:

```
"Run a full pentest on https://target.com"
"Enumerate subdomains of target.com then scan for CVEs"
"Find SQLi vulnerabilities on https://target.com/login"
"Generate an attack chain for the login endpoint"
"Run nuclei with all critical and high templates on target.com"
"Test the API at https://target.com/api for OWASP API Top 10"
"Crawl https://target.com and find all parameters, then fuzz them"
```

---

## 6. Full Automated Pipeline — Single Command

```bash
# Start monitor + server, then run full multi-phase agent
./pentest_monitor.sh --with-server &
sleep 5
source aegis-360-env/bin/activate
python3 aegis360chat.py --agent \
  "Full web application pentest on https://target.com. \
   Phase 1: subfinder subdomain enum, nmap service scan, httpx probing, katana crawl. \
   Phase 2: ffuf directory brute-force, arjun parameter discovery, wafw00f WAF detection. \
   Phase 3: nuclei full scan, nikto, dalfox XSS, sqlmap on all forms. \
   Phase 4: report all findings with CVSS scores." \
  --max-iter 25
```

---

## 7. Model Routing Cheat Sheet

```
--model auto        default — auto-detects task type and routes appropriately
--model deepseek    DeepSeek V4 Pro — recon, enumeration, analysis (OpenRouter)
--model claude      Claude Sonnet 4.6 — exploitation, payloads (Anthropic, paid)
--model llama33     Llama 3.3 70B — planning, strategy (Groq free)
--model qwen3       Qwen3 32B — code, PoC writing (Groq free)
--model gptoss      OpenAI OSS 120B — deep analysis (Groq free)
--model fast        Llama 3.1 8B — quick lookups (Groq free)
--model all         broadcast query to all models simultaneously and compare
```

### Routing table by task type

| Task type | Model | Provider | Cost |
|---|---|---|---|
| Recon / enumeration | DeepSeek V4 Pro | OpenRouter | Paid |
| OSINT / deep analysis | DeepSeek V4 Pro | OpenRouter | Paid |
| Code / PoC scripts | DeepSeek V4 Pro | OpenRouter | Paid |
| Quick lookups | DeepSeek V4 Pro | OpenRouter | Paid |
| Planning / strategy | DeepSeek V4 Pro | OpenRouter | Paid |
| Exploitation / payloads / RCE / bypass | Claude Sonnet 4.6 | Anthropic | Paid |
| Planning / strategy (chat) | Llama 3.3 70B | Groq | Free |
| OSINT / info gather | OpenAI OSS 120B | Groq | Free |
| Code / PoC writing | Qwen3 32B | Groq | Free |
| Log / output parsing | Qwen3 32B | Groq | Free |
| Quick lookups | Llama 3.1 8B | Groq | Free |

---

## 8. Tool Categories Reference

### Reconnaissance & Discovery

| Tool | Capability |
|---|---|
| `nmap` | Port scanning, service/version detection, OS fingerprinting, NSE scripts |
| `masscan` | High-speed internet-scale port scanning (10M packets/sec) |
| `rustscan` | Fast pre-scanner that feeds results into nmap |
| `amass` | Deep subdomain enumeration — passive and active modes |
| `subfinder` | Passive subdomain discovery via 40+ data sources |
| `fierce` | DNS recon, zone transfers, wildcard detection |
| `dnsenum` | DNS enumeration, brute-force subdomains, reverse lookups |
| `katana` | Fast web crawler with headless JS rendering, form discovery |
| `hakrawler` | Endpoint and link harvesting from HTML and JS |
| `gau` | Pull all known URLs from Wayback Machine and AlienVault OTX |
| `waybackurls` | Historical URL recovery from Wayback Machine |
| `paramspider` | Passive parameter mining from archived URLs |
| `httpx` | Bulk HTTP probing — status codes, titles, TLS, CDN detection |

### Web Application Testing

| Tool | Capability |
|---|---|
| `gobuster` | Dir/file/vhost/DNS brute-force |
| `feroxbuster` | Recursive content discovery with auto-calibration |
| `ffuf` | Fast multi-purpose fuzzer — dirs, params, headers, vhosts |
| `dirb` | Classic directory brute-force |
| `dirsearch` | Web path discovery with threading and smart filtering |
| `wfuzz` | General-purpose web fuzzer — any injection point |
| `nuclei` | Template-based scanner — 500+ MB templates (CVEs, misconfigs, exposures) |
| `nikto` | Web server misconfiguration and vulnerability scanner |
| `jaeles` | Signature-based active web scanner |
| `zaproxy` | OWASP ZAP — active/passive scan, spider, AJAX crawler |
| `sqlmap` | Automated SQLi: union, blind, time-based, error-based. DB dump, OS shell |
| `dalfox` | Parameter-based XSS scanner with blind XSS callback server |
| `xsstrike` | Crawl-and-fuzz XSS discovery with intelligent payload generation |
| `xsser` | XSS exploitation framework with encoding and bypass |
| `dotdotpwn` | Directory traversal fuzzer across HTTP, FTP, SMTP, TFTP |
| `wafw00f` | Identify and fingerprint WAF products (Cloudflare, Akamai, AWS WAF, etc.) |
| `wpscan` | Full WordPress security scanner: plugins, themes, users, API keys |

### API Security Testing

| Tool | Capability |
|---|---|
| `arjun` | HTTP parameter discovery across GET, POST, JSON, XML |
| `x8` | Hidden parameter discovery using response change detection |
| `paramspider` | Passive URL parameter mining from archives |
| `graphql-scanner` | Introspection abuse, batching attacks, IDOR via GraphQL |
| `jwt-analyzer` | JWT decode, alg:none bypass, RS→HS confusion, weak secret brute-force |
| `api-schema-analyzer` | OpenAPI/Swagger analysis — exposed endpoints, auth gaps |
| `apiharvester` | OWASP API Top 10 automation with 13 attack modules |
| `api_fuzzer` | Custom parameter fuzzing against REST API endpoints |
| `comprehensive_api_audit` | AI-driven full API security assessment |

### Credential Testing

| Tool | Capability |
|---|---|
| `hydra` | Network login brute-forcer — SSH, FTP, HTTP, SMB, RDP, 50+ protocols |
| `john` | Hash cracking with wordlist, rules, incremental modes |
| `hashcat` | GPU-accelerated hash cracking — all major hash types |
| `medusa` | Parallel network login brute-forcer |
| `hash-identifier` | Identify hash type from format |

### Active Directory & Windows

| Tool | Capability |
|---|---|
| `impacket-secretsdump` | Dump NTLM hashes, LSA secrets via SMB |
| `impacket-GetUserSPNs` | Kerberoasting — request TGS tickets for cracking |
| `netexec` / `nxc` | SMB, WinRM, LDAP, MSSQL, RDP enumeration and lateral movement |
| `enum4linux-ng` | Full Windows/Samba enumeration — shares, users, groups, policies |
| `smbmap` | SMB share enumeration and read/write access testing |
| `responder` | NBT-NS/LLMNR/mDNS poisoning for NTLM credential capture |
| `evil-winrm` | WinRM shell with PowerShell upload/download, bypass techniques |
| `bloodhound` | AD attack path visualization |

### Cloud & Container Security

| Tool | Capability |
|---|---|
| `trivy` | Container image CVE scanning, IaC scanning, SBOM generation |
| `checkov` | Terraform, CloudFormation, Kubernetes, Dockerfile policy analysis |
| `prowler` | AWS/GCP/Azure security posture — CIS, GDPR, PCI-DSS checks |
| `scout-suite` | Multi-cloud security posture assessment |
| `kube-hunter` | Active Kubernetes cluster attack surface discovery |
| `pacu` | AWS exploitation — IAM privilege escalation, S3, EC2, Lambda |

### OSINT & Intelligence

| Tool | Capability |
|---|---|
| `theharvester` | Email, domain, IP harvesting from 20+ public sources |
| `recon-ng` | Modular OSINT framework with 80+ modules |
| `spiderfoot` | Automated OSINT — 200+ data source integrations |
| `sherlock` | Username discovery across 400+ platforms |
| `shodan-cli` | Shodan host lookup, search, CVE correlation |
| `censys-cli` | Certificate transparency, host intelligence |
| `noseyparker` | Secret scanning in source repos, filesystems, S3 buckets |

---

## 9. AI-Powered Tools Reference

```bash
# Full AI-driven recon with dynamic tool selection
curl -s -X POST http://127.0.0.1:8888/api/tools/ai_reconnaissance_workflow \
  -H "Content-Type: application/json" -d '{"target":"target.com"}'

# AI vulnerability prioritization and severity analysis
curl -s -X POST http://127.0.0.1:8888/api/tools/ai_vulnerability_assessment \
  -H "Content-Type: application/json" -d '{"target":"https://target.com"}'

# AI-crafted payloads for specific vulnerability classes
curl -s -X POST http://127.0.0.1:8888/api/tools/ai_generate_payload \
  -H "Content-Type: application/json" -d '{"vuln_type":"sqli","target":"https://target.com/login"}'

# AI selects best tool combination for a given task
curl -s -X POST http://127.0.0.1:8888/api/tools/select_optimal_tools_ai \
  -H "Content-Type: application/json" -d '{"task":"find XSS on https://target.com"}'

# Multi-step exploitation path generation
curl -s -X POST http://127.0.0.1:8888/api/tools/create_attack_chain_ai \
  -H "Content-Type: application/json" -d '{"target":"https://target.com","vuln":"sqli"}'

# AI-powered tech stack and framework fingerprinting
curl -s -X POST http://127.0.0.1:8888/api/tools/detect_technologies_ai \
  -H "Content-Type: application/json" -d '{"url":"https://target.com"}'

# Qwen3-Coder end-to-end pentest pipeline
curl -s -X POST http://127.0.0.1:8888/api/tools/qwen_full_pipeline \
  -H "Content-Type: application/json" -d '{"target":"https://target.com"}'

# AI-written proof-of-concept exploit code
curl -s -X POST http://127.0.0.1:8888/api/tools/qwen_generate_poc \
  -H "Content-Type: application/json" -d '{"vuln":"sqli","target":"https://target.com/login"}'

# Autonomous recon agent — runs full discovery lifecycle
curl -s -X POST http://127.0.0.1:8888/api/agent/run \
  -H "Content-Type: application/json" \
  -d '{"task":"recon target.com","agent_type":"recon","max_iterations":10}'

# Autonomous vulnerability agent
curl -s -X POST http://127.0.0.1:8888/api/agent/run \
  -H "Content-Type: application/json" \
  -d '{"task":"find vulns on https://target.com","agent_type":"vuln","max_iterations":15}'
```

---

## 10. Built-in Methodology Guides

50+ structured guides available as MCP tools — reference during engagements:

### Web & API
- SQLi methodology (all injection types, detection, exploitation, WAF bypass)
- XSS methodology (reflected, stored, DOM, blind, CSP bypass)
- SSRF methodology (internal, cloud metadata, protocol smuggling)
- SSTI methodology (Jinja2, Twig, Freemarker, Pebble payloads)
- XXE methodology (classic, blind, OOB, SSRF via XXE)
- RCE methodology (OS command injection, deserialization, SSTI→RCE)
- IDOR methodology (horizontal/vertical, mass assignment, UUID bypass)
- Open redirect methodology (parameter identification, bypass techniques)
- File upload methodology (extension bypass, MIME manipulation, path traversal)
- Request smuggling methodology (CL.TE, TE.CL, TE.TE, HTTP/2)
- GraphQL methodology (introspection, batching, field suggestions, IDOR)
- OAuth attacks methodology (state bypass, redirect_uri manipulation, token leakage)
- JWT attacks methodology (alg:none, key confusion, kid injection, weak secrets)
- WAF bypass methodology (encoding, chunking, case variation, unicode)
- Race condition methodology (limit overrun, state confusion, TOCTOU)
- Business logic methodology (workflow bypass, price manipulation, trust boundaries)
- Parameter pollution methodology (HPP, JSON pollution, array injection)

### Engagement Workflows
- Bug bounty reconnaissance workflow
- Bug bounty vulnerability hunting guide
- Bug bounty authentication bypass testing
- Bug bounty business logic testing
- Bug bounty file upload testing
- OSINT methodology and tools guide
- Fast recon methodology (speed-optimized)
- Advanced red team methodology
- Vulnerability classes overview

### Binary & Exploit Dev
- Buffer overflow methodology (stack, heap, format string)
- ROP chain methodology (gadget selection, chain construction, libc leak)
- Shellcode development (x86/x64, syscall-based, staged)
- Fuzzing methodology (harness design, corpus creation, coverage analysis)
- Crash analysis (triaging, root cause, exploitability)
- Deserialization methodology (Java, PHP, Python pickle, .NET)
- Security mitigations bypass (ASLR, NX, PIE, canary)

### Windows & AD
- Initial access methodology (phishing, exposed services, credential stuffing)
- Windows security bypass (UAC, AppLocker, AMSI, ETW)
- EDR evasion (obfuscation, indirect syscalls, process injection)

### Cloud
- Cloud security methodology (AWS, GCP, Azure enumeration and attack paths)
- Kubernetes attack methodology (RBAC abuse, container escape, lateral movement)

---

## 11. Reporting Tools

```bash
# Structured pentest finding with CVSS, reproduction steps, remediation
curl -s -X POST http://127.0.0.1:8888/api/tools/create_vulnerability_report \
  -H "Content-Type: application/json" \
  -d '{"title":"SQL Injection","severity":"critical","target":"https://target.com/login","description":"..."}'

# Executive-level scan summary with risk ratings
curl -s -X POST http://127.0.0.1:8888/api/tools/create_scan_summary \
  -H "Content-Type: application/json" \
  -d '{"target":"https://target.com","findings":[...]}'

# Multi-vector attack path documentation
curl -s -X POST http://127.0.0.1:8888/api/tools/discover_attack_chains \
  -H "Content-Type: application/json" \
  -d '{"target":"https://target.com"}'

# TTP mapping to MITRE ATT&CK framework
curl -s -X POST http://127.0.0.1:8888/api/tools/correlate_threat_intelligence \
  -H "Content-Type: application/json" \
  -d '{"findings":[...]}'
```

---

## 12. Architecture Overview

```
Claude Desktop / Claude Code (Orchestrator)
    │
    ├── aegis_360_mcp.py       (spawned per session — MCP stdio protocol)
    │       │
    │       └── HTTP ──► aegis_360_server.py (127.0.0.1:8888)
    │                           │
    │                           ├── System tools (nmap, nuclei, ffuf, sqlmap …)
    │                           ├── Go tools (subfinder, httpx, katana …)
    │                           ├── AI APIs (Anthropic, Groq, OpenRouter, DeepSeek)
    │                           └── Modules (augustus, praetorian)
    │
    ├── aegis_360_orchestrator.py  (multi-model phased workflow engine)
    │       │
    │       ├── DeepSeek V4 Pro  → RECON / ENUMERATION / VULN ANALYSIS
    │       └── Claude API       → EXPLOITATION / REPORTING (post-gate only)
    │
    └── aegis360chat.py        (optional standalone CLI — no Claude Desktop needed)
```

| Component | Role | Size |
|---|---|---|
| `aegis_360_server.py` | Flask API server — 300+ endpoints, all tool execution | ~19,800 lines |
| `aegis_360_mcp.py` | MCP client — 288 tools exposed to Claude Desktop | ~13,100 lines |
| `aegis_360_orchestrator.py` | Multi-model phased workflow engine with validation gate | ~600 lines |
| `aegis360chat.py` | Standalone CLI with auto-routing between AI models | ~690 lines |
| `modules/augustus.py` | LLM adversarial testing (210+ attack probes) | ~413 lines |
| `modules/praetorian.py` | Praetorian commercial toolset integration | ~792 lines |
| `pentest_monitor.sh` | Real-time tmux monitoring layout | ~115 lines |

---

## 13. Summary Numbers

| Metric | Value |
|---|---|
| Total tool integrations | 127+ (123 verified at 98.4%) |
| MCP tools exposed to Claude Desktop | 288 |
| API endpoints in Flask server | 300+ |
| Tool categories | 14 |
| AI models integrated | 6 |
| Built-in methodology guides | 50+ |
| Verified success rate | 98.4% |
| Go tools installed | 18 |
| Python packages in requirements | 30+ |
| Praetorian tools integrated | 14 |
| LLM adversarial probes (Augustus) | 210+ |

---

*Aegis-360 AI v1.1.0 — Professional penetration testing framework for authorized engagements only.*
