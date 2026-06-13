# Aegis-360 AI v1.1.0 — Capabilities Reference

**Architecture:** 34,423 lines of code across 5 files — Flask API server + FastMCP bridge exposing 200+ tools to Claude Desktop. 123/127 tools verified at 98.4% success rate.

---

## Table of Contents

1. [Core Architecture](#1-core-architecture)
2. [Reconnaissance & Discovery](#2-reconnaissance--discovery)
3. [Web Application Testing](#3-web-application-testing)
4. [API Security Testing](#4-api-security-testing)
5. [Burp Suite Integration](#5-burp-suite-integration)
6. [Binary Exploitation & Reverse Engineering](#6-binary-exploitation--reverse-engineering)
7. [Active Directory & Windows](#7-active-directory--windows)
8. [Cloud & Container Security](#8-cloud--container-security)
9. [Credential Testing](#9-credential-testing)
10. [OSINT & Intelligence](#10-osint--intelligence)
11. [Forensics & Steganography](#11-forensics--steganography)
12. [Praetorian Commercial Toolset](#12-praetorian-commercial-toolset-full-integration)
13. [AI Model Routing](#13-ai-model-routing-multi-model-intelligence)
14. [Methodology Guides](#14-methodology-guides-built-in-knowledge-base)
15. [Reporting & Output](#15-reporting--output)
16. [Summary Numbers](#16-summary-numbers)

---

## 1. Core Architecture

| Component | Role | Size |
|-----------|------|------|
| `aegis_360_server.py` | Flask API server — 300+ endpoints, all tool execution | 19,511 lines |
| `aegis_360_mcp.py` | MCP client — exposes 200+ tools directly to Claude Desktop | 13,100 lines |
| `hexchat.py` | Standalone CLI with auto-routing between AI models | 607 lines |
| `modules/augustus.py` | LLM adversarial testing (210+ attack probes) | 413 lines |
| `modules/praetorian.py` | Full Praetorian commercial toolset integration | 792 lines |

**Two-component design:**

```
Claude Desktop
    │
    ├── aegis_360_mcp.py  (spawned per session via MCP protocol)
    │       │
    │       └── HTTP → aegis_360_server.py (127.0.0.1:8888)
    │                       │
    │                       ├── System tools (nmap, nuclei, ffuf, sqlmap...)
    │                       ├── Go tools (subfinder, httpx, katana...)
    │                       ├── AI APIs (Anthropic, Groq, OpenRouter)
    │                       └── Blueprints (augustus, praetorian)
    │
    └── hexchat.py  (optional standalone CLI fallback)
```

---

## 2. Reconnaissance & Discovery

### Network Recon

| Tool | Capability |
|------|-----------|
| `nmap` | Port scanning, service/version detection, OS fingerprinting, NSE scripts, all scan types |
| `masscan` | High-speed internet-scale port scanning (10M packets/sec) |
| `rustscan` | Fast pre-scanner that feeds results into nmap |
| `amass` | Deep subdomain enumeration — passive and active modes, graph analysis |
| `subfinder` | Passive subdomain discovery via 40+ data sources (CT logs, DNS, APIs) |
| `fierce` | DNS reconnaissance, zone transfers, wildcard detection |
| `dnsenum` | DNS enumeration, brute-force subdomains, reverse lookups |
| `arp-scan` | LAN host discovery via ARP broadcast |
| `nbtscan` | NetBIOS name and MAC address enumeration |
| `autorecon` | Automated multi-tool recon orchestration |
| `fingerprintx` | Praetorian service fingerprinting beyond standard banners |
| `nmap_advanced_scan` | AI-assisted scan profile selection |

### Web Crawling & URL Discovery

| Tool | Capability |
|------|-----------|
| `katana` | Fast web crawler with headless JS rendering, form discovery |
| `hakrawler` | Endpoint and link harvesting from HTML and JS |
| `gau` | Pull all known URLs from Wayback Machine and AlienVault OTX |
| `waybackurls` | Historical URL recovery from Wayback Machine |
| `paramspider` | Passive parameter mining from archived URLs |
| `httpx` | Bulk HTTP probing — status codes, titles, TLS info, CDN detection |

---

## 3. Web Application Testing

### Directory & Content Discovery

| Tool | Notes |
|------|-------|
| `gobuster` | Dir/file/vhost/DNS brute-force |
| `feroxbuster` | Recursive content discovery with auto-calibration |
| `ffuf` | Fast multi-purpose fuzzer — directories, parameters, headers, vhosts |
| `dirb` | Classic directory brute-force |
| `dirsearch` | Web path discovery with threading and smart filtering |
| `wfuzz` | General-purpose web fuzzer — any injection point |

### Vulnerability Scanning

| Tool | Notes |
|------|-------|
| `nuclei` | Template-based scanner — 500+ MB templates covering CVEs, misconfigs, exposures, OAST callbacks |
| `nikto` | Web server misconfiguration and vulnerability scanner |
| `jaeles` | Signature-based active web scanner |
| `zaproxy` | OWASP ZAP — active/passive scan, spider, AJAX crawler |

### SQL Injection

- `sqlmap` — Automated SQLi detection and exploitation: union, blind, time-based, error-based, stacked queries. DB dump, file read/write, OS shell, WAF bypass modes.

### XSS

| Tool | Notes |
|------|-------|
| `dalfox` | Parameter-based XSS scanner with blind XSS callback server |
| `xsstrike` | Crawl-and-fuzz XSS discovery with intelligent payload generation |
| `xsser` | XSS exploitation framework with encoding and bypass techniques |

### Path Traversal

- `dotdotpwn` — Directory traversal fuzzer across HTTP, FTP, SMTP, TFTP

### WAF Detection

- `wafw00f` — Identify and fingerprint WAF products (Cloudflare, Akamai, AWS WAF, etc.)

### CMS

- `wpscan` — Full WordPress security scanner: plugins, themes, users, API keys in source

### Browser Automation

- **Selenium + Chromium agent** — Full JavaScript rendering, form interaction, authenticated crawling, screenshot capture, session handling

---

## 4. API Security Testing

| Tool | Capability |
|------|-----------|
| `arjun` | HTTP parameter discovery across GET, POST, JSON, XML |
| `x8` | Hidden parameter discovery using response change detection |
| `paramspider` | Passive URL parameter mining from archives |
| `graphql-scanner` | Introspection abuse, batching attacks, field enumeration, IDOR via GraphQL |
| `jwt-analyzer` | JWT decode, `alg:none` bypass, RS→HS confusion, weak secret brute-force, kid injection |
| `api-schema-analyzer` | OpenAPI/Swagger analysis — exposed endpoints, auth gaps, deprecated paths |
| `api_fuzzer` | Custom parameter fuzzing against REST API endpoints |
| `http_intruder` | Burp Intruder-style position-based fuzzing |
| `http_repeater` | Request replay and manipulation |
| `comprehensive_api_audit` | AI-driven full API security assessment |

---

## 5. Burp Suite Integration

Full two-way integration via Burp Suite REST API (port 1337):

| Tool | Capability |
|------|-----------|
| `burp_proxy_request` | Route any request through Burp proxy |
| `burp_active_scan` | Trigger Burp active scanner on a URL |
| `burp_get_issues` | Pull all scanner findings |
| `burp_get_proxy_history` | Retrieve full intercept history |
| `burp_send_to_repeater` | Send specific requests to Repeater |
| `burp_proxy_status` | Check proxy running state |
| `burp_scan_status` | Monitor active scan progress |
| `http_set_scope` | Configure target scope |
| `http_set_rules` | Set match/replace rules |
| `qwen_fetch_and_parse_burp` | AI-parse Burp history for vulnerability patterns |

---

## 6. Binary Exploitation & Reverse Engineering

### Debuggers

| Tool | Capability |
|------|-----------|
| `gdb` + PEDA | Enhanced debugging — pattern search, ROP assistance, heap visualization |
| `rr` | Deterministic record-and-replay debugger for reproducible crash analysis |
| `gdb_peda_debug` | Automated GDB+PEDA session via MCP |

### Static Analysis

| Tool | Capability |
|------|-----------|
| `ghidra` | NSA decompiler — full binary analysis, pseudocode, data flow |
| `radare2` | Disassembly, emulation, Radare2 scripting (r2pipe) |
| `objdump` | ELF/PE disassembly and section analysis |
| `strings` | Binary string extraction with encoding detection |
| `xxd` | Hex dump with ASCII annotation |
| `binwalk` | Firmware analysis and embedded file extraction |
| `checksec` | Binary security mitigations audit (ASLR, NX, PIE, stack canary, RELRO) |

### Exploit Development

| Tool | Capability |
|------|-----------|
| `pwntools` | Python exploit framework — shellcode, cyclic patterns, ROP chains, remote/local/SSH |
| `angr` | Symbolic execution — automatic vulnerability discovery, path exploration |
| `ROPgadget` | ROP chain construction from ELF/PE/raw binaries |
| `ropper` | ROP/JOP/COP gadget search with chain building |
| `one_gadget` | Find one-shot `execve("/bin/sh")` gadgets in libc |
| `libc-database` | Identify libc version from leaked symbol offsets for ASLR bypass |
| `pwninit` | Patch CTF binaries with correct libc/linker for local exploitation |
| `hashpump` | Hash length extension attacks (MD5, SHA1, SHA256) |
| `msfvenom` | Payload generation — shellcode, staged/stageless, encoders, formats |

### Fuzzing

| Tool | Capability |
|------|-----------|
| `AFL++` | Coverage-guided fuzzer — QEMU mode (no source), persistent mode, network fuzzing, crash triage |
| `raptor` | Praetorian static analysis + CodeQL integration for source-level vulnerability research |

---

## 7. Active Directory & Windows

| Tool | Capability |
|------|-----------|
| `impacket-secretsdump` | Dump NTLM hashes, LSA secrets, DPAPI masterkeys via SMB |
| `impacket-GetUserSPNs` | Kerberoasting — request TGS tickets for cracking |
| `impacket` (suite) | psexec, wmiexec, smbexec, pass-the-hash, pass-the-ticket |
| `netexec` / `nxc` | CrackMapExec successor — SMB, WinRM, LDAP, MSSQL, RDP enumeration and lateral movement |
| `enum4linux` / `enum4linux-ng` | Full Windows/Samba enumeration — shares, users, groups, policies |
| `smbmap` | SMB share enumeration and read/write access testing |
| `rpcclient` | RPC endpoint enumeration — SIDs, users, groups, printers |
| `responder` | NBT-NS/LLMNR/mDNS poisoning for NTLM credential capture |
| `evil-winrm` | WinRM shell with PowerShell upload/download, bypass techniques |
| `trident` | Praetorian password spraying with AD lockout-aware throttling |
| `NTLMRecon` | NTLM endpoint discovery and authentication server fingerprinting |

---

## 8. Cloud & Container Security

| Tool | Capability |
|------|-----------|
| `trivy` | Container image CVE scanning, IaC scanning, SBOM generation |
| `checkov` | Terraform, CloudFormation, Kubernetes, Dockerfile policy analysis |
| `terrascan` | IaC security scanning (500+ policies, CIS benchmarks) |
| `prowler` | AWS/GCP/Azure security posture — CIS, GDPR, PCI-DSS, HIPAA checks |
| `scout-suite` | Multi-cloud security posture assessment with visual reporting |
| `kube-bench` | CIS Kubernetes benchmark verification |
| `kube-hunter` | Active Kubernetes cluster attack surface discovery |
| `pacu` | AWS exploitation framework — IAM privilege escalation, S3, EC2, Lambda, SSM |
| `cloudmapper` | AWS environment visualization and public exposure analysis |
| `falco` | Runtime threat detection via syscall-level behavioral monitoring |
| `clair` | Container image CVE scanning (Quay/Docker) |
| `docker-bench-security` | Docker host and daemon CIS benchmark audit |

---

## 9. Credential Testing

| Tool | Capability |
|------|-----------|
| `hydra` | Network login brute-forcer — SSH, FTP, HTTP, SMB, RDP, SMTP, telnet, 50+ protocols |
| `john` | John the Ripper — hash cracking with wordlist, rules, incremental modes |
| `hashcat` | GPU-accelerated hash cracking — all major hash types, rule-based attacks |
| `medusa` | Parallel network login brute-forcer |
| `patator` | Modular brute-forcer with fine-grained control |
| `trident` | Smart AD password spraying with lockout detection |
| `hash-identifier` | Identify hash type from format |

---

## 10. OSINT & Intelligence

| Tool | Capability |
|------|-----------|
| `theharvester` | Email, domain, IP, hostname harvesting from 20+ public sources |
| `recon-ng` | Modular OSINT framework with 80+ modules |
| `spiderfoot` | Automated OSINT — 200+ data source integrations |
| `sherlock` | Username availability and account discovery across 400+ platforms |
| `shodan-cli` | Shodan host lookup, search, CVE correlation (requires API key) |
| `censys-cli` | Certificate transparency, host intelligence, IP/domain lookup |
| `have-i-been-pwned` | Credential breach checking via HIBP API |
| `noseyparker` | Secret scanning in source repos, filesystems, S3 buckets |
| `gau` / `waybackurls` | Historical URL and endpoint recovery from internet archives |
| `anew` | Append-only deduplication for large OSINT output streams |
| `uro` | URL list deduplication and filtering |
| `qsreplace` | Bulk URL parameter value replacement for automation |
| `exploit-db` | ExploitDB / searchsploit lookup by keyword or CVE |

---

## 11. Forensics & Steganography

| Tool | Capability |
|------|-----------|
| `volatility3` | Memory forensics — process trees, network connections, registry hives, injected DLLs, malware artifacts |
| `foremost` / `scalpel` | File carving and recovery by file signature |
| `autopsy` + Sleuth Kit | Disk forensics, timeline analysis, deleted file recovery |
| `bulk-extractor` | High-speed artifact extraction — emails, URLs, credit cards, phone numbers |
| `exiftool` | Metadata extraction from documents, images, audio, video |
| `steghide` | Steganography — embed/extract data from JPEG, BMP, WAV |
| `stegsolve` | Visual steganography analysis — bit plane inspection, color channel analysis |
| `zsteg` | PNG/BMP steganography detection (LSB, pixel channels) |
| `outguess` | JPEG steganography detection and extraction |
| `binwalk` | Firmware analysis, embedded file extraction, entropy visualization |

---

## 12. Praetorian Commercial Toolset (Full Integration)

The entire Praetorian open-source security toolset is integrated as a Flask blueprint (`modules/praetorian.py`):

| Tool | Capability |
|------|-----------|
| `augustus` | 210+ LLM adversarial probes — jailbreak, prompt injection, PII extraction, model inversion |
| `titus` | Attack surface intelligence and exposure mapping |
| `nerva` | Deep network reconnaissance and service correlation |
| `brutus` | Advanced credential attacks with protocol-specific optimizations |
| `hadrian` | Autonomous attack planning and orchestration |
| `trajan` | Lateral movement path discovery and execution |
| `vespasian` | Post-exploitation persistence, collection, exfiltration |
| `julius` | Intelligent target probing and vulnerability correlation |
| `aurelian` | End-to-end security assessment workflow automation |
| `MCPHammer` | MCP server security testing — tool injection, boundary testing |
| `NTLMRecon` | NTLM endpoint discovery and authentication fingerprinting |
| `noseyparker` | Multi-source secret scanning with pattern matching |
| `gokart` | Go source code static security analysis |
| `trident` | Password spraying with AD lockout-aware rate limiting |

---

## 13. AI Model Routing (Multi-Model Intelligence)

Aegis360 automatically routes tasks to the optimal AI model to minimize cost while maximizing capability:

### Routing Table

| Task Type | Model | API | Cost |
|-----------|-------|-----|------|
| Exploitation, payload generation, RCE, bypass | **Claude Sonnet 4.6** | Anthropic | Paid |
| Reconnaissance, planning, OSINT, methodology | **Llama 3.3 70B** | Groq | Free |
| Code generation, exploit scripting, analysis | **Qwen3-Coder 32B** | OpenRouter | Free tier |
| Fast answers, summaries, classification | **Llama 3.1 8B** | Groq | Free |
| Multi-turn complex reasoning | **Llama 4** | Groq | Free |
| Security-specific analysis | **Qwen3 32B** | Groq | Free |

### AI-Powered Tools

| Tool | Capability |
|------|-----------|
| `ai_reconnaissance_workflow` | Full AI-driven recon with dynamic tool selection |
| `ai_vulnerability_assessment` | AI-analyzed vulnerability prioritization and severity |
| `ai_generate_attack_suite` | Generate custom attack chains tailored to a specific target |
| `ai_generate_payload` | AI-crafted payloads for specific vulnerability classes |
| `intelligent_smart_scan` | AI selects and tunes optimal tools for the target |
| `create_attack_chain_ai` | Multi-step exploitation path generation with chaining logic |
| `detect_technologies_ai` | AI-powered tech stack and framework fingerprinting |
| `optimize_tool_parameters_ai` | AI tunes tool flags and wordlists for the target context |
| `select_optimal_tools_ai` | AI selects best tool combination for a given task |
| `smart_chat` | Context-aware AI routing with security domain knowledge |
| `chat_all_models` | Query all 6 models simultaneously and compare responses |
| `qwen_full_pipeline` | Qwen3-Coder end-to-end pentest pipeline |
| `qwen_generate_poc` | AI-written proof-of-concept exploit code |
| `qwen_write_exploit` | Full exploit development with Qwen3-Coder |
| `qwen_analyze_code` | Static code security analysis via AI |
| `qwen_crawl_webapp` | AI-guided web application crawling and analysis |
| `run_recon_agent` | Autonomous recon agent — runs full discovery lifecycle |
| `run_vuln_agent` | Autonomous vulnerability discovery agent |
| `run_exploit_agent` | Autonomous exploitation agent with approval gates |
| `augustus_multi_turn` | Multi-turn LLM adversarial red-teaming sessions |

---

## 14. Methodology Guides (Built-in Knowledge Base)

50+ structured methodology guides available as MCP tools — reference during engagements:

### Web & API

- SQLi methodology (all injection types, detection, exploitation, bypass)
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

### Binary & Exploit Dev

- Buffer overflow methodology (stack, heap, format string)
- ROP chain methodology (gadget selection, chain construction, libc leak)
- Shellcode development methodology (x86/x64, syscall-based, staged)
- Exploit development curriculum (beginner to advanced, CTF to real-world)
- Fuzzing methodology (harness design, corpus creation, coverage analysis)
- Crash analysis methodology (triaging, root cause, exploitability)
- Deserialization methodology (Java, PHP, Python pickle, .NET)
- Security mitigations methodology (ASLR, NX, PIE, canary bypass techniques)

### Windows & AD

- Initial access methodology (phishing, exposed services, credential stuffing)
- Windows security bypass methodology (UAC, AppLocker, AMSI, ETW)
- EDR evasion methodology (obfuscation, indirect syscalls, process injection)
- Keylogger architecture methodology (kernel, user-mode, accessibility API)

### Cloud

- Cloud security methodology (AWS, GCP, Azure enumeration and attack paths)
- Kubernetes attack methodology (RBAC abuse, container escape, lateral movement)

### Engagement

- Bug bounty reconnaissance workflow
- Bug bounty vulnerability hunting guide
- Bug bounty authentication bypass testing
- Bug bounty business logic testing
- Bug bounty file upload testing
- OSINT methodology and tools guide
- Fast recon methodology (speed-optimized)
- Advanced red team methodology
- Vulnerability classes overview

---

## 15. Reporting & Output

| Tool | Capability |
|------|-----------|
| `create_vulnerability_report` | Structured pentest finding with CVSS, reproduction steps, remediation |
| `create_scan_summary` | Executive-level scan summary with risk ratings |
| `create_attack_chain_ai` | Documented multi-step attack narrative for reporting |
| `format_tool_output_visual` | Rich terminal output with hacker-theme color palette |
| `vulnerability_intelligence_dashboard` | CVE feed correlation and trending vulnerability tracking |
| `correlate_threat_intelligence` | TTP mapping to MITRE ATT&CK framework |
| `threat_hunting_assistant` | Detection and hunting guidance for identified findings |
| `analyze_target_intelligence` | Consolidated target intelligence report |
| `discover_attack_chains` | Multi-vector attack path discovery and documentation |
| `monitor_cve_feeds` | Real-time CVE monitoring for target technologies |
| `research_zero_day_opportunities` | AI-guided zero-day research targeting for in-scope assets |

---

## 16. Summary Numbers

| Metric | Value |
|--------|-------|
| Total tool integrations | 127 (123 verified working) |
| MCP tools exposed to Claude Desktop | 200+ |
| API endpoints in Flask server | 300+ |
| Total lines of code | 34,423 |
| Tool categories | 14 |
| AI models integrated | 6 |
| Built-in methodology guides | 50+ |
| Verified success rate | 98.4% |
| Go tools installed | 18 |
| Python packages in requirements | 30+ |
| Praetorian tools integrated | 14 |

---

*Aegis-360 AI is a professional penetration testing framework. All capabilities are intended for use against authorized targets only.*
