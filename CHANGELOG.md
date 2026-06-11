# Changelog

All notable changes to aegis-360-ai are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.0.0] — 2025-06-11

### Added
- Initial public release of aegis-360-ai
- `aegis_360_server.py` — Flask REST API server with 300+ endpoints
- `aegis_360_mcp.py` — MCP bridge exposing 200+ tools to Claude Desktop
- `aegis360chat.py` — Standalone fallback CLI with auto-routing between AI models
- `modules/augustus.py` — LLM adversarial testing (210+ probes, 28 providers)
- `modules/praetorian.py` — Praetorian commercial toolset integration
- Smart AI model routing: Claude Sonnet for exploitation, Groq (free) for everything else
- Autonomous ReAct agent loop for multi-step exploit chains
- Burp Suite Pro integration via proxy chaining and REST API
- Binary exploitation support: pwntools, angr, AFL++, rr-debugger, CodeQL
- Active Directory tools: Impacket, Bloodhound, NetExec, evil-winrm
- Cloud security: Prowler, Trivy, kube-hunter, ScoutSuite, Checkov
- 150+ external security tool integrations (nmap, nuclei, ffuf, sqlmap, etc.)
- Automated installer (`install.sh`) for Linux and macOS
- Windows installer (`install.bat`)
- Full `.env`-based secrets management

---
