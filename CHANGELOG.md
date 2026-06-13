# Changelog

All notable changes to aegis-360-ai are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.1.0] — 2026-06-13

### Added
- `aegis_360_orchestrator.py` — Multi-model phased workflow engine with enforced model separation
  - Strict phase sequence: START → RECON → ENUMERATION → VULNERABILITY_ANALYSIS → VALIDATION_GATE → EXPLOITATION → REPORTING → END
  - DeepSeek V4 Pro handles RECON, ENUMERATION, and VULNERABILITY_ANALYSIS phases
  - Claude API (claude-sonnet-4-6) restricted to EXPLOITATION and REPORTING phases only
  - `PhaseViolationError` raised if Claude API is invoked in any pre-exploitation phase
  - `PhaseGateError` raised if exploitation is attempted before all pre-gate phases complete
  - Workflow state persisted to `workflow_states/`, reports to `pentest_reports/`
  - Flask Blueprint integration — mounts directly into `aegis_360_server.py`
  - All model handoffs logged with timestamps and decision context
- `tools/arjun` — HTTP parameter discovery tool (bundled)
- `tools/dotdotpwn` — Directory traversal fuzzer (bundled)
- `tools/mcphammer` — MCP-aware fuzzing/stress tool (bundled)
- `tools/paramspider` — Parameter mining from web archives (bundled)
- `tools/xsstrike` — Advanced XSS detection suite (bundled)
- `tools/burp_history_exporter.py` — Burp Suite history export helper
- `tools/fetch_burp_history.py` — Fetches and parses Burp proxy history via REST API

### Changed
- Architecture updated to include orchestrator layer between Claude Code and Claude API
- AI model routing extended: DeepSeek V4 Pro added for recon/enumeration/vuln analysis phases
- README architecture diagram, component table, and features list updated to reflect orchestrator and bundled tools
- README clone URL corrected to `Mafia721/aegis-360-ai`
- README version banner updated to v1.1.0
- README screenshots section updated — replaced outdated server screenshot with `usage_server2.png`, removed logo image
- README contributing section added with workflow, tool integration steps, and security disclosure note
- README author section updated with GitHub profile link for BinaryGalaxys
- README stars badge added
- `INSTALL.md` version updated to v1.1.0, all repo URLs corrected to `Mafia721/aegis-360-ai`, `hexchat.py` references replaced with `aegis360chat.py`
- `CAPABILITIES.md` and `TOOLS.md` version updated to v1.1.0
- `CONTRIBUTING.md` repo links corrected, orchestrator phase guidance added, author set to BinaryGalaxys
- `SECURITY.md` supported versions table updated (1.1.x active, 1.0.x best-effort), repo URL and maintainer contact corrected

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
