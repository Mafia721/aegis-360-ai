# Aegis-360-AI — Project Instructions

## Session Startup (REQUIRED before any pentest work)

Before running any recon or tool calls, complete this checklist:

### 1. Verify Aegis server is running
```bash
curl -s http://127.0.0.1:8888/health | python3 -m json.tool | grep status
```
If not running: `/home/kali/aegis-360-ai-master/aegis-360-env/bin/python3 /home/kali/aegis-360-ai-master/aegis_360_server.py --port 8888 &`
(Must use venv Python — system Python lacks `anthropic` and `openai` packages.)

### 2. Set the engagement scope
```bash
export AEGIS_SCOPE="target.example.com,192.168.1.0/24"
# or write to file:
echo "target.example.com" > /home/kali/aegis-360-ai-master/.aegis_scope
```
The scope guard hook (`scripts/scope_guard.py`) reads this before every Bash call.
**No Bash command runs against an out-of-scope target without scope being set.**

### 3. Verify Burp Suite is running (if using proxy tools)
```bash
nc -zv 127.0.0.1 8080 && echo "Burp proxy: UP" || echo "Burp proxy: DOWN — start Burp first"
nc -zv 127.0.0.1 9876 && echo "Burp MCP:   UP" || echo "Burp MCP:   DOWN — enable SSE bridge in Burp"
```

### 4. Start the orchestration workflow
For every new engagement, start the multi-model workflow **before** any recon:
```bash
curl -s -X POST http://127.0.0.1:8888/api/orchestration/start \
  -H "Content-Type: application/json" \
  -d '{"target":"<TARGET>","scope":["<SCOPE_DOMAIN>"],"engagement_id":"<ID>"}' \
  | python3 -m json.tool
```
Save the returned `workflow_id`. Pass it to every subsequent orchestration call.

## Orchestration Model Routing

| Phase | Model | Invoke via |
|---|---|---|
| RECON | Claude Code (claude-sonnet-4-6) | `POST /api/orchestration/advance` with `phase=RECON` |
| ENUMERATION | Claude Code (claude-sonnet-4-6) | `POST /api/orchestration/advance` with `phase=ENUMERATION` |
| VULNERABILITY_ANALYSIS | Claude Code (claude-sonnet-4-6) | `POST /api/orchestration/advance` |
| VALIDATION_GATE | Orchestrator (auto) | Automatic after VULNERABILITY_ANALYSIS |
| EXPLOITATION | Claude Code (claude-sonnet-4-6) | Only unlocked after gate passes |
| REPORTING | Claude Code (claude-sonnet-4-6) | `POST /api/orchestration/report` |

**Do not use raw Bash curl for pentest HTTP calls when an MCP tool exists for it.**
Use the MCP tools (available in this session via the `aegis-360-ai` server).

## MCP Tools Available

This session has access to 315 tools via the `aegis-360-ai` MCP server and graphify knowledge graph queries. Prefer MCP tools over raw Bash. Key tools:

- **Recon:** `nmap_scan`, `subfinder_scan`, `httpx_probe`, `amass_scan`, `katana_crawl`, `gau_url_discovery`
- **Web:** `ffuf_scan`, `nuclei_scan`, `dalfox_xss_scan`, `sqlmap_scan`, `graphql_scanner`, `jwt_analyzer`
- **Burp:** `burp_get_proxy_history`, `burp_active_scan`, `burp_get_issues` (requires Burp running)
- **AI pipelines:** `run_recon_agent`, `run_vuln_agent`, `qwen_full_pipeline`
- **Reporting:** `create_vulnerability_report`

## Scope Enforcement

The `scripts/scope_guard.py` hook blocks Bash calls to out-of-scope IPs/hostnames.
To activate: set `AEGIS_SCOPE` env var or create `.aegis_scope` in the project root.
Format: one domain/IP per line (supports suffix matching, e.g. `example.com` matches `api.example.com`).

## Tool Status Notes

- `jaeles` — binary unavailable; use `nuclei` directly
- `arjun` — installed in venv at `aegis-360-env/bin/arjun`
- `playwright` — module installed; `playwright install chromium` already run
- SpecterOps tools installed: `noseyparker`, `fingerprintx`, `ntlmrecon`
- SpecterOps tools NOT installed (proprietary): augustus, brutus, nerva, hadrian, trajan, vespasian, julius, mcphammer, aurelian, trident, titus, pius
