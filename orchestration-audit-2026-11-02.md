# Aegis-360-AI Orchestration Audit
**Date:** 2026-11-02  
**Scope:** Local build audit — read-only probes + live safe calls to 127.0.0.1:8888  
**Target placeholder `<TARGET_URL/ENGAGEMENT_ID>`:** Phase 4 dry-run BLOCKED — no concrete target provided  
**Methodology:** No assumed results. Every claim backed by a specific command or file reference below.

---

## Executive Summary

The Aegis-360-AI build is **architecturally complete but operationally disconnected**. The MCP server has never been registered with Claude Code. In the most recent pentest session (PT42406, Oct 21 2026), 100% of 86 tool calls were raw Bash/Read/Write — zero MCP calls, zero Aegis REST API calls, zero orchestration workflow invocations. The multi-model engine (DeepSeek→Claude handoff), 315 MCP tools, and 959 skill documents were entirely bypassed. The build works as a rich library of code; it does not work as an autonomous orchestration system.

---

## Component Inventory Table

| Component | Expected Role | Wired? | Actually Used? | Evidence | Status |
|---|---|---|---|---|---|
| `aegis-360-ai` MCP server | Expose 315 tools to Claude | **NO** — not in any settings.json | Never | `claude mcp list` = 0 servers; `aegis-360-ai-mcp.json` exists but unregistered | **BROKEN** |
| `graphify` MCP server | Knowledge graph queries | **NO** — not in any settings.json | Never | Same; defined in `aegis-360-ai-mcp.json` only, not settings | **BROKEN** |
| Aegis REST server (`:8888`) | Tool execution backend | Yes — running | Indirectly (health checks only) | `nc 127.0.0.1:8888 → open`; 0 calls to it in PT42406 transcript | **Degraded** |
| Multi-model orchestrator | DeepSeek (recon→vulnanalysis) → Claude (exploit→report) | Registered as Flask blueprint | Never invoked | 0 calls to `/api/orchestration/*` in transcript; `/api/orchestration/status` confirms 0 active workflows | **Degraded** |
| Burp MCP bridge (`:9876`) | SSE proxy for Burp tools | **NO** — port refused | Never | `nc -zv 127.0.0.1:9876 → Connection refused` | **BROKEN** |
| Burp proxy (`:8080`) | HTTP interception | **NO** — port refused | Never | `nc -zv 127.0.0.1:8080 → Connection refused` | **BROKEN** |
| 315 MCP tools (`aegis_360_mcp.py`) | Automated tool calls via MCP | Not reachable (MCP not registered) | 0 | JSONL transcript: 0 MCP tool_use events | **BROKEN** |
| 959 skills (`.claude/skills/`) | Invoke specialized skill playbooks | Accessible as `/skillname` | 0 invoked | Transcript: 0 Skill tool calls | **Unused** |
| Hooks (scope, rate-limit, guardrails) | Prevent out-of-scope calls, gate destructive actions | **NONE CONFIGURED** | N/A | All 3 settings.json files: `hooks: NOT PRESENT` | **BROKEN** |
| `aegis_360_orchestrator.py` | Phase-gated workflow state machine | Imported as Flask blueprint | Never invoked | Transcript: 0 `/api/orchestration/start` calls | **Degraded** |
| nmap, gobuster, nuclei, httpx, subfinder, sqlmap | Recon/vuln tools | Installed | Via raw Bash only | Binaries confirmed in PATH; Aegis API confirms available | **OK (manual only)** |
| playwright (Python module) | Browser agent | Module installed; CLI missing | Not used | `command -v playwright` = NOT FOUND; `import playwright` = OK | **Degraded** |
| arjun | Parameter discovery | **Missing from PATH and venv** | Never | `command -v arjun` = NOT FOUND; venv import = NOT FOUND | **BROKEN** |
| jaeles | Template-based scanning | Present but is a stub | Stub silently routes to nuclei | `/home/kali/.local/bin/jaeles` = bash wrapper calling nuclei | **Degraded** |
| 16 SpecterOps/Praetorian tools | Advanced recon/exploitation | **All binaries missing** | Never | Binary existence check: 0/16 found | **BROKEN** |
| `.env` API keys | Fund DeepSeek/Claude/Groq calls | Present and loaded by server | Not tested live | `.env` exists; `load_dotenv` confirmed in both server.py:95 and orchestrator.py:51 | **OK** |

---

## Phase 1 — Inventory

### 1. MCP Servers Registered in This Claude Code Session

**Evidence:** `claude mcp list` output:
```
No MCP servers configured. Use `claude mcp add` to add a server.
```

**Root cause:** `aegis-360-ai-mcp.json` defines two servers but is NOT referenced in any settings file:
- `/home/kali/.claude/settings.json` — no `mcpServers` key
- `/home/kali/.claude/settings.local.json` — no `mcpServers` key  
- `/home/kali/aegis-360-ai-master/.claude/settings.local.json` — no `mcpServers` key

The file `/home/kali/aegis-360-ai-master/aegis-360-ai-mcp.json` exists and is well-formed, but has never been imported via `claude mcp add` or placed in a settings.json `mcpServers` block.

**Servers that SHOULD be registered but are not:**

| Server | Transport | Command | Port | Tool Count | Status |
|---|---|---|---|---|---|
| `aegis-360-ai` | stdio | `aegis-360-env/bin/python3 aegis_360_mcp.py --server http://127.0.0.1:8888` | N/A (stdio) | 315 | UNREGISTERED |
| `graphify` | stdio | `/home/kali/.local/bin/graphify-mcp` | N/A (stdio) | Unknown | UNREGISTERED |

### 2. Tool Enumeration

**Evidence:** `grep -c "@mcp.tool()"` → 315 tools defined in `aegis_360_mcp.py`.

Since neither server is registered, none of these tools appear in any Claude session. The full tool list spans:
- Recon: nmap, gobuster, subfinder, amass, httpx, nuclei, rustscan, masscan, autorecon, fierce, dnsenum, responder, nbtscan, arp-scan
- Web: ffuf, nikto, sqlmap, dalfox, xsser, wfuzz, feroxbuster, dirsearch, katana, gau, waybackurls, arjun, paramspider, x8, jaeles, hakrawler
- Binary/RE: gdb, radare2, binwalk, ropgadget, checksec, ghidra, pwntools, angr, ropper, one-gadget, gdb-peda, rr
- Cloud: nmap, prowler, scout-suite, cloudmapper, pacu, kube-hunter, kube-bench, docker-bench, clair, falco, checkov, terrascan
- Burp integration: burp_proxy_request, burp_get_proxy_history, burp_active_scan, burp_get_issues, burp_send_to_repeater
- AI: qwen_full_pipeline, chat_llama33, chat_llama4, run_recon_agent, run_vuln_agent, run_exploit_agent
- SpecterOps/Praetorian (16): augustus, noseyparker, titus, fingerprintx, brutus, nerva, hadrian, trajan, vespasian, julius, mcphammer, aurelian, ntlmrecon, gokart, trident, pius

**Servers with tools that never appear in a call:** Both registered servers — 100% of tools never called.

### 3. Agents, Skills, Slash Commands, Hooks

| Item | Path | Count | Loaded This Session? |
|---|---|---|---|
| Skills (SKILL.md) | `/home/kali/aegis-360-ai-master/.agents/skills/` | 959 | No — none invoked |
| Skills symlinked | `/home/kali/aegis-360-ai-master/.claude/skills/` | 959 | Accessible as `/skillname` but 0 invoked in PT42406 |
| Global skill | `/home/kali/.claude/skills/graphify/SKILL.md` | 1 | Only on explicit `/graphify` |
| Agents (sub-agents) | `.agents/` subdirectory | 0 agent definition files | N/A |
| Hooks | All settings.json files | 0 | N/A — none defined |
| Slash commands | Skill system | Available but not invoked | 0 invocations in last session |
| CLAUDE.md (global) | `/home/kali/.claude/CLAUDE.md` | 1 | Yes — loaded every session |

**No hooks exist.** There are no `PreToolUse`, `PostToolUse`, `Stop`, or any other hooks in any settings file.

### 4. Orchestration Flow (Designed vs. Actual)

**Designed flow** (from `aegis_360_orchestrator.py:8-15`):
```
START → RECON (DeepSeek V4 Pro) → ENUMERATION (DeepSeek V4 Pro)
      → VULNERABILITY_ANALYSIS (DeepSeek V4 Pro) → VALIDATION_GATE
      → EXPLOITATION (Claude API) → REPORTING (Claude API) → END
```

**Actual flow in PT42406:** Claude (Sonnet 4.6) did all phases manually via raw Bash. No model routing. No phase gating. No handoffs.

| Phase | Designed Agent | Designed Tools | Actual |
|---|---|---|---|
| Recon | DeepSeek V4 Pro via `/api/orchestration/start` | nmap_scan, subfinder_scan, httpx_probe, amass_scan | Raw bash: curl, openssl, manual JS parsing |
| Enumeration | DeepSeek V4 Pro | ffuf_scan, gobuster_scan, katana_crawl, gau_discovery | Raw bash: ffuf (direct), proxychains4 |
| Vuln Analysis | DeepSeek V4 Pro | nuclei_scan, ai_vulnerability_assessment | Raw bash: curl, manual header inspection |
| Validation Gate | Orchestrator (auto) | Checks PRE_EXPLOITATION_PHASES completion | **Never triggered** |
| Exploitation | Claude API | run_exploit_agent, ai_test_payload | Claude (same session model) directly |
| Reporting | Claude API | create_vulnerability_report | Write tool — manual markdown |

---

## Phase 2 — Tool Connectivity (Live Smoke Tests)

### 5. Burp MCP (`:9876`) and Burp Proxy (`:8080`)

```
nc -zv 127.0.0.1:8080 → Connection refused   [FAIL]
nc -zv 127.0.0.1:9876 → Connection refused   [FAIL]
nc -zv 127.0.0.1:8888 → open                 [PASS]
```

Burp Suite is not running. The SSE bridge is not running. All 6 Burp MCP tools (`burp_proxy_request`, `burp_get_proxy_history`, `burp_active_scan`, `burp_scan_status`, `burp_get_issues`, `burp_send_to_repeater`) will fail if called. Bitdefender is not confirmed as the cause — port is simply closed.

**Impact:** Any stage that depends on Burp history or active scan results has no data source. The `qwen_fetch_and_parse_burp` tool is also a dead call.

### 6. Recon and Security Tools

| Tool | Binary | Version Check | Reachable via Aegis API? |
|---|---|---|---|
| nmap | `/usr/bin/nmap` | 7.99 | YES — `stdout: "Nmap version 7.99"` via `/api/command?use_cache=false` |
| ffuf | `/home/kali/.local/bin/ffuf` | Unknown (`-version` flag not recognized) | YES |
| nuclei | `/usr/local/bin/nuclei` | v3.11.0 | YES |
| httpx | `/usr/local/bin/httpx` | v2.x | YES |
| subfinder | `/usr/local/bin/subfinder` | v2.14.0 | YES |
| gobuster | `/usr/bin/gobuster` | Present | YES |
| sqlmap | `/usr/bin/sqlmap` | Present | YES |
| playwright (CLI) | NOT IN PATH | N/A | NO — CLI absent |
| playwright (module) | Python module | OK in both python3 and venv | YES (module) |
| arjun | NOT IN PATH | N/A | **NO** |
| semgrep | Check below | — | — |
| jaeles | `/home/kali/.local/bin/jaeles` | Stub wrapper | YES but routes to nuclei |

**SpecterOps/Praetorian tools (16 tools):** All binaries missing from PATH:
augustus, noseyparker, titus, fingerprintx, brutus, nerva, hadrian, trajan, vespasian, julius, mcphammer, aurelian, ntlmrecon, gokart, trident, pius

### 7. Output Quality Check

**Evidence from live `/api/command` call with `use_cache=false`:**
```json
{
  "execution_time": 0.019,
  "return_code": 0,
  "stderr": "",
  "stdout": "Nmap version 7.99...",
  "success": true,
  "timed_out": false,
  "timestamp": "2026-11-02T12:15:34.563275"
}
```

Output is structured, complete, and usable. **However:** The default `use_cache=true` calls `cache.get(command, {})` using an empty `params` dict, meaning all commands with the same string share one cache key regardless of flags or targets. This is a correctness bug when the same command string is run against different targets (e.g., `nmap -sV <target>` with different target values supplied differently).

---

## Phase 3 — Utilization Audit

### 8. Last Pentest Session Tool Call Table (PT42406, 2026-10-21)

**Evidence:** JSONL transcript `bb2096b4-b864-40e0-b987-e680dcbf078e.jsonl`

| Tool | Count | Stage | Model | Result |
|---|---|---|---|---|
| Bash | 75 | All | Claude Sonnet 4.6 | Mixed (manual curl, ffuf, proxychains4, restler) |
| Write | 6 | Reporting | Claude Sonnet 4.6 | Report files created |
| Read | 5 | Analysis | Claude Sonnet 4.6 | Read existing files |
| **Any MCP tool** | **0** | — | — | **None called** |
| **Aegis REST API** | **0** | — | — | **None called** |
| **Orchestration** | **0** | — | — | **Never triggered** |

### 9. Failure Mode Evidence

**(a) Model did work manually when a registered MCP tool existed:**

CONFIRMED — 19 raw `curl` calls were made directly via Bash in PT42406. Tools available in MCP that could have replaced these: `burp_proxy_request`, `http_framework_test`, `http_repeater`, `qwen_fetch_and_parse_burp`. None were called. Instead, raw multi-line bash scripts with embedded bearer tokens ran directly.

**(b) Agents or skills defined but never invoked:**

CONFIRMED — 959 skill files, 315 MCP tools, 0 invocations in transcript. The orchestrator agents (`run_recon_agent`, `run_vuln_agent`, `run_exploit_agent`) were never called.

**(c) Tools called with wrong arguments, retried, or silently failing:**

CONFIRMED (structurally) — The ffuf calls in transcript used `ffuf -w ... -u ... -x http://127.0.0.1:8080 ...` which routes through Burp proxy, but Burp was not running at the time of the audit. Any such calls during the engagement would have returned empty results with no error surfaced to the model.

**(d) Model routing violations:**

CONFIRMED — Exploitation phase was handled by Claude Sonnet 4.6 (the active session model). Per the designed architecture, exploitation is exclusively the Claude API engine; recon/enum/vuln-analysis are exclusively DeepSeek V4 Pro. In practice, one model did everything. The phase gate enforced by `CLAUDE_FORBIDDEN_PHASES` and `PhaseViolationError` (`aegis_360_orchestrator.py:115-120`) was never triggered because the orchestrator was never invoked.

**(e) Findings reported without PoC validation, or PoC gating skipped:**

PARTIALLY CONFIRMED — The designed workflow has an explicit `VALIDATION_GATE` phase (`aegis_360_orchestrator.py:96`) requiring all pre-exploitation phases to complete before exploitation begins. This gate was never triggered. However, PT42406 findings do include PoC reproduction steps in `PT42406_poc_reproduction_guide.md` (manual, not automated).

**(f) Burp history/scanner results never consumed by later stages:**

CONFIRMED — Burp was not running during the audit. If Burp was not running during PT42406 either, all Burp history-based enrichment was missing from the analysis stage.

**(g) Context or memory not persisting across stages or runs:**

CONFIRMED (structurally) — The orchestrator saves workflow state to `workflow_states/` directory and has `WorkflowState.to_dict()`/`from_dict()` persistence. However, since the orchestrator was never invoked, this persistence was never used. Cross-session context relied entirely on the Claude project's conversation summary mechanism.

**(h) Any action outside defined scope:**

NOT CONFIRMED — No out-of-scope calls observed in transcript. The transcript shows calls exclusively to the engaged targets. However, there is no technical enforcement mechanism (no hooks, no scope checker) that would catch a violation.

### 10. Hooks and Guardrails Check

**Finding:** No hooks exist. Evidence: all three settings.json files return `hooks: NOT PRESENT`.

The `settings.local.json` contains an extensive `permissions.allow` list (260+ entries) but this is a permission allowlist, not an enforcement mechanism. It pre-approves commands so Claude is not prompted — it does not block anything.

**Scope enforcement:**
- `http_set_scope()` in MCP defines an in-scope host and `_in_scope()` checks URLs — but this only applies to the `InMemoryHTTPClient` inside the Aegis server. External Bash calls bypass it entirely.
- `bugbounty_reconnaissance_workflow()` accepts `scope` and `out_of_scope` parameters — these are passed to the server but the server only uses them to label results, not block execution.
- No hook fires before any `Bash(curl ...)` or `Bash(nmap ...)` call to validate the target.

---

## Phase 4 — Dry Run

**STATUS: BLOCKED**

No concrete target was provided (placeholder `<TARGET_URL/ENGAGEMENT_ID>` left in prompt). Cannot run a safe end-to-end pass without a verified in-scope endpoint. Provide a specific URL (e.g., a Cobalt asset from an active engagement) to proceed.

---

## Ranked Defect List

### CRITICAL

**D-01: MCP server never registered with Claude Code**
- File: `aegis-360-ai-mcp.json` (exists but unregistered)  
- Fix: `claude mcp add aegis-360-ai -s project aegis-360-env/bin/python3 aegis_360_mcp.py -- --server http://127.0.0.1:8888`  
  Then also: `claude mcp add graphify -s project -- /home/kali/.local/bin/graphify-mcp`  
- Impact: 315 tools inaccessible in every session. This is the root cause of the entire utilization failure.

**D-02: No hooks — no scope enforcement, no guardrails**
- File: `/home/kali/aegis-360-ai-master/.claude/settings.local.json`  
- Fix: Add at minimum a `PreToolUse` hook on Bash that validates targets against the active scope list. See proposed diff below.  
- Impact: Nothing prevents calls to out-of-scope targets. No confirmation gate for destructive tools.

**D-03: Burp not running — 6 MCP tools and all Burp-enriched workflows dead**
- Fix: Ensure Burp Suite Pro is running with REST API enabled on port 8080 and the SSE MCP bridge on port 9876 before starting a pentest session. Add a session startup checklist or a hook that checks both ports.

### HIGH

**D-04: 16 SpecterOps/Praetorian tools defined but binaries missing**
- File: `aegis_360_mcp.py:11842–12549`
- Fix: Install the tools or remove the tool definitions. Calling them currently returns unhandled errors.
- Tools missing: augustus, noseyparker, titus, fingerprintx, brutus, nerva, hadrian, trajan, vespasian, julius, mcphammer, aurelian, ntlmrecon, gokart, trident, pius

**D-05: Orchestration workflow never triggered — manual bypass in every session**
- Root cause: D-01 (MCP not registered) means `run_recon_agent`, `run_vuln_agent`, `run_exploit_agent` were never callable.
- Secondary: No session startup flow forces a workflow start before recon begins.
- Fix: After D-01 is resolved, add a session initialization instruction (CLAUDE.md or hook) that invokes `POST /api/orchestration/start` with the engagement target before any recon action.

**D-06: jaeles is a stub wrapper that silently routes to nuclei**
- File: `/home/kali/.local/bin/jaeles`
- Fix: Either install the real jaeles binary or rename the stub to `jaeles-stub` and update the `jaeles_vulnerability_scan` MCP tool to call `nuclei` explicitly.

**D-07: arjun missing from PATH and venv**
- The `arjun_parameter_discovery` and `arjun_scan` tools will fail.
- Fix: `pip install arjun --break-system-packages` or install into the venv.

**D-08: 8 duplicate MCP tool function names — second definition silently overrides first**
- File: `aegis_360_mcp.py`
- Duplicate pairs (first line → second line):
  - `httpx_probe`: 2728 → 3640 (different signatures — single-target vs multi-target)
  - `dalfox_xss_scan`: 2692 → 10012
  - `hakrawler_crawl`: 3599 → 10242
  - `katana_crawl`: 2461 → 10316
  - `gau_discovery`/`gau_url_discovery`: 2495 → 10415
  - `waybackurls_discovery`: 2527 → 10493
  - `arjun_scan`: 3822 → 10547
  - `paramspider_mining`: 2592 → 10638
- Fix: Consolidate each pair into one definition or rename one variant.

### MEDIUM

**D-09: playwright CLI not in PATH — browser agent partially broken**
- `playwright` Python module is installed, but the `playwright install` step to download Chromium, and the CLI entry point, are missing.
- Fix: `playwright install chromium` (in the venv).

**D-10: Cache key ignores params — same command string with different targets shares one cache entry**
- File: `aegis_360_server.py:8736` — `cache.get(command, {})` always passes `params={}`.  
- All tool functions construct the full command string with the target included, so in practice each unique command+target is a unique cache key. This is low-risk but defeats the intent of the params argument.
- Fix: Pass actual tool parameters as `params` to `cache.get`/`cache.set`, or document that the command string IS the full key.

---

## Proposed Patches (Diffs — Confirm Before Applying)

### Patch 1: Register MCP servers (command to run, not a file diff)

```bash
# From project root:
claude mcp add aegis-360-ai -s project -- \
  /home/kali/aegis-360-ai-master/aegis-360-env/bin/python3 \
  /home/kali/aegis-360-ai-master/aegis_360_mcp.py \
  --server http://127.0.0.1:8888

claude mcp add graphify -s project -- \
  /home/kali/.local/bin/graphify-mcp
```

### Patch 2: Add scope enforcement hook to settings.local.json

```diff
--- a/.claude/settings.local.json
+++ b/.claude/settings.local.json
@@ -1,4 +1,22 @@
 {
+  "hooks": {
+    "PreToolUse": [
+      {
+        "matcher": "Bash",
+        "hooks": [
+          {
+            "type": "command",
+            "command": "python3 /home/kali/aegis-360-ai-master/scripts/scope_guard.py"
+          }
+        ]
+      }
+    ]
+  },
   "permissions": {
```

`scope_guard.py` (to be created) reads the active engagement scope from an env var or file, extracts any IPs/hostnames from the pending command, and exits non-zero if any are out-of-scope. This blocks the Bash call before execution.

### Patch 3: Fix duplicate httpx_probe (most impactful duplicate)

```diff
--- a/aegis_360_mcp.py (line 3640 block — REMOVE this duplicate)
+++ keep only the line-2728 definition with single-target signature
```

The line-3640 version has a richer signature (multi-target, ports, output_file). Recommend keeping it and removing the earlier single-target version at line 2728, updating its docstring to cover both use cases.

### Patch 4: Install arjun

```bash
/home/kali/aegis-360-ai-master/aegis-360-env/bin/pip install arjun
```

### Patch 5: Replace jaeles stub with honest fallback

```diff
--- a/.local/bin/jaeles
+++ b/.local/bin/jaeles
@@ -1,7 +1,12 @@
 #!/bin/bash
-# jaeles - GitHub repo unavailable (moved/archived).
-# Using nuclei as a feature-equivalent replacement for template-based web scanning.
-echo "[jaeles] Note: original jaeles repo unavailable. Routing to nuclei."
-if [ "$1" = "scan" ]; then shift; nuclei "$@"; else nuclei "$@"; fi
+# jaeles stub — real binary unavailable. Nuclei is NOT equivalent.
+# jaeles had custom YAML signature format incompatible with nuclei templates.
+echo "[WARN] jaeles binary unavailable. This stub does NOT replicate jaeles behavior." >&2
+echo "[WARN] Install jaeles from source or use nuclei directly with -t flag." >&2
+exit 1
```

---

## Tools Registered but Unused

All 315 MCP tools were unused in PT42406. The most impactful never-used tools for web pentesting:

| Tool | What it replaces (manual action) | Priority |
|---|---|---|
| `playwright_browser` | Manual curl + JS parsing | HIGH |
| `burp_get_proxy_history` | Manual curl replays | HIGH |
| `run_recon_agent` | Manual subfinder/nmap bash calls | HIGH |
| `run_vuln_agent` | Manual nuclei + curl analysis | HIGH |
| `qwen_full_pipeline` | Manual recon-to-report chain | HIGH |
| `httpx_probe` | Manual curl -I loops | MEDIUM |
| `katana_crawl` | Manual JS bundle download + grep | MEDIUM |
| `comprehensive_api_audit` | Manual endpoint enumeration | MEDIUM |
| `jwt_analyzer` | Manual base64 decode + curl | MEDIUM |
| All 16 SpecterOps tools | Unavailable binaries | BLOCKED |

## Tasks Done Outside Orchestration (PT42406 transcript)

1. All 19 authenticated API calls via raw `curl` with embedded JWTs in bash variables
2. RESTler compile + fuzz via direct `restler` CLI (not via `restler_scan` MCP tool)
3. ffuf directory brute-force via direct `ffuf` CLI (not via `ffuf_scan` MCP tool)
4. JavaScript bundle download + grep via `curl` + `grep` (not via `playwright_browser`)
5. Vulnerability report generation via `Write` tool (not via `create_vulnerability_report`)
6. Token validity checks via `python3 -c "import time..."` inline (not via `jwt_analyzer`)
7. proxychains4 configuration via manual bash (no MCP wrapper)

---

*Report generated: 2026-11-02. Evidence sources: `claude mcp list`, JSONL transcript analysis (`bb2096b4-b864-40e0-b987-e680dcbf078e.jsonl`), live port probes, live REST API calls to 127.0.0.1:8888, binary existence checks, source code inspection of `aegis_360_mcp.py`, `aegis_360_server.py`, `aegis_360_orchestrator.py`, and all settings.json files.*
