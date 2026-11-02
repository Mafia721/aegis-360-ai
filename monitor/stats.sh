#!/usr/bin/env bash
# stats.sh — tool-call statistics. Run via: watch -n5 ./monitor/stats.sh
# shellcheck disable=SC2034,SC2059
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG="${PROJECT_ROOT}/logs/toolcalls.jsonl"

BOLD=$'\033[1m'
DIM=$'\033[2m'
RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
CYAN=$'\033[0;36m'
NC=$'\033[0m'

printf '\033]2;STATS\007'  # pane title

[[ ! -f "$LOG" ]] && { printf "${DIM}no toolcalls.jsonl yet${NC}\n"; exit 0; }

total=$(wc -l < "$LOG" 2>/dev/null || echo 0)
[[ "$total" -eq 0 ]] && { printf "${DIM}no tool calls logged yet${NC}\n"; exit 0; }

# Counts per category
mcp_count=$(grep -c '"tool_name":"mcp__' "$LOG" 2>/dev/null || echo 0)
bash_count=$(grep -c '"tool_name":"Bash"' "$LOG" 2>/dev/null || echo 0)
bypass_count=$(python3 - <<'EOF'
import json, sys, re, os

log = os.environ.get("LOG", "")
log_path = log if log else "/home/kali/aegis-360-ai-master/logs/toolcalls.jsonl"
bypass_re = re.compile(r'\b(curl|wget|nmap|ffuf|sqlmap|nikto|gobuster|nuclei)\b')
count = 0
try:
    with open(log_path) as f:
        for line in f:
            try:
                d = json.loads(line)
                if d.get("tool_name") == "Bash":
                    cmd = d.get("tool_input", {}).get("command", "")
                    if bypass_re.search(cmd):
                        count += 1
            except (json.JSONDecodeError, KeyError):
                pass
except FileNotFoundError:
    pass
print(count)
EOF
)

other_count=$((total - mcp_count - bash_count))
if [[ "$total" -gt 0 ]]; then
    mcp_pct=$(( mcp_count * 100 / total ))
    bash_pct=$(( bash_count * 100 / total ))
else
    mcp_pct=0
    bash_pct=0
fi

printf "${BOLD}══ AEGIS TOOL STATS ══════════════════════════════ %s ${NC}\n" "$(date +%H:%M:%S)"
printf "${DIM}%s${NC}\n" "─────────────────────────────────────────────────────"
printf "  Total calls : ${BOLD}%d${NC}\n" "$total"
printf "  ${GREEN}MCP tools   : %d (%d%%)${NC}\n" "$mcp_count" "$mcp_pct"
printf "  ${YELLOW}Bash        : %d (%d%%)${NC}\n" "$bash_count" "$bash_pct"
printf "  Other       : %d\n" "$other_count"
if [[ "$bypass_count" -gt 0 ]]; then
    printf "  ${RED}BYPASS      : %d  ← direct tool calls bypassing MCP${NC}\n" "$bypass_count"
else
    printf "  ${GREEN}BYPASS      : 0${NC}\n"
fi

printf "\n${BOLD}TOP 10 TOOLS${NC}\n"
printf "${DIM}%s${NC}\n" "─────────────────────────────────────────────────────"

python3 - <<'EOF'
import json, os
from collections import Counter

log_path = "/home/kali/aegis-360-ai-master/logs/toolcalls.jsonl"
counts = Counter()
try:
    with open(log_path) as f:
        for line in f:
            try:
                d = json.loads(line)
                name = d.get("tool_name", "")
                # Display name: strip mcp server prefix
                display = name.split("__")[-1] if name.startswith("mcp__") else name
                counts[display] += 1
            except (json.JSONDecodeError, KeyError):
                pass
except FileNotFoundError:
    pass

for i, (name, cnt) in enumerate(counts.most_common(10), 1):
    bar = "█" * min(cnt, 40)
    print(f"  {i:2}. {name:<28} {cnt:4}  {bar}")
EOF

printf "\n${BOLD}REGISTERED MCP TOOLS — NEVER CALLED${NC}\n"
printf "${DIM}%s${NC}\n" "─────────────────────────────────────────────────────"

python3 - <<'EOF'
import json, urllib.request, urllib.error, os
from collections import Counter

log_path = "/home/kali/aegis-360-ai-master/logs/toolcalls.jsonl"
called = set()
try:
    with open(log_path) as f:
        for line in f:
            try:
                d = json.loads(line)
                name = d.get("tool_name", "")
                if name.startswith("mcp__"):
                    called.add(name.split("__")[-1])
            except (json.JSONDecodeError, KeyError):
                pass
except FileNotFoundError:
    pass

# Fetch registered tools from server
try:
    req = urllib.request.urlopen("http://127.0.0.1:8888/health", timeout=2)
    health = json.loads(req.read())
    registered = set(health.get("tools_status", {}).keys())
    never = sorted(registered - called)
    if never:
        for t in never[:15]:
            print(f"  {t}")
        if len(never) > 15:
            print(f"  ... and {len(never)-15} more")
    else:
        print("  all registered tools have been called")
except Exception:
    print("  (server unreachable — start aegis_360_server.py)")
EOF
