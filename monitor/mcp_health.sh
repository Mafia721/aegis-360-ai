#!/usr/bin/env bash
# mcp_health.sh — check claude mcp list every 30 s and show server status
# shellcheck disable=SC2034,SC2059
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

BOLD=$'\033[1m'
DIM=$'\033[2m'
RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
NC=$'\033[0m'

printf '\033]2;MCP-HEALTH\007'  # pane title

check_aegis_server() {
    python3 - <<'PYEOF'
import json, urllib.request

try:
    req = urllib.request.urlopen("http://127.0.0.1:8888/health", timeout=2)
    data = json.loads(req.read())
    tools  = data.get("tools_status", {})
    total  = len(tools)
    avail  = sum(1 for v in tools.values() if v)
    engines = data.get("engines", {})
    claude_ok = engines.get("claude", {}).get("enabled", False)
    print(f"\033[0;32m  aegis_360_server  UP  (tools: {avail}/{total}, claude_engine: {'OK' if claude_ok else 'DISABLED'})\033[0m")
except Exception as e:
    print(f"\033[0;31m  aegis_360_server  DOWN  ({e})\033[0m")
PYEOF
}

while true; do
    clear
    printf "${BOLD}══ MCP HEALTH ════════════════════════════════ %s ${NC}\n" "$(date +%H:%M:%S)"
    printf "${DIM}%s${NC}\n" "────────────────────────────────────────────────────────"

    printf "\n${YELLOW}${BOLD}— Aegis-360 server —${NC}\n"
    check_aegis_server

    printf "\n${YELLOW}${BOLD}— claude mcp list —${NC}\n"
    if command -v claude > /dev/null 2>&1; then
        # Run claude mcp list and parse; handle non-zero exit gracefully
        mcp_output=$(claude mcp list 2>&1 || true)
        if [[ -z "$mcp_output" ]]; then
            printf "  ${DIM}(no output — session may not have MCP servers loaded)${NC}\n"
        else
            while IFS= read -r line; do
                if echo "$line" | grep -qiE '(connected|running|ok|\bup\b)'; then
                    printf "  ${GREEN}%s${NC}\n" "$line"
                elif echo "$line" | grep -qiE '(error|failed|down|disconnected)'; then
                    printf "  ${RED}%s${NC}\n" "$line"
                else
                    printf "  %s\n" "$line"
                fi
            done <<< "$mcp_output"
        fi
    else
        printf "  ${DIM}claude CLI not in PATH — MCP status unavailable${NC}\n"
    fi

    printf "\n${YELLOW}${BOLD}— graphify server —${NC}\n"
    if pgrep -f graphify > /dev/null 2>&1; then
        printf "  ${GREEN}graphify-mcp  running${NC}\n"
    else
        printf "  ${DIM}graphify-mcp  not running (start: graphify-mcp)${NC}\n"
    fi

    printf "\n${DIM}  next check in 30 s | Ctrl-C to quit${NC}\n"
    sleep 30
done
