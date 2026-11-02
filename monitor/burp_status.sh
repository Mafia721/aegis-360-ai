#!/usr/bin/env bash
# burp_status.sh — monitor Burp Suite proxy (8080) and MCP bridge (9876) every 5 s
# shellcheck disable=SC2059
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL_LOG="${PROJECT_ROOT}/logs/toolcalls.jsonl"

BOLD=$'\033[1m'
DIM=$'\033[2m'
RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
NC=$'\033[0m'

printf '\033]2;BURP\007'  # pane title

check_port() {
    local host="$1"
    local port="$2"
    ss -tnH "dst ${host}:${port}" 2>/dev/null | grep -q ESTAB \
        || nc -z -w1 "${host}" "${port}" 2>/dev/null
}

last_burp_call() {
    if [[ -f "$TOOL_LOG" ]]; then
        grep -i 'burp' "$TOOL_LOG" 2>/dev/null | tail -1 | \
            jq -r '.ts // "never"' 2>/dev/null || echo "never"
    else
        echo "never"
    fi
}

prev_proxy_state=""
prev_mcp_state=""

while true; do
    clear
    printf "${BOLD}══ BURP SUITE STATUS ══════════════════════════ %s ${NC}\n" "$(date +%H:%M:%S)"
    printf "${DIM}%s${NC}\n" "────────────────────────────────────────────────────────"

    # Proxy port 8080
    if check_port 127.0.0.1 8080; then
        proxy_state="UP"
        proxy_color="$GREEN"
        [[ "$prev_proxy_state" == "DOWN" ]] && \
            printf "${GREEN}  ✔ Burp proxy came back UP at %s${NC}\n" "$(date +%H:%M:%S)"
    else
        proxy_state="DOWN"
        proxy_color="$RED"
        [[ "$prev_proxy_state" == "UP" ]] && \
            printf "${RED}  ✘ Burp proxy WENT DOWN at %s${NC}\n" "$(date +%H:%M:%S)"
    fi

    # MCP SSE bridge 9876
    if check_port 127.0.0.1 9876; then
        mcp_state="UP"
        mcp_color="$GREEN"
        [[ "$prev_mcp_state" == "DOWN" ]] && \
            printf "${GREEN}  ✔ Burp MCP bridge came back UP at %s${NC}\n" "$(date +%H:%M:%S)"
    else
        mcp_state="DOWN"
        mcp_color="$RED"
        [[ "$prev_mcp_state" == "UP" ]] && \
            printf "${RED}  ✘ Burp MCP bridge WENT DOWN at %s${NC}\n" "$(date +%H:%M:%S)"
    fi

    printf "\n  Proxy  127.0.0.1:8080  ${proxy_color}${BOLD}%-4s${NC}   %s\n" \
        "$proxy_state" "$(date +%H:%M:%S)"
    printf "  MCP    127.0.0.1:9876  ${mcp_color}${BOLD}%-4s${NC}   %s\n\n" \
        "$mcp_state" "$(date +%H:%M:%S)"

    last=$(last_burp_call)
    printf "  Last Burp MCP call: ${CYAN}%s${NC}\n" "$last"

    if [[ "$proxy_state" == "DOWN" && "$mcp_state" == "DOWN" ]]; then
        printf "\n  ${RED}${BOLD}⚠  Burp is NOT running — start it before active scanning${NC}\n"
        printf "  ${DIM}  Enable SSE bridge: Burp → Extensions → Burp MCP → Enable${NC}\n"
    elif [[ "$proxy_state" == "UP" && "$mcp_state" == "DOWN" ]]; then
        printf "\n  ${YELLOW}⚠  Burp proxy up but MCP bridge DOWN${NC}\n"
        printf "  ${DIM}  Enable SSE bridge in Burp Extensions → Burp MCP${NC}\n"
    fi

    printf "\n${DIM}  refreshes every 5 s | Ctrl-C to quit${NC}\n"

    prev_proxy_state="$proxy_state"
    prev_mcp_state="$mcp_state"

    sleep 5
done
