#!/usr/bin/env bash
# agents.sh — live subagent and orchestration phase monitor
# Tails logs/agents.jsonl (SubagentStart/Stop hooks) and /tmp/aegis_server.log
# Routing check: edit EXPECTED_MODELS below to match your deployment.
# NOTE: current config routes ALL phases to claude-api (all-Claude mode).
# shellcheck disable=SC2034,SC2059
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AGENT_LOG="${PROJECT_ROOT}/logs/agents.jsonl"
SERVER_LOG="/tmp/aegis_server.log"

BOLD=$'\033[1m'
DIM=$'\033[2m'
RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
CYAN=$'\033[0;36m'
NC=$'\033[0m'

# Expected model per phase — edit here if you re-enable DeepSeek routing
declare -A EXPECTED_MODELS=(
    [RECON]="claude-api"
    [ENUMERATION]="claude-api"
    [VULNERABILITY_ANALYSIS]="claude-api"
    [VALIDATION_GATE]="orchestrator"
    [EXPLOITATION]="claude-api"
    [REPORTING]="claude-api"
)

printf '\033]2;AGENTS\007'  # pane title

check_routing() {
    local phase="$1"
    local model="$2"
    local expected="${EXPECTED_MODELS[$phase]:-unknown}"
    if [[ "$model" != *"$expected"* && "$expected" != "unknown" ]]; then
        printf "${RED}  ⚠ ROUTING VIOLATION: %s → %s (expected %s)${NC}\n" \
            "$phase" "$model" "$expected"
    fi
}

print_banner() {
    clear
    printf "${BOLD}══ AEGIS AGENTS & ORCHESTRATION ═══════════════ %s ${NC}\n" "$(date +%H:%M:%S)"
    printf "${DIM}%s${NC}\n" "────────────────────────────────────────────────────────"
}

print_banner

# Section 1: recent subagent events from agents.jsonl
printf "${CYAN}${BOLD}─── Subagent Events (last 10) ───${NC}\n"
if [[ -f "$AGENT_LOG" ]] && [[ -s "$AGENT_LOG" ]]; then
    tail -20 "$AGENT_LOG" | while IFS= read -r line; do
        ts=$(jq -r '.ts // "" | .[11:19]' <<< "$line" 2>/dev/null)
        event=$(jq -r '.event // ""' <<< "$line" 2>/dev/null)
        agent=$(jq -r '.agent_name // ""' <<< "$line" 2>/dev/null)
        model=$(jq -r '.model // ""' <<< "$line" 2>/dev/null)
        phase=$(jq -r '.phase // ""' <<< "$line" 2>/dev/null)

        if [[ "$event" == *"Start"* ]]; then
            printf "  ${GREEN}▶ %-8s${NC} %-20s model=%-20s %s\n" \
                "${ts:0:8}" "${agent:0:20}" "${model:0:20}" "$phase"
        elif [[ "$event" == *"Stop"* ]]; then
            printf "  ${DIM}■ %-8s %-20s DONE${NC}\n" "${ts:0:8}" "${agent:0:20}"
        fi
    done
else
    printf "  ${DIM}no subagent events yet (logs/agents.jsonl empty)${NC}\n"
fi

printf "\n${CYAN}${BOLD}─── Orchestration Phases (server log) ───${NC}\n"
if [[ -f "$SERVER_LOG" ]]; then
    # Extract recent phase dispatch lines
    grep -E "(phase=|RECON|ENUMERATION|VULNERABILITY|EXPLOITATION|REPORTING|VALIDATION|Claude API|DeepSeek)" \
        "$SERVER_LOG" 2>/dev/null | tail -20 | while IFS= read -r line; do

        ts=$(echo "$line" | grep -oE '[0-9]{2}:[0-9]{2}:[0-9]{2}' | head -1)
        phase=$(echo "$line" | grep -oE 'phase=[A-Z_]+' | head -1 | cut -d= -f2)
        model=$(echo "$line" | grep -oE '(deepseek|claude|orchestrator)[^|]*' | head -1)

        if echo "$line" | grep -qiE 'violation|error|forbidden'; then
            printf "  ${RED}%-8s %s${NC}\n" "${ts:0:8}" "${line: -80}"
        elif echo "$line" | grep -qiE 'claude.*api|claude.*sonnet'; then
            printf "  ${GREEN}%-8s %s${NC}\n" "${ts:0:8}" "${line: -80}"
        else
            printf "  ${DIM}%-8s %s${NC}\n" "${ts:0:8}" "${line: -80}"
        fi

        # Routing check when phase info is available
        if [[ -n "$phase" && -n "$model" ]]; then
            check_routing "$phase" "$model"
        fi
    done
else
    printf "  ${DIM}server log not found — start server first${NC}\n"
fi

printf "\n${CYAN}${BOLD}─── Current Phase Summary ───${NC}\n"
python3 - <<'PYEOF'
import json, urllib.request

try:
    req = urllib.request.urlopen("http://127.0.0.1:8888/api/orchestration/status", timeout=2)
    data = json.loads(req.read())
    workflows = data.get("workflows", [])
    if not workflows:
        print("  no active workflows")
    for wf in workflows[-3:]:
        wid = wf.get("workflow_id", "?")[:8]
        target = wf.get("target", "?")
        phase = wf.get("current_phase", "?")
        status = wf.get("status", "?")
        model = wf.get("assigned_model", {}).get(phase, "?")
        print(f"  [{wid}] {target} | phase={phase:<25} status={status} model={model}")
except Exception as e:
    print(f"  (server unreachable: {e})")
PYEOF
