#!/usr/bin/env bash
# stream_tools.sh — live colour-coded tool-call stream for Aegis-360 monitoring
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG="${PROJECT_ROOT}/logs/toolcalls.jsonl"

RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
CYAN=$'\033[0;36m'
DIM=$'\033[2m'
NC=$'\033[0m'
BOLD=$'\033[1m'

# Set tmux pane title
printf '\033]2;TOOLS\007'

mkdir -p "$(dirname "$LOG")"
touch "$LOG"

print_header() {
    clear
    printf "${BOLD}%s${NC}\n" "━━━ AEGIS TOOL CALLS (live) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    printf "${DIM}%-8s │ %-7s │ %-32s │ %s${NC}\n" "TIME" "CAT" "TOOL" "ARGUMENT"
    printf "${DIM}%s${NC}\n" "────────┼─────────┼────────────────────────────────┼───────────────────────────────────"
}

print_header

tail -F "$LOG" 2>/dev/null | while IFS= read -r line; do
    # Extract ts, tool_name, and primary argument in a single jq call
    parsed=$(jq -r '
        [
            (.ts // "" | .[11:19]),
            (.tool_name // ""),
            (.tool_input // {} |
                .command // .url // .target // .host //
                .query // .file_path // .path // "" |
                tostring | .[0:60])
        ] | join("\t")
    ' <<< "$line" 2>/dev/null) || continue

    IFS=$'\t' read -r ts tool arg <<< "$parsed"
    [[ -z "$tool" ]] && continue

    # Derive display name (strip mcp server prefix)
    if [[ "$tool" == mcp__* ]]; then
        display="${tool##*__}"
        color="$GREEN"
        cat_label="MCP"
    elif [[ "$tool" == "Bash" ]]; then
        display="Bash"
        if [[ "$arg" =~ (^|[[:space:]])(curl|wget|nmap|ffuf|sqlmap|nikto|gobuster|nuclei)([[:space:]]|$) ]]; then
            color="$RED"
            cat_label="BYPASS"
        elif [[ "$arg" =~ (playwright|chromium|browser|puppeteer) ]]; then
            color="$CYAN"
            cat_label="BROWSER"
        else
            color="$YELLOW"
            cat_label="BASH"
        fi
    else
        display="$tool"
        color="$NC"
        cat_label="OTHER"
    fi

    printf "${color}%-8s │ %-7s │ %-32s │ %s${NC}\n" \
        "${ts:0:8}" "$cat_label" "${display:0:32}" "${arg:0:55}"
done
