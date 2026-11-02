#!/usr/bin/env bash
# scope_guard.sh — tail toolcalls.jsonl and flag any calls targeting out-of-scope hosts
# shellcheck disable=SC2059
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG="${PROJECT_ROOT}/logs/toolcalls.jsonl"
SCOPE_FILE="${PROJECT_ROOT}/scope.txt"
AEGIS_SCOPE_FILE="${PROJECT_ROOT}/.aegis_scope"

BOLD=$'\033[1m'
DIM=$'\033[2m'
RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
NC=$'\033[0m'

ALWAYS_ALLOWED="127.0.0.1 localhost ::1 8.8.8.8 1.1.1.1"

printf '\033]2;SCOPE\007'  # pane title

load_scope() {
    local scopes=()
    # 1. env var
    if [[ -n "${AEGIS_SCOPE:-}" ]]; then
        IFS=',' read -ra parts <<< "$AEGIS_SCOPE"
        for p in "${parts[@]}"; do scopes+=("$p"); done
    fi
    # 2. .aegis_scope file
    if [[ -f "$AEGIS_SCOPE_FILE" ]]; then
        while IFS= read -r line || [[ -n "$line" ]]; do
            line="${line%%#*}"
            line="${line//[[:space:]]/}"
            [[ -n "$line" ]] && scopes+=("$line")
        done < "$AEGIS_SCOPE_FILE"
    fi
    # 3. scope.txt
    if [[ -f "$SCOPE_FILE" ]]; then
        while IFS= read -r line || [[ -n "$line" ]]; do
            line="${line%%#*}"
            line="${line//[[:space:]]/}"
            [[ -n "$line" ]] && scopes+=("$line")
        done < "$SCOPE_FILE"
    fi
    printf '%s\n' "${scopes[@]}"
}

is_in_scope() {
    local host="$1"
    local scope_list="$2"

    # Always-allowed list
    for aa in $ALWAYS_ALLOWED; do
        [[ "$host" == "$aa" ]] && return 0
    done
    # Internal RFC1918 (monitoring only — not auto-allowed by scope guard)
    [[ "$host" =~ ^192\.168\. || "$host" =~ ^10\. || "$host" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] && return 0

    [[ -z "$scope_list" ]] && return 0  # no scope configured → permissive

    while IFS= read -r entry; do
        [[ -z "$entry" ]] && continue
        # suffix match
        [[ "$host" == "$entry" || "$host" == *".$entry" ]] && return 0
        # CIDR prefix match (simple)
        [[ "$host" == "${entry%.*}"* ]] && return 0
    done <<< "$scope_list"
    return 1
}

scope_list=$(load_scope)

if [[ -z "$scope_list" ]]; then
    printf "${YELLOW}⚠  No scope configured — all targets treated as in-scope${NC}\n"
    printf "${DIM}  Set AEGIS_SCOPE env var or add entries to scope.txt / .aegis_scope${NC}\n\n"
fi

printf "${BOLD}══ SCOPE MONITOR ══════════════════════════════ %s ${NC}\n" "$(date +%H:%M:%S)"
printf "${DIM}Scope: %s${NC}\n\n" "${scope_list:-'<unrestricted>'}"
printf "${DIM}%-8s │ %-7s │ %-32s │ %s${NC}\n" "TIME" "STATUS" "TOOL" "HOST/TARGET"
printf "${DIM}%s${NC}\n" "────────┼─────────┼────────────────────────────────┼──────────────────────"

touch "$LOG"
tail -F "$LOG" 2>/dev/null | while IFS= read -r line; do
    parsed=$(python3 - <<'PYEOF'
import json, sys, re

line = sys.stdin.readline()
try:
    d = json.loads(line)
except (json.JSONDecodeError, ValueError):
    sys.exit(0)

name = d.get("tool_name", "")
inp  = d.get("tool_input", {})
ts   = (d.get("ts") or "")[-8:][:8]  # HH:MM:SS from ISO timestamp

# Extract host candidates
hosts = set()
for key in ("target", "host", "url", "domain"):
    v = inp.get(key, "")
    if v:
        # Strip protocol
        v = re.sub(r'^https?://', '', str(v))
        v = v.split('/')[0].split(':')[0]
        hosts.add(v)

cmd = inp.get("command", "")
if cmd:
    # Extract IPs and hostnames from shell command
    for m in re.findall(r'(?:^|\s)((?:\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,})', cmd):
        hosts.add(m.strip())

display = name.split("__")[-1] if name.startswith("mcp__") else name

for h in sorted(hosts):
    print(f"{ts}\t{display}\t{h}")
PYEOF
    ) <<< "$line"

    [[ -z "$parsed" ]] && continue

    while IFS=$'\t' read -r ts display host; do
        [[ -z "$host" ]] && continue
        scope_list=$(load_scope)  # reload on each call in case file changes
        if is_in_scope "$host" "$scope_list"; then
            printf "${GREEN}%-8s │ IN-SCOPE │ %-32s │ %s${NC}\n" \
                "${ts:0:8}" "${display:0:32}" "$host"
        else
            printf "${RED}%-8s │ OOS!     │ %-32s │ %s  ← OUT-OF-SCOPE${NC}\n" \
                "${ts:0:8}" "${display:0:32}" "$host"
        fi
    done <<< "$parsed"
done
