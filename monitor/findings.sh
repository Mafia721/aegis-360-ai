#!/usr/bin/env bash
# findings.sh — watch pentest_reports/ and findings/ for new/updated finding files
# shellcheck disable=SC2034,SC2059
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT_DIR="${PROJECT_ROOT}/pentest_reports"
FINDINGS_DIR="${PROJECT_ROOT}/findings"

BOLD=$'\033[1m'
DIM=$'\033[2m'
RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
CYAN=$'\033[0;36m'
NC=$'\033[0m'

printf '\033]2;FINDINGS\007'  # pane title

summary_report() {
    local file="$1"
    python3 - "$file" <<'PYEOF'
import sys, re, os, datetime

path = sys.argv[1]
try:
    with open(path) as f:
        content = f.read(4096)
except OSError:
    print("  (unreadable)")
    sys.exit(0)

fname = os.path.basename(path)
mtime_str = datetime.datetime.fromtimestamp(os.path.getmtime(path)).strftime("%H:%M %d-%b")

severities = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
for sev in severities:
    severities[sev] = len(re.findall(rf'\b{sev}\b', content, re.IGNORECASE))

has_poc = bool(re.search(
    r'(PoC|proof.of.concept|Validation|Burp.*History|screenshot|curl.*response)',
    content, re.IGNORECASE))
poc_status = "\033[0;32m✔ PoC\033[0m" if has_poc else "\033[1;33m? PoC unconfirmed\033[0m"

total = sum(severities.values())
sev_str = " ".join(f"{k[0]}:{v}" for k, v in severities.items() if v > 0) or "no severity markers"
print(f"  {fname:<40} {mtime_str}  [{total:3d} refs: {sev_str}]  {poc_status}")
PYEOF
}

while true; do
    clear
    printf "${BOLD}══ FINDINGS MONITOR ══════════════════════════ %s ${NC}\n" "$(date +%H:%M:%S)"
    printf "${DIM}%s${NC}\n" "────────────────────────────────────────────────────────"

    # pentest_reports/
    if [[ -d "$REPORT_DIR" ]]; then
        mapfile -t reports < <(find "$REPORT_DIR" -name "*.md" -o -name "*.txt" 2>/dev/null | sort -t/ -k1)
        if [[ "${#reports[@]}" -gt 0 ]]; then
            printf "\n${CYAN}${BOLD}pentest_reports/ (%d files)${NC}\n" "${#reports[@]}"
            for rpt in "${reports[@]}"; do
                summary_report "$rpt"
            done
        fi
    fi

    # findings/ (auto-created findings dir)
    if [[ -d "$FINDINGS_DIR" ]]; then
        mapfile -t findings < <(find "$FINDINGS_DIR" -type f \( -name "*.md" -o -name "*.txt" -o -name "*.json" \) 2>/dev/null | sort)
        if [[ "${#findings[@]}" -gt 0 ]]; then
            printf "\n${CYAN}${BOLD}findings/ (%d files)${NC}\n" "${#findings[@]}"
            for f in "${findings[@]}"; do
                summary_report "$f"
            done
        fi
    fi

    [[ ! -d "$REPORT_DIR" && ! -d "$FINDINGS_DIR" ]] && \
        printf "\n  ${DIM}no report dirs found yet${NC}\n"

    printf "\n${DIM}Refreshing every 15 s | Ctrl-C to quit${NC}\n"
    sleep 15
done
