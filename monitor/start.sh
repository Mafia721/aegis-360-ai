#!/usr/bin/env bash
# start.sh — launch (or re-attach to) the Aegis-360 monitoring tmux session
set -euo pipefail

SESSION="aegis"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MONITOR="${PROJECT_ROOT}/monitor"
CONF="${MONITOR}/tmux.conf"
LOGS="${PROJECT_ROOT}/logs"

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

# Ensure log files exist
mkdir -p "$LOGS"
touch "${LOGS}/toolcalls.jsonl" "${LOGS}/agents.jsonl"

# Re-attach if session already running
if tmux -f "$CONF" has-session -t "$SESSION" 2>/dev/null; then
    echo "  → re-attaching to existing '$SESSION' session"
    exec tmux -f "$CONF" attach-session -t "$SESSION"
fi

echo "  → starting Aegis monitoring session …"

# Create session detached; window 1 = "live"
tmux -f "$CONF" new-session -d -s "$SESSION" -n "live" -x 220 -y 50

# ─── Window 1: live ────────────────────────────────────────────────────
# Layout: large left (stream_tools) | right column split into 3 rows
#   Pane 1 (left, ~60%): stream_tools.sh
#   Pane 2 (top-right, ~33% of right): agents.sh
#   Pane 3 (mid-right, ~33% of right): watch stats.sh
#   Pane 4 (bot-right, ~34% of right): scope_guard.sh

# Start in left pane
tmux -f "$CONF" send-keys -t "${SESSION}:live" \
    "bash ${MONITOR}/stream_tools.sh" Enter

# Split right column
tmux -f "$CONF" split-window -h -t "${SESSION}:live" -p 40

# Top-right: agents.sh (auto-refresh loop)
tmux -f "$CONF" send-keys -t "${SESSION}:live.2" \
    "while true; do bash ${MONITOR}/agents.sh; sleep 10; done" Enter
tmux -f "$CONF" select-pane -t "${SESSION}:live.2" -T "AGENTS"

# Split mid-right
tmux -f "$CONF" split-window -v -t "${SESSION}:live.2" -p 66

# Mid-right: watch stats.sh
tmux -f "$CONF" send-keys -t "${SESSION}:live.3" \
    "watch -n5 -t bash ${MONITOR}/stats.sh" Enter
tmux -f "$CONF" select-pane -t "${SESSION}:live.3" -T "STATS"

# Split bot-right
tmux -f "$CONF" split-window -v -t "${SESSION}:live.3" -p 50

# Bottom-right: scope_guard.sh
tmux -f "$CONF" send-keys -t "${SESSION}:live.4" \
    "bash ${MONITOR}/scope_guard.sh" Enter
tmux -f "$CONF" select-pane -t "${SESSION}:live.4" -T "SCOPE"

# Label left pane title (must be last or it resets)
tmux -f "$CONF" select-pane -t "${SESSION}:live.1" -T "TOOLS"

# ─── Window 2: infra ───────────────────────────────────────────────────
tmux -f "$CONF" new-window -t "$SESSION" -n "infra"

# Top pane: burp_status.sh
tmux -f "$CONF" send-keys -t "${SESSION}:infra" \
    "bash ${MONITOR}/burp_status.sh" Enter
tmux -f "$CONF" select-pane -t "${SESSION}:infra.1" -T "BURP"

# Mid pane: mcp_health.sh
tmux -f "$CONF" split-window -v -t "${SESSION}:infra" -p 50
tmux -f "$CONF" send-keys -t "${SESSION}:infra.2" \
    "bash ${MONITOR}/mcp_health.sh" Enter
tmux -f "$CONF" select-pane -t "${SESSION}:infra.2" -T "MCP-HEALTH"

# Bottom pane: process monitor (java / node / python)
tmux -f "$CONF" split-window -v -t "${SESSION}:infra.2" -p 40
tmux -f "$CONF" send-keys -t "${SESSION}:infra.3" \
    "watch -n5 -t 'ps aux | grep -E \"java|node|python|ruby\" | grep -v grep | awk \"{printf \\\"%-8s %-5s %s\\\\n\\\", \\\$1, \\\$2, \\\$11}\"'" Enter
tmux -f "$CONF" select-pane -t "${SESSION}:infra.3" -T "PROCS"

# ─── Window 3: findings ────────────────────────────────────────────────
tmux -f "$CONF" new-window -t "$SESSION" -n "findings"

# Left pane: findings.sh
tmux -f "$CONF" send-keys -t "${SESSION}:findings" \
    "bash ${MONITOR}/findings.sh" Enter
tmux -f "$CONF" select-pane -t "${SESSION}:findings.1" -T "FINDINGS"

# Right pane: tail newest log
tmux -f "$CONF" split-window -h -t "${SESSION}:findings" -p 35
tmux -f "$CONF" send-keys -t "${SESSION}:findings.2" \
    "bash -c 'tail -F \"\$(ls -t ${LOGS}/*.jsonl 2>/dev/null | head -1)\" 2>/dev/null || { echo \"no logs yet\"; sleep 60; }'" Enter
tmux -f "$CONF" select-pane -t "${SESSION}:findings.2" -T "LATEST-LOG"

# ─── Window 4: shell ───────────────────────────────────────────────────
tmux -f "$CONF" new-window -t "$SESSION" -n "shell"
tmux -f "$CONF" send-keys -t "${SESSION}:shell" \
    "cd ${PROJECT_ROOT} && echo 'Aegis-360 shell | project: ${PROJECT_ROOT}'" Enter

# Focus window 1
tmux -f "$CONF" select-window -t "${SESSION}:live"
tmux -f "$CONF" select-pane  -t "${SESSION}:live.1"

# Attach
exec tmux -f "$CONF" attach-session -t "$SESSION"
