#!/usr/bin/env bash
# statusline.sh — emits bypass count and out-of-scope hit count for tmux status bar
# Usage: called by tmux status-right via #(...)
# shellcheck disable=SC2034
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

PROJECT_ROOT="/home/kali/aegis-360-ai-master"
LOG="${PROJECT_ROOT}/logs/toolcalls.jsonl"
SCOPE_FILE="${PROJECT_ROOT}/scope.txt"
AEGIS_SCOPE_FILE="${PROJECT_ROOT}/.aegis_scope"

[[ ! -f "$LOG" ]] && { echo "bypass:0 oos:0"; exit 0; }

python3 - <<'PYEOF'
import json, re, os

PROJECT_ROOT = "/home/kali/aegis-360-ai-master"
log_path = os.path.join(PROJECT_ROOT, "logs", "toolcalls.jsonl")
scope_file = os.path.join(PROJECT_ROOT, "scope.txt")
aegis_scope = os.path.join(PROJECT_ROOT, ".aegis_scope")

ALWAYS_ALLOWED = {"127.0.0.1", "localhost", "::1", "8.8.8.8", "1.1.1.1"}
INTERNAL_RE = re.compile(r'^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)')
bypass_re = re.compile(r'\b(curl|wget|nmap|ffuf|sqlmap|nikto|gobuster|nuclei)\b')

# Load scope
scope_entries = []
for path in (aegis_scope, scope_file):
    if os.path.isfile(path):
        for line in open(path):
            line = line.split('#')[0].strip()
            if line:
                scope_entries.append(line)
if os.environ.get("AEGIS_SCOPE"):
    scope_entries.extend(s.strip() for s in os.environ["AEGIS_SCOPE"].split(',') if s.strip())

def in_scope(host):
    if not host:
        return True
    if host in ALWAYS_ALLOWED:
        return True
    if INTERNAL_RE.match(host):
        return True
    if not scope_entries:
        return True
    for entry in scope_entries:
        if host == entry or host.endswith('.' + entry):
            return True
    return False

bypasses = 0
oos = 0

try:
    with open(log_path) as f:
        for line in f:
            try:
                d = json.loads(line)
                name = d.get("tool_name", "")
                inp = d.get("tool_input", {})

                if name == "Bash":
                    cmd = inp.get("command", "")
                    if bypass_re.search(cmd):
                        bypasses += 1

                hosts = set()
                for key in ("target", "host", "url", "domain"):
                    v = inp.get(key, "")
                    if v:
                        v = re.sub(r'^https?://', '', str(v))
                        v = v.split('/')[0].split(':')[0]
                        hosts.add(v)
                cmd = inp.get("command", "")
                if cmd:
                    for m in re.findall(r'(?:^|\s)((?:\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,})', cmd):
                        hosts.add(m.strip())

                for h in hosts:
                    if not in_scope(h):
                        oos += 1
            except (json.JSONDecodeError, KeyError):
                pass
except FileNotFoundError:
    pass

bypass_color = "#[fg=red]" if bypasses > 0 else "#[fg=green]"
oos_color = "#[fg=red]" if oos > 0 else "#[fg=green]"
print(f"{bypass_color}bypass:{bypasses}#[default] {oos_color}oos:{oos}#[default]")
PYEOF
