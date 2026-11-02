#!/usr/bin/env python3
"""
scope_guard.py — PreToolUse hook for Claude Code.

Reads the pending Bash command from stdin (Claude Code passes the tool input
as JSON on stdin for hooks), extracts any IP addresses or hostnames, and blocks
the call if any are outside the active scope list.

Scope is loaded from AEGIS_SCOPE env var (comma-separated) or
from .aegis_scope in the project root. If neither is set, the
guard passes (permissive-by-default until scope is configured).

Exit codes:
  0 — allow the tool call
  1 — block the tool call (Claude Code will surface the stderr message)
  2 — internal error (allow, don't block on guard failures)
"""

import json
import os
import re
import sys
from pathlib import Path

SCOPE_FILE = Path(__file__).parent.parent / ".aegis_scope"

_IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_HOST_RE = re.compile(r'(?:https?://|@)([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})(?:[:/]|$)')
_DIRECT_HOST_RE = re.compile(r'(?:^|\s)([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})(?:\s|:|/|$)')

ALWAYS_ALLOWED = {
    '127.0.0.1', 'localhost', '::1',
    '8.8.8.8', '1.1.1.1',  # DNS probes
}

INTERNAL_PREFIXES = ('192.168.', '10.', '172.16.', '172.17.', '172.18.',
                     '172.19.', '172.2', '172.3')


def load_scope():
    # Env var takes priority
    env_scope = os.environ.get('AEGIS_SCOPE', '')
    if env_scope:
        return [s.strip() for s in env_scope.split(',') if s.strip()]
    # Fall back to scope file
    if SCOPE_FILE.exists():
        return [line.strip() for line in SCOPE_FILE.read_text().splitlines()
                if line.strip() and not line.startswith('#')]
    return []


def extract_targets(command: str):
    targets = set()
    targets.update(_IP_RE.findall(command))
    targets.update(_HOST_RE.findall(command))
    return targets - ALWAYS_ALLOWED


def in_scope(target: str, scope: list) -> bool:
    if not scope:
        return True
    if any(target.startswith(p) for p in INTERNAL_PREFIXES):
        return True
    return any(target == s or target.endswith('.' + s) for s in scope)


def main():
    try:
        raw = sys.stdin.read()
        data = json.loads(raw) if raw.strip() else {}
    except Exception:
        sys.exit(2)

    command = data.get('input', {}).get('command', '')
    if not command:
        sys.exit(0)

    scope = load_scope()
    if not scope:
        # No scope configured — pass through with a warning
        print('[scope_guard] WARNING: No scope configured. Set AEGIS_SCOPE or create .aegis_scope', file=sys.stderr)
        sys.exit(0)

    targets = extract_targets(command)
    out_of_scope = [t for t in targets if not in_scope(t, scope)]

    if out_of_scope:
        print(f'[scope_guard] BLOCKED: targets outside scope: {", ".join(out_of_scope)}', file=sys.stderr)
        print(f'[scope_guard] Active scope: {", ".join(scope)}', file=sys.stderr)
        sys.exit(1)

    sys.exit(0)


if __name__ == '__main__':
    main()
