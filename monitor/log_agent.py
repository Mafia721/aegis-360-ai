#!/usr/bin/env python3
"""SubagentStart/SubagentStop hook — appends events to logs/agents.jsonl."""
import json
import os
import sys
from datetime import datetime, timezone

PROJECT_ROOT = "/home/kali/aegis-360-ai-master"
LOG_PATH = os.path.join(PROJECT_ROOT, "logs", "agents.jsonl")


def main() -> None:
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    try:
        raw = sys.stdin.read()
        data = json.loads(raw) if raw.strip() else {}
    except (json.JSONDecodeError, ValueError):
        return

    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": data.get("hook_event_name", data.get("event_name", "")),
        "agent_name": data.get("agent_name", data.get("subagent_name", "")),
        "model": data.get("model", ""),
        "session_id": data.get("session_id", ""),
        "phase": data.get("phase", ""),
    }

    with open(LOG_PATH, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
