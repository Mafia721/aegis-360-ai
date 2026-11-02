#!/usr/bin/env python3
"""PostToolUse hook — appends each tool call to logs/toolcalls.jsonl."""
import json
import os
import sys
from datetime import datetime, timezone

PROJECT_ROOT = "/home/kali/aegis-360-ai-master"
LOG_PATH = os.path.join(PROJECT_ROOT, "logs", "toolcalls.jsonl")


def main() -> None:
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    try:
        raw = sys.stdin.read()
        data = json.loads(raw) if raw.strip() else {}
    except (json.JSONDecodeError, ValueError):
        return

    tool_resp = data.get("tool_response", {})
    resp_str = (
        json.dumps(tool_resp, separators=(",", ":"))
        if isinstance(tool_resp, dict)
        else str(tool_resp)
    )

    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "session_id": data.get("session_id", ""),
        "tool_name": data.get("tool_name", ""),
        "tool_input": data.get("tool_input", {}),
        "tool_response": resp_str[:500],
        "duration_ms": data.get("duration_ms"),
    }

    with open(LOG_PATH, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
