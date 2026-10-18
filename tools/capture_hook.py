"""Record a raw hook payload to tests/fixtures/<agent>/ for use as a fixture.

Usage, from a hook command:
    python tools/capture_hook.py claude

Reads stdin verbatim, writes it under a name derived from the event, and exits
0 so the agent is never disturbed.
"""

import json
import pathlib
import sys
import time

FIXTURES = pathlib.Path(__file__).parent.parent / "tests" / "fixtures"


def main():
    agent = sys.argv[1] if len(sys.argv) > 1 else "unknown"
    raw = sys.stdin.read()
    directory = FIXTURES / agent / "captured"
    directory.mkdir(parents=True, exist_ok=True)
    try:
        payload = json.loads(raw)
        event = payload.get("hook_event_name") or payload.get("event") or "unknown"
        tool = payload.get("tool_name") or payload.get("tool") or ""
    except ValueError:
        payload, event, tool = raw, "unparseable", ""
    name = f"{event}_{tool}_{int(time.time() * 1000)}".strip("_").replace("/", "_")
    (directory / f"{name}.json").write_text(
        json.dumps(payload, indent=2) if isinstance(payload, (dict, list)) else str(payload)
    )
    print(json.dumps({"continue": True, "suppressOutput": True}))


if __name__ == "__main__":
    main()
