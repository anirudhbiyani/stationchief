"""Codex session transcripts -> ActivityRecords (spec: "Ingest adapters").

Reads ~/.codex/sessions/**/rollout-*.jsonl once a file has been idle for
common.SETTLE_MS. Each file is read from the top, line by line, because
session and turn context sit there, but only calls at or past the byte-offset
watermark are emitted, and only their outputs are kept in memory.

Known limit: a call before the watermark whose output lands after it keeps the
status it had at the last run. Settled-only reading makes that rare.

Step 6 (replacing the starter fixture with a real capture and verifying the
three assumptions below) was skipped by controller ruling for this task. The
starter fixture is kept, `CALL_IDS_MATCH` stays at its documented default, and
every record stays `Decision.OBSERVED` (no approval-decision mapping was
added, since it was never verified against a real rollout).
"""

import ast
import hashlib
import json
import pathlib
import re
import socket
import time
import traceback

from stationchief.adapters.codex import AGENT_NAME, DEFAULT_SESSIONS_DIR, _command_line, classify, patch_action
from stationchief.config import Config
from stationchief.core.records import Action, ActionKind, ActivityRecord, Actor, Decision
from stationchief.ingest import common
from stationchief.pipeline import log_error

# Whether hook payload call ids equal rollout call ids. Verified in Step 6;
# set False if they differ and dedup falls back to session level.
CALL_IDS_MATCH = True

TOOL_CALLS = frozenset({"function_call", "custom_tool_call", "local_shell_call", "web_search_call"})
TOOL_OUTPUTS = frozenset({"function_call_output", "custom_tool_call_output"})


def _as_dict(value, fallback_key: str) -> dict:
    if isinstance(value, dict):
        return value
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        parsed = None
    if isinstance(parsed, dict):
        return parsed
    return {} if value is None else {fallback_key: value}


# Code mode: the model's tool call is a script, `exec`, that calls the real
# tools, e.g. `text(await tools.exec_command({cmd:"ls"}))`. Only the script
# reaches the transcript, so the inner tool and its command are read from it.
CODE_MODE_TOOL = re.compile(r"\btools\.(\w+)\(")
CODE_MODE_CMD = re.compile(r"""\bexec_command\(\{\s*"?cmd"?\s*:\s*("(?:[^"\\]|\\.)*")""")


def _code_mode(script: str):
    """(tool, kind, input) for a code-mode script, or None. Several commands
    in one script are joined by newlines.

    Known limit: regex over JS, not a parser. A cmd built at runtime (a variable,
    a template string) is not recovered and stays an unknown `exec` call."""
    tool = CODE_MODE_TOOL.search(script)
    if tool is None:
        return None
    commands = []
    for literal in CODE_MODE_CMD.findall(script):
        try:
            # A JS string literal; Python's reads its escapes (\', \x27, \u00e9).
            commands.append(str(ast.literal_eval(literal)))
        except (ValueError, SyntaxError):
            pass
    if commands:
        return "exec_command", ActionKind.SHELL, {"command": "\n".join(commands), "code": script}
    name = tool.group(1)
    if name == "exec_command":  # a command we could not recover is not a shell event
        return None
    return name, classify(name), {"code": script}


def _call(payload: dict) -> tuple[str, str, dict]:
    """(tool, kind, input) for one tool-call response item."""
    item_type = payload.get("type")
    if item_type == "local_shell_call":
        action = payload.get("action") or {}
        return "local_shell", ActionKind.SHELL, _command_line(
            {"command": action.get("command"), "workdir": action.get("working_directory")}
        )
    if item_type == "web_search_call":
        return "web_search", classify("web_search"), {"query": (payload.get("action") or {}).get("query")}
    name = payload.get("name") or ""
    # MCP calls carry the server separately: namespace "mcp__<server>__".
    namespace = payload.get("namespace")
    if isinstance(namespace, str) and namespace and not name.startswith(namespace):
        name = namespace + name if namespace.endswith("__") else f"{namespace}__{name}"
    raw = payload.get("arguments") if item_type == "function_call" else payload.get("input")
    tool_input = _as_dict(raw, "input")
    if name == "exec" and isinstance(raw, str):
        inner = _code_mode(raw)
        if inner:
            return inner
    if name == "apply_patch":
        patched = patch_action(tool_input)
        if patched:
            return name, *patched
    return name, classify(name), _command_line(tool_input)


def _status(output) -> tuple[str, str | None]:
    if output is None:
        return "unknown", None
    metadata = _as_dict(output, "output").get("metadata")
    code = metadata.get("exit_code") if isinstance(metadata, dict) else None
    if isinstance(code, int) and code != 0:
        return "failure", f"exit code {code}"
    return "success", None


def parse(data, *, start_offset: int = 0, hostname: str, user_name: str):
    """Return (session id, records, malformed line count).

    ``data`` is a whole file as bytes, or an iterable of byte lines (an open
    binary file), so a large rollout is never held in memory at once.
    """
    session_id, version, cwd, model = None, "unknown", "", None
    posture: dict = {}
    prompt = turn_id = None
    last_ts = 0
    pending, outputs, wanted = [], {}, set()
    malformed = 0
    offset = 0

    for raw_line in data.splitlines(keepends=True) if isinstance(data, bytes) else data:
        line_offset, offset = offset, offset + len(raw_line)
        try:
            entry = json.loads(raw_line)
        except ValueError:
            malformed += 1
            continue
        if not isinstance(entry, dict):
            malformed += 1
            continue
        payload = entry.get("payload") if isinstance(entry.get("payload"), dict) else {}
        ts = common.iso_ms(entry.get("timestamp")) or last_ts
        last_ts = ts
        kind = entry.get("type")

        if kind == "session_meta":
            session_id = payload.get("id") or session_id
            version = payload.get("cli_version") or version
            cwd = payload.get("cwd") or cwd
        elif kind == "turn_context":
            cwd = payload.get("cwd") or cwd
            model = payload.get("model") or model
            sandbox = payload.get("sandbox_policy")
            posture = {
                "sandbox": sandbox.get("mode") if isinstance(sandbox, dict) else sandbox,
                "approval_policy": payload.get("approval_policy"),
            }
        elif kind == "event_msg" and payload.get("type") == "user_message":
            prompt = payload.get("message")
            turn_id = hashlib.sha256(f"{session_id}\x00{prompt}".encode()).hexdigest()[:16]
        elif kind == "response_item" and payload.get("type") in TOOL_OUTPUTS:
            # An output follows its call, so only calls already pending matter.
            if payload.get("call_id") in wanted:
                outputs[payload.get("call_id")] = payload.get("output")
        elif kind == "response_item" and payload.get("type") in TOOL_CALLS and line_offset >= start_offset:
            pending.append((payload, ts, prompt, turn_id, dict(posture), model, cwd))
            wanted.add(payload.get("call_id") or payload.get("id"))

    records = []
    for payload, ts, call_prompt, call_turn, call_posture, call_model, call_cwd in pending:
        call_id = payload.get("call_id") or payload.get("id")
        tool, kind, tool_input = _call(payload)
        output = outputs.get(call_id)
        status, error = _status(output)
        records.append(
            ActivityRecord(
                source="codex",
                session_id=session_id or "unknown",
                turn_id=call_turn,
                ts=ts,
                event="transcript",
                actor=Actor(
                    user_name=user_name,
                    agent_name=AGENT_NAME,
                    agent_version=version,
                    model=call_model,
                    model_provider="OpenAI" if call_model else None,
                    pid=None,
                ),
                cwd=call_cwd,
                hostname=hostname,
                posture=common.transcript_posture(call_id, **call_posture),
                prompt=call_prompt,
                action=Action(
                    tool=tool,
                    kind=kind,
                    input=tool_input,
                    output=None if output is None else str(output),
                    status=status,
                    error=error,
                ),
                decision=Decision.OBSERVED,
            )
        )
    return session_id, records, malformed


def ingest(config: Config, source=None, *, now_ms: int | None = None) -> tuple[int, int, int]:
    """Ingest every settled rollout file. Returns (emitted, skipped, gap findings)."""
    directory = pathlib.Path(source or DEFAULT_SESSIONS_DIR)
    now_ms = now_ms or int(time.time() * 1000)
    marks = common.load_watermark(config, "codex")
    files = marks.setdefault("files", {})
    host, user = socket.gethostname(), common.user_name()
    totals = [0, 0, 0]

    for path in sorted(directory.rglob("rollout-*.jsonl")) if directory.is_dir() else []:
        try:
            info = path.stat()
            if not common.settled(int(info.st_mtime * 1000), now_ms):
                continue
            start = files.get(str(path), 0)
            if info.st_size < start:  # truncated or replaced: start over
                start = 0
            if info.st_size == start:
                continue
            with path.open("rb") as lines:
                session_id, records, malformed = parse(lines, start_offset=start, hostname=host, user_name=user)
            if malformed:
                log_error(config, f"codex ingest: {path.name}: skipped {malformed} malformed line(s)")
            result = common.emit_session(config, session_id or "unknown", records, call_ids_match=CALL_IDS_MATCH)
            totals = [a + b for a, b in zip(totals, result)]
            files[str(path)] = info.st_size
        except common.NotDelivered as error:
            log_error(config, f"codex ingest: {path.name}: {error}; watermark kept for a retry")
        except Exception:
            log_error(config, f"codex ingest failed on {path}: {traceback.format_exc()}")

    common.save_watermark(config, "codex", marks)
    return tuple(totals)
