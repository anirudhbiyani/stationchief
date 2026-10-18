"""Cursor hook adapter.

Cursor double-fires: a single shell command produces both
`beforeShellExecution` and `preToolUse`, and a single edit produces both
`afterFileEdit` and `postToolUse`. Subscribing to both would double-count every
action, so we wire only the generic pair — it carries the richest uniform
payload and covers every tool. The granular events are listed here and
explicitly dropped, so that installing them later is a visible decision rather
than an accident.

Cursor also names its session field `conversation_id`, not `session_id`, and
scopes work to `workspace_roots` rather than a single `cwd`.

Real-capture step (brief Step 6) was skipped by controller ruling: it would
have edited the developer's real `~/.cursor/hooks.json` and recorded real
prompts. The starter fixtures below stand in for captured payloads.
"""

import getpass
import hashlib
import pathlib
import socket
import time
import traceback

from stationchief import state
from stationchief.adapters import components
from stationchief.check import emit_checked, reason_text
from stationchief.config import Config
from stationchief.core.records import Action, ActionKind, ActivityRecord, Actor, Decision
from stationchief.pipeline import emit_many, log_error

AGENT_NAME = "cursor"
GENERIC_EVENTS = frozenset({"preToolUse", "postToolUse"})
GRANULAR_EVENTS = frozenset(
    {"beforeShellExecution", "afterShellExecution", "beforeFileEdit", "afterFileEdit", "beforeReadFile", "beforeMCPExecution"}
)
STATE_ONLY_EVENTS = frozenset({"sessionStart", "sessionEnd", "beforeSubmitPrompt", "stop"})

TOOL_TO_KIND = {
    "shell": ActionKind.SHELL,
    "terminal": ActionKind.SHELL,
    "read": ActionKind.FILE_READ,
    "read_file": ActionKind.FILE_READ,
    "write": ActionKind.FILE_CREATE,
    "write_file": ActionKind.FILE_CREATE,
    "edit": ActionKind.FILE_UPDATE,
    "edit_file": ActionKind.FILE_UPDATE,
    "search_replace": ActionKind.FILE_UPDATE,
    "delete_file": ActionKind.FILE_DELETE,
    "web": ActionKind.HTTP,
    "fetch": ActionKind.HTTP,
    "web_search": ActionKind.MCP_CALL,
}


def classify(tool_name: str) -> str:
    lowered = (tool_name or "").lower()
    if lowered in TOOL_TO_KIND:
        return TOOL_TO_KIND[lowered]
    if lowered.startswith("mcp"):
        return ActionKind.MCP_CALL
    return ActionKind.UNKNOWN


def _tool_name(payload: dict) -> str:
    """MCP tools as `mcp__<server>__<tool>`, the form the policy and mapping
    expect. Cursor sends the bare tool name with the server in
    `mcp_server_name`, and may prefix the name with `MCP:`. A server we
    cannot name becomes `unknown`, which no approved list contains, so the
    call is asked about rather than waved through."""
    name = str(payload.get("tool_name") or "")
    server = payload.get("mcp_server_name")
    if name.startswith("mcp__") or not (name.startswith("MCP:") or server):
        return name
    return f"mcp__{server or 'unknown'}__{name.removeprefix('MCP:')}"


def _cwd(payload: dict) -> str:
    roots = payload.get("workspace_roots")
    if isinstance(roots, list) and roots:
        return str(roots[0])
    return str(payload.get("cwd") or "")


def _status(payload: dict) -> tuple[str, str | None]:
    output = payload.get("tool_output")
    if output is None:
        return "unknown", None
    if isinstance(output, dict):
        if output.get("success") is False or output.get("error"):
            return "failure", str(output.get("error") or "tool reported failure")
        return "success", None
    return "success", None


def to_record(payload: dict, session_state: dict, *, hostname: str, user_name: str):
    """Return an ActivityRecord, or None when the payload carries no action."""
    event = payload.get("hook_event_name", "")
    if event not in GENERIC_EVENTS:
        # Granular duplicates and state-only events produce nothing.
        return None

    tool_name = _tool_name(payload)
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        tool_input = {}
    status, error = _status(payload)
    output = payload.get("tool_output")

    return ActivityRecord(
        source="cursor",
        session_id=payload.get("conversation_id") or "unknown",
        turn_id=payload.get("generation_id") or session_state.get("turn_id"),
        ts=int(time.time() * 1000),
        event=event,
        actor=Actor(
            user_name=user_name,
            agent_name=AGENT_NAME,
            agent_version=session_state.get("agent_version") or "unknown",
            model=session_state.get("model"),
            model_provider="Cursor" if session_state.get("model") else None,
            pid=None,
        ),
        cwd=_cwd(payload),
        hostname=hostname,
        posture={"permission_mode": payload.get("permission_mode") or "unknown"},
        prompt=session_state.get("prompt"),
        action=Action(
            tool=tool_name,
            kind=classify(tool_name),
            input=tool_input,
            output=None if output is None else str(output),
            status=status,
            error=error,
        ),
        decision=Decision.OBSERVED,
    )


def verdict_response(verdict) -> dict:
    """Cursor's permission envelope for a deny or ask verdict."""
    reason = reason_text(verdict)
    if verdict.decision == "deny":
        return {"permission": "deny", "user_message": reason, "agent_message": reason}
    return {"permission": "ask", "user_message": reason}


def handle(payload, config: Config) -> dict:
    """Process one hook payload. Always returns Cursor's permission envelope."""
    response = {"permission": "allow"}
    try:
        if not isinstance(payload, dict):
            return response
        session_id = payload.get("conversation_id") or "unknown"
        event = payload.get("hook_event_name")

        if event == "beforeSubmitPrompt":
            prompt = payload.get("prompt") or ""
            state.update(
                config,
                session_id,
                prompt=prompt,
                turn_id=payload.get("generation_id")
                or hashlib.sha256(f"{session_id}\x00{prompt}".encode()).hexdigest()[:16],
            )
            return response
        if event == "sessionStart":
            state.update(config, session_id, model=payload.get("model"), agent_version=payload.get("version"))
            cwd = _cwd(payload)
            emit_many(
                components.records(
                    components.discover("cursor", pathlib.Path.home(), cwd),
                    source="cursor",
                    agent_name=AGENT_NAME,
                    model_provider="Cursor",
                    session_id=session_id,
                    cwd=cwd,
                    hostname=socket.gethostname(),
                    user_name=_user_name(),
                    session_state=state.read(config, session_id),
                ),
                config,
            )
            return response

        record = to_record(
            payload, state.read(config, session_id), hostname=socket.gethostname(), user_name=_user_name()
        )
        if record is not None:
            verdict = emit_checked(record, config, pre_tool=event == "preToolUse")
            # Marked only after the emit, so a hook that dies mid-emit leaves the
            # call for transcript ingest to recover.
            try:
                state.mark_seen(config, session_id, state.call_id(payload), record.ts)
            except BaseException:
                # Dedup bookkeeping only: never let it skip /check or the event.
                log_error(config, f"mark_seen failed: {traceback.format_exc()}")
            if verdict is not None and verdict.decision != "allow":
                return verdict_response(verdict)
    except BaseException:
        log_error(config, f"cursor adapter failed: {traceback.format_exc()}")
    return response


def _user_name() -> str:
    try:
        return getpass.getuser()
    except BaseException:
        return "unknown"
