"""Claude Code hook adapter.

Reads one hook payload and produces one ActivityRecord, or None for events that
only update session state. Never raises: the caller runs inside the agent's
critical path, and a crashing hook degrades a developer's session.
"""

import hashlib
import pathlib
import socket
import time

from stationchief import state
from stationchief.adapters import components
from stationchief.check import emit_checked, reason_text
from stationchief.config import Config
from stationchief.core.records import Action, ActionKind, ActivityRecord, Actor, Decision
from stationchief.pipeline import emit_many, log_error

AGENT_NAME = "claude-code"
MODEL_PROVIDER = "Anthropic"

# Claude accepts this envelope; Codex does not (see adapters/codex.py).
RESPONSE = {"continue": True, "suppressOutput": True}

TOOL_TO_KIND = {
    "Bash": ActionKind.SHELL,
    "BashOutput": ActionKind.SHELL,
    "KillShell": ActionKind.SHELL,
    "Read": ActionKind.FILE_READ,
    "NotebookRead": ActionKind.FILE_READ,
    "Write": ActionKind.FILE_CREATE,
    "Edit": ActionKind.FILE_UPDATE,
    "MultiEdit": ActionKind.FILE_UPDATE,
    "NotebookEdit": ActionKind.FILE_UPDATE,
    "WebFetch": ActionKind.HTTP,
    "WebSearch": ActionKind.MCP_CALL,
}

# These carry no tool action; they update state and emit nothing.
STATE_ONLY_EVENTS = {"UserPromptSubmit", "SessionStart", "SessionEnd", "Stop", "SubagentStop", "PreCompact", "Notification"}


def classify(tool_name: str) -> str:
    if tool_name in TOOL_TO_KIND:
        return TOOL_TO_KIND[tool_name]
    if tool_name.startswith("mcp__"):
        return ActionKind.MCP_CALL
    return ActionKind.UNKNOWN


def _turn_id(session_id: str, prompt: str) -> str:
    return hashlib.sha256(f"{session_id}\x00{prompt}".encode()).hexdigest()[:16]


def _status(payload: dict) -> tuple[str, str | None]:
    response = payload.get("tool_response")
    if response is None:
        return "unknown", None
    if isinstance(response, dict):
        if response.get("success") is False or response.get("error"):
            return "failure", str(response.get("error") or "tool reported failure")
        return "success", None
    return "success", None


def _decision(payload: dict) -> str:
    if payload.get("hook_event_name") != "PermissionRequest":
        return Decision.OBSERVED
    verdict = str(payload.get("decision") or payload.get("permissionDecision") or "").lower()
    if verdict in ("allow", "approved", "accept"):
        return Decision.ALLOWED
    if verdict in ("deny", "denied", "reject"):
        return Decision.DENIED
    return Decision.OBSERVED


def to_record(payload: dict, session_state: dict, *, hostname: str, user_name: str):
    """Return an ActivityRecord, or None when the payload carries no action."""
    event = payload.get("hook_event_name", "Unknown")
    if event in STATE_ONLY_EVENTS:
        return None

    tool_name = payload.get("tool_name") or ""
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        tool_input = {}
    status, error = _status(payload)
    response = payload.get("tool_response")

    return ActivityRecord(
        source="claude",
        session_id=payload.get("session_id") or "unknown",
        turn_id=session_state.get("turn_id"),
        ts=int(time.time() * 1000),
        event=event,
        actor=Actor(
            user_name=user_name,
            agent_name=AGENT_NAME,
            agent_version=session_state.get("agent_version") or "unknown",
            model=session_state.get("model"),
            model_provider=MODEL_PROVIDER if session_state.get("model") else None,
            pid=None,
        ),
        cwd=payload.get("cwd") or "",
        hostname=hostname,
        posture={"permission_mode": payload.get("permission_mode") or "unknown"},
        prompt=session_state.get("prompt"),
        action=Action(
            tool=tool_name,
            kind=classify(tool_name),
            input=tool_input,
            output=None if response is None else str(response),
            status=status,
            error=error,
        ),
        decision=_decision(payload),
    )


def verdict_response(verdict) -> dict:
    """Claude's PreToolUse permission envelope for a deny or ask verdict."""
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": verdict.decision,
            "permissionDecisionReason": reason_text(verdict),
        }
    }


def handle(payload, config: Config) -> dict:
    """Process one hook payload. Always returns a response; never raises."""
    try:
        if not isinstance(payload, dict):
            return dict(RESPONSE)
        session_id = payload.get("session_id") or "unknown"
        event = payload.get("hook_event_name")

        if event == "UserPromptSubmit":
            prompt = payload.get("prompt") or ""
            state.update(
                config, session_id, prompt=prompt, turn_id=_turn_id(session_id, prompt)
            )
            return dict(RESPONSE)
        if event == "SessionStart":
            state.update(
                config,
                session_id,
                model=payload.get("model"),
                agent_version=payload.get("version"),
            )
            cwd = payload.get("cwd") or ""
            emit_many(
                components.records(
                    components.discover("claude", pathlib.Path.home(), cwd),
                    source="claude",
                    agent_name=AGENT_NAME,
                    model_provider=MODEL_PROVIDER,
                    session_id=session_id,
                    cwd=cwd,
                    hostname=socket.gethostname(),
                    user_name=_user_name(),
                    session_state=state.read(config, session_id),
                ),
                config,
            )
            return dict(RESPONSE)

        record = to_record(
            payload,
            state.read(config, session_id),
            hostname=socket.gethostname(),
            user_name=_user_name(),
        )
        if record is not None:
            verdict = emit_checked(record, config, pre_tool=event == "PreToolUse")
            if verdict is not None and verdict.decision != "allow":
                return verdict_response(verdict)
    except BaseException:
        import traceback

        log_error(config, f"claude adapter failed: {traceback.format_exc()}")
    return dict(RESPONSE)


def _user_name() -> str:
    import getpass

    try:
        return getpass.getuser()
    except BaseException:
        return "unknown"
