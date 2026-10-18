"""Codex hook adapter.

Two quirks drive this module's shape.

First, Codex's hook payloads omit sandbox mode and approval policy. That is the
single most security-relevant fact about a Codex session — `danger-full-access`
and `workspace-write` are very different things to a reviewer — and it is
otherwise invisible. It is recoverable from the rollout transcript under
`~/.codex/sessions/`, so we read it once per session on SessionStart and cache
it in session state rather than paying the read on every tool event.

Second, Codex rejects the `{continue, suppressOutput}` response envelope that
Claude Code accepts, so it gets an empty object.
"""

import getpass
import glob
import hashlib
import json
import pathlib
import re
import shlex
import socket
import time
import traceback

from stationchief import state
from stationchief.adapters import components
from stationchief.check import emit_checked, reason_text
from stationchief.config import Config
from stationchief.core.records import Action, ActionKind, ActivityRecord, Actor, Decision
from stationchief.pipeline import emit_many, log_error

AGENT_NAME = "codex"
DEFAULT_SESSIONS_DIR = pathlib.Path.home() / ".codex" / "sessions"

# Codex rejects Claude's envelope.
RESPONSE: dict = {}

# Known limit: ceiling on how many rollout files a SessionStart hook will ever open
# when the session id isn't in any filename yet -- without a cap, a session
# directory with months of history turns one hook invocation into thousands of
# file opens.
FALLBACK_FILES = 20

STATE_ONLY_EVENTS = frozenset(
    {"SessionStart", "UserPromptSubmit", "PreCompact", "PostCompact", "SubagentStart", "SubagentStop", "Stop"}
)

TOOL_TO_KIND = {
    "bash": ActionKind.SHELL,  # Codex 0.158+ hooks
    "shell": ActionKind.SHELL,
    "local_shell": ActionKind.SHELL,
    "exec_command": ActionKind.SHELL,
    "read_file": ActionKind.FILE_READ,
    "write_file": ActionKind.FILE_CREATE,
    "apply_patch": ActionKind.FILE_UPDATE,
    "edit_file": ActionKind.FILE_UPDATE,
    "web_search": ActionKind.MCP_CALL,
}


PATCH_FILE = re.compile(r"^\*\*\* (Add|Update|Delete) File: (.+)$", re.M)
PATCH_KIND = {"Add": ActionKind.FILE_CREATE, "Update": ActionKind.FILE_UPDATE, "Delete": ActionKind.FILE_DELETE}


def patch_action(tool_input: dict) -> tuple[str, dict] | None:
    """(kind, input) for an apply_patch call, from the first file the patch
    touches. Transcripts carry the patch under `input`; hooks (0.158+) under
    `command`, where it must not be mistaken for a shell command."""
    patch = str(tool_input.get("input") or tool_input.get("command") or "")
    match = PATCH_FILE.search(patch)
    if not match:
        return None
    rest = {key: value for key, value in tool_input.items() if key not in ("command", "input")}
    return PATCH_KIND[match.group(1)], {**rest, "input": patch, "file_path": match.group(2).strip()}


def classify(tool_name: str) -> str:
    lowered = (tool_name or "").lower()
    if lowered in TOOL_TO_KIND:
        return TOOL_TO_KIND[lowered]
    if lowered.startswith("mcp"):
        return ActionKind.MCP_CALL
    return ActionKind.UNKNOWN


def _read_session_meta(path, session_id: str):
    """Read session_meta and first turn_context lines from a rollout file.

    Returns a dict with sandbox, approval_policy, model, agent_version, cwd.
    Reads up to 200 lines. Session_meta provides session id validation, agent_version,
    and cwd. Turn_context (if present) overrides sandbox, approval_policy, model, and cwd.
    """
    session_meta = None
    turn_context = None

    with open(path, encoding="utf-8") as handle:
        for line_num, line in enumerate(handle):
            # Stop after 200 lines (Known limit: cap rollout read on critical path)
            if line_num >= 200:
                break

            try:
                entry = json.loads(line)
            except ValueError:
                break

            if entry.get("type") == "session_meta":
                meta = entry.get("payload") or {}
                # Verify session id matches
                if meta.get("id") != session_id:
                    break
                session_meta = meta
            elif entry.get("type") == "turn_context" and turn_context is None:
                # Capture first turn_context only
                turn_context = entry.get("payload") or {}

            # Stop reading once both lines are found
            if session_meta is not None and turn_context is not None:
                break

    if session_meta is None:
        return None

    # Start with session_meta values
    sandbox = session_meta.get("sandbox_policy") or {}
    result = {
        "sandbox": sandbox.get("mode") if isinstance(sandbox, dict) else str(sandbox),
        "approval_policy": session_meta.get("approval_policy"),
        "model": session_meta.get("model"),
        "agent_version": session_meta.get("cli_version"),
        "cwd": session_meta.get("cwd"),
    }

    # Override with turn_context values if present
    if turn_context:
        # sandbox: from sandbox_policy dict or string
        tc_sandbox = turn_context.get("sandbox_policy")
        if tc_sandbox is not None:
            result["sandbox"] = tc_sandbox.get("mode") if isinstance(tc_sandbox, dict) else str(tc_sandbox)

        # approval_policy
        if turn_context.get("approval_policy") is not None:
            result["approval_policy"] = turn_context.get("approval_policy")

        # model
        if turn_context.get("model") is not None:
            result["model"] = turn_context.get("model")

        # cwd (turn_context's cwd takes precedence)
        if turn_context.get("cwd") is not None:
            result["cwd"] = turn_context.get("cwd")

    return result


def _first_match(paths, session_id: str):
    for path in paths:
        found = _read_session_meta(path, session_id)
        if found is not None:
            return found
    return None


def read_posture(sessions_dir, session_id: str) -> dict:
    """Recover sandbox and approval posture from the rollout transcript.

    Returns {} on any failure. Looks first at files named for the session id
    (Codex names rollouts `rollout-<timestamp>-<session id>.jsonl`), which costs
    one small, targeted directory walk. Only when that name match misses --
    e.g. the hook fired before Codex wrote the rollout for this session -- does
    it fall back to the FALLBACK_FILES most recently modified rollout files, so
    a SessionStart hook never opens every rollout ever written.
    """
    try:
        directory = pathlib.Path(sessions_dir)

        if session_id and session_id != "unknown":
            named = directory.rglob(f"rollout-*{glob.escape(session_id)}*.jsonl")
            found = _first_match(named, session_id)
            if found is not None:
                return found

        candidates = sorted(
            directory.rglob("rollout-*.jsonl"),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )[:FALLBACK_FILES]
        found = _first_match(candidates, session_id)
        return found if found is not None else {}
    except BaseException:
        return {}


SHELLS = frozenset({"sh", "bash", "zsh"})


def _command_line(tool_input: dict) -> dict:
    """Codex reports shell commands as argv lists; the core expects a string.

    `cmd`/`script` are aliases for `command`. A `[bash, -lc, SCRIPT]` wrapper is
    unwrapped to SCRIPT: the script is what policy and detection must see.
    """
    command = tool_input.get("command") or tool_input.get("cmd") or tool_input.get("script")
    normalised = dict(tool_input)
    if isinstance(command, list):
        parts = [str(part) for part in command]
        if len(parts) == 3 and parts[0].rsplit("/", 1)[-1] in SHELLS and parts[1] in ("-c", "-lc"):
            normalised["command"] = parts[2]
        else:
            normalised["command"] = shlex.join(parts)
    elif isinstance(command, str):
        normalised["command"] = command
    return normalised


def _status(output) -> tuple[str, str | None]:
    """Map explicit failure indicators in tool output; anything else is success."""
    if output is None:
        return "unknown", None
    fields = output
    if isinstance(output, str):
        try:
            fields = json.loads(output)
        except ValueError:
            return "success", None
    if not isinstance(fields, dict):
        return "success", None
    metadata = fields.get("metadata")
    for code in (fields.get("exit_code"), metadata.get("exit_code") if isinstance(metadata, dict) else None):
        if isinstance(code, int) and not isinstance(code, bool) and code != 0:
            return "failure", f"exit code {code}"
    if fields.get("success") is False:
        return "failure", str(fields.get("error") or "success false")
    if fields.get("error"):
        return "failure", str(fields["error"])
    return "success", None


def _decision(payload: dict) -> str:
    if payload.get("hook_event_name") != "PermissionRequest":
        return Decision.OBSERVED
    verdict = str(payload.get("decision") or "").lower()
    if verdict in ("allow", "allowed", "approved"):
        return Decision.ALLOWED
    if verdict in ("deny", "denied", "rejected"):
        return Decision.DENIED
    return Decision.OBSERVED


def to_record(payload: dict, session_state: dict, *, hostname: str, user_name: str):
    event = payload.get("hook_event_name", "")
    if event in STATE_ONLY_EVENTS:
        return None

    tool_name = payload.get("tool_name") or ""
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        tool_input = {}
    posture = dict(session_state.get("posture") or {})
    # 0.158+ hooks send tool_response, like Claude Code.
    output = payload.get("tool_response", payload.get("tool_output"))
    status, error = _status(output)
    kind, tool_input = (tool_name == "apply_patch" and patch_action(tool_input)) or (
        classify(tool_name),
        _command_line(tool_input),
    )

    return ActivityRecord(
        source="codex",
        session_id=payload.get("session_id") or "unknown",
        turn_id=session_state.get("turn_id"),
        ts=int(time.time() * 1000),
        event=event,
        actor=Actor(
            user_name=user_name,
            agent_name=AGENT_NAME,
            agent_version=session_state.get("agent_version") or "unknown",
            model=session_state.get("model") or payload.get("model"),
            model_provider="OpenAI" if session_state.get("model") or payload.get("model") else None,
            pid=None,
        ),
        cwd=payload.get("cwd") or posture.get("cwd") or "",
        hostname=hostname,
        posture=posture,
        prompt=session_state.get("prompt"),
        action=Action(
            tool=tool_name,
            kind=kind,
            input=tool_input,
            output=None if output is None else str(output),
            status=status,
            error=error,
        ),
        decision=_decision(payload),
    )


def verdict_response(verdict) -> dict:
    """Codex takes Claude's deny envelope. An ask returns the empty response:
    Codex's own approval policy decides whether to prompt the user."""
    if verdict.decision != "deny":
        return dict(RESPONSE)
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason_text(verdict),
        }
    }


def handle(payload, config: Config, sessions_dir=DEFAULT_SESSIONS_DIR) -> dict:
    try:
        if not isinstance(payload, dict):
            return dict(RESPONSE)
        session_id = payload.get("session_id") or "unknown"
        event = payload.get("hook_event_name")

        if event == "SessionStart":
            recovered = read_posture(sessions_dir, session_id)
            state.update(
                config,
                session_id,
                model=recovered.get("model"),
                agent_version=recovered.get("agent_version"),
                posture={
                    "sandbox": recovered.get("sandbox") or "unknown",
                    "approval_policy": recovered.get("approval_policy") or "unknown",
                    "cwd": recovered.get("cwd"),
                },
            )
            cwd = payload.get("cwd") or recovered.get("cwd") or ""
            emit_many(
                components.records(
                    components.discover("codex", pathlib.Path.home(), cwd),
                    source="codex",
                    agent_name=AGENT_NAME,
                    model_provider="OpenAI",
                    session_id=session_id,
                    cwd=cwd,
                    hostname=socket.gethostname(),
                    user_name=_user_name(),
                    session_state=state.read(config, session_id),
                ),
                config,
            )
            return dict(RESPONSE)
        if event == "UserPromptSubmit":
            prompt = payload.get("prompt") or ""
            state.update(
                config,
                session_id,
                prompt=prompt,
                turn_id=hashlib.sha256(f"{session_id}\x00{prompt}".encode()).hexdigest()[:16],
            )
            return dict(RESPONSE)

        record = to_record(
            payload, state.read(config, session_id), hostname=socket.gethostname(), user_name=_user_name()
        )
        if record is not None:
            verdict = emit_checked(record, config, pre_tool=event == "PreToolUse")
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
        log_error(config, f"codex adapter failed: {traceback.format_exc()}")
    return dict(RESPONSE)


def _user_name() -> str:
    try:
        return getpass.getuser()
    except BaseException:
        return "unknown"
