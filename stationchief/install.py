"""Idempotent hook config installation.

Every hook we write carries SIGNATURE in its command string. That is the whole
trick: install replaces what bears it (keeping it when the command is unchanged), and uninstall removes exactly
and only what bears it, so a user's own hooks in the same file survive both.

A config file we cannot parse, or whose shape is not ours to guess at (a
top-level value or `hooks` that is not an object), is an error, not an
invitation to overwrite it. Writes are atomic: a temp file beside the target,
then os.replace, keeping the file's permissions.

With fail_closed, the pre-tool hook also carries the agent's own fail-closed
switch, so a hook that crashes or times out blocks the call instead of
allowing it (each agent's default). Codex has no such switch: there a broken
hook always allows.
"""

import dataclasses
import json
import os
import pathlib
import tempfile

SIGNATURE = "# stationchief-managed"


@dataclasses.dataclass(frozen=True)
class AgentSpec:
    config_path: pathlib.Path
    events: tuple[str, ...]
    style: str  # "nested" for Claude Code and Codex, "flat" for Cursor
    # (event, key, value) that makes the agent block when that hook fails.
    fail_closed: tuple[str, str, object] | None = None


AGENTS = {
    "claude": AgentSpec(
        config_path=pathlib.Path.home() / ".claude" / "settings.json",
        events=(
            "SessionStart",
            "SessionEnd",
            "UserPromptSubmit",
            "PreToolUse",
            "PostToolUse",
            "PermissionRequest",
            "Stop",
            "SubagentStop",
            "PreCompact",
            "Notification",
        ),
        style="nested",
        fail_closed=("PreToolUse", "onFailure", "block"),
    ),
    "cursor": AgentSpec(
        config_path=pathlib.Path.home() / ".cursor" / "hooks.json",
        # Only the generic pair. The granular hooks double-fire for the same
        # action; see stationchief/adapters/cursor.py.
        events=("sessionStart", "sessionEnd", "beforeSubmitPrompt", "preToolUse", "postToolUse"),
        style="flat",
        fail_closed=("preToolUse", "failClosed", True),
    ),
    "codex": AgentSpec(
        config_path=pathlib.Path.home() / ".codex" / "hooks.json",
        events=(
            "SessionStart",
            "UserPromptSubmit",
            "PreToolUse",
            "PostToolUse",
            "PermissionRequest",
            "PreCompact",
            "PostCompact",
            "SubagentStart",
            "SubagentStop",
            "Stop",
        ),
        style="nested",
    ),
}


def _load(path: pathlib.Path) -> dict:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
    except ValueError as error:
        raise ValueError(f"{path} could not be parsed as JSON; refusing to overwrite it") from error
    if not isinstance(data, dict):
        raise ValueError(f"{path} does not hold a JSON object; refusing to overwrite it")
    if not isinstance(data.get("hooks", {}), dict):
        raise ValueError(f"{path} has a \"hooks\" value that is not a JSON object; refusing to overwrite it")
    return data


def _save(path: pathlib.Path, settings: dict) -> None:
    path = path.resolve()  # replace a symlink's target, not the link
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        mode = path.stat().st_mode & 0o7777
    except FileNotFoundError:
        umask = os.umask(0)
        os.umask(umask)
        mode = 0o666 & ~umask
    descriptor, temp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(settings, indent=2) + "\n")
        os.chmod(temp, mode)
        os.replace(temp, path)
    except BaseException:
        pathlib.Path(temp).unlink(missing_ok=True)
        raise


def _entry(command: str, style: str, extra: dict | None = None) -> dict:
    """Create a hook entry in the appropriate format for the agent style."""
    hook = {"command": f"{command}  {SIGNATURE}", **(extra or {})}
    if style == "flat":
        return hook
    return {"hooks": [{"type": "command", **hook}]}


def _commands(entry, style: str) -> list[str]:
    """The command strings of one entry: flat entries carry one, nested
    entries a list of hooks."""
    if style == "flat":
        return [str(entry.get("command", ""))]
    return [str(hook.get("command", "")) for hook in entry.get("hooks", [])]


def _strip_ours(entries, style: str) -> tuple[list, bool]:
    """Remove every hook bearing SIGNATURE, keeping the user's (including a
    user hook that shares a nested entry with ours). Returns (kept, changed)."""
    kept, changed = [], False
    for entry in entries or []:
        if style == "flat":
            if SIGNATURE in str(entry.get("command", "")):
                changed = True
            else:
                kept.append(entry)
            continue
        hooks = entry.get("hooks", [])
        surviving = [hook for hook in hooks if SIGNATURE not in str(hook.get("command", ""))]
        if len(surviving) != len(hooks):
            changed = True
        if surviving:
            kept.append({**entry, "hooks": surviving})
    return kept, changed


def install(agent: str, *, config_path=None, command: str, fail_closed: bool = False) -> bool:
    """Write our hooks. Returns True if anything changed.

    An event that already has exactly our current entry is left alone. Any
    other hook of ours there (an older command, say a moved interpreter, or a
    changed fail_closed) is replaced; the user's hooks are kept."""
    spec = AGENTS[agent]
    path = pathlib.Path(config_path or spec.config_path)
    settings = _load(path)
    hooks = settings.setdefault("hooks", {})

    # For flat-style agents, ensure "version" is present
    if spec.style == "flat" and "version" not in settings:
        settings["version"] = 1
        # Don't set changed here yet; only if we actually add hooks

    changed = False
    for event in spec.events:
        extra = {}
        if fail_closed and spec.fail_closed and spec.fail_closed[0] == event:
            extra = {spec.fail_closed[1]: spec.fail_closed[2]}
        wanted = _entry(command, spec.style, extra)
        entries = hooks.get(event) or []
        ours = [entry for entry in entries if any(SIGNATURE in c for c in _commands(entry, spec.style))]
        if ours == [wanted]:
            continue
        kept, _ = _strip_ours(entries, spec.style)
        hooks[event] = kept + [wanted]
        changed = True

    if changed:
        _save(path, settings)
    return changed


def uninstall(agent: str, *, config_path=None) -> bool:
    """Remove our hooks and nothing else. Returns True if anything changed."""
    spec = AGENTS[agent]
    path = pathlib.Path(config_path or spec.config_path)
    settings = _load(path)
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        return False

    changed = False
    for event in list(hooks):
        kept, stripped = _strip_ours(hooks[event], spec.style)
        changed = changed or stripped
        if kept:
            hooks[event] = kept
        else:
            del hooks[event]
            changed = True

    if not hooks:
        settings.pop("hooks", None)
    if changed:
        _save(path, settings)
    return changed
