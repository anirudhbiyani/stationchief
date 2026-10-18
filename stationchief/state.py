"""Per-session scratch state shared between hook invocations.

A hook process handles one event and exits, but the prompt arrives on
UserPromptSubmit and is needed on every PreToolUse that follows. This is the
only place adapters keep anything between invocations.

Contents include prompt text, so files are 0600. Reads never raise.
"""

import json
import os
import re
import pathlib

from stationchief.config import Config

UNSAFE = re.compile(r"[^A-Za-z0-9._-]")
FILE_MODE = 0o600
DIRECTORY_MODE = 0o700


def _path(config: Config, session_id: str) -> pathlib.Path:
    # A session id reaches us from an external process; never let it choose a
    # path outside the state directory.
    safe = UNSAFE.sub("_", session_id or "unknown")[:128]
    return config.home / "state" / f"{safe}.json"


def read(config: Config, session_id: str) -> dict:
    try:
        data = json.loads(_path(config, session_id).read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def update(config: Config, session_id: str, **fields) -> dict:
    merged = read(config, session_id)
    merged.update({key: value for key, value in fields.items() if value is not None})
    path = _path(config, session_id)
    path.parent.mkdir(parents=True, exist_ok=True, mode=DIRECTORY_MODE)
    # Write a sibling temp file and rename it over the old one, so a concurrent
    # reader sees the old state or the new one, never a truncated file.
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, FILE_MODE)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(merged, handle)
        os.chmod(temporary, FILE_MODE)
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return merged


CALL_ID_KEYS = ("tool_use_id", "tool_call_id", "call_id")


def exists(config: Config, session_id: str) -> bool:
    """True once any hook has written state for this session."""
    return _path(config, session_id).exists()


def call_id(payload: dict) -> str | None:
    for key in CALL_ID_KEYS:
        value = payload.get(key)
        if value:
            return str(value)
    return None


def _seen_path(config: Config, session_id: str) -> pathlib.Path:
    return config.home / "seen" / _path(config, session_id).stem


def mark_seen(config: Config, session_id: str, call_id: str | None, now_ms: int) -> None:
    """Record that a hook emitted this tool call, so ingest will not repeat it.

    Known limit: seen files and state files are never pruned; add an age-based sweep
    to `stationchief ingest` if ~/.stationchief/seen grows enough to matter.
    """
    if not call_id:
        return
    path = _seen_path(config, session_id)
    path.parent.mkdir(parents=True, exist_ok=True, mode=DIRECTORY_MODE)
    new = not path.exists()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, FILE_MODE)
    with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
        if new:
            handle.write(f"#since {now_ms}\n")
        handle.write(call_id.replace("\n", " ") + "\n")


def seen(config: Config, session_id: str) -> tuple[int | None, set[str]]:
    try:
        lines = _seen_path(config, session_id).read_text().splitlines()
    except OSError:
        return None, set()
    since = None
    if lines and lines[0].startswith("#since "):
        try:
            since = int(lines[0].split()[1])
        except (IndexError, ValueError):
            pass
        lines = lines[1:]
    return since, set(lines)
