"""Cursor workspace traces -> ActivityRecords (spec: "Ingest adapters").

Reads Cursor's own agent history from <user dir>/globalStorage/state.vscdb,
opened read-only while Cursor holds it. A conversation is read once it has been
idle for common.SETTLE_MS.

Every stored message of a conversation is read, not only
fullConversationHeadersOnly: when Cursor summarises a long conversation it
drops the early messages from the headers but keeps them in the store
(verified on a real Cursor store: 3,689 of 12,305 tool calls were only there).
The watermark keeps, per conversation, the tool-call messages already emitted,
so a shrinking header list can never hide new calls.

This is Cursor's private database. Messages whose `_v` we have not verified are
skipped and logged, never guessed at.
"""

import json
import os
import pathlib
import socket
import sqlite3
import sys
import time
import traceback
import urllib.parse

from stationchief.adapters.cursor import AGENT_NAME, classify
from stationchief.config import Config
from stationchief.core.records import Action, ActionKind, ActivityRecord, Actor, Decision
from stationchief.ingest import common
from stationchief.pipeline import log_error

# Whether hook payload call ids equal toolFormerData.toolCallId. Verified in
# Step 6; set False if they differ and dedup falls back to session level.
CALL_IDS_MATCH = True
KNOWN_BUBBLE_VERSIONS = frozenset({3})
PATH_KEYS = ("targetFile", "relativeWorkspacePath", "file_path", "target_file", "path")
# Cursor's own tool names the hook adapter's table does not cover.
EXTRA_KINDS = {
    "run_terminal_command": ActionKind.SHELL,
    "run_terminal_cmd": ActionKind.SHELL,
    "read_file": ActionKind.FILE_READ,
    "edit_file": ActionKind.FILE_UPDATE,
    "write": ActionKind.FILE_CREATE,
    "delete_file": ActionKind.FILE_DELETE,
    "web_fetch": ActionKind.HTTP,
}
DECISIONS = {"accepted": Decision.ALLOWED, "rejected": Decision.DENIED}
STATUSES = {"completed": ("success", None), "error": ("failure", "tool reported error"), "cancelled": ("failure", "cancelled")}


def default_user_dir() -> pathlib.Path:
    if sys.platform == "darwin":
        return pathlib.Path.home() / "Library" / "Application Support" / "Cursor" / "User"
    if sys.platform == "win32":
        return pathlib.Path(os.environ.get("APPDATA", pathlib.Path.home())) / "Cursor" / "User"
    return pathlib.Path(os.environ.get("XDG_CONFIG_HOME", pathlib.Path.home() / ".config")) / "Cursor" / "User"


def _as_dict(value) -> dict:
    if isinstance(value, dict):
        return value
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _uri_path(value: str) -> str:
    return urllib.parse.unquote(urllib.parse.urlsplit(value).path) if value.startswith("file://") else value


def _workspace_folder(user_dir: pathlib.Path, workspace_id, cache: dict) -> str:
    if not workspace_id:
        return ""
    if workspace_id not in cache:
        try:
            meta = json.loads((user_dir / "workspaceStorage" / str(workspace_id) / "workspace.json").read_text())
        except (OSError, ValueError):
            meta = {}
        folder = meta.get("folder") if isinstance(meta, dict) else None
        cache[workspace_id] = _uri_path(folder) if isinstance(folder, str) else ""
    return cache[workspace_id]


def _tool_call(tool: dict, folder: str) -> tuple[str, str, dict]:
    """(tool, kind, input) for one toolFormerData entry."""
    name = str(tool.get("name") or "").removesuffix("_v2")
    kind = EXTRA_KINDS.get(name) or classify(name)
    merged = {**_as_dict(tool.get("params")), **_as_dict(tool.get("rawArgs"))}
    if kind == ActionKind.MCP_CALL and merged.get("toolName"):
        name = f"mcp__{merged.get('providerIdentifier') or 'unknown'}__{merged['toolName']}"
        args = merged.get("args")
        return name, kind, args if isinstance(args, dict) else {}
    # The other MCP shape (tool type 19): the bubble name is a mangled
    # `mcp_<server>_<tool>` or `mcp-<server>-<tool>`, but params carries the
    # one called tool and its server exactly.
    listed = merged.get("tools")
    if isinstance(listed, list) and len(listed) == 1 and isinstance(listed[0], dict):
        server, tool_name = listed[0].get("serverName"), listed[0].get("name")
        if isinstance(server, str) and server and isinstance(tool_name, str) and tool_name:
            return f"mcp__{server}__{tool_name}", ActionKind.MCP_CALL, _as_dict(tool.get("rawArgs"))
    path = next((merged[k] for k in PATH_KEYS if isinstance(merged.get(k), str) and merged[k]), None)
    if path:
        path = _uri_path(path)
        merged["file_path"] = os.path.join(folder, path) if folder and not os.path.isabs(path) else path
    return name, kind, merged


def _connect(db: pathlib.Path) -> sqlite3.Connection:
    return sqlite3.connect(db.as_uri() + "?mode=ro", uri=True, timeout=1)


def _headers(conn) -> dict:
    try:
        rows = conn.execute("SELECT composerId, workspaceId, lastUpdatedAt FROM composerHeaders").fetchall()
    except sqlite3.Error:  # older Cursor: no headers table; also a locked/corrupt db
        return {}
    return {composer_id: (workspace_id, updated) for composer_id, workspace_id, updated in rows}


def _ordered_bubbles(conn, composer: dict) -> list[tuple[str, dict]]:
    """(bubble id, bubble) for every stored message of the conversation: the
    ones a summary dropped from the headers first, by createdAt (they predate
    the remaining headers), then the headers in their own order."""
    prefix = f"bubbleId:{composer['composerId']}:"
    # A key range, not LIKE: `_` and `%` in an id must not act as wildcards.
    stored = {
        key[len(prefix):]: _as_dict(value)
        for key, value in conn.execute(
            "SELECT key, value FROM cursorDiskKV WHERE key >= ? AND key < ?", (prefix, prefix[:-1] + ";")
        )
    }
    listed = [h.get("bubbleId") for h in composer.get("fullConversationHeadersOnly") or [] if isinstance(h, dict)]
    listed_set = set(listed)
    dropped = sorted(
        ((bubble_id, bubble) for bubble_id, bubble in stored.items() if bubble_id not in listed_set),
        key=lambda item: str(item[1].get("createdAt") or ""),
    )
    return dropped + [(bubble_id, stored[bubble_id]) for bubble_id in listed if bubble_id in stored]


def _conversation(conn, composer: dict, done: set, *, folder, hostname, user_name, unknown_versions: set):
    """Records for the conversation's tool calls not in ``done``, each with the
    prompt that preceded it. Returns (records, ids of the calls emitted).

    Known limit: re-reads the whole conversation whenever it changed; read only
    the new tail if very long conversations make ingest slow."""
    composer_id = composer["composerId"]
    model = (composer.get("modelConfig") or {}).get("modelName")
    prompt = turn_id = None

    records, emitted = [], set()
    for bubble_id, bubble in _ordered_bubbles(conn, composer):
        if bubble.get("_v") not in KNOWN_BUBBLE_VERSIONS:
            unknown_versions.add(bubble.get("_v"))
            continue
        if bubble.get("type") == 1:
            prompt, turn_id = bubble.get("text"), bubble_id
            continue
        tool = bubble.get("toolFormerData")
        if not isinstance(tool, dict) or not tool.get("name") or bubble_id in done:
            continue
        emitted.add(bubble_id)
        name, kind, tool_input = _tool_call(tool, folder)
        params = _as_dict(tool.get("params"))
        sandbox = params.get("requestedSandboxPolicy")
        status, error = STATUSES.get(tool.get("status"), ("unknown", None))
        result = tool.get("result")
        records.append(
            ActivityRecord(
                source="cursor",
                session_id=composer_id,
                turn_id=turn_id,
                ts=common.iso_ms(bubble.get("createdAt")) or int(composer.get("createdAt") or 0),
                event="transcript",
                actor=Actor(
                    user_name=user_name,
                    agent_name=AGENT_NAME,
                    agent_version="unknown",
                    model=model,
                    model_provider="Cursor" if model else None,
                    pid=None,
                ),
                cwd=str(params.get("cwd") or folder),
                hostname=hostname,
                posture=common.transcript_posture(
                    tool.get("toolCallId"),
                    sandbox=sandbox.get("type") if isinstance(sandbox, dict) else sandbox,
                ),
                prompt=prompt,
                action=Action(
                    tool=name,
                    kind=kind,
                    input=tool_input,
                    output=None if result is None else str(result),
                    status=status,
                    error=error,
                ),
                decision=DECISIONS.get(tool.get("userDecision"), Decision.OBSERVED),
            )
        )
    return records, emitted


def ingest(config: Config, source=None, *, now_ms: int | None = None) -> tuple[int, int, int]:
    """Ingest every settled Cursor conversation. Returns (emitted, skipped, gap findings)."""
    user_dir = pathlib.Path(source or default_user_dir())
    db = user_dir / "globalStorage" / "state.vscdb"
    if not db.exists():
        return 0, 0, 0
    now_ms = now_ms or int(time.time() * 1000)
    marks = common.load_watermark(config, "cursor")
    # "composers" held header counts, which a summary invalidates; a store
    # with only that is read again once.
    marks.pop("composers", None)
    done = marks.setdefault("emitted", {})
    host, user = socket.gethostname(), common.user_name()
    folders: dict = {}
    unknown_versions: set = set()
    totals = [0, 0, 0]

    conn = None
    try:
        try:
            conn = _connect(db)
            headers = _headers(conn)
            rows = conn.execute("SELECT key, value FROM cursorDiskKV WHERE key LIKE 'composerData:%'")
        except sqlite3.Error as error:
            # Never log the db contents: a bare exception type and message only.
            log_error(config, f"cursor ingest: cannot read {db}: {type(error).__name__}: {error}")
            common.save_watermark(config, "cursor", marks)
            return tuple(totals)

        for key, value in rows:
            try:
                composer = _as_dict(value)
                composer_id = composer.get("composerId") or key.split(":", 1)[1]
                composer["composerId"] = composer_id
                workspace_id, updated = headers.get(composer_id, (None, None))
                last_activity = updated or composer.get("lastUpdatedAt") or composer.get("createdAt") or 0
                if not common.settled(int(last_activity), now_ms):
                    continue
                already = set(done.get(composer_id) or [])
                records, emitted = _conversation(
                    conn,
                    composer,
                    already,
                    folder=_workspace_folder(user_dir, workspace_id, folders),
                    hostname=host,
                    user_name=user,
                    unknown_versions=unknown_versions,
                )
                result = common.emit_session(config, composer_id, records, call_ids_match=CALL_IDS_MATCH)
                totals = [a + b for a, b in zip(totals, result)]
                done[composer_id] = sorted(already | emitted)
            except common.NotDelivered as error:
                log_error(config, f"cursor ingest: {error}; watermark kept for a retry")
            except Exception:
                log_error(config, f"cursor ingest failed on {key}: {traceback.format_exc()}")
    finally:
        if conn is not None:
            conn.close()

    if unknown_versions:
        log_error(
            config,
            "cursor ingest: skipped messages with unverified bubble version "
            + ", ".join(sorted(map(str, unknown_versions))),
        )
    common.save_watermark(config, "cursor", marks)
    return tuple(totals)
