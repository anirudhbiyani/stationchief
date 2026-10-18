"""Shared by the data-at-rest ingest adapters (spec: "Ingest adapters").

Watermarks, the settled-only rule, and the dedup table that keeps transcript
capture from double counting what the hooks already emitted.
"""

import datetime
import getpass
import json
import os

from stationchief import state
from stationchief.config import Config
from stationchief.core.redact import redact_record
from stationchief.detect.rules import coverage_gap_finding
from stationchief.pipeline import emit_many

SETTLE_MS = 10 * 60 * 1000
FILE_MODE = 0o600
DIRECTORY_MODE = 0o700


def iso_ms(text) -> int | None:
    try:
        parsed = datetime.datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return int(parsed.timestamp() * 1000)


def settled(last_activity_ms: int | None, now_ms: int) -> bool:
    """Live sessions belong to the hooks; ingest reads only idle ones."""
    return last_activity_ms is not None and now_ms - last_activity_ms >= SETTLE_MS


def user_name() -> str:
    try:
        return getpass.getuser()
    except BaseException:
        return "unknown"


def transcript_posture(call_id, **extra) -> dict:
    """Provenance for the enrichment: which path captured this, and its call id."""
    posture = {"capture": "transcript", "tool_call_id": call_id}
    posture.update({key: value for key, value in extra.items() if value is not None})
    return posture


def _watermark_path(config: Config, agent: str):
    return config.home / "ingest" / f"{agent}.json"


def load_watermark(config: Config, agent: str) -> dict:
    try:
        data = json.loads(_watermark_path(config, agent).read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def save_watermark(config: Config, agent: str, data: dict) -> None:
    path = _watermark_path(config, agent)
    path.parent.mkdir(parents=True, exist_ok=True, mode=DIRECTORY_MODE)
    temporary = path.with_suffix(".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, FILE_MODE)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(data, handle)
    os.replace(temporary, path)


class NotDelivered(RuntimeError):
    """No sink captured the session's events; its watermark must not advance."""


def emit_session(config: Config, session_id: str, records: list, *, call_ids_match: bool) -> tuple[int, int, int]:
    """Apply the dedup table to one session. Returns (emitted, skipped, gap findings).

    Raises NotDelivered when every sink failed, so the caller keeps its
    watermark and the next run retries the session."""
    if not records:
        return 0, 0, 0
    if not state.exists(config, session_id):
        if not emit_many(records, config):
            raise NotDelivered(f"no sink captured session {session_id}")
        return len(records), 0, 0
    if not call_ids_match:
        return 0, len(records), 0

    since, seen_ids = state.seen(config, session_id)
    missing = [
        record
        for record in records
        if record.posture.get("tool_call_id")
        and record.posture["tool_call_id"] not in seen_ids
        and (since is None or record.ts >= since)
    ]
    if missing:
        # One write for the whole session: the calls and their gap finding.
        cleaned, _ = redact_record(missing[0], enabled=config.redact)
        if not emit_many(missing, config, extra=[coverage_gap_finding(cleaned, len(missing))]):
            raise NotDelivered(f"no sink captured session {session_id}")
    return len(missing), len(records) - len(missing), 1 if missing else 0
