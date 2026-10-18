"""The single path from an ActivityRecord to the sinks.

Order is load-bearing: redaction runs first, then detection on the cleaned
record plus the redaction hits (so a secret finding knows a secret was there
without ever holding its value), then mapping, then sinks. No adapter may
skip a step, because no adapter has any other way to emit.
"""

import datetime
import os
import traceback

from stationchief.config import Config
from stationchief.core.mapping import map_record
from stationchief.core.records import ActivityRecord
from stationchief.core.redact import redact_record


def log_error(config: Config, message: str) -> None:
    """Best-effort error logging. Never raises: this runs inside an agent hook."""
    try:
        config.home.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(config.home, 0o700)
        stamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        # Created 0600 by os.open itself: tracebacks can quote local paths.
        descriptor = os.open(config.home / "errors.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
            handle.write(f"{stamp} {message}\n")
    except BaseException:
        pass


def _refuse_raw_off_machine(name: str, config: Config) -> None:
    """`redact: false` keeps raw events on this machine only (the NDJSON and
    stdout sinks). A sink that sends events elsewhere is refused."""
    if not config.redact:
        raise ValueError(f"refusing the {name} sink while redact is false")


def _make_sink(name: str, config: Config):
    if name == "ndjson":
        from stationchief.sinks.ndjson import NdjsonSink

        return NdjsonSink(config.home)
    if name == "stdout":
        from stationchief.sinks.base import StdoutSink

        return StdoutSink()
    if name == "http" and config.http_url:
        _refuse_raw_off_machine(name, config)
        from stationchief.sinks.http import HttpSink

        return HttpSink(config.http_url, token=config.http_token)
    if name == "server" and config.server_url and config.server_token:
        _refuse_raw_off_machine(name, config)
        from stationchief.sinks.otlp import OtlpSink

        return OtlpSink(
            config.server_url,
            config.server_token,
            spool_dir=config.home / "spool",
            log=lambda message: log_error(config, message),
        )
    raise ValueError(f"unknown or unconfigured sink {name!r}")


def build_sinks(config: Config) -> list:
    """Construct each configured sink independently.

    One broken sink (a bad URL, a missing module) is logged and skipped; it must
    never take the NDJSON sink down with it.
    """
    sinks = []
    for name in config.sinks:
        try:
            sinks.append(_make_sink(name, config))
        except BaseException:
            log_error(config, f"sink {name!r} unavailable: {traceback.format_exc()}")
    return sinks


def write(events: list[dict], config: Config, sinks=None) -> bool:
    """Hand events to every sink. Sink failures are logged, never raised.

    Returns True when at least one sink stored (or spooled) the events, so
    callers keeping checkpoints know the events are durably captured."""
    delivered = False
    for sink in sinks if sinks is not None else build_sinks(config):
        try:
            sink.write(events)
            delivered = True
        except BaseException:
            log_error(config, f"sink {type(sink).__name__} failed: {traceback.format_exc()}")
    return delivered


def _events_for(record: ActivityRecord, config: Config) -> list[dict]:
    """Detection findings plus the mapped event for one record. Never raises:
    a record that cannot be mapped is logged and yields no activity event."""
    events: list[dict] = []
    try:
        cleaned, hits = redact_record(record, enabled=config.redact)
    except BaseException:
        log_error(config, f"redaction failed; record dropped: {traceback.format_exc()}")
        return events

    if config.detect:
        try:
            from stationchief.detect.rules import findings_for

            events.extend(findings_for(cleaned, hits))
        except ImportError:
            pass
        except BaseException:
            log_error(config, f"detection failed: {traceback.format_exc()}")

    try:
        events.append(map_record(cleaned))
    except BaseException:
        log_error(config, f"mapping failed: {traceback.format_exc()}")
    return events


def emit(record: ActivityRecord, config: Config, sinks=None) -> list[dict]:
    """Run one record through redaction, detection, mapping, and every sink.

    Returns the events that were produced, so callers and tests can inspect
    them. Never raises: every failure is logged.
    """
    events = _events_for(record, config)
    write(events, config, sinks)
    return events


def emit_many(records, config: Config, sinks=None, *, extra=()) -> bool:
    """`emit` for several records with a single sink write, so a hook that
    produces many records (SessionStart's component loads, a backfilled
    session) pays at most one network timeout. `extra` events (already
    redacted and mapped) join the same write. Never raises.

    Returns whether the events were durably captured (True when there was
    nothing to write), so ingest advances its watermark only on success."""
    events: list[dict] = []
    try:
        for record in records:
            events.extend(_events_for(record, config))
        events.extend(extra)
    except BaseException:
        log_error(config, f"emit_many failed: {traceback.format_exc()}")
        return False
    if not events:
        return True
    return write(events, config, sinks)
