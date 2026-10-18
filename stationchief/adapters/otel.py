"""OTEL LogRecordProcessor for agents whose code we control.

The spec's Finding 3 holds: OTEL is an envelope, not a schema. So this adapter
does not try to interpret arbitrary OTEL records - it reads an explicit
`stationchief.*` attribute namespace that an instrumented agent sets deliberately,
and produces the same ActivityRecord a hook would. One mapping core, two
transports.

`attributes_to_record` is pure and carries the tests; the processor class is a
thin wrapper so that the opentelemetry-sdk dependency stays optional.
"""

import json
import queue
import threading
import time
import traceback

from stationchief.config import Config
from stationchief.core.records import Action, ActionKind, ActivityRecord, Actor, Decision
from stationchief.pipeline import emit_many, log_error

ATTRIBUTE_PREFIX = "stationchief."
REQUIRED = ("session_id", "agent_name", "tool")


def _get(attributes, name, default=None):
    return attributes.get(ATTRIBUTE_PREFIX + name, default)


def _as_dict(value):
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except ValueError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def attributes_to_record(attributes, *, hostname: str, user_name: str):
    """Build an ActivityRecord from an `stationchief.*` attribute namespace.

    Returns None for records that are not ours or that omit a required field:
    a partial record is worse than no record, because it looks like evidence.
    """
    if not any(str(key).startswith(ATTRIBUTE_PREFIX) for key in attributes):
        return None
    if any(_get(attributes, name) is None for name in REQUIRED):
        return None

    kind = _get(attributes, "kind", ActionKind.UNKNOWN)
    if kind not in ActionKind.ALL:
        kind = ActionKind.UNKNOWN
    decision = _get(attributes, "decision", Decision.OBSERVED)
    if decision not in Decision.ALL:
        decision = Decision.OBSERVED
    model = _get(attributes, "model")

    return ActivityRecord(
        source="otel",
        session_id=str(_get(attributes, "session_id")),
        turn_id=_get(attributes, "turn_id"),
        ts=int(_get(attributes, "ts") or time.time() * 1000),
        event=str(_get(attributes, "event", "otel.log")),
        actor=Actor(
            user_name=user_name,
            agent_name=str(_get(attributes, "agent_name")),
            agent_version=str(_get(attributes, "agent_version", "unknown")),
            model=model,
            model_provider=_get(attributes, "model_provider") if model else None,
            pid=None,
        ),
        cwd=str(_get(attributes, "cwd", "")),
        hostname=hostname,
        posture=_as_dict(_get(attributes, "posture", {})),
        prompt=_get(attributes, "prompt"),
        action=Action(
            tool=str(_get(attributes, "tool")),
            kind=kind,
            input=_as_dict(_get(attributes, "input", {})),
            output=_get(attributes, "output"),
            status=str(_get(attributes, "status", "unknown")),
            error=_get(attributes, "error"),
        ),
        decision=decision,
    )


class StationChiefLogRecordProcessor:
    """Attach to an OTEL LoggerProvider to translate in-process agent activity.

        provider.add_log_record_processor(StationChiefLogRecordProcessor(Config.load()))

    Implements the LogRecordProcessor interface structurally rather than by
    inheritance, so importing this module does not require the OTEL SDK.

    Built for long-lived processes: `emit` only queues, so the caller's
    logging thread never waits on the network. One worker thread translates
    and writes in batches (one sink write per batch), and every
    SPOOL_FLUSH_SECONDS resends what an outage left in the spool. When the
    queue is full, records are dropped and counted rather than blocking the
    application. `shutdown` drains the queue and the spool before returning.
    """

    QUEUE_SIZE = 10_000
    BATCH_SIZE = 500
    SPOOL_FLUSH_SECONDS = 60

    def __init__(self, config: Config = None, *, hostname=None, user_name=None):
        import getpass
        import socket

        self._config = config or Config.load()
        self._hostname = hostname or socket.gethostname()
        try:
            self._user_name = user_name or getpass.getuser()
        except BaseException:
            self._user_name = "unknown"
        self._queue = queue.Queue(maxsize=self.QUEUE_SIZE)
        self._dropped = 0
        self._closed = False
        self._worker = threading.Thread(target=self._run, name="stationchief-otel-processor", daemon=True)
        self._worker.start()

    def emit(self, log_data):
        if self._closed:
            return
        try:
            # Copy now: the SDK may reuse the record once emit returns.
            attributes = dict(getattr(log_data.log_record, "attributes", None) or {})
            self._queue.put_nowait(attributes)
        except queue.Full:
            self._dropped += 1
            if self._dropped == 1 or self._dropped % 1000 == 0:
                log_error(self._config, f"otel processor queue full; {self._dropped} record(s) dropped so far")
        except BaseException:
            log_error(self._config, f"otel processor failed: {traceback.format_exc()}")

    def _run(self):
        last_flush = time.monotonic()
        while True:
            try:
                first = self._queue.get(timeout=self.SPOOL_FLUSH_SECONDS)
            except queue.Empty:
                first = None
            batch = [] if first is None else [first]
            while first is not _STOP and len(batch) < self.BATCH_SIZE:
                try:
                    batch.append(self._queue.get_nowait())
                except queue.Empty:
                    break
            stop = _STOP in batch
            self._write([item for item in batch if item is not _STOP])
            for _ in batch:
                self._queue.task_done()
            if stop or time.monotonic() - last_flush >= self.SPOOL_FLUSH_SECONDS:
                self._flush_spool()
                last_flush = time.monotonic()
            if stop:
                return

    def _write(self, batch):
        try:
            records = []
            for attributes in batch:
                record = attributes_to_record(attributes, hostname=self._hostname, user_name=self._user_name)
                if record is not None:
                    records.append(record)
            if records:
                emit_many(records, self._config)
        except BaseException:
            log_error(self._config, f"otel processor failed: {traceback.format_exc()}")

    def _flush_spool(self):
        config = self._config
        if not (config.server_url and config.server_token):
            return
        try:
            from stationchief.sinks.otlp import OtlpSink, flush

            spool = config.home / "spool"
            if spool.is_dir():
                flush(OtlpSink(config.server_url, config.server_token, spool_dir=spool), spool)
        except BaseException:
            log_error(config, f"otel processor spool flush failed: {traceback.format_exc()}")

    def force_flush(self, timeout_millis=30_000):
        """Wait until everything queued so far is written. False on timeout."""
        deadline = time.monotonic() + timeout_millis / 1000
        with self._queue.all_tasks_done:
            while self._queue.unfinished_tasks:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._queue.all_tasks_done.wait(remaining)
        return True

    def shutdown(self, timeout_millis=30_000):
        if self._closed:
            return
        self._closed = True
        try:
            self._queue.put(_STOP, timeout=timeout_millis / 1000)
        except queue.Full:
            log_error(self._config, "otel processor shutdown: queue still full; unsent records are lost")
            return
        self._worker.join(timeout_millis / 1000)


_STOP = object()
