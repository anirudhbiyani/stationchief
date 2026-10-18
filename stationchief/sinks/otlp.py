"""Ship events to the stationchief service's /otel endpoint as OTLP/HTTP JSON logs.

Runs inside the hook: stdlib only, a 1 s overall deadline, and it never
raises. When the server cannot be reached, the batch is appended to a local
spool file (0600) and `stationchief flush` resends it later. After a network or 5xx
failure, later writes in the same process spool straight away for
UNREACHABLE_COOLDOWN_SECONDS, so a hook never waits on a dead server twice.
The server deduplicates on metadata.uid, so a batch that reached it before a
timeout is not stored twice.

The default opener refuses redirects (stationchief.sinks.http): a bearer token
going to the service must never follow a redirect to a different server.
"""

import contextlib
import json
import os
import pathlib
import socket
import time
import urllib.error
import urllib.request

from stationchief.sinks.http import call_with_deadline, default_opener, require_secure_url
from stationchief.sinks.ndjson import NdjsonSink

try:
    import fcntl
except ImportError:  # Known limit: no flock on Windows; spool/flush races stay possible there.
    fcntl = None

TIMEOUT_SECONDS = 1
FLUSH_TIMEOUT_SECONDS = 10
LOGS_PATH = "/otel/v1/logs"
EVENT_NAME = "stationchief.ocsf"
SPOOL_PREFIX = "spool"
FLUSH_BATCH = 500
# The server refuses bodies over 5 MiB; stay well under it.
MAX_BATCH_BYTES = 4 * 1024 * 1024
RECORD_OVERHEAD_BYTES = 256
SENDING_SUFFIX = ".sending"
REJECTED_DIR = "rejected"
LOCK_FILE = ".lock"
FLUSH_LOCK_FILE = ".flush.lock"
UNREACHABLE_COOLDOWN_SECONDS = 30
# Only these mean "these bytes will never be accepted". 401/403/408/429 and
# every other 4xx keep the spool file for a later flush.
# Known limit: Retry-After is not honoured; flush just stops and the next run retries.
REJECT_STATUSES = frozenset({400, 413, 422})


# Server URL -> time.monotonic() of the last network/5xx failure in this
# process. A hook is one short-lived process; the cooldown is for long-lived
# callers (the OTel processor, ingest) so they resume after an outage.
_unreachable: dict[str, float] = {}


class ServerStatus(RuntimeError):
    """The server answered with a non-2xx status."""

    def __init__(self, status: int):
        super().__init__(f"server answered HTTP {status}")
        self.status = status


class ServerRejected(ServerStatus):
    """400/413/422: resending the same bytes will never succeed."""


def _status_error(status: int) -> ServerStatus:
    return ServerRejected(status) if status in REJECT_STATUSES else ServerStatus(status)


def _is_outage(error: BaseException) -> bool:
    """Network failures and 5xx mean the service is down; a 4xx does not."""
    return not (isinstance(error, ServerStatus) and error.status < 500)


@contextlib.contextmanager
def _locked(spool_dir: pathlib.Path, name: str = LOCK_FILE):
    """Exclusive interprocess lock on spool_dir/name (flock)."""
    if fcntl is None:
        yield
        return
    spool_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(spool_dir / name, os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def _string(key: str, value) -> dict:
    return {"key": key, "value": {"stringValue": str(value)}}


def build_request(events: list[dict], hostname: str) -> dict:
    """One OTLP ExportLogsServiceRequest carrying one log record per event."""
    records = []
    for event in events:
        attributes = [_string("event.name", EVENT_NAME)]
        session = (event.get("metadata") or {}).get("correlation_uid")
        if session:
            attributes.append(_string("session.id", session))
        records.append(
            {
                "timeUnixNano": str(int(event.get("time", 0)) * 1_000_000),
                "body": {"stringValue": json.dumps(event, sort_keys=True)},
                "attributes": attributes,
            }
        )
    return {
        "resourceLogs": [
            {
                "resource": {"attributes": [_string("service.name", "stationchief"), _string("host.name", hostname)]},
                "scopeLogs": [{"scope": {"name": "stationchief"}, "logRecords": records}],
            }
        ]
    }


class OtlpSink:
    def __init__(self, server_url: str, token: str, *, spool_dir, opener=None, log=None):
        parts = require_secure_url(server_url)
        self._url = server_url.rstrip("/") + LOGS_PATH
        self._token = token
        self._open = opener or default_opener(parts)
        self._spool_dir = pathlib.Path(spool_dir)
        self._spool = NdjsonSink(self._spool_dir, prefix=SPOOL_PREFIX)
        self._log = log or (lambda message: None)
        self._hostname = socket.gethostname()

    def send(self, events: list[dict], *, timeout: float = TIMEOUT_SECONDS) -> int:
        """POST one batch. Raises on any failure. Returns rejected-record count."""
        body = json.dumps(build_request(events, self._hostname)).encode()
        request = urllib.request.Request(
            self._url,
            data=body,
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self._token}"},
            method="POST",
        )
        try:
            with self._open(request, timeout=timeout) as response:
                status = getattr(response, "status", 200)
                if status >= 300:
                    raise _status_error(status)
                raw = response.read() or b"{}"
        except urllib.error.HTTPError as error:
            raise _status_error(error.code) from None
        try:
            reply = json.loads(raw)
        except ValueError:
            reply = {}
        partial = reply.get("partialSuccess") if isinstance(reply, dict) else None
        rejected = int((partial or {}).get("rejectedLogRecords") or 0)
        if rejected:
            self._log(f"server rejected {rejected} event(s): {(partial or {}).get('errorMessage', '')}")
        return rejected

    def _spool_write(self, events: list[dict]) -> None:
        # Under the spool lock, so a flush never renames a file mid-append.
        with _locked(self._spool_dir):
            self._spool.write(events)

    def write(self, events: list[dict]) -> None:
        if not events:
            return
        failed_at = _unreachable.get(self._url)
        if failed_at is not None and time.monotonic() - failed_at < UNREACHABLE_COOLDOWN_SECONDS:
            self._spool_write(events)
            self._log(f"server unreachable earlier in this process; spooled {len(events)} event(s)")
            return
        try:
            # An overall deadline: urlopen's timeout is per socket operation.
            call_with_deadline(lambda: self.send(events), TIMEOUT_SECONDS)
        except Exception as error:
            if _is_outage(error):
                _unreachable[self._url] = time.monotonic()
            self._spool_write(events)
            self._log(f"server unreachable ({type(error).__name__}); spooled {len(events)} event(s)")
        else:
            _unreachable.pop(self._url, None)


def _park(lines: list[str], name: str, spool_dir: pathlib.Path) -> None:
    """Keep lines the server refused (0600) for a human to inspect, out of the
    queue so they stop blocking it."""
    rejected = spool_dir / REJECTED_DIR
    rejected.mkdir(mode=0o700, exist_ok=True)
    os.chmod(rejected, 0o700)
    target = rejected / f"{name.removesuffix(SENDING_SUFFIX)}.{time.time_ns()}"
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.writelines(line if line.endswith("\n") else line + "\n" for line in lines)


def _batches(path: pathlib.Path):
    """Stream one spool file as (events, lines) batches under FLUSH_BATCH events
    and MAX_BATCH_BYTES. An event too big to ever send comes alone as (None, [line])."""
    events, lines, size = [], [], 0
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            try:
                event = json.loads(line)
            except ValueError:
                continue  # a torn final line from a crash mid-write
            # The request carries each event as an escaped JSON string.
            cost = len(json.dumps(line.strip())) + RECORD_OVERHEAD_BYTES
            if cost > MAX_BATCH_BYTES:
                yield None, [line]
                continue
            if events and (len(events) >= FLUSH_BATCH or size + cost > MAX_BATCH_BYTES):
                yield events, lines
                events, lines, size = [], [], 0
            events.append(event)
            lines.append(line)
            size += cost
    if events:
        yield events, lines


def flush(sink: OtlpSink, spool_dir, *, timeout: float = FLUSH_TIMEOUT_SECONDS) -> tuple[int, int]:
    """Resend every spool file, oldest first; delete each once sent.

    Each file is renamed to `*.sending`, under the spool lock hooks take to
    append, before it is read, so no event can land in a file that is about to
    be deleted. A file left `.sending` by an interrupted flush is resent first.
    Concurrent flushes are serialized. Files are streamed in batches capped by
    count and bytes. A 400/413/422 answer, or an event too big to send, moves
    those lines to `rejected/` and the flush continues; any other failure keeps
    the file and stops, so the order of what the server receives stays roughly
    intact (batches already sent from that file are resent; the server dedups).

    Returns (events sent, spool files still waiting).
    """
    spool_dir = pathlib.Path(spool_dir)
    with _locked(spool_dir, FLUSH_LOCK_FILE):
        leftovers = sorted(spool_dir.glob(f"{SPOOL_PREFIX}-*.ndjson{SENDING_SUFFIX}"))
        files = leftovers + sorted(spool_dir.glob(f"{SPOOL_PREFIX}-*.ndjson"))
        sent = 0
        for index, path in enumerate(files):
            if not path.name.endswith(SENDING_SUFFIX):
                sending = path.with_name(path.name + SENDING_SUFFIX)
                with _locked(spool_dir):
                    os.replace(path, sending)
                path = sending
            try:
                for events, lines in _batches(path):
                    if events is None:
                        _park(lines, path.name, spool_dir)
                        continue
                    try:
                        sink.send(events, timeout=timeout)
                    except ServerRejected:
                        _park(lines, path.name, spool_dir)
                        continue
                    sent += len(events)
            except Exception:
                return sent, len(files) - index
            path.unlink()
        return sent, 0
