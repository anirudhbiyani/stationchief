"""Where the server keeps OCSF events: gzip NDJSON objects in S3 or GCS.

`EventStore` is one method, like the client's `Sink`. Each stored line is
{"principal", "received_at", "event"}; the principal comes from the bearer
token, never from the payload.

Object storage has no ON CONFLICT: a client retry after a lost response can
store an event twice. Every event carries a deterministic `metadata.uid`, so
readers deduplicate on (principal, event.metadata.uid) at query time.

Retention is a bucket lifecycle rule, not a server command.
"""

import gzip
import json
import threading
import time
import urllib.parse
import uuid
from typing import Protocol

# Concurrent writes within this window share one object (group commit), so
# the object count is bounded by 1/window per replica, not by request rate.
# Every writer waits for the upload before returning, so nothing is
# acknowledged that is not stored. Known limit: one window for all traffic;
# make it configurable if latency or object count needs tuning.
GROUP_COMMIT_SECONDS = 0.2
UPLOAD_TIMEOUT_SECONDS = 10


class EventRejected(ValueError):
    """This event can never be stored (bad data, not an outage). The
    server reports it in partialSuccess instead of failing the request.

    ``rejected`` set means the store already wrote every other event in the
    call and refused this many, so the caller must not retry one by one."""

    def __init__(self, message: str, rejected: int | None = None):
        super().__init__(message)
        self.rejected = rejected


class EventStore(Protocol):
    def write(self, events: list[dict], principal: str) -> int:
        """Persist ``events`` for ``principal``; return how many were written."""


class MemoryStore:
    """For tests and `stationchief-server serve --memory`. Lost on restart."""

    def __init__(self):
        self.rows: dict[tuple[str, str], tuple[str, dict]] = {}

    def write(self, events: list[dict], principal: str) -> int:
        inserted = 0
        for event in events:
            key = (principal, event["metadata"]["uid"])
            if key not in self.rows:
                self.rows[key] = (principal, event)
                inserted += 1
        return inserted

    def events(self) -> list[dict]:
        return [event for _, event in self.rows.values()]


def line(event: dict, principal: str, received_at_ms: int) -> bytes:
    """One stored NDJSON line. allow_nan=False: NaN is not JSON, and no
    query engine should have to guess what it means."""
    try:
        return json.dumps(
            {"principal": principal, "received_at": received_at_ms, "event": event},
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode() + b"\n"
    except (TypeError, ValueError, RecursionError) as error:
        raise EventRejected(f"unstorable event ({type(error).__name__})") from error


def object_key(prefix: str, now: float) -> str:
    """Hive-style date/hour partitions (by receive time), so Athena and
    BigQuery prune by time instead of scanning the bucket."""
    stamp = time.gmtime(now)
    name = f"{time.strftime('dt=%Y-%m-%d/hour=%H', stamp)}/{int(now * 1000)}-{uuid.uuid4().hex}.ndjson.gz"
    return f"{prefix.strip('/')}/{name}" if prefix.strip("/") else name


class _Batch:
    def __init__(self):
        self.lines: list[bytes] = []
        self.done = threading.Event()
        self.error: BaseException | None = None


class ObjectStore:
    """Group-committed writes through ``put(key, data)``. `write` blocks (it
    runs in the server's thread pool): the first writer in a window waits
    GROUP_COMMIT_SECONDS, uploads everything that joined, and wakes the rest;
    an upload failure raises in every writer that joined, so each request
    gets its 503 and its client retries."""

    def __init__(self, put, prefix: str = "", *, window_s: float = GROUP_COMMIT_SECONDS):
        self._put = put
        self._prefix = prefix
        self._window_s = window_s
        self._lock = threading.Lock()
        self._batch: _Batch | None = None

    def write(self, events: list[dict], principal: str) -> int:
        if not events:
            return 0
        now_ms = int(time.time() * 1000)
        lines, rejected = [], 0
        for event in events:  # bad events are dropped before joining a batch
            try:
                lines.append(line(event, principal, now_ms))
            except EventRejected:
                rejected += 1
        if not lines:
            raise EventRejected(f"{rejected} unstorable event(s)", rejected=rejected)
        with self._lock:
            batch, leader = self._batch, self._batch is None
            if leader:
                batch = self._batch = _Batch()
            batch.lines.extend(lines)
        if leader:
            time.sleep(self._window_s)
            with self._lock:
                self._batch = None
            try:
                self._put(object_key(self._prefix, time.time()), gzip.compress(b"".join(batch.lines)))
            except BaseException as error:
                batch.error = error
            finally:
                batch.done.set()
        else:
            batch.done.wait()
        if batch.error is not None:
            raise batch.error
        if rejected:
            raise EventRejected(f"{rejected} unstorable event(s)", rejected=rejected)
        return len(lines)


def s3_put(bucket: str, *, client=None):
    if client is None:
        import boto3
        from botocore.config import Config

        client = boto3.client(
            "s3",
            config=Config(
                connect_timeout=3,
                read_timeout=UPLOAD_TIMEOUT_SECONDS,
                retries={"max_attempts": 3, "mode": "standard"},
            ),
        )

    def put(key: str, data: bytes) -> None:
        client.put_object(Bucket=bucket, Key=key, Body=data, ContentType="application/gzip")

    return put


def gcs_put(bucket: str, *, client=None):
    if client is None:
        from google.cloud import storage

        client = storage.Client()
    target = client.bucket(bucket)

    def put(key: str, data: bytes) -> None:
        # if_generation_match=0: create only; a key is never overwritten.
        target.blob(key).upload_from_string(
            data, content_type="application/gzip", timeout=UPLOAD_TIMEOUT_SECONDS, if_generation_match=0
        )

    return put


def store_from_url(url: str, *, client=None) -> ObjectStore:
    """``s3://bucket/prefix`` or ``gs://bucket/prefix``. Credentials come
    from the SDK's default chain (IAM role, workload identity, env)."""
    parts = urllib.parse.urlsplit(url)
    if not parts.netloc:
        raise ValueError(f"storage_url needs a bucket: {url!r}")
    if parts.scheme == "s3":
        return ObjectStore(s3_put(parts.netloc, client=client), parts.path)
    if parts.scheme == "gs":
        return ObjectStore(gcs_put(parts.netloc, client=client), parts.path)
    raise ValueError(f"storage_url must be s3://bucket/prefix or gs://bucket/prefix, not {url!r}")
