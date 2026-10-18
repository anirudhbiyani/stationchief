"""The stationchief service: /otel for telemetry and storage, /check for policy.

Every route except /healthz requires a bearer token that maps to a
principal (see config.py). The principal is stored with every event.
"""

import json
import logging
import time
import zlib

import anyio.to_thread
from starlette.applications import Starlette
from starlette.background import BackgroundTask
from starlette.concurrency import run_in_threadpool
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.routing import Route

from stationchief.core.mapping import map_record
from stationchief.policy import CheckRequest, Verdict
from stationchief.server.check import decision_record
from stationchief.server.native import NativeMapper
from stationchief.server.otlp import process_logs
from stationchief.server.policy import build_engine
from stationchief.server.store import EventRejected

log = logging.getLogger("stationchief.server")
PUBLIC_PATHS = frozenset({"/healthz"})
PROTOBUF = "application/x-protobuf"
# Separate thread budgets. A storage write holds its thread for the group-
# commit window plus the upload, so storage on the shared pool (40 threads)
# would queue /check behind it until clients hit their deadline and fail
# open. Storage threads mostly wait, so its budget is large; /check gets its
# own so nothing else can starve a verdict.
STORE_THREADS = 256
CHECK_THREADS = 64


def _limiter(app, name: str, size: int) -> anyio.CapacityLimiter:
    # Created on first use: a limiter belongs to the running event loop.
    limiter = getattr(app.state, name, None)
    if limiter is None:
        limiter = anyio.CapacityLimiter(size)
        setattr(app.state, name, limiter)
    return limiter


async def _in_store_thread(app, fn, *args):
    return await anyio.to_thread.run_sync(lambda: fn(*args), limiter=_limiter(app, "store_limiter", STORE_THREADS))


class BodyTooLarge(Exception):
    pass


class BearerAuth(BaseHTTPMiddleware):
    def __init__(self, app, config):
        super().__init__(app)
        self.config = config

    async def dispatch(self, request, call_next):
        if request.url.path in PUBLIC_PATHS:
            return await call_next(request)
        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        principal = self.config.principal_for(token.strip()) if scheme.lower() == "bearer" and token else None
        if principal is None:
            return JSONResponse({"error": "unauthorized"}, status_code=401, headers={"WWW-Authenticate": "Bearer"})
        request.state.principal = principal
        return await call_next(request)


class BadGzip(ValueError):
    pass


async def _read_body(request, limit: int) -> bytes:
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > limit:
        raise BodyTooLarge()
    size, chunks = 0, []
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise BodyTooLarge()
        chunks.append(chunk)
    return b"".join(chunks)


def _gunzip(raw: bytes, limit: int) -> bytes:
    """Decompress a gzip body, never past ``limit`` bytes (no zip bombs)."""
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        body = decompressor.decompress(raw, limit + 1)
    except zlib.error:
        raise BadGzip() from None
    if len(body) > limit:
        raise BodyTooLarge()
    if not decompressor.eof:
        raise BadGzip()
    return body


def _parse_json(raw: bytes):
    try:
        return json.loads(raw or b"null")
    except RecursionError:
        # A body nested deeper than the parser can follow is the client's
        # fault: a 400, never a 500.
        raise ValueError("request body is nested too deeply") from None


async def _read_json(request, limit: int):
    return _parse_json(await _read_body(request, limit))


def _store_each(store, events: list, principal: str) -> tuple[int, bool]:
    """Store the batch; if the store rejects it, retry event by event so one
    unstorable event cannot fail the rest.

    Returns (events not stored, whether any failure looked like an outage
    rather than an `EventRejected`). The first outage error stops the retry:
    the request is answered 503 and resent whole, so trying the rest would
    only hammer storage that is down. Store errors are logged here, never
    sent to the client."""
    try:
        store.write(events, principal)
        return 0, False
    except EventRejected as error:
        if error.rejected is not None:  # the store kept the rest already
            log.warning("store rejected %d event(s)", error.rejected)
            return error.rejected, False
        log.exception("batch insert failed; retrying %d event(s) one by one", len(events))
    except Exception:
        log.exception("batch insert failed; retrying %d event(s) one by one", len(events))
    unstored = 0
    for index, event in enumerate(events):
        try:
            store.write([event], principal)
        except EventRejected:
            log.exception("event rejected by the store")
            unstored += 1
        except Exception:
            log.exception("could not store event; storage looks unavailable")
            return unstored + len(events) - index, True
    return unstored, False


def _store_decision(store, event: dict, principal: str) -> None:
    """Background task: the verdict is already sent, so a slow or down
    store can never delay (and so fail open) a /check answer."""
    try:
        store.write([event], principal)
    except Exception:
        # The decision still stands; losing the audit row is logged, not fatal.
        log.exception("failed to store /check decision")


async def healthz(request):
    return JSONResponse({"status": "ok"})


async def accept_and_drop(request):
    """Metrics and traces: accepted so native exporters don't log errors, not kept."""
    return JSONResponse({})


async def otel_logs(request):
    state = request.app.state
    if request.headers.get("content-type", "").split(";")[0].strip() == PROTOBUF:
        return JSONResponse(
            {"error": "OTLP protobuf is not supported; set OTEL_EXPORTER_OTLP_PROTOCOL=http/json"},
            status_code=415,
        )
    encoding = request.headers.get("content-encoding", "identity").strip().lower()
    if encoding not in ("identity", "gzip"):
        return JSONResponse({"error": "unsupported Content-Encoding; send gzip or none"}, status_code=415)
    limit = state.config.max_body_bytes
    try:
        raw = await _read_body(request, limit)
        payload = _parse_json(_gunzip(raw, limit) if encoding == "gzip" else raw)
    except BodyTooLarge:
        return JSONResponse({"error": "request body too large"}, status_code=413)
    except BadGzip:
        return JSONResponse({"error": "request body is not valid gzip"}, status_code=400)
    except ValueError:
        return JSONResponse({"error": "request body is not valid JSON"}, status_code=400)
    try:
        # Native mapping and redaction are CPU-bound: a large batch on the
        # event loop would stall every concurrent /check.
        outcome = await run_in_threadpool(process_logs, payload, native=state.native, principal=request.state.principal)
    except Exception:
        # Defence in depth: process_logs is expected to handle every
        # malformed shape itself. If it doesn't, never leak exception
        # details to the client; log them server-side instead.
        log.exception("process_logs raised on an OTLP request")
        return JSONResponse(
            {"partialSuccess": {"rejectedLogRecords": 0, "errorMessage": "malformed OTLP request"}},
            status_code=400,
        )
    if outcome.events:
        unstored, outage = await _in_store_thread(request.app, _store_each, state.store, outcome.events, request.state.principal)
        if outage:
            # At least one event failed for an outage, not bad data. A 5xx
            # keeps the client's spool so the whole batch is resent later;
            # what was stored is deduplicated on (principal, uid). Events
            # the store rejects as bad data are a 200 with partialSuccess,
            # so they never poison the client's spool.
            return JSONResponse({"error": "storage unavailable"}, status_code=503)
        if unstored:
            outcome.rejected += unstored
            outcome.errors.append(f"{unstored} event(s) could not be stored")
    return JSONResponse(outcome.response())


async def check(request):
    state = request.app.state
    try:
        body = await _read_json(request, state.config.max_body_bytes)
        check_request = CheckRequest.from_json(body)
    except BodyTooLarge:
        return JSONResponse({"error": "request body too large"}, status_code=413)
    except ValueError as error:
        return JSONResponse({"error": str(error)}, status_code=400)
    except RecursionError:
        return JSONResponse({"error": "request body is nested too deeply"}, status_code=400)

    principal = request.state.principal
    try:
        verdict = await anyio.to_thread.run_sync(
            lambda: state.engine.decide(check_request, principal=principal),
            limiter=_limiter(request.app, "check_limiter", CHECK_THREADS),
        )
        if not isinstance(verdict, Verdict):
            raise TypeError(f"engine returned {type(verdict).__name__}, not Verdict")
    except Exception:
        log.exception("policy engine failed; answering %s", state.config.on_engine_error)
        verdict = Verdict(decision=state.config.on_engine_error, reason="policy engine error", policy=None)

    try:
        event = map_record(decision_record(check_request, verdict, now_ms=int(time.time() * 1000), principal=principal))
    except Exception:
        # The decision still stands; a record that can't be built is logged
        # and skipped, never turned into a 500 or leaked to the client.
        log.exception("failed to build /check decision event")
        return JSONResponse(verdict.to_json())
    return JSONResponse(
        verdict.to_json(),
        background=BackgroundTask(_in_store_thread, request.app, _store_decision, state.store, event, principal),
    )


def create_app(config, store, engine=None) -> Starlette:
    app = Starlette(
        routes=[
            Route("/healthz", healthz, methods=["GET"]),
            Route("/otel/v1/logs", otel_logs, methods=["POST"]),
            Route("/otel/v1/metrics", accept_and_drop, methods=["POST"]),
            Route("/otel/v1/traces", accept_and_drop, methods=["POST"]),
            Route("/check", check, methods=["POST"]),
        ],
        middleware=[Middleware(BearerAuth, config=config)],
    )
    app.state.config = config
    app.state.store = store
    app.state.engine = engine if engine is not None else build_engine(config.engine)
    app.state.native = NativeMapper()
    return app
