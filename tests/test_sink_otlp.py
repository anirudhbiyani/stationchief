import http.server
import json
import socketserver
import stat
import threading

import pytest

from stationchief.core.mapping import map_record
from stationchief.core.records import Action, ActionKind, ActivityRecord, Actor, Decision
from stationchief.sinks.otlp import OtlpSink, build_request, flush

TOKEN = "client-token"


def ocsf_event(session_id="sess-abc", command="ls -la"):
    """A real, schema-valid OCSF event, as the pipeline would hand the sink.
    (Same shape as tests/server_helpers.ocsf_event, kept local so this task
    does not depend on the server tasks.)"""
    return map_record(
        ActivityRecord(
            source="claude",
            session_id=session_id,
            turn_id="turn-1",
            ts=1789898400000,
            event="PreToolUse",
            actor=Actor(user_name="dev", agent_name="claude-code", agent_version="2.0.1"),
            cwd="/repo",
            hostname="laptop",
            posture={"permission_mode": "default"},
            prompt="list files",
            action=Action(tool="Bash", kind=ActionKind.SHELL, input={"command": command}),
            decision=Decision.OBSERVED,
        )
    )


class FakeServer:
    """Stands in for urllib.request.urlopen."""

    def __init__(self, reply=None, status=200, raises=None):
        self.reply, self.status, self.raises = reply or {}, status, raises
        self.requests = []

    def __call__(self, request, timeout):
        self.requests.append((request, timeout))
        if self.raises is not None:
            raise self.raises
        outer = self

        class Response:
            status = outer.status

            def read(self):
                return json.dumps(outer.reply).encode()

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        return Response()


def sink(tmp_path, server, log=None):
    return OtlpSink("https://stationchief.example.com/", TOKEN, spool_dir=tmp_path / "spool", opener=server, log=log)


def entries(spool):
    """What is in the spool directory, ignoring the flock files."""
    return [p for p in sorted(spool.iterdir()) if not p.name.startswith(".")]


def spooled(tmp_path):
    # `*.sending` too: flush renames a file before it sends it.
    return [json.loads(l) for p in (tmp_path / "spool").glob("spool-*.ndjson*") for l in p.read_text().splitlines()]


def test_build_request_is_an_otlp_logs_export():
    event = ocsf_event(session_id="sess-9")
    payload = build_request([event], "laptop")
    resource = payload["resourceLogs"][0]
    assert {"key": "service.name", "value": {"stringValue": "stationchief"}} in resource["resource"]["attributes"]
    assert {"key": "host.name", "value": {"stringValue": "laptop"}} in resource["resource"]["attributes"]
    (record,) = resource["scopeLogs"][0]["logRecords"]
    assert record["timeUnixNano"] == str(event["time"] * 1_000_000)
    assert json.loads(record["body"]["stringValue"]) == event
    assert {"key": "event.name", "value": {"stringValue": "stationchief.ocsf"}} in record["attributes"]
    assert {"key": "session.id", "value": {"stringValue": "sess-9"}} in record["attributes"]


def test_posts_to_the_logs_path_with_the_token(tmp_path):
    server = FakeServer()
    sink(tmp_path, server).write([ocsf_event()])
    request, timeout = server.requests[0]
    assert request.full_url == "https://stationchief.example.com/otel/v1/logs"
    assert request.get_header("Authorization") == f"Bearer {TOKEN}"
    assert request.get_header("Content-type") == "application/json"
    assert timeout <= 2
    assert not (tmp_path / "spool").exists()


@pytest.mark.parametrize("server", [FakeServer(raises=OSError("unreachable")), FakeServer(status=503)])
def test_failures_spool_instead_of_raising(tmp_path, server):
    messages = []
    event = ocsf_event()
    sink(tmp_path, server, log=messages.append).write([event])
    assert spooled(tmp_path) == [event]
    spool_file = entries(tmp_path / "spool")[0]
    assert stat.S_IMODE(spool_file.stat().st_mode) == 0o600
    assert any("spooled 1" in m for m in messages)
    assert all(TOKEN not in m for m in messages)


def test_partial_rejections_are_logged_not_spooled(tmp_path):
    messages = []
    server = FakeServer({"partialSuccess": {"rejectedLogRecords": 1, "errorMessage": "bad"}})
    sink(tmp_path, server, log=messages.append).write([ocsf_event()])
    assert spooled(tmp_path) == []
    assert any("rejected 1" in m for m in messages)


@pytest.mark.parametrize("url", ["http://stationchief.example.com", "stationchief.example.com", "https://"])
def test_refuses_plaintext_servers(tmp_path, url):
    with pytest.raises(ValueError, match="refusing"):
        OtlpSink(url, TOKEN, spool_dir=tmp_path)


def test_flush_resends_and_deletes_the_spool(tmp_path):
    down = sink(tmp_path, FakeServer(raises=OSError("down")))
    first, second = ocsf_event(command="a"), ocsf_event(command="b")
    down.write([first])
    down.write([second])
    server = FakeServer()
    assert flush(sink(tmp_path, server), tmp_path / "spool") == (2, 0)
    assert list(entries(tmp_path / "spool")) == []
    sent = [json.loads(r["body"]["stringValue"]) for req, _ in server.requests
            for r in json.loads(req.data)["resourceLogs"][0]["scopeLogs"][0]["logRecords"]]
    assert sent == [first, second]


def test_flush_keeps_the_spool_when_the_server_is_still_down(tmp_path):
    sink(tmp_path, FakeServer(raises=OSError("down"))).write([ocsf_event()])
    assert flush(sink(tmp_path, FakeServer(raises=OSError("down"))), tmp_path / "spool") == (0, 1)
    assert spooled(tmp_path)


def test_flush_skips_a_torn_final_line(tmp_path):
    sink(tmp_path, FakeServer(raises=OSError("down"))).write([ocsf_event()])
    spool_file = entries(tmp_path / "spool")[0]
    with open(spool_file, "a") as handle:
        handle.write('{"truncated')
    assert flush(sink(tmp_path, FakeServer()), tmp_path / "spool") == (1, 0)


def test_end_to_end_against_a_real_local_server(tmp_path):
    received = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            received.append((self.path, json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
            body = b"{}"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    class LoopbackServer(http.server.HTTPServer):
        def server_bind(self):  # skip HTTPServer's slow reverse-DNS getfqdn()
            socketserver.TCPServer.server_bind(self)
            self.server_name, self.server_port = "127.0.0.1", self.server_address[1]

    server = LoopbackServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.handle_request)
    thread.start()
    OtlpSink(f"http://127.0.0.1:{server.server_port}", TOKEN, spool_dir=tmp_path / "spool").write([ocsf_event()])
    thread.join(timeout=5)
    server.server_close()
    path, payload = received[0]
    assert path == "/otel/v1/logs"
    assert payload["resourceLogs"][0]["scopeLogs"][0]["logRecords"]


def test_a_redirect_from_the_server_is_never_followed_and_the_token_never_leaks(tmp_path):
    """The bearer token going to the stationchief service must never follow a redirect
    to a different server. Server A answers the OTLP POST with a 302 pointing at
    server B; write() must not raise, B must receive nothing, and the batch must
    land in the spool instead (so it is not lost)."""
    server_b_received = []

    class HandlerB(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            server_b_received.append((self.command, self.path, self.headers.get("Authorization")))
            self.send_response(200)
            self.end_headers()

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            server_b_received.append((self.command, self.path, self.headers.get("Authorization")))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    class HandlerA(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{server_b.server_port}/steal")
            self.end_headers()

        def log_message(self, *args):
            pass

    server_b = http.server.HTTPServer(("127.0.0.1", 0), HandlerB)
    server_a = http.server.HTTPServer(("127.0.0.1", 0), HandlerA)
    server_b.timeout = 1
    server_a.timeout = 1

    thread_a = threading.Thread(target=server_a.handle_request, daemon=True)
    thread_b = threading.Thread(target=server_b.handle_request, daemon=True)
    try:
        thread_a.start()
        thread_b.start()

        event = ocsf_event()
        # write() never raises, even though A answers with a redirect.
        OtlpSink(f"http://127.0.0.1:{server_a.server_port}", TOKEN, spool_dir=tmp_path / "spool").write([event])

        thread_a.join(timeout=5)
        thread_b.join(timeout=5)

        assert server_b_received == [], "the redirect target must receive nothing"
        assert spooled(tmp_path) == [event]
    finally:
        server_a.server_close()
        server_b.server_close()


def test_the_server_decoder_accepts_what_the_sink_sends():
    otlp = pytest.importorskip("stationchief.server.otlp", reason="server tasks not merged yet")
    event = ocsf_event()
    outcome = otlp.process_logs(json.loads(json.dumps(build_request([event], "laptop"))))
    assert outcome.events == [event] and outcome.rejected == 0


def test_the_server_sink_is_refused_when_redaction_is_off(tmp_path):
    from stationchief.config import Config
    from stationchief.pipeline import build_sinks

    config = Config(home=tmp_path, redact=False, sinks=("server", "ndjson"),
                    server_url="https://stationchief.example.com", server_token=TOKEN)
    assert [type(s).__name__ for s in build_sinks(config)] == ["NdjsonSink"]
    assert "redact is false" in (tmp_path / "errors.log").read_text()


def test_build_sinks_makes_the_server_sink(tmp_path):
    from stationchief.config import Config
    from stationchief.pipeline import build_sinks

    config = Config(home=tmp_path, sinks=("server",), server_url="https://stationchief.example.com", server_token=TOKEN)
    assert [type(s).__name__ for s in build_sinks(config)] == ["OtlpSink"]


def _http_error(code):
    import urllib.error

    return urllib.error.HTTPError("https://stationchief.example.com/otel/v1/logs", code, "nope", {}, None)


def _spool_files(tmp_path, n):
    """n spool files, one event each, oldest first."""
    spool = tmp_path / "spool"
    spool.mkdir(mode=0o700)
    events = []
    for index in range(n):
        event = ocsf_event(command=f"cmd-{index}")
        (spool / f"spool-2026-09-2{index}.ndjson").write_text(json.dumps(event) + "\n")
        events.append(event)
    return spool, events


class ScriptedServer(FakeServer):
    """Answers each request from a list: None for 200, an exception to raise, or a status."""

    def __init__(self, script):
        super().__init__()
        self.script = list(script)

    def __call__(self, request, timeout):
        step = self.script.pop(0) if self.script else None
        self.raises = step if isinstance(step, BaseException) else None
        self.status = step if isinstance(step, int) else 200
        return super().__call__(request, timeout)


@pytest.mark.parametrize("rejection", [_http_error(400), _http_error(413), 422])
def test_flush_moves_a_4xx_file_to_rejected_and_continues(tmp_path, rejection):
    spool, events = _spool_files(tmp_path, 2)
    server = ScriptedServer([rejection, None])
    assert flush(sink(tmp_path, server), spool) == (1, 0)
    (rejected,) = (spool / "rejected").iterdir()
    assert json.loads(rejected.read_text()) == events[0]
    assert stat.S_IMODE(rejected.stat().st_mode) == 0o600
    assert stat.S_IMODE((spool / "rejected").stat().st_mode) == 0o700
    assert [p.name for p in entries(spool)] == ["rejected"]


@pytest.mark.parametrize(
    "failure", [_http_error(503), 500, OSError("down"), _http_error(401), 403, _http_error(408), _http_error(429), 429]
)
def test_flush_keeps_the_file_and_stops_on_5xx_network_or_retryable_4xx(tmp_path, failure):
    spool, _ = _spool_files(tmp_path, 2)
    server = ScriptedServer([failure, None])
    sent, waiting = flush(sink(tmp_path, server), spool)
    assert (sent, waiting) == (0, 2)
    assert len(server.requests) == 1
    assert not (spool / "rejected").exists()
    assert len([p for p in entries(spool)]) == 2


def test_flush_renames_a_spool_file_before_reading_it(tmp_path):
    spool, events = _spool_files(tmp_path, 1)
    original = entries(spool)[0]
    seen = []

    class Watching(FakeServer):
        def __call__(self, request, timeout):
            seen.append(original.exists())
            return super().__call__(request, timeout)

    assert flush(sink(tmp_path, Watching()), spool) == (1, 0)
    assert seen == [False], "a hook appending during flush must start a fresh file"
    assert list(entries(spool)) == []


def test_flush_resends_a_file_left_mid_send_by_an_earlier_flush(tmp_path):
    spool, events = _spool_files(tmp_path, 1)
    original = entries(spool)[0]
    original.rename(original.with_name(original.name + ".sending"))
    server = FakeServer()
    assert flush(sink(tmp_path, server), spool) == (1, 0)
    assert list(entries(spool)) == []


def test_after_one_failure_later_writes_in_this_process_spool_without_the_network(tmp_path):
    down = FakeServer(raises=OSError("down"))
    sink(tmp_path, down).write([ocsf_event(command="a")])
    assert len(down.requests) == 1
    # A second sink in the same process (e.g. SessionStart's second write)
    # must not pay another timeout.
    later = FakeServer()
    sink(tmp_path, later).write([ocsf_event(command="b")])
    assert later.requests == []
    assert sorted(e["process"]["cmd_line"] for e in spooled(tmp_path)) == ["a", "b"]


def test_flush_still_tries_the_network_after_a_failed_write(tmp_path):
    sink(tmp_path, FakeServer(raises=OSError("down"))).write([ocsf_event()])
    server = FakeServer()
    assert flush(sink(tmp_path, server), tmp_path / "spool") == (1, 0)


def test_the_hook_timeout_is_one_second(tmp_path):
    server = FakeServer()
    sink(tmp_path, server).write([ocsf_event()])
    assert server.requests[0][1] == 1


def test_flush_splits_by_bytes_and_parks_an_oversized_event_alone(tmp_path, monkeypatch):
    import stationchief.sinks.otlp as otlp

    monkeypatch.setattr(otlp, "MAX_BATCH_BYTES", 4000)  # about two small events per request
    spool = tmp_path / "spool"
    spool.mkdir(mode=0o700)
    small = [ocsf_event(command=f"cmd-{i}") for i in range(5)]
    huge = ocsf_event(command="x" * 5000)
    lines = [small[0], small[1], huge, small[2], small[3]]
    (spool / "spool-2026-09-20.ndjson").write_text("".join(json.dumps(e, sort_keys=True) + "\n" for e in lines))
    (spool / "spool-2026-09-21.ndjson").write_text(json.dumps(small[4], sort_keys=True) + "\n")
    server = FakeServer()
    assert flush(sink(tmp_path, server), spool) == (5, 0)
    assert all(len(request.data) < 5000 for request, _ in server.requests)
    sent = [json.loads(r["body"]["stringValue"]) for req, _ in server.requests
            for r in json.loads(req.data)["resourceLogs"][0]["scopeLogs"][0]["logRecords"]]
    assert sorted(e["process"]["cmd_line"] for e in sent) == [f"cmd-{i}" for i in range(5)]
    (parked,) = (spool / "rejected").iterdir()
    assert [json.loads(l) for l in parked.read_text().splitlines()] == [huge]
    assert [p.name for p in entries(spool)] == ["rejected"]


def test_flush_uses_a_longer_timeout_than_the_hook(tmp_path):
    spool, _ = _spool_files(tmp_path, 1)
    server = FakeServer()
    flush(sink(tmp_path, server), spool)
    assert server.requests[0][1] == 10


def test_a_4xx_does_not_mark_the_server_unreachable(tmp_path):
    sink(tmp_path, FakeServer(status=401)).write([ocsf_event(command="a")])
    later = FakeServer()
    sink(tmp_path, later).write([ocsf_event(command="b")])
    assert len(later.requests) == 1


def test_sending_resumes_after_the_unreachable_cooldown(tmp_path, monkeypatch):
    import stationchief.sinks.otlp as otlp

    clock = [1000.0]
    monkeypatch.setattr(otlp.time, "monotonic", lambda: clock[0])
    sink(tmp_path, FakeServer(raises=OSError("down"))).write([ocsf_event(command="a")])
    clock[0] += otlp.UNREACHABLE_COOLDOWN_SECONDS - 1
    early = FakeServer()
    sink(tmp_path, early).write([ocsf_event(command="b")])
    assert early.requests == []
    clock[0] += 2
    later = FakeServer()
    sink(tmp_path, later).write([ocsf_event(command="c")])
    assert len(later.requests) == 1


def test_a_slow_server_is_spooled_after_an_overall_deadline(tmp_path, monkeypatch):
    import time

    import stationchief.sinks.otlp as otlp

    monkeypatch.setattr(otlp, "TIMEOUT_SECONDS", 0.2)
    release = threading.Event()

    def trickling(request, timeout):
        release.wait(5)
        return FakeServer()(request, timeout)

    event = ocsf_event()
    started = time.monotonic()
    try:
        sink(tmp_path, trickling).write([event])
        assert time.monotonic() - started < 1
        assert spooled(tmp_path) == [event]
    finally:
        release.set()


def test_flush_waits_for_a_hook_holding_the_spool_lock_before_rotating(tmp_path):
    import stationchief.sinks.otlp as otlp

    if otlp.fcntl is None:
        pytest.skip("no flock on this platform")
    spool, _ = _spool_files(tmp_path, 1)
    original = entries(spool)[0]
    result = []
    with otlp._locked(spool):  # a hook mid-append
        thread = threading.Thread(target=lambda: result.append(flush(sink(tmp_path, FakeServer()), spool)))
        thread.start()
        thread.join(0.3)
        assert thread.is_alive() and original.exists(), "flush must not rename under a writer"
    thread.join(5)
    assert result == [(1, 0)]
    assert entries(spool) == []
