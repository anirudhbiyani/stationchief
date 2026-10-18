import http.server
import json
import threading
import urllib.error
import urllib.request

import pytest

from stationchief.sinks.http import HttpSink

EVENTS = [{"class_uid": 1007, "time": 1758326400000}, {"class_uid": 1001, "time": 1758326401000}]


class Recorder:
    """Stands in for urllib.request.urlopen and keeps the request it was given."""

    def __init__(self):
        self.request = None
        self.timeout = None

    def __call__(self, request, timeout):
        self.request, self.timeout = request, timeout

        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        return Response()


def test_generic_endpoint_receives_ndjson_with_a_bearer_token():
    opener = Recorder()
    HttpSink("https://logs.example.com/ingest", token="t0k", opener=opener).write(EVENTS)
    body = opener.request.data.decode()
    assert [json.loads(line)["class_uid"] for line in body.splitlines()] == [1007, 1001]
    assert opener.request.get_header("Content-type") == "application/x-ndjson"
    assert opener.request.get_header("Authorization") == "Bearer t0k"
    assert opener.request.get_method() == "POST"


def test_hec_endpoint_gets_hec_envelopes_and_a_splunk_token():
    opener = Recorder()
    HttpSink("https://splunk.example.com:8088/services/collector/event", token="t0k", opener=opener).write(EVENTS)
    envelopes = [json.loads(line) for line in opener.request.data.decode().splitlines()]
    assert envelopes[0] == {"event": EVENTS[0], "sourcetype": "ocsf", "time": 1758326400.0}
    assert opener.request.get_header("Authorization") == "Splunk t0k"


def test_no_token_sends_no_authorization_header():
    opener = Recorder()
    HttpSink("https://logs.example.com/ingest", opener=opener).write(EVENTS)
    assert opener.request.get_header("Authorization") is None


def test_timeout_is_short_because_this_runs_in_the_hook():
    opener = Recorder()
    HttpSink("https://logs.example.com/ingest", opener=opener).write(EVENTS)
    assert opener.timeout <= 2


def test_empty_write_sends_nothing():
    opener = Recorder()
    HttpSink("https://logs.example.com/ingest", opener=opener).write([])
    assert opener.request is None


@pytest.mark.parametrize("url", ["http://logs.example.com/ingest", "ftp://x/y", "logs.example.com"])
def test_refuses_to_send_prompts_in_plaintext(url):
    with pytest.raises(ValueError, match="refusing"):
        HttpSink(url)


def test_plain_http_to_loopback_is_allowed_for_local_collectors():
    HttpSink("http://127.0.0.1:8088/services/collector")
    HttpSink("http://localhost:9000/ingest")


def test_end_to_end_against_a_real_local_server():
    received = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            received.append(self.rfile.read(int(self.headers["Content-Length"])))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    server.timeout = 1
    thread = threading.Thread(target=server.handle_request, daemon=True)
    try:
        thread.start()
        HttpSink(f"http://127.0.0.1:{server.server_port}/ingest").write(EVENTS)
        thread.join(timeout=5)
        assert len(received[0].decode().splitlines()) == 2
    finally:
        server.server_close()


def test_redirects_are_refused_and_token_never_leaks_to_a_different_server():
    """_NoRedirect prevents redirect-based token leakage to a different server."""
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

        with pytest.raises(urllib.error.HTTPError) as excinfo:
            HttpSink(f"http://127.0.0.1:{server_a.server_port}/ingest", token="t0k").write(EVENTS)

        # Verify the error is the 302, not a later error
        assert excinfo.value.code == 302

        thread_a.join(timeout=5)
        thread_b.join(timeout=5)

        # Verify server B never received the redirect request (token is safe)
        assert server_b_received == [], "token must not reach the redirect target"
    finally:
        server_a.server_close()
        server_b.server_close()


def test_default_urllib_would_leak_token_on_redirect():
    """Demonstrates the exact leak `_NoRedirect` prevents: with the real, unguarded
    urllib opener, a 302 from the configured collector is followed and the bearer
    token is sent to whatever server the redirect names."""
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

        # The real default urllib opener, which follows redirects.
        HttpSink(
            f"http://127.0.0.1:{server_a.server_port}/ingest",
            token="t0k",
            opener=urllib.request.urlopen,
        ).write(EVENTS)

        thread_a.join(timeout=5)
        thread_b.join(timeout=5)

        assert len(server_b_received) == 1, "the redirect target must receive exactly one request"
        _, _, auth = server_b_received[0]
        assert auth == "Bearer t0k", "the bearer token leaked to the redirect target"
    finally:
        server_a.server_close()
        server_b.server_close()


def test_hec_path_must_be_exact():
    """HEC detection requires exact path match or path/..., not prefix match."""
    opener = Recorder()
    # /services/collectorx is generic, not HEC
    HttpSink("https://splunk.example.com/services/collectorx", token="t0k", opener=opener).write(EVENTS)
    assert opener.request.get_header("Authorization") == "Bearer t0k"
    assert opener.request.get_header("Content-type") == "application/x-ndjson"


def test_the_http_sink_is_refused_when_redaction_is_off(tmp_path):
    # Like the server sink: raw events never leave this machine.
    from stationchief.config import Config
    from stationchief.pipeline import build_sinks

    config = Config(home=tmp_path, redact=False, sinks=("http", "ndjson"), http_url="https://siem.example.com/ingest")
    assert [type(s).__name__ for s in build_sinks(config)] == ["NdjsonSink"]
    assert "redact is false" in (tmp_path / "errors.log").read_text()


def test_the_http_sink_is_built_when_redaction_is_on(tmp_path):
    from stationchief.config import Config
    from stationchief.pipeline import build_sinks

    config = Config(home=tmp_path, sinks=("http",), http_url="https://siem.example.com/ingest")
    assert [type(s).__name__ for s in build_sinks(config)] == ["HttpSink"]


def test_a_slow_server_cannot_hold_the_hook_past_the_deadline(monkeypatch):
    import time

    import stationchief.sinks.http as http_sink

    monkeypatch.setattr(http_sink, "TIMEOUT_SECONDS", 0.2)
    release = threading.Event()

    def trickling(request, timeout):  # every socket read is fast; the whole is not
        release.wait(5)
        return Recorder()(request, timeout)

    started = time.monotonic()
    try:
        with pytest.raises(TimeoutError):
            HttpSink("https://logs.example.com/ingest", opener=trickling).write(EVENTS)
        assert time.monotonic() - started < 1
    finally:
        release.set()


def test_loopback_requests_bypass_http_proxy():
    """urllib reads http_proxy when the opener is built (at import), so the
    sink runs in a child process started with the proxy variable set."""
    import os
    import subprocess
    import sys

    received = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            received.append(self.rfile.read(int(self.headers["Content-Length"])))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    server.timeout = 5
    thread = threading.Thread(target=server.handle_request, daemon=True)
    env = {k: v for k, v in os.environ.items() if k.lower() != "no_proxy"}
    env["http_proxy"] = "http://127.0.0.1:9"  # nothing listens there
    code = (
        "from stationchief.sinks.http import HttpSink; "
        f"HttpSink('http://127.0.0.1:{server.server_port}/ingest', token='t0k').write([{{}}])"
    )
    try:
        thread.start()
        subprocess.run([sys.executable, "-c", code], env=env, check=True, timeout=10,
                       cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        thread.join(timeout=5)
        assert received
    finally:
        server.server_close()
