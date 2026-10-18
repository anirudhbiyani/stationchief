import http.server
import json
import socketserver
import threading
import time

import pytest

from stationchief.adapters import claude, codex, cursor
from stationchief.check import ask, request_for
from stationchief.config import Config
from stationchief.core.records import Action, ActionKind, ActivityRecord, Actor, Decision
from stationchief.core.redact import redact_record

SECRET = "AKIAIOSFODNN7EXAMPLE"


class _LoopbackServer(http.server.ThreadingHTTPServer):
    def server_bind(self):
        # HTTPServer.server_bind does a reverse-DNS getfqdn(), which can take
        # tens of seconds on some networks. Loopback needs no name.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = "127.0.0.1", self.server_address[1]


class PolicyServer:
    """A real loopback HTTP server answering /check with a canned verdict."""

    def __init__(self, verdict):
        self.verdict, self.requests = verdict, []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.requests.append((self.path, dict(self.headers), body))
                reply = json.dumps(outer.verdict).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(reply)))
                self.end_headers()
                self.wfile.write(reply)

            def log_message(self, *args):
                pass

        self.server = _LoopbackServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def policy_server():
    servers = []

    def start(decision, reason="policy says so", policy="p1"):
        server = PolicyServer({"decision": decision, "reason": reason, "policy": policy})
        servers.append(server)
        return server

    yield start
    for server in servers:
        server.close()


def config(tmp_path, url=None, **overrides):
    return Config(home=tmp_path, detect=False, server_url=url, server_token="t0k" if url else None, **overrides)


PRE = {
    "claude": (claude, {"session_id": "s", "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "rm -rf build"}, "cwd": "/repo"}),
    "cursor": (cursor, {"conversation_id": "s", "hook_event_name": "preToolUse", "tool_name": "Shell", "tool_input": {"command": "rm -rf build"}, "workspace_roots": ["/repo"]}),
    "codex": (codex, {"session_id": "s", "hook_event_name": "PreToolUse", "tool_name": "shell", "tool_input": {"command": ["rm", "-rf", "build"]}, "cwd": "/repo"}),
}
POST_EVENT = {"claude": "PostToolUse", "cursor": "postToolUse", "codex": "PostToolUse"}


def is_deny(agent, response):
    if agent == "cursor":
        return response.get("permission") == "deny"
    return response.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"


def activity(home):
    return [json.loads(l) for p in home.glob("events-*.ndjson") for l in p.read_text().splitlines()]


def record(command=f"deploy {SECRET}"):
    return ActivityRecord(
        source="claude", session_id="s", turn_id=None, ts=1, event="PreToolUse",
        actor=Actor(user_name="dev", agent_name="claude-code", agent_version="2"),
        cwd="/repo", hostname="laptop", posture={"permission_mode": "default"},
        prompt=f"use {SECRET}", action=Action(tool="Bash", kind=ActionKind.SHELL, input={"command": command}),
        decision=Decision.OBSERVED,
    )


def test_no_server_configured_means_no_check(tmp_path):
    assert ask(record(), [], config(tmp_path)) is None


def test_request_carries_redacted_input_and_rule_names_but_never_the_prompt(tmp_path, policy_server):
    server = policy_server("allow")
    cleaned, hits = redact_record(record())
    verdict = ask(cleaned, hits, config(tmp_path, server.url))
    assert verdict.decision == "allow"
    path, headers, body = server.requests[0]
    assert path == "/check" and headers["Authorization"] == "Bearer t0k"
    assert SECRET not in json.dumps(body)
    assert body["redaction_rules"] == ["aws_access_key_id"]
    assert "prompt" not in body
    assert body == request_for(cleaned, hits).to_json()


@pytest.mark.parametrize("agent", sorted(PRE))
def test_deny_blocks_the_call_and_records_it(agent, tmp_path, policy_server, assert_valid_ocsf):
    module, payload = PRE[agent]
    response = module.handle(dict(payload), config(tmp_path, policy_server("deny", "no rm").url))
    assert is_deny(agent, response)
    (event,) = activity(tmp_path)
    assert (event["action_id"], event["disposition_id"]) == (2, 2)
    assert_valid_ocsf(event)


def test_deny_reason_reaches_the_agent(tmp_path, policy_server):
    module, payload = PRE["claude"]
    response = module.handle(dict(payload), config(tmp_path, policy_server("deny", "no rm").url))
    assert "no rm" in response["hookSpecificOutput"]["permissionDecisionReason"]


@pytest.mark.parametrize("agent, expected", [
    ("claude", lambda r: r["hookSpecificOutput"]["permissionDecision"] == "ask"),
    ("cursor", lambda r: r == {"permission": "ask", "user_message": "Blocked by stationchief policy: check with security"}),
    ("codex", lambda r: r == {}),
])
def test_ask_uses_each_agents_prompt(agent, expected, tmp_path, policy_server):
    module, payload = PRE[agent]
    response = module.handle(dict(payload), config(tmp_path, policy_server("ask", "check with security").url))
    assert expected(response)
    assert activity(tmp_path)[0]["action_id"] == 3


@pytest.mark.parametrize("agent", sorted(PRE))
def test_allow_is_the_normal_path(agent, tmp_path, policy_server):
    module, payload = PRE[agent]
    response = module.handle(dict(payload), config(tmp_path, policy_server("allow").url))
    assert not is_deny(agent, response)
    assert activity(tmp_path)[0]["action_id"] == 3


@pytest.mark.parametrize("agent", sorted(PRE))
def test_post_tool_events_are_never_checked(agent, tmp_path, policy_server):
    server = policy_server("deny")
    module, payload = PRE[agent]
    response = module.handle(dict(payload, hook_event_name=POST_EVENT[agent]), config(tmp_path, server.url))
    assert not is_deny(agent, response)
    assert server.requests == []


@pytest.mark.parametrize("agent", sorted(PRE))
def test_an_unreachable_server_fails_open_by_default(agent, tmp_path):
    module, payload = PRE[agent]
    response = module.handle(dict(payload), config(tmp_path, "http://127.0.0.1:9", check_timeout_ms=200))
    assert not is_deny(agent, response)
    assert "falling back to allow" in (tmp_path / "errors.log").read_text()


def test_fail_closed_denies_when_the_server_is_unreachable(tmp_path):
    module, payload = PRE["claude"]
    response = module.handle(dict(payload), config(tmp_path, "http://127.0.0.1:9", check_timeout_ms=200, fail_closed=True))
    assert is_deny("claude", response)
    assert "failing closed" in response["hookSpecificOutput"]["permissionDecisionReason"]


def test_a_garbage_verdict_is_treated_as_a_failure(tmp_path, policy_server):
    server = policy_server("maybe")
    cleaned, hits = redact_record(record("ls"))
    assert ask(cleaned, hits, config(tmp_path, server.url)).decision == "allow"


def test_the_check_is_redacted_even_when_local_redaction_is_off(tmp_path, policy_server):
    server = policy_server("allow")
    module, payload = PRE["claude"]
    module.handle(dict(payload, tool_input={"command": f"echo {SECRET}"}), config(tmp_path, server.url, redact=False))
    assert SECRET not in json.dumps(server.requests[0][2])


def test_ask_never_follows_a_redirect_with_the_bearer_token(tmp_path):
    """A (the configured server_url) answers /check with a 302 to B. A bearer
    token must never follow a redirect, so ask()'s default opener
    (stationchief.sinks.http.no_redirect_open) must refuse to follow it: B must never
    see the request, and ask() must fall back to the fail-open (or fail-closed)
    verdict exactly as it would for any other unreachable-server failure."""
    b_calls = []

    class BHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            b_calls.append(("GET", self.path, self.headers.get("Authorization")))
            self.send_response(200)
            self.end_headers()

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            b_calls.append(("POST", self.path, self.headers.get("Authorization")))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    b_server = http.server.HTTPServer(("127.0.0.1", 0), BHandler)
    b_server.timeout = 1
    b_port = b_server.server_port
    b_stop = threading.Event()

    def serve_b():
        while not b_stop.is_set():
            b_server.handle_request()

    b_thread = threading.Thread(target=serve_b, daemon=True)
    b_thread.start()

    class AHandler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{b_port}/check")
            self.end_headers()

        def log_message(self, *args):
            pass

    a_server = http.server.HTTPServer(("127.0.0.1", 0), AHandler)
    a_server.timeout = 1
    a_port = a_server.server_port
    a_stop = threading.Event()

    def serve_a():
        while not a_stop.is_set():
            a_server.handle_request()

    a_thread = threading.Thread(target=serve_a, daemon=True)
    a_thread.start()

    try:
        cfg = config(tmp_path, f"http://127.0.0.1:{a_port}")
        verdict = ask(record(), [], cfg)
        assert verdict is not None and verdict.decision == "allow"  # fail-open default
        assert b_calls == []

        cfg_closed = config(tmp_path, f"http://127.0.0.1:{a_port}", fail_closed=True)
        verdict_closed = ask(record(), [], cfg_closed)
        assert verdict_closed is not None and verdict_closed.decision == "deny"  # fail-closed when configured
        assert b_calls == []
    finally:
        a_stop.set()
        b_stop.set()
        a_thread.join(timeout=5)
        b_thread.join(timeout=5)
        a_server.server_close()
        b_server.server_close()


def _mock_deny(monkeypatch):
    from stationchief import check
    from stationchief.policy import Verdict

    monkeypatch.setattr(check, "ask", lambda *a, **k: Verdict(decision="deny", reason="nope"))


def test_a_non_string_url_still_returns_the_deny_and_emits(tmp_path, monkeypatch):
    _mock_deny(monkeypatch)
    payload = {"session_id": "s", "hook_event_name": "PreToolUse", "tool_name": "WebFetch", "tool_input": {"url": 12345}, "cwd": "/repo"}
    response = claude.handle(payload, config(tmp_path, "http://127.0.0.1:9"))
    assert is_deny("claude", response)
    (event,) = activity(tmp_path)
    assert event["http_request"]["url"]["url_string"] == "12345"


def test_a_deny_survives_an_emit_that_raises(tmp_path, monkeypatch):
    import stationchief.pipeline

    _mock_deny(monkeypatch)

    def boom(*args, **kwargs):
        raise RuntimeError("emit exploded")

    monkeypatch.setattr(stationchief.pipeline, "emit", boom)
    module, payload = PRE["claude"]
    assert is_deny("claude", module.handle(dict(payload), config(tmp_path, "http://127.0.0.1:9")))
    assert "emit exploded" in (tmp_path / "errors.log").read_text()


def test_a_map_record_failure_is_logged_not_raised(tmp_path, monkeypatch):
    import stationchief.pipeline

    def boom(record):
        raise RuntimeError("mapping exploded")

    monkeypatch.setattr(stationchief.pipeline, "map_record", boom)
    events = stationchief.pipeline.emit(record("ls"), config(tmp_path))
    assert events == []
    assert "mapping exploded" in (tmp_path / "errors.log").read_text()


def test_non_string_file_paths_map_without_raising(assert_valid_ocsf):
    from stationchief.core.mapping import map_record

    rec = ActivityRecord(
        source="claude", session_id="s", turn_id=None, ts=1, event="PreToolUse",
        actor=Actor(user_name="dev", agent_name="claude-code", agent_version="2"),
        cwd="/repo", hostname="laptop", posture={}, prompt=None,
        action=Action(tool="Read", kind=ActionKind.FILE_READ, input={"file_path": 123}),
        decision=Decision.OBSERVED,
    )
    event = map_record(rec)
    assert event["file"]["path"] == "123"
    assert_valid_ocsf(event)


@pytest.mark.parametrize("agent", ["cursor", "codex"])
def test_a_mark_seen_failure_never_skips_the_check_or_the_event(agent, tmp_path, monkeypatch):
    from stationchief import state

    _mock_deny(monkeypatch)

    def boom(*args, **kwargs):
        raise OSError("seen dir unwritable")

    monkeypatch.setattr(state, "mark_seen", boom)
    module, payload = PRE[agent]
    payload = {**payload, "tool_call_id": "call-1"}
    assert is_deny(agent, module.handle(payload, config(tmp_path, "http://127.0.0.1:9")))
    assert len(activity(tmp_path)) == 1
    assert "seen dir unwritable" in (tmp_path / "errors.log").read_text()


def test_redaction_rules_come_only_from_tool_input_and_never_name_email():
    import dataclasses

    with_email = dataclasses.replace(record("ls"), prompt="mail dev@example.com the AKIAIOSFODNN7EXAMPLE key")
    cleaned, hits = redact_record(with_email)
    assert request_for(cleaned, hits).redaction_rules == ()

    emailed_input = record("git log --author dev@example.com")
    cleaned, hits = redact_record(emailed_input)
    assert request_for(cleaned, hits).redaction_rules == ()

    cleaned, hits = redact_record(record(f"deploy {SECRET}"))
    assert request_for(cleaned, hits).redaction_rules == ("aws_access_key_id",)


def test_a_server_trickling_bytes_cannot_hold_the_hook_past_the_deadline(tmp_path):
    """urlopen's timeout is per socket operation; a byte every 50 ms never
    trips it. check_timeout_ms must still bound the whole request."""
    stop = threading.Event()

    class Trickle(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(200)
            self.send_header("Content-Length", "1000")
            self.end_headers()
            while not stop.wait(0.05):
                try:
                    self.wfile.write(b" ")
                    self.wfile.flush()
                except OSError:
                    return

        def log_message(self, *args):
            pass

    server = _LoopbackServer(("127.0.0.1", 0), Trickle)
    threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{server.server_port}"
        started = time.monotonic()
        verdict = ask(record("ls"), [], config(tmp_path, url, check_timeout_ms=300, fail_closed=True))
        assert time.monotonic() - started < 1.0
        assert verdict.decision == "deny"
    finally:
        stop.set()
        server.shutdown()
        server.server_close()


def test_ask_to_a_loopback_server_bypasses_http_proxy(tmp_path, monkeypatch):
    from stationchief.sinks import http

    used = []

    def fake_open(request, timeout):
        used.append(request.full_url)
        raise OSError("stop here")

    monkeypatch.setattr(http, "loopback_open", fake_open)
    ask(record(), [], config(tmp_path, url="http://127.0.0.1:1"))
    assert used == ["http://127.0.0.1:1/check"]
