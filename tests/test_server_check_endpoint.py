import pytest

pytest.importorskip("starlette")
from starlette.testclient import TestClient

from stationchief.policy import Verdict
from stationchief.server.app import create_app
from stationchief.server.store import MemoryStore
from server_helpers import AUTH, PRINCIPAL, server_config
from test_server_check import REQUEST


class Fixed:
    def __init__(self, verdict):
        self.verdict, self.seen = verdict, []

    def decide(self, request, principal=None):
        self.seen.append(request)
        self.principal = principal
        return self.verdict


class Broken:
    def decide(self, request, principal=None):
        raise RuntimeError("engine down")


def make(engine=None, **config):
    store = MemoryStore()
    return TestClient(create_app(server_config(**config), store, engine)), store


def test_default_engine_allows_and_records_the_decision(assert_valid_ocsf):
    client, store = make()
    response = client.post("/check", json=REQUEST, headers=AUTH)
    assert response.status_code == 200
    assert response.json() == {"decision": "allow", "reason": "no policy configured", "policy": None}
    ((principal, event),) = store.rows.values()
    assert principal == PRINCIPAL
    assert_valid_ocsf(event)


def test_engine_verdicts_are_returned_and_denies_recorded_as_blocked():
    engine = Fixed(Verdict("deny", "rm -rf is not allowed", "no-rm"))
    client, store = make(engine)
    response = client.post("/check", json=REQUEST, headers=AUTH)
    assert response.json() == {"decision": "deny", "reason": "rm -rf is not allowed", "policy": "no-rm"}
    assert engine.seen[0].tool == "Bash"
    assert engine.principal == PRINCIPAL  # the authenticated caller, not the claimed user
    (_, event), = store.rows.values()
    assert (event["action_id"], event["disposition_id"]) == (2, 2)


def test_invalid_requests_are_a_400_and_never_reach_the_engine():
    engine = Fixed(Verdict("allow"))
    client, store = make(engine)
    response = client.post("/check", json={**REQUEST, "kind": "teleport"}, headers=AUTH)
    assert response.status_code == 400 and "unknown kind" in response.json()["error"]
    assert engine.seen == [] and store.rows == {}


@pytest.mark.parametrize("fallback", ["allow", "deny"])
def test_engine_errors_answer_the_configured_fallback(fallback):
    client, _ = make(Broken(), on_engine_error=fallback)
    response = client.post("/check", json=REQUEST, headers=AUTH)
    assert response.status_code == 200
    assert response.json()["decision"] == fallback


def test_an_engine_returning_garbage_is_an_engine_error():
    client, _ = make(Fixed({"decision": "deny"}), on_engine_error="deny")
    assert client.post("/check", json=REQUEST, headers=AUTH).json()["decision"] == "deny"


def test_a_store_failure_does_not_change_the_answer():
    class FailingStore:
        def write(self, events, principal):
            raise RuntimeError("db down")

    client = TestClient(create_app(server_config(), FailingStore(), Fixed(Verdict("deny", "no", "p"))))
    assert client.post("/check", json=REQUEST, headers=AUTH).json()["decision"] == "deny"


def test_the_verdict_is_sent_before_a_slow_audit_write_finishes():
    # A slow database must not delay /check past the client's timeout (a
    # deny would fail open). Drive the ASGI app directly and time the reply:
    # TestClient waits for background tasks, a real server does not.
    import json
    import time

    import anyio

    class SlowStore(MemoryStore):
        def write(self, events, principal):
            time.sleep(2)
            return super().write(events, principal)

    store = SlowStore()
    app = create_app(server_config(), store, Fixed(Verdict("deny", "no", "p")))
    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST", "scheme": "http",
        "path": "/check", "raw_path": b"/check", "query_string": b"", "root_path": "",
        "client": ("127.0.0.1", 1), "server": ("testserver", 80),
        "headers": [(b"authorization", AUTH["Authorization"].encode()), (b"content-type", b"application/json")],
    }
    messages = [{"type": "http.request", "body": json.dumps(REQUEST).encode(), "more_body": False}]
    reply = {"body": b""}

    async def receive():
        if messages:
            return messages.pop()
        await anyio.sleep(10)  # the client stays connected

    async def send(message):
        if message["type"] == "http.response.body" and "at" not in reply:
            reply["body"] += message.get("body", b"")
            if not message.get("more_body"):
                reply["at"] = time.monotonic()

    start = time.monotonic()
    anyio.run(app, scope, receive, send)
    assert json.loads(reply["body"])["decision"] == "deny"
    assert reply["at"] - start < 0.3
    assert len(store.rows) == 1  # still recorded, just after the answer


def test_non_object_json_body_is_a_400():
    client, store = make()
    response = client.post("/check", content=b"[1, 2, 3]", headers={**AUTH, "content-type": "application/json"})
    assert response.status_code == 400
    assert "error" in response.json()
    assert store.rows == {}


def test_input_not_an_object_is_a_400():
    client, store = make()
    response = client.post("/check", json={**REQUEST, "input": "not-an-object"}, headers=AUTH)
    assert response.status_code == 400
    assert "input must be an object" in response.json()["error"]
    assert store.rows == {}


def _nest(depth, leaf):
    value = leaf
    for _ in range(depth):
        value = {"child": value}
    return value


def test_a_deeply_nested_input_is_still_a_valid_decision_not_a_500():
    client, store = make()
    # mcp_call is the one action kind whose mapper carries the whole
    # (redacted) input dict into the stored event, so the too-deep marker is
    # observable in what actually gets persisted, not just in an internal
    # object this test can't otherwise see.
    body = {**REQUEST, "kind": "mcp_call", "input": {"tree": _nest(3000, "leaf")}}
    response = client.post("/check", json=body, headers=AUTH)
    assert response.status_code == 200
    assert response.json()["decision"] == "allow"
    ((_, event),) = store.rows.values()
    dumped = str(event)
    assert "[REDACTED:too_deep]" in dumped
    assert "leaf" not in dumped


def test_an_opa_failure_answers_the_fallback_and_is_still_recorded():
    from stationchief.server.policy import OpaEngine
    from test_server_policy import FakeOpa

    client, store = make(OpaEngine(opener=FakeOpa({})), on_engine_error="deny")
    response = client.post("/check", json=REQUEST, headers=AUTH)
    assert response.json() == {"decision": "deny", "reason": "policy engine error", "policy": None}
    assert len(store.rows) == 1


def test_the_configured_engine_is_used_when_none_is_passed():
    config = server_config(engine={"type": "opa", "url": "http://127.0.0.1:9", "timeout_ms": 50})
    client = TestClient(create_app(config, MemoryStore()))
    # Nothing listens on port 9: the OPA call fails and the fallback answers.
    assert client.post("/check", json=REQUEST, headers=AUTH).json()["reason"] == "policy engine error"


def test_a_check_body_nested_too_deep_to_parse_is_a_400_not_a_500():
    import json as _json

    client, store = make()
    client = TestClient(client.app, raise_server_exceptions=False)
    prefix = _json.dumps({**REQUEST, "input": None})[:-1]  # drop the closing brace
    body = prefix.replace('"input": null', '"input": {"x": ' + "[" * 200_000 + "]" * 200_000 + "}")
    response = client.post("/check", content=body + "}", headers={**AUTH, "Content-Type": "application/json"})
    assert response.status_code == 400
    assert store.rows == {}
