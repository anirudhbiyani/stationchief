import json

import pytest

pytest.importorskip("starlette")
from starlette.testclient import TestClient

from stationchief.server.app import create_app
from stationchief.server.store import EventRejected, MemoryStore
from server_helpers import AUTH, PRINCIPAL, log_record, ocsf_event, otlp_payload, server_config


@pytest.fixture
def store():
    return MemoryStore()


@pytest.fixture
def client(store):
    return TestClient(create_app(server_config(), store))


def post(client, records):
    return client.post("/otel/v1/logs", json=otlp_payload(records), headers=AUTH)


def test_stores_stationchief_events_with_the_principal(client, store):
    event = ocsf_event()
    response = post(client, [log_record("stationchief.ocsf", body=json.dumps(event))])
    assert response.status_code == 200 and response.json() == {}
    assert store.rows[(PRINCIPAL, event["metadata"]["uid"])] == (PRINCIPAL, event)


def test_a_retried_batch_is_not_stored_twice(client, store):
    records = [log_record("stationchief.ocsf", body=json.dumps(ocsf_event()))]
    post(client, records)
    post(client, records)
    assert len(store.rows) == 1


def test_partial_success_reports_rejections(client, store):
    response = post(client, [log_record("stationchief.ocsf", body="{bad"), log_record("stationchief.ocsf", body=json.dumps(ocsf_event()))])
    assert response.status_code == 200
    assert response.json()["partialSuccess"]["rejectedLogRecords"] == 1
    assert len(store.rows) == 1


def test_protobuf_is_refused_with_a_hint(client):
    response = client.post("/otel/v1/logs", content=b"\x0a\x00", headers={**AUTH, "Content-Type": "application/x-protobuf"})
    assert response.status_code == 415
    assert "http/json" in response.json()["error"]


def test_invalid_json_is_a_400(client):
    response = client.post("/otel/v1/logs", content=b"{nope", headers={**AUTH, "Content-Type": "application/json"})
    assert response.status_code == 400


def test_bodies_over_the_limit_are_a_413(store):
    client = TestClient(create_app(server_config(max_body_bytes=1024), store))
    records = [log_record("stationchief.ocsf", body=json.dumps(ocsf_event()))]
    response = client.post("/otel/v1/logs", json=otlp_payload(records * 10), headers=AUTH)
    assert response.status_code == 413
    assert store.rows == {}


def test_gzip_bodies_are_accepted_with_the_limit_on_the_decompressed_size(store):
    import gzip

    body = json.dumps(otlp_payload([log_record("stationchief.ocsf", body=json.dumps(ocsf_event()))])).encode()
    client = TestClient(create_app(server_config(max_body_bytes=len(body)), store))

    def send(content, encoding="gzip"):
        headers = {**AUTH, "Content-Type": "application/json", "Content-Encoding": encoding}
        return client.post("/otel/v1/logs", content=content, headers=headers)

    assert send(gzip.compress(body)).status_code == 200
    assert len(store.rows) == 1
    assert send(gzip.compress(body + b" ")).status_code == 413  # small on the wire, too big unpacked
    assert send(b"not gzip").status_code == 400
    assert send(body, encoding="br").status_code == 415


def _lenient_client(store, **overrides):
    """A malformed-envelope request must never crash the endpoint (500).
    raise_server_exceptions=False makes that assertion checkable: an
    unhandled exception would otherwise surface as a Python exception in
    the test rather than as a response we can inspect."""
    return TestClient(create_app(server_config(**overrides), store), raise_server_exceptions=False)


def test_a_non_dict_resource_container_does_not_crash(store):
    client = _lenient_client(store)
    payload = {"resourceLogs": [{"resource": "oops", "scopeLogs": []}]}
    response = client.post("/otel/v1/logs", json=payload, headers=AUTH)
    assert response.status_code == 200
    assert response.json() == {}
    assert store.rows == {}


def test_non_dict_scope_and_record_entries_do_not_crash(store):
    client = _lenient_client(store)
    payload = {"resourceLogs": [{"scopeLogs": ["oops", {"logRecords": ["oops"]}]}]}
    response = client.post("/otel/v1/logs", json=payload, headers=AUTH)
    assert response.status_code != 500
    assert store.rows == {}


def test_non_list_resource_logs_does_not_crash(store):
    client = _lenient_client(store)
    payload = {"resourceLogs": "oops"}
    response = client.post("/otel/v1/logs", json=payload, headers=AUTH)
    assert response.status_code != 500
    assert store.rows == {}


def _nested_array_value(depth, leaf):
    """Build an OTLP AnyValue nested `depth` arrayValue levels deep, bottom
    up (no Python recursion), to reproduce a hostile/broken exporter."""
    value = leaf
    for _ in range(depth):
        value = {"arrayValue": {"values": [value]}}
    return value


def test_a_deeply_nested_attribute_does_not_crash_and_the_record_is_still_stored(store):
    client = _lenient_client(store)
    event = ocsf_event()
    record = log_record("stationchief.ocsf", body=json.dumps(event))
    record["attributes"].append({"key": "deep", "value": _nested_array_value(3000, {"stringValue": "leaf"})})
    response = client.post("/otel/v1/logs", json=otlp_payload([record]), headers=AUTH)
    assert response.status_code != 500
    assert store.rows[(PRINCIPAL, event["metadata"]["uid"])] == (PRINCIPAL, event)


def test_an_unexpected_process_logs_failure_is_a_400_that_does_not_leak_details(store, monkeypatch):
    client = _lenient_client(store)

    def raiser(*args, **kwargs):
        raise RuntimeError("secret detail")

    monkeypatch.setattr("stationchief.server.app.process_logs", raiser)
    response = post(client, [log_record("stationchief.ocsf", body=json.dumps(ocsf_event()))])
    assert response.status_code == 400
    assert "secret detail" not in response.text
    assert store.rows == {}


def test_process_logs_runs_off_the_event_loop(client, store, monkeypatch):
    # CPU-bound native mapping on the loop would stall concurrent /check calls.
    import asyncio

    from stationchief.server import otlp

    def off_loop(*args, **kwargs):
        with pytest.raises(RuntimeError):
            asyncio.get_running_loop()
        return otlp.process_logs(*args, **kwargs)

    monkeypatch.setattr("stationchief.server.app.process_logs", off_loop)
    assert post(client, [log_record("stationchief.ocsf", body=json.dumps(ocsf_event()))]).status_code == 200
    assert len(store.rows) == 1


class PickyStore(MemoryStore):
    """Rejects one event, as the store would reject an unstorable event."""

    def __init__(self, bad_uids=(), down=False):
        super().__init__()
        self.bad_uids, self.down = set(bad_uids), down

    def write(self, events, principal):
        if self.down:
            raise RuntimeError("connection failed: secret detail")
        if any(e["metadata"]["uid"] in self.bad_uids for e in events):
            raise EventRejected("insert failed: secret detail")
        return super().write(events, principal)


def test_one_unstorable_event_is_rejected_and_the_rest_are_stored():
    good, bad = ocsf_event(command="a"), ocsf_event(command="b")
    store = PickyStore(bad_uids={bad["metadata"]["uid"]})
    client = TestClient(create_app(server_config(), store))
    response = post(client, [log_record("stationchief.ocsf", body=json.dumps(e)) for e in (good, bad)])
    assert response.status_code == 200
    partial = response.json()["partialSuccess"]
    assert partial["rejectedLogRecords"] == 1
    assert "secret detail" not in response.text
    assert store.events() == [good]


def test_a_store_that_rejects_everything_is_a_503_so_the_client_keeps_its_spool():
    client = TestClient(create_app(server_config(), PickyStore(down=True)), raise_server_exceptions=False)
    response = post(client, [log_record("stationchief.ocsf", body=json.dumps(ocsf_event()))])
    assert response.status_code == 503
    assert "secret detail" not in response.text


def test_a_single_unstorable_event_is_a_200_rejection_not_a_503():
    # A 503 would keep the event in the client's spool and resend it forever.
    event = ocsf_event()
    store = PickyStore(bad_uids={event["metadata"]["uid"]})
    client = TestClient(create_app(server_config(), store))
    response = post(client, [log_record("stationchief.ocsf", body=json.dumps(event))])
    assert response.status_code == 200
    assert response.json()["partialSuccess"]["rejectedLogRecords"] == 1
    assert "secret detail" not in response.text
    assert store.rows == {}


def test_an_outage_mid_retry_is_a_503_and_stops_retrying():
    # A 200 here would drop the unstored events from the client's spool.
    class Blip(MemoryStore):
        """The batch fails, the first single write succeeds, then the db drops."""

        def __init__(self):
            super().__init__()
            self.calls = 0

        def write(self, events, principal):
            self.calls += 1
            if len(events) > 1 or self.calls > 2:
                raise ConnectionError("db gone")
            return super().write(events, principal)

    store = Blip()
    client = TestClient(create_app(server_config(), store))
    events = [ocsf_event(command=c) for c in "abc"]
    response = post(client, [log_record("stationchief.ocsf", body=json.dumps(e)) for e in events])
    assert response.status_code == 503
    assert store.calls == 3  # batch, a (stored), b (outage); c never tried
    assert store.events() == [events[0]]


DEEP =b'{"resourceLogs": ' + b"[" * 200_000 + b"]" * 200_000 + b"}"


def test_a_body_nested_too_deep_to_parse_is_a_400_not_a_500(store):
    client = TestClient(create_app(server_config(), store), raise_server_exceptions=False)
    response = client.post(
        "/otel/v1/logs", content=DEEP, headers={**AUTH, "Content-Type": "application/json"}
    )
    assert response.status_code == 400
    assert store.rows == {}
