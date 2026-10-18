import json

import pytest

from stationchief.server.otlp import any_value, attributes, iter_log_records, process_logs
from server_helpers import log_record, ocsf_event, otlp_payload


def test_any_value_decodes_every_otlp_type():
    assert any_value({"stringValue": "a"}) == "a"
    assert any_value({"intValue": "42"}) == 42, "int64 arrives as a JSON string"
    assert any_value({"intValue": 7}) == 7
    assert any_value({"doubleValue": 1.5}) == 1.5
    assert any_value({"boolValue": False}) is False
    assert any_value({"arrayValue": {"values": [{"stringValue": "x"}, {"intValue": "1"}]}}) == ["x", 1]
    assert any_value({"kvlistValue": {"values": [{"key": "k", "value": {"stringValue": "v"}}]}}) == {"k": "v"}
    assert any_value({}) is None
    assert any_value("not a dict") is None


def test_user_email_is_dropped_before_anything_sees_it():
    attrs = attributes([
        {"key": "user.email", "value": {"stringValue": "dev@example.com"}},
        {"key": "session.id", "value": {"stringValue": "s"}},
    ])
    assert attrs == {"session.id": "s"}


def test_iter_reads_name_time_resource_and_body():
    payload = otlp_payload([log_record("stationchief.ocsf", {"session.id": "s"}, body="{}", time_ms=1500)], resource={"host.name": "laptop"})
    (record,) = list(iter_log_records(payload))
    assert (record.name, record.time_ms, record.body) == ("stationchief.ocsf", 1500, "{}")
    assert record.resource == {"host.name": "laptop"}


def test_event_name_falls_back_to_the_otlp_event_name_field():
    payload = {"resourceLogs": [{"scopeLogs": [{"logRecords": [{"eventName": "codex.user_prompt", "attributes": []}]}]}]}
    assert [r.name for r in iter_log_records(payload)] == ["codex.user_prompt"]


def test_stationchief_events_pass_through(assert_valid_ocsf):
    event = ocsf_event()
    outcome = process_logs(otlp_payload([log_record("stationchief.ocsf", body=json.dumps(event))]))
    assert outcome.events == [event]
    assert (outcome.rejected, outcome.dropped) == (0, 0)
    assert outcome.response() == {}
    assert_valid_ocsf(outcome.events[0])


@pytest.mark.parametrize(
    "body, reason",
    [
        ("{not json", "not a JSON object"),
        ("[1, 2]", "not a JSON object"),
        (json.dumps({"metadata": {"uid": "u", "version": "1.9.0"}}), "class_uid"),
        (json.dumps({"class_uid": 1007, "metadata": {"version": "1.9.0"}}), "metadata.uid"),
        (json.dumps({"class_uid": 1007, "metadata": {"uid": "u", "version": "1.8.0"}}), "1.9.0"),
    ],
)
def test_malformed_stationchief_events_are_rejected_with_a_reason(body, reason):
    outcome = process_logs(otlp_payload([log_record("stationchief.ocsf", body=body)]))
    assert outcome.events == [] and outcome.rejected == 1
    assert reason in outcome.response()["partialSuccess"]["errorMessage"]


def test_unknown_event_names_are_dropped_not_rejected():
    outcome = process_logs(otlp_payload([log_record("claude_code.api_request"), log_record("something.else")]))
    assert (outcome.dropped, outcome.rejected) == (2, 0)
    assert outcome.response() == {}


def test_a_non_object_payload_is_rejected():
    assert process_logs([1, 2]).rejected == 1


def test_one_bad_record_does_not_fail_the_batch():
    good = log_record("stationchief.ocsf", body=json.dumps(ocsf_event()))
    bad = log_record("stationchief.ocsf", body="nope")
    outcome = process_logs(otlp_payload([good, bad]))
    assert len(outcome.events) == 1 and outcome.rejected == 1


def test_non_finite_numbers_do_not_fail_the_batch():
    # json.loads turns 1e999 and Infinity into float inf; int(inf) overflows.
    odd = log_record("stationchief.ocsf", body=json.dumps(ocsf_event(command="a")))
    odd["timeUnixNano"] = "__INF__"
    odd["attributes"].append({"key": "n", "value": {"intValue": "__INF__"}})
    good = log_record("stationchief.ocsf", body=json.dumps(ocsf_event(command="b")))
    text = json.dumps(otlp_payload([odd, good])).replace('"__INF__"', "1e999", 1).replace('"__INF__"', "Infinity")
    outcome = process_logs(json.loads(text))
    assert len(outcome.events) == 2 and outcome.rejected == 0


def test_every_event_of_a_finding_producing_record_is_stored():
    import dataclasses

    from stationchief.core.records import ActivityRecord
    from stationchief.core.redact import redact_record
    from stationchief.detect.rules import findings_for
    from stationchief.core.mapping import map_record
    from stationchief.server.store import MemoryStore
    from stationchief.core.records import Action, ActionKind, Actor, Decision

    record = ActivityRecord(
        source="claude", session_id="s", turn_id="t", ts=1789898400000, event="PreToolUse",
        actor=Actor(user_name="dev", agent_name="claude-code", agent_version="1"),
        cwd="/repo", hostname="h", posture={}, prompt="key AKIAIOSFODNN7EXAMPLE",
        action=Action(tool="Bash", kind=ActionKind.SHELL, input={"command": "rm -rf /"}),
        decision=Decision.OBSERVED,
    )
    cleaned, hits = redact_record(record)
    events = [*findings_for(cleaned, hits), map_record(cleaned)]
    assert len(events) == 3
    outcome = process_logs(otlp_payload([log_record("stationchief.ocsf", body=json.dumps(e)) for e in events]))
    store = MemoryStore()
    assert store.write(outcome.events, "p") == 3
    assert len(store.events()) == 3


def _without(key):
    event = ocsf_event()
    event.pop(key)
    return event


@pytest.mark.parametrize(
    "event, reason",
    [
        (_without("time"), "time"),
        ({**ocsf_event(), "time": True}, "time"),
        ({**ocsf_event(), "time": "1789898400000"}, "time"),
        ({**ocsf_event(), "metadata": {**ocsf_event()["metadata"], "correlation_uid": 42}}, "correlation_uid"),
        # Longer than any real id: rejected, never a 503 loop.
        ({**ocsf_event(), "metadata": {**ocsf_event()["metadata"], "correlation_uid": "s" * 257}}, "correlation_uid"),
        ({**ocsf_event(), "metadata": {**ocsf_event()["metadata"], "uid": "u" * 257}}, "metadata.uid"),
    ],
)
def test_unstorable_time_and_correlation_uid_are_rejected(event, reason):
    outcome = process_logs(otlp_payload([log_record("stationchief.ocsf", body=json.dumps(event))]))
    assert outcome.events == [] and outcome.rejected == 1
    assert reason in outcome.response()["partialSuccess"]["errorMessage"]


def test_an_event_without_correlation_uid_is_accepted():
    event = ocsf_event()
    event["metadata"].pop("correlation_uid")
    assert process_logs(otlp_payload([log_record("stationchief.ocsf", body=json.dumps(event))])).events == [event]
