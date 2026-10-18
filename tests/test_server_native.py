import json
import pathlib

import pytest

from stationchief.core.records import ActionKind
from stationchief.server.native import NativeMapper
from stationchief.server.otlp import iter_log_records, process_logs
from server_helpers import log_record, otlp_payload

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "otel"
SECRET = "AKIAIOSFODNN7EXAMPLE"


def load(name):
    return json.loads((FIXTURES / f"{name}_export.json").read_text())


def activity(events):
    return [e for e in events if e["class_uid"] != 2004]


def test_claude_export_maps_decision_and_result(assert_valid_ocsf):
    outcome = process_logs(load("claude_code"), native=NativeMapper())
    assert outcome.dropped == 1, "api_request is not an activity"
    assert outcome.rejected == 0
    decision, result = activity(outcome.events)
    assert (decision["class_uid"], decision["action_id"], decision["disposition_id"]) == (1007, 1, 8)
    assert result["process"]["cmd_line"] == "ls -la"
    assert result["status_id"] == 1
    assert result["metadata"]["correlation_uid"] == "sess-native"
    assert result["device"]["hostname"] == "laptop"
    assert result["enrichments"][0]["data"]["capture"] == "otel-native"
    for event in outcome.events:
        assert_valid_ocsf(event)


def test_real_claude_code_export_is_mapped(assert_valid_ocsf):
    """Captured from Claude Code 2.1.296 (identity replaced): event.name is
    unqualified ("tool_result") and the qualified name is the body."""
    outcome = process_logs(load("claude_code_real"), native=NativeMapper())
    assert outcome.dropped == 0 and outcome.rejected == 0
    events = activity(outcome.events)
    assert len(events) == 2
    assert {e["process"]["cmd_line"] for e in events} == {"echo stationchief-pov"}
    assert events[-1]["message_context"]["prompt_text"].startswith("Run the shell command")
    for event in outcome.events:
        assert "dev@example.com" not in json.dumps(event)
        assert_valid_ocsf(event)


def test_real_codex_export_is_mapped(assert_valid_ocsf):
    """Captured from Codex 0.158 (ids replaced): qualified event names, and
    the shell command under arguments.cmd."""
    outcome = process_logs(load("codex_real"), native=NativeMapper())
    assert outcome.rejected == 0
    commands = [e["process"]["cmd_line"] for e in activity(outcome.events) if e["process"]["cmd_line"]]
    assert commands == ["echo stationchief-codex-ok"]
    for event in outcome.events:
        assert "dev@example.com" not in json.dumps(event)
        assert_valid_ocsf(event)


def test_prompts_attach_to_later_tool_events_redacted():
    outcome = process_logs(load("claude_code"), native=NativeMapper())
    result = activity(outcome.events)[-1]
    assert result["message_context"]["prompt_text"].startswith("deploy with")
    assert SECRET not in json.dumps(outcome.events)


def test_secret_in_a_native_prompt_raises_a_finding():
    outcome = process_logs(load("claude_code"), native=NativeMapper())
    findings = [e for e in outcome.events if e["class_uid"] == 2004]
    assert findings and all(f["finding_info"]["title"] == "Secret material present in prompt" for f in findings)


def test_user_email_never_reaches_an_event():
    outcome = process_logs(load("claude_code"), native=NativeMapper())
    assert "dev@example.com" not in json.dumps(outcome.events)


def test_codex_export_maps_posture_denial_and_failure(assert_valid_ocsf):
    outcome = process_logs(load("codex"), native=NativeMapper())
    decision, result = activity(outcome.events)
    assert (decision["action_id"], decision["disposition_id"]) == (2, 2)
    assert result["process"]["cmd_line"] == "bash -lc ls"
    assert result["status_id"] == 2
    posture = result["enrichments"][0]["data"]
    assert (posture["sandbox"], posture["approval_policy"]) == ("workspace-write", "on-request")
    assert posture["tool_call_id"] == "call_2"
    assert result["message_context"]["prompt_text"] == "list the files"
    for event in outcome.events:
        assert_valid_ocsf(event)


def test_config_approvals_are_observed_not_user_allowed():
    mapper = NativeMapper()
    payload = load("claude_code")
    records = payload["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
    for attr in records[1]["attributes"]:
        if attr["key"] == "source":
            attr["value"]["stringValue"] = "config"
    decision = activity(process_logs(payload, native=mapper).events)[0]
    assert decision["action_id"] == 3


def test_tool_kind_uses_the_adapters_classifier():
    mapper = NativeMapper()
    (record,) = [r for r in iter_log_records(load("codex")) if r.name == "codex.tool_result"]
    events = mapper.map(record)
    assert activity(events)[0]["class_uid"] == 1007
    assert ActionKind.SHELL == "shell"


def test_session_cache_is_bounded():
    mapper = NativeMapper(cache_size=2)
    for session in ("a", "b", "c"):
        mapper._session(session)
    assert list(mapper._sessions) == ["b", "c"]


def test_a_mapper_error_rejects_one_record_not_the_batch(monkeypatch):
    # S2 hardening: exception text (e.g. "boom") must never reach the client;
    # only the static "<record.name>: could not be mapped" is client-visible,
    # while the real exception is logged server-side via log.exception.
    mapper = NativeMapper()
    monkeypatch.setattr(mapper, "_tool_events", lambda *a: (_ for _ in ()).throw(RuntimeError("boom")))
    outcome = process_logs(load("codex"), native=mapper)
    assert outcome.rejected == 2
    error_message = outcome.response()["partialSuccess"]["errorMessage"]
    assert "boom" not in error_message
    assert "could not be mapped" in error_message


def test_prompt_cache_is_isolated_per_principal():
    """A session id is only unique per authenticated caller. Principal A's
    cached prompt for session "shared-session" must never attach to
    principal B's tool event for the same session id."""
    mapper = NativeMapper()
    prompt_payload = otlp_payload(
        [log_record("claude_code.user_prompt", {"session.id": "shared-session", "prompt": "alpha secret plan"})]
    )
    process_logs(prompt_payload, native=mapper, principal="alice")

    decision_payload = otlp_payload(
        [
            log_record(
                "claude_code.tool_decision",
                {
                    "session.id": "shared-session",
                    "tool_name": "Bash",
                    "decision": "accept",
                    "source": "user_temporary",
                },
            )
        ]
    )
    outcome = process_logs(decision_payload, native=mapper, principal="bob")
    result = activity(outcome.events)[0]
    assert "alpha" not in json.dumps(result)
    assert result.get("message_context", {}).get("prompt_text") is None


def test_user_account_uuid_is_dropped_and_actor_is_the_principal():
    """user.account_uuid never reaches a mapper or a stored event; the only
    identity that lands in actor.user.name is the authenticated principal."""
    mapper = NativeMapper()
    payload = otlp_payload(
        [
            log_record(
                "codex.tool_result",
                {
                    "conversation.id": "conv-x",
                    "tool_name": "shell",
                    "call_id": "call_9",
                    "arguments": json.dumps({"command": ["ls"]}),
                    "success": "true",
                    "user.account_uuid": "acct-123",
                },
            )
        ]
    )
    outcome = process_logs(payload, native=mapper, principal="carol")
    result = activity(outcome.events)[0]
    assert "acct-123" not in json.dumps(outcome.events)
    assert result["actor"]["user"]["name"] == "carol"
