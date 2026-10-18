from stationchief.core import ocsf
from stationchief.core.records import Action, ActionKind, ActivityRecord, Actor, Decision


def make_record(**overrides):
    fields = {
        "source": "claude",
        "session_id": "sess-abc",
        "turn_id": "turn-1",
        "ts": 1758326400000,
        "event": "PreToolUse",
        "actor": Actor(
            user_name="dev",
            agent_name="claude-code",
            agent_version="2.0.1",
            model="claude-opus-5",
            model_provider="Anthropic",
            pid=4242,
        ),
        "cwd": "/repo",
        "hostname": "laptop",
        "posture": {"permission_mode": "acceptEdits", "sandbox": "workspace-write"},
        "prompt": "refactor the parser",
        "action": Action(tool="Bash", kind=ActionKind.SHELL, input={"command": "ls"}),
        "decision": Decision.OBSERVED,
    }
    fields.update(overrides)
    return ActivityRecord(**fields)


def envelope(**overrides):
    return ocsf.base_event(
        make_record(**overrides), class_uid=1007, category_uid=1, activity_id=1
    )


def test_declares_all_three_profiles():
    assert envelope()["metadata"]["profiles"] == ["security_control", "host", "ai_operation"]


def test_type_uid_is_derived_not_written():
    assert envelope()["type_uid"] == 100701


def test_session_id_becomes_correlation_uid():
    assert envelope()["metadata"]["correlation_uid"] == "sess-abc"


def test_time_comes_from_the_record_not_the_clock():
    assert envelope()["time"] == 1758326400000
    assert envelope() == envelope(), "envelope must be deterministic"


def test_agent_identity_uses_the_ratified_ai_agent_object():
    ai_agent = envelope()["ai_agent"]
    assert ai_agent["name"] == "claude-code"
    assert ai_agent["version"] == "2.0.1"
    assert ai_agent["instance_uid"] == "sess-abc"
    assert ai_agent["type_id"] == 99


def test_model_uses_the_ratified_ai_model_object():
    assert envelope()["ai_model"] == {
        "name": "claude-opus-5",
        "ai_provider": "Anthropic",
        "uid": "claude-opus-5",
    }


def test_prompt_uses_message_context_not_an_enrichment():
    context = envelope()["message_context"]
    assert context["prompt_text"] == "refactor the parser"
    assert context["ai_role_id"] == 1
    assert context["uid"] == "turn-1"
    serialized = str(envelope()["enrichments"])
    assert "refactor the parser" not in serialized


def test_posture_rides_in_enrichments_having_no_ratified_home():
    enrichment = envelope()["enrichments"][0]
    assert enrichment["name"] == "agent_posture"
    assert enrichment["data"]["permission_mode"] == "acceptEdits"
    assert enrichment["data"]["cwd"] == "/repo"
    assert enrichment["data"]["hook_event"] == "PreToolUse"


def test_omits_ai_model_when_the_agent_did_not_report_one():
    record_actor = Actor(user_name="dev", agent_name="codex", agent_version="1.0", pid=1)
    assert "ai_model" not in envelope(actor=record_actor)


def test_omits_message_context_when_there_is_no_prompt():
    assert "message_context" not in envelope(prompt=None, turn_id=None)


def test_observed_decision_emits_action_id_only():
    event = envelope(decision=Decision.OBSERVED)
    assert event["action_id"] == 3
    assert "disposition_id" not in event


def test_allowed_decision_emits_approved_disposition():
    event = envelope(decision=Decision.ALLOWED)
    assert (event["action_id"], event["disposition_id"]) == (1, 8)


def test_denied_and_blocked_decisions_both_emit_denied_blocked():
    for decision in (Decision.DENIED, Decision.BLOCKED):
        event = envelope(decision=decision)
        assert (event["action_id"], event["disposition_id"]) == (2, 2)


def test_event_uid_is_stable_and_distinguishes_records():
    assert ocsf.event_uid(make_record()) == ocsf.event_uid(make_record())
    assert ocsf.event_uid(make_record()) != ocsf.event_uid(make_record(ts=1758326400001))


def test_actor_process_satisfies_the_at_least_one_constraint():
    assert ocsf.actor(make_record())["process"]["pid"] == 4242


def test_device_reports_the_host():
    assert ocsf.device(make_record()) == {"type_id": 3, "hostname": "laptop"}


def test_posture_cannot_override_cwd_hook_event_or_source():
    posture = {"cwd": "/elsewhere", "hook_event": "Forged", "source": "codex", "sandbox": "none"}
    data = ocsf.enrichments(make_record(posture=posture))[0]["data"]
    assert (data["cwd"], data["hook_event"], data["source"]) == ("/repo", "PreToolUse", "claude")
    assert data["sandbox"] == "none"


def test_a_missing_record_field_does_not_clobber_a_posture_value():
    data = ocsf.enrichments(make_record(cwd=None, posture={"cwd": "/from-posture"}))[0]["data"]
    assert data["cwd"] == "/from-posture"
