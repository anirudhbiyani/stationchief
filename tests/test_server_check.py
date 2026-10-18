import pytest

from stationchief.core.mapping import map_record
from stationchief.policy import CheckRequest, Verdict
from stationchief.server.check import AllowAllEngine, decision_record

REQUEST = {
    "agent": "claude",
    "session_id": "sess-abc",
    "tool": "Bash",
    "kind": "shell",
    "input": {"command": "rm -rf build"},
    "redaction_rules": ["aws_access_key_id"],
    "cwd": "/repo",
    "user": "dev",
    "hostname": "laptop",
    "posture": {"permission_mode": "default"},
    "hook_event": "PreToolUse",
}


def test_request_round_trips():
    request = CheckRequest.from_json(REQUEST)
    assert request.to_json() == REQUEST


@pytest.mark.parametrize(
    "change, reason",
    [
        ({"kind": "teleport"}, "unknown kind"),
        ({"input": "rm"}, "input must be an object"),
        ({"posture": []}, "posture must be an object"),
        ({"redaction_rules": [1]}, "redaction_rules"),
        ({"session_id": ""}, "session_id is required"),
        ({"agent": None}, "agent is required"),
        ({"tool": "x" * 5000}, "at most"),
    ],
)
def test_invalid_requests_are_rejected_with_a_reason(change, reason):
    with pytest.raises(ValueError, match=reason):
        CheckRequest.from_json({**REQUEST, **change})


def test_optional_fields_default():
    request = CheckRequest.from_json({k: REQUEST[k] for k in ("agent", "session_id", "tool", "kind")})
    assert (request.input, request.redaction_rules, request.hook_event) == ({}, (), "PreToolUse")


def test_verdicts_validate_their_decision():
    assert Verdict.from_json({"decision": "ask", "reason": "r", "policy": "p1"}) == Verdict("ask", "r", "p1")
    with pytest.raises(ValueError, match="unknown decision"):
        Verdict.from_json({"decision": "maybe"})


def test_allow_all_engine_allows_without_attribution():
    verdict = AllowAllEngine().decide(CheckRequest.from_json(REQUEST))
    assert (verdict.decision, verdict.policy) == ("allow", None)


@pytest.mark.parametrize("decision, action_disposition", [("deny", (2, 2)), ("allow", (3, None)), ("ask", (3, None))])
def test_decisions_become_valid_ocsf_audit_events(decision, action_disposition, assert_valid_ocsf):
    verdict = Verdict(decision, "because", "no-rm")
    event = map_record(decision_record(CheckRequest.from_json(REQUEST), verdict, now_ms=1789898400000, principal="fleet"))
    assert_valid_ocsf(event)
    assert (event["action_id"], event.get("disposition_id")) == action_disposition
    data = event["enrichments"][0]["data"]
    assert (data["policy_decision"], data["policy"], data["capture"]) == (decision, "no-rm", "check")
    assert data["redaction_rules"] == ["aws_access_key_id"]
    assert "message_context" not in event or "prompt_text" not in event["message_context"]


def test_the_decision_actor_is_the_authenticated_principal_not_the_client_user():
    # "user" is whatever the client typed; the principal is who the token belongs to.
    request = CheckRequest.from_json({**REQUEST, "user": "someone-else"})
    event = map_record(decision_record(request, Verdict("deny", "no", "p"), now_ms=1789898400000, principal="fleet"))
    assert event["actor"]["user"]["name"] == "fleet"
    assert "someone-else" not in str(event["actor"])
