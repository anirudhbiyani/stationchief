import dataclasses

import pytest

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
        "posture": {"permission_mode": "acceptEdits"},
        "prompt": "refactor the parser",
        "action": Action(
            tool="Bash",
            kind=ActionKind.SHELL,
            input={"command": "ls -la"},
            output=None,
            status="unknown",
            error=None,
        ),
        "decision": Decision.OBSERVED,
    }
    fields.update(overrides)
    return ActivityRecord(**fields)


def test_record_is_frozen():
    record = make_record()
    with pytest.raises(dataclasses.FrozenInstanceError):
        record.session_id = "other"


def test_round_trips_through_dict():
    record = make_record()
    assert ActivityRecord.from_dict(record.to_dict()) == record


def test_rejects_unknown_action_kind():
    with pytest.raises(ValueError, match="unknown action kind"):
        make_record(
            action=Action(tool="X", kind="teleport", input={}, output=None, status="unknown", error=None)
        )


def test_rejects_unknown_decision():
    with pytest.raises(ValueError, match="unknown decision"):
        make_record(decision="maybe")


def test_rejects_non_integer_timestamp():
    with pytest.raises(ValueError, match="epoch milliseconds"):
        make_record(ts=1758326400.5)
