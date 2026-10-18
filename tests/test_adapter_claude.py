import dataclasses
import json

from stationchief.adapters import claude
from stationchief.config import Config
from stationchief.core.records import ActionKind, Decision

CONTEXT = {"hostname": "laptop", "user_name": "dev"}
STATE = {
    "prompt": "clean up the build directory",
    "turn_id": "turn-1",
    "model": "claude-opus-5",
    "agent_version": "2.0.1",
}


def test_user_prompt_submit_emits_no_event(load_fixture):
    payload = load_fixture("claude", "user_prompt_submit")
    assert claude.to_record(payload, {}, **CONTEXT) is None


def test_user_prompt_submit_stores_the_prompt(tmp_path, load_fixture):
    from stationchief import state

    config = Config(home=tmp_path, detect=False)
    claude.handle(load_fixture("claude", "user_prompt_submit"), config)
    stored = state.read(config, "sess-abc")
    assert stored["prompt"] == "clean up the build directory"
    assert stored["turn_id"]


def test_bash_becomes_a_shell_record(load_fixture):
    record = claude.to_record(load_fixture("claude", "pre_tool_use_bash"), STATE, **CONTEXT)
    assert record.action.kind == ActionKind.SHELL
    assert record.action.input["command"] == "rm -rf build"
    assert record.decision == Decision.OBSERVED
    assert record.source == "claude"


def test_prompt_and_model_come_from_session_state(load_fixture):
    record = claude.to_record(load_fixture("claude", "pre_tool_use_bash"), STATE, **CONTEXT)
    assert record.prompt == "clean up the build directory"
    assert record.actor.model == "claude-opus-5"
    assert record.actor.model_provider == "Anthropic"
    assert record.turn_id == "turn-1"


def test_permission_mode_is_carried_as_posture(load_fixture):
    record = claude.to_record(load_fixture("claude", "pre_tool_use_bash"), STATE, **CONTEXT)
    assert record.posture["permission_mode"] == "acceptEdits"


def test_edit_becomes_a_file_update_record(load_fixture):
    record = claude.to_record(load_fixture("claude", "post_tool_use_edit"), STATE, **CONTEXT)
    assert record.action.kind == ActionKind.FILE_UPDATE
    assert record.action.status == "success"


def test_mcp_tool_becomes_an_mcp_call_record(load_fixture):
    record = claude.to_record(load_fixture("claude", "pre_tool_use_mcp"), STATE, **CONTEXT)
    assert record.action.kind == ActionKind.MCP_CALL
    assert record.action.tool == "mcp__github__create_issue"


def test_handle_returns_the_envelope_claude_accepts(tmp_path, load_fixture):
    config = Config(home=tmp_path, detect=False)
    response = claude.handle(load_fixture("claude", "pre_tool_use_bash"), config)
    assert response == {"continue": True, "suppressOutput": True}


def test_handle_never_raises_on_a_malformed_payload(tmp_path):
    config = Config(home=tmp_path, detect=False)
    assert claude.handle({"hook_event_name": "PreToolUse"}, config) == {
        "continue": True,
        "suppressOutput": True,
    }


def test_handle_never_raises_on_a_payload_that_is_not_a_dict(tmp_path):
    config = Config(home=tmp_path, detect=False)
    assert claude.handle("not a dict", config)["continue"] is True


GOLDEN_CASES = [
    ("pre_tool_use_bash", 1007),
    ("post_tool_use_edit", 1001),
    ("pre_tool_use_mcp", 6003),
]


def test_golden_outputs(load_fixture, assert_golden):
    from stationchief.core.mapping import map_record

    for name, class_uid in GOLDEN_CASES:
        record = claude.to_record(load_fixture("claude", name), STATE, **CONTEXT)
        record = dataclasses.replace(record, ts=1758326400000)
        event = map_record(record)
        assert event["class_uid"] == class_uid
        assert_golden("claude", name, event)
