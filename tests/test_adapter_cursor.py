import dataclasses

import pytest

from stationchief.adapters import cursor
from stationchief.config import Config
from stationchief.core.records import ActionKind

CONTEXT = {"hostname": "laptop", "user_name": "dev"}
STATE = {"prompt": "install the dependencies", "turn_id": "gen-1", "model": "composer-1"}


def test_granular_events_are_ignored_to_avoid_double_counting(load_fixture):
    payload = load_fixture("cursor", "before_shell_execution")
    assert cursor.to_record(payload, STATE, **CONTEXT) is None


def test_granular_event_set_is_explicit():
    assert "beforeShellExecution" in cursor.GRANULAR_EVENTS
    assert "afterFileEdit" in cursor.GRANULAR_EVENTS
    assert "preToolUse" not in cursor.GRANULAR_EVENTS


def test_the_same_shell_action_is_recorded_exactly_once(tmp_path, load_fixture):
    config = Config(home=tmp_path, detect=False)
    cursor.handle(load_fixture("cursor", "before_shell_execution"), config)
    cursor.handle(load_fixture("cursor", "pre_tool_use_shell"), config)
    lines = list(tmp_path.glob("events-*.ndjson"))[0].read_text().splitlines()
    assert len(lines) == 1


def test_conversation_id_becomes_the_session_id(load_fixture):
    record = cursor.to_record(load_fixture("cursor", "pre_tool_use_shell"), STATE, **CONTEXT)
    assert record.session_id == "conv-xyz"
    assert record.source == "cursor"


def test_shell_tool_becomes_a_shell_record(load_fixture):
    record = cursor.to_record(load_fixture("cursor", "pre_tool_use_shell"), STATE, **CONTEXT)
    assert record.action.kind == ActionKind.SHELL
    assert record.action.input["command"] == "npm install"


def test_write_tool_becomes_a_file_create_record(load_fixture):
    record = cursor.to_record(load_fixture("cursor", "post_tool_use_write"), STATE, **CONTEXT)
    assert record.action.kind == ActionKind.FILE_CREATE
    assert record.action.status == "success"


def test_first_workspace_root_becomes_the_cwd(load_fixture):
    record = cursor.to_record(load_fixture("cursor", "pre_tool_use_shell"), STATE, **CONTEXT)
    assert record.cwd == "/repo"


def test_before_submit_prompt_stores_the_prompt_and_emits_nothing(tmp_path, load_fixture):
    from stationchief import state

    config = Config(home=tmp_path, detect=False)
    cursor.handle(load_fixture("cursor", "before_submit_prompt"), config)
    assert state.read(config, "conv-xyz")["prompt"] == "install the dependencies"
    assert list(tmp_path.glob("events-*.ndjson")) == []


def test_pre_tool_use_response_permits_by_default(tmp_path, load_fixture):
    config = Config(home=tmp_path, detect=False)
    response = cursor.handle(load_fixture("cursor", "pre_tool_use_shell"), config)
    assert response == {"permission": "allow"}


def test_handle_never_raises_on_a_malformed_payload(tmp_path):
    config = Config(home=tmp_path, detect=False)
    assert cursor.handle({"hook_event_name": "preToolUse"}, config) == {"permission": "allow"}


def test_golden_outputs(load_fixture, assert_golden):
    from stationchief.core.mapping import map_record

    for name, class_uid in [("pre_tool_use_shell", 1007), ("post_tool_use_write", 1001)]:
        record = cursor.to_record(load_fixture("cursor", name), STATE, **CONTEXT)
        record = dataclasses.replace(record, ts=1758326400000)
        event = map_record(record)
        assert event["class_uid"] == class_uid
        assert_golden("cursor", name, event)


def test_a_call_is_marked_seen_only_after_it_is_emitted(load_fixture, tmp_path, monkeypatch):
    from stationchief import state

    config = Config(home=tmp_path)
    payload = {**load_fixture("cursor", "pre_tool_use_shell"), "tool_call_id": "call-1"}
    session = payload.get("conversation_id") or "unknown"
    seen_at_emit = []

    def fake_emit_checked(record, config, pre_tool):
        seen_at_emit.append(state.seen(config, session)[1])

    monkeypatch.setattr(cursor, "emit_checked", fake_emit_checked)
    cursor.handle(payload, config)
    assert seen_at_emit == [set()]
    assert state.seen(config, session)[1] == {"call-1"}


@pytest.mark.parametrize(
    "fields,expected",
    [
        ({"tool_name": "create_issue", "mcp_server_name": "github"}, "mcp__github__create_issue"),
        ({"tool_name": "MCP:create_issue", "mcp_server_name": "github"}, "mcp__github__create_issue"),
        ({"tool_name": "MCP:create_issue"}, "mcp__unknown__create_issue"),
        ({"tool_name": "mcp__github__create_issue"}, "mcp__github__create_issue"),
        ({"tool_name": "Shell"}, "Shell"),
    ],
)
def test_mcp_tools_are_named_like_the_policy_expects(fields, expected):
    payload = {"hook_event_name": "preToolUse", "conversation_id": "c", "tool_input": {}, **fields}
    record = cursor.to_record(payload, STATE, **CONTEXT)
    assert record.action.tool == expected
    if expected.startswith("mcp__"):
        assert record.action.kind == ActionKind.MCP_CALL
