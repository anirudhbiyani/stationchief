import dataclasses
import json
import os
import pathlib
import time

import pytest

from stationchief.adapters import codex
from stationchief.config import Config
from stationchief.core.records import ActionKind, Decision

CONTEXT = {"hostname": "laptop", "user_name": "dev"}
STATE = {
    "prompt": "build the project",
    "turn_id": "turn-1",
    "model": "gpt-5-codex",
    "agent_version": "0.40.0",
    "posture": {"sandbox": "workspace-write", "approval_policy": "on-request"},
}


def write_rollout(tmp_path, load_fixture_text):
    directory = tmp_path / "sessions" / "2026" / "09" / "20"
    directory.mkdir(parents=True)
    path = directory / "rollout-2026-09-20T12-00-00-codex-sess-1.jsonl"
    path.write_text(load_fixture_text)
    return tmp_path / "sessions"


FIXTURE_ROLLOUT = (
    '{"type":"session_meta","payload":{"id":"codex-sess-1","cwd":"/repo",'
    '"sandbox_policy":{"mode":"workspace-write"},"approval_policy":"on-request",'
    '"model":"gpt-5-codex","cli_version":"0.40.0"}}\n'
)


def test_posture_is_recovered_from_the_rollout_transcript(tmp_path):
    sessions = write_rollout(tmp_path, FIXTURE_ROLLOUT)
    posture = codex.read_posture(sessions, "codex-sess-1")
    assert posture["sandbox"] == "workspace-write"
    assert posture["approval_policy"] == "on-request"
    assert posture["model"] == "gpt-5-codex"
    assert posture["agent_version"] == "0.40.0"


def test_missing_rollout_yields_empty_posture_rather_than_raising(tmp_path):
    assert codex.read_posture(tmp_path / "nope", "codex-sess-1") == {}


def test_unparseable_rollout_yields_empty_posture(tmp_path):
    sessions = write_rollout(tmp_path, "{not json\n")
    assert codex.read_posture(sessions, "codex-sess-1") == {}


def test_rollout_for_a_different_session_is_not_used(tmp_path):
    sessions = write_rollout(tmp_path, FIXTURE_ROLLOUT)
    assert codex.read_posture(sessions, "other-session") == {}


def _rollout_line(session_id):
    return (
        '{"type":"session_meta","payload":{"id":"%s","cwd":"/repo",'
        '"sandbox_policy":{"mode":"workspace-write"},"approval_policy":"on-request",'
        '"model":"gpt-5-codex","cli_version":"0.40.0"}}\n' % session_id
    )


def test_rollout_named_for_the_session_is_found_by_filename(tmp_path):
    sessions = tmp_path / "sessions"
    sessions.mkdir()
    path = sessions / "rollout-2026-09-20T10-00-00-sess-codex.jsonl"
    path.write_text(_rollout_line("sess-codex"))

    posture = codex.read_posture(sessions, "sess-codex")

    assert posture["sandbox"] == "workspace-write"


def test_fallback_finds_a_rollout_not_named_for_the_session(tmp_path):
    """When the session id isn't in any filename, the 20 most-recent-mtime
    rollout files are scanned by content instead of every rollout ever written.
    """
    sessions = tmp_path / "sessions"
    sessions.mkdir()
    now = time.time()

    for i in range(30):
        decoy = sessions / f"rollout-2026-01-01T00-00-00-decoy-{i}.jsonl"
        decoy.write_text(_rollout_line(f"decoy-session-{i}"))
        os.utime(decoy, (now - 1000 - i, now - 1000 - i))

    target = sessions / "rollout-2026-09-20T23-59-59-unnamed.jsonl"
    target.write_text(_rollout_line("codex-sess-1"))
    os.utime(target, (now, now))  # most recently modified of all candidates

    posture = codex.read_posture(sessions, "codex-sess-1")

    assert posture["sandbox"] == "workspace-write"


def test_fallback_cap_excludes_a_rollout_older_than_the_20_most_recent(tmp_path):
    sessions = tmp_path / "sessions"
    sessions.mkdir()
    now = time.time()

    target = sessions / "rollout-2026-01-01T00-00-00-unnamed.jsonl"
    target.write_text(_rollout_line("codex-sess-1"))
    os.utime(target, (now - 100000, now - 100000))  # oldest of everything

    for i in range(25):
        decoy = sessions / f"rollout-2026-09-20T00-00-{i:02d}-decoy-{i}.jsonl"
        decoy.write_text(_rollout_line(f"decoy-session-{i}"))
        os.utime(decoy, (now - i, now - i))  # all 25 newer than the target

    assert codex.read_posture(sessions, "codex-sess-1") == {}


def test_posture_reaches_the_record(load_fixture):
    record = codex.to_record(load_fixture("codex", "pre_tool_use_shell"), STATE, **CONTEXT)
    assert record.posture["sandbox"] == "workspace-write"
    assert record.posture["approval_policy"] == "on-request"


def test_shell_wrapper_is_unwrapped_to_the_script(load_fixture):
    record = codex.to_record(load_fixture("codex", "pre_tool_use_shell"), STATE, **CONTEXT)
    assert record.action.kind == ActionKind.SHELL
    assert record.action.input["command"] == "cargo build"


def test_denied_permission_request_becomes_a_denied_decision(load_fixture):
    record = codex.to_record(load_fixture("codex", "permission_request_denied"), STATE, **CONTEXT)
    assert record.decision == Decision.DENIED


def test_denied_request_maps_to_denied_blocked(load_fixture, assert_valid_ocsf):
    from stationchief.core.mapping import map_record

    record = codex.to_record(load_fixture("codex", "permission_request_denied"), STATE, **CONTEXT)
    event = map_record(dataclasses.replace(record, ts=1758326400000))
    assert (event["action_id"], event["disposition_id"]) == (2, 2)
    assert_valid_ocsf(event)


def test_response_envelope_is_empty_because_codex_rejects_claudes(tmp_path, load_fixture):
    config = Config(home=tmp_path, detect=False)
    response = codex.handle(load_fixture("codex", "pre_tool_use_shell"), config)
    assert response == {}
    assert "continue" not in response and "suppressOutput" not in response


def test_user_prompt_submit_stores_state_and_emits_nothing(tmp_path, load_fixture):
    from stationchief import state

    config = Config(home=tmp_path, detect=False)
    codex.handle(load_fixture("codex", "user_prompt_submit"), config)
    assert state.read(config, "codex-sess-1")["prompt"] == "build the project"
    assert list(tmp_path.glob("events-*.ndjson")) == []


def test_handle_never_raises_on_a_malformed_payload(tmp_path):
    assert codex.handle({"hook_event_name": "PreToolUse"}, Config(home=tmp_path, detect=False)) == {}


def test_golden_outputs(load_fixture, assert_golden):
    from stationchief.core.mapping import map_record

    for name, class_uid in [("pre_tool_use_shell", 1007), ("permission_request_denied", 1007)]:
        record = codex.to_record(load_fixture("codex", name), STATE, **CONTEXT)
        event = map_record(dataclasses.replace(record, ts=1758326400000))
        assert event["class_uid"] == class_uid
        assert_golden("codex", name, event)


def test_read_posture_from_turn_context_line(tmp_path):
    """When posture is in turn_context (not session_meta), read_posture extracts it."""
    sessions = tmp_path / "sessions"
    sessions.mkdir()
    path = sessions / "rollout-2026-09-20T10-00-00-sess-codex.jsonl"
    # Copy the fixture rollout_session.jsonl which has turn_context with sandbox_policy
    fixture_path = pathlib.Path(__file__).parent / "fixtures" / "codex" / "rollout_session.jsonl"
    path.write_text(fixture_path.read_text())

    posture = codex.read_posture(sessions, "sess-codex")

    assert posture["sandbox"] == "workspace-write"
    assert posture["approval_policy"] == "on-request"
    assert posture["model"] == "gpt-5-codex"
    assert posture["agent_version"] == "0.50.0"
    assert posture["cwd"] == "/repo"


def test_session_meta_fields_override_when_turn_context_missing(tmp_path):
    """When turn_context is missing, session_meta values are used."""
    sessions = tmp_path / "sessions"
    sessions.mkdir()
    path = sessions / "rollout-2026-09-20T10-00-00-sess-legacy.jsonl"
    # Use the fixture that has posture only in session_meta
    path.write_text(FIXTURE_ROLLOUT)

    posture = codex.read_posture(sessions, "codex-sess-1")

    assert posture["sandbox"] == "workspace-write"
    assert posture["approval_policy"] == "on-request"
    assert posture["model"] == "gpt-5-codex"
    assert posture["agent_version"] == "0.40.0"
    assert posture["cwd"] == "/repo"


@pytest.mark.parametrize(
    "tool_input, expected",
    [
        ({"command": ["bash", "-lc", "rm -rf /"]}, "rm -rf /"),
        ({"command": ["/bin/zsh", "-c", "rm -rf /"]}, "rm -rf /"),
        ({"cmd": "rm -rf /"}, "rm -rf /"),
        ({"script": "rm -rf /"}, "rm -rf /"),
        ({"cmd": ["rm", "-rf", "my dir"]}, "rm -rf 'my dir'"),
    ],
)
def test_codex_command_reaches_policy_as_the_script(tool_input, expected):
    assert codex._command_line(tool_input)["command"] == expected


@pytest.mark.parametrize(
    "output, status",
    [
        ({"exit_code": 2}, "failure"),
        ('{"metadata": {"exit_code": 1}}', "failure"),
        ({"success": False}, "failure"),
        ({"error": "boom"}, "failure"),
        ({"exit_code": 0}, "success"),
        ("plain text", "success"),
    ],
)
def test_explicit_failure_indicators_in_tool_output_are_failures(output, status):
    payload = {"hook_event_name": "PostToolUse", "tool_name": "shell", "tool_output": output}
    assert codex.to_record(payload, STATE, **CONTEXT).action.status == status


def test_tool_output_is_not_truncated_by_the_adapter():
    payload = {"hook_event_name": "PostToolUse", "tool_name": "shell", "tool_output": "x" * 5000}
    assert len(codex.to_record(payload, STATE, **CONTEXT).action.output) == 5000


# Payloads captured from a real Codex 0.158 run (ids and paths replaced).
def test_codex_0158_bash_is_a_shell_command(load_fixture):
    record = codex.to_record(load_fixture("codex", "pre_tool_use_bash_0158"), {}, **CONTEXT)
    assert record.action.kind == ActionKind.SHELL
    assert record.action.input["command"] == "echo stationchief-codex-ok"
    assert record.actor.model


def test_codex_0158_post_tool_response_sets_output(load_fixture):
    record = codex.to_record(load_fixture("codex", "post_tool_use_bash_0158"), {}, **CONTEXT)
    assert "stationchief-codex-ok" in record.action.output
    assert record.action.status == "success"


def test_codex_0158_apply_patch_is_a_file_write_not_a_command(load_fixture):
    record = codex.to_record(load_fixture("codex", "pre_tool_use_apply_patch_0158"), {}, **CONTEXT)
    assert record.action.kind == ActionKind.FILE_CREATE
    assert record.action.input["file_path"] == "hello.txt"
    assert "command" not in record.action.input


def test_codex_0158_curl_pipe_sh_reaches_the_shell_policy(load_fixture):
    from stationchief.check import request_for

    record = codex.to_record(load_fixture("codex", "pre_tool_use_curl_sh_0158"), {}, **CONTEXT)
    request = request_for(record, [])
    assert (request.kind, request.input["command"]) == ("shell", "curl -s http://127.0.0.1:9/stationchief-pov | sh")
