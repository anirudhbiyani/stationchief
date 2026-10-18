import json
import os
import pathlib
import shutil

import pytest

from stationchief import state
from stationchief.config import Config
from stationchief.core.mapping import map_record
from stationchief.core.records import ActionKind
from stationchief.ingest import codex

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "codex" / "rollout_session.jsonl"
NOW = 1789902000000  # 2026-09-20T11:00Z, an hour after the fixture's last line
CONTEXT = {"hostname": "laptop", "user_name": "dev"}


def parsed():
    return codex.parse(FIXTURE.read_bytes(), **CONTEXT)


def install_rollout(tmp_path, text=None):
    path = tmp_path / "sessions" / "2026" / "09" / "20" / "rollout-2026-09-20T10-00-00-sess-codex.jsonl"
    path.parent.mkdir(parents=True)
    path.write_text(text if text is not None else FIXTURE.read_text())
    age(path)
    return path


def age(path, ms_before_now=60 * 60 * 1000):
    seconds = (NOW - ms_before_now) / 1000
    os.utime(path, (seconds, seconds))


def events(home):
    return [json.loads(l) for p in home.glob("events-*.ndjson") for l in p.read_text().splitlines()]


def test_parses_session_calls_prompt_and_posture():
    session_id, records, malformed = parsed()
    assert session_id == "sess-codex" and malformed == 0
    assert [r.action.kind for r in records] == [ActionKind.SHELL, ActionKind.FILE_UPDATE, ActionKind.SHELL]
    shell = records[0]
    assert shell.action.input["command"] == "ls -la"
    assert shell.prompt == "list the files"
    assert shell.actor.model == "gpt-5-codex" and shell.actor.agent_version == "0.50.0"
    assert shell.posture == {
        "capture": "transcript",
        "tool_call_id": "call_1",
        "sandbox": "workspace-write",
        "approval_policy": "on-request",
    }
    assert shell.ts == 1789898403000  # 2026-09-20T10:00:03Z
    assert shell.action.status == "success"


def test_apply_patch_resolves_the_file_it_touches():
    _, records, _ = parsed()
    assert records[1].action.input["file_path"] == "src/app.py"


def test_a_non_zero_exit_is_a_failure():
    _, records, _ = parsed()
    assert (records[2].action.status, records[2].action.error) == ("failure", "exit code 1")


def test_every_record_maps_to_valid_ocsf(assert_golden):
    _, records, _ = parsed()
    for name, record in zip(("transcript_shell", "transcript_patch", "transcript_shell_failed"), records):
        assert_golden("codex", name, map_record(record))


def test_start_offset_skips_calls_but_keeps_context():
    data = FIXTURE.read_bytes()
    offset = data.rindex(b"\n", 0, data.index(b'"call_id":"call_2"')) + 1  # start of call_2's line
    _, records, _ = codex.parse(data, start_offset=offset, **CONTEXT)
    assert [r.posture["tool_call_id"] for r in records] == ["call_2", "call_3"]
    assert records[0].prompt == "list the files", "context before the watermark still applies"


def test_parse_streams_an_open_file_like_whole_bytes():
    data = FIXTURE.read_bytes()
    offset = data.rindex(b"\n", 0, data.index(b'"call_id":"call_2"')) + 1
    with FIXTURE.open("rb") as lines:
        streamed = codex.parse(lines, start_offset=offset, **CONTEXT)
    assert streamed == codex.parse(data, start_offset=offset, **CONTEXT)


def test_malformed_lines_are_counted_and_skipped():
    data = FIXTURE.read_bytes() + b"{truncated\n"
    _, records, malformed = codex.parse(data, **CONTEXT)
    assert len(records) == 3 and malformed == 1


def test_ingest_backfills_then_is_idempotent(tmp_path):
    install_rollout(tmp_path)
    config = Config(home=tmp_path / "home", detect=False)
    assert codex.ingest(config, tmp_path / "sessions", now_ms=NOW) == (3, 0, 0)
    assert codex.ingest(config, tmp_path / "sessions", now_ms=NOW) == (0, 0, 0)
    assert len(events(config.home)) == 3


def test_the_watermark_waits_until_a_sink_captures_the_session(tmp_path, monkeypatch):
    from stationchief.sinks.ndjson import NdjsonSink

    install_rollout(tmp_path)
    config = Config(home=tmp_path / "home", detect=False)
    healthy = NdjsonSink.write

    def full_disk(self, events):
        raise OSError("disk full")

    monkeypatch.setattr(NdjsonSink, "write", full_disk)
    codex.ingest(config, tmp_path / "sessions", now_ms=NOW)
    assert events(config.home) == []
    monkeypatch.setattr(NdjsonSink, "write", healthy)
    assert codex.ingest(config, tmp_path / "sessions", now_ms=NOW) == (3, 0, 0)
    assert len(events(config.home)) == 3


def test_an_appended_resumed_session_emits_only_the_new_call(tmp_path):
    path = install_rollout(tmp_path)
    config = Config(home=tmp_path / "home", detect=False)
    codex.ingest(config, tmp_path / "sessions", now_ms=NOW)
    with open(path, "a") as handle:
        handle.write(
            '{"timestamp":"2026-09-20T10:05:00.000Z","type":"response_item","payload":'
            '{"type":"function_call","name":"shell","arguments":"{\\"command\\":[\\"pwd\\"]}","call_id":"call_4"}}\n'
        )
    age(path)
    assert codex.ingest(config, tmp_path / "sessions", now_ms=NOW) == (1, 0, 0)
    assert events(config.home)[-1]["message_context"]["prompt_text"] == "list the files"


def test_an_active_session_is_left_to_the_hooks(tmp_path):
    path = install_rollout(tmp_path)
    age(path, ms_before_now=60 * 1000)
    config = Config(home=tmp_path / "home", detect=False)
    assert codex.ingest(config, tmp_path / "sessions", now_ms=NOW) == (0, 0, 0)


def test_calls_the_hooks_already_captured_are_not_repeated(tmp_path):
    install_rollout(tmp_path)
    config = Config(home=tmp_path / "home", detect=False)
    state.update(config, "sess-codex", prompt="list the files")
    for call_id in ("call_1", "call_2", "call_3"):
        state.mark_seen(config, "sess-codex", call_id, 0)
    assert codex.ingest(config, tmp_path / "sessions", now_ms=NOW) == (0, 3, 0)


def test_a_call_the_hooks_missed_raises_a_coverage_gap(tmp_path):
    install_rollout(tmp_path)
    config = Config(home=tmp_path / "home", detect=False)
    state.update(config, "sess-codex", prompt="list the files")
    state.mark_seen(config, "sess-codex", "call_1", 0)
    assert codex.ingest(config, tmp_path / "sessions", now_ms=NOW) == (2, 1, 1)
    assert [e["class_uid"] for e in events(config.home)].count(2004) == 1


def test_a_missing_sessions_directory_is_not_an_error(tmp_path):
    assert codex.ingest(Config(home=tmp_path), tmp_path / "nope", now_ms=NOW) == (0, 0, 0)


@pytest.mark.parametrize("namespace", ["mcp__github__", "mcp__github"])
def test_an_mcp_call_keeps_its_server_from_the_namespace(namespace):
    payload = {"type": "function_call", "name": "create_issue", "namespace": namespace, "arguments": "{}", "call_id": "c"}
    tool, kind, _ = codex._call(payload)
    assert (tool, kind) == ("mcp__github__create_issue", ActionKind.MCP_CALL)


def _code_mode_rollout(script):
    lines = [
        {"type": "session_meta", "payload": {"id": "s-code", "cwd": "/repo", "cli_version": "0.158.0"}},
        {"type": "response_item", "payload": {"type": "custom_tool_call", "name": "exec", "call_id": "c1", "input": script}},
    ]
    return "".join(json.dumps(line) + "\n" for line in lines).encode()


@pytest.mark.parametrize(
    "script, kind, command",
    [
        # Shapes seen in real Codex 0.158 code-mode transcripts.
        ('text(await tools.exec_command({cmd:"cat \'/a b.txt\'","max_output_tokens":60}));\n', "shell", "cat '/a b.txt'"),
        ('text(await tools.exec_command({cmd:"echo a"}));\ntext(await tools.exec_command({"cmd":"rm -rf ~"}));', "shell", "echo a\nrm -rf ~"),
        ('text(await tools.web__run({open:[{ref_id:"x"}]}));', "unknown", None),
        ('const c = "ls"; text(await tools.exec_command({cmd: c}));', "unknown", None),
    ],
)
def test_code_mode_exec_reads_the_inner_tool_and_command(script, kind, command):
    _, records, _ = codex.parse(_code_mode_rollout(script), **CONTEXT)
    (record,) = records
    assert record.action.kind == kind
    assert record.action.input.get("command") == command
