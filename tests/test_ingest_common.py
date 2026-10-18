import json
import stat

from stationchief import state
from stationchief.adapters import codex, cursor
from stationchief.config import Config
from stationchief.core.records import Action, ActionKind, ActivityRecord, Actor, Decision
from stationchief.ingest import common

SECRET = "AKIAIOSFODNN7EXAMPLE"


def rec(call_id, ts=1758326400000, prompt="list files"):
    return ActivityRecord(
        source="codex",
        session_id="sess-x",
        turn_id="t1",
        ts=ts,
        event="transcript",
        actor=Actor(user_name="dev", agent_name="codex", agent_version="0.50.0", pid=None),
        cwd="/repo",
        hostname="laptop",
        posture=common.transcript_posture(call_id, sandbox="workspace-write"),
        prompt=prompt,
        action=Action(tool="shell", kind=ActionKind.SHELL, input={"command": "ls"}),
        decision=Decision.OBSERVED,
    )


def written(home):
    return [json.loads(l) for p in home.glob("events-*.ndjson") for l in p.read_text().splitlines()]


def hooks_were_live(config, *seen_ids, since=0):
    state.update(config, "sess-x", prompt="list files")
    for call_id in seen_ids:
        state.mark_seen(config, "sess-x", call_id, since)


def test_backfills_a_session_hooks_never_saw(tmp_path, assert_valid_ocsf):
    config = Config(home=tmp_path, detect=False)
    assert common.emit_session(config, "sess-x", [rec("c1"), rec("c2")], call_ids_match=True) == (2, 0, 0)
    events = written(tmp_path)
    assert len(events) == 2
    assert events[0]["enrichments"][0]["data"]["capture"] == "transcript"
    assert events[0]["enrichments"][0]["data"]["tool_call_id"] == "c1"
    for event in events:
        assert_valid_ocsf(event)


def test_skips_calls_the_hooks_already_emitted(tmp_path):
    config = Config(home=tmp_path, detect=False)
    hooks_were_live(config, "c1", "c2")
    assert common.emit_session(config, "sess-x", [rec("c1"), rec("c2")], call_ids_match=True) == (0, 2, 0)
    assert written(tmp_path) == []


def test_a_call_the_hooks_missed_is_emitted_with_one_gap_finding(tmp_path, assert_valid_ocsf):
    config = Config(home=tmp_path, detect=False)
    hooks_were_live(config, "c1")
    assert common.emit_session(config, "sess-x", [rec("c1"), rec("c2"), rec("c3")], call_ids_match=True) == (2, 1, 1)
    events = written(tmp_path)
    findings = [e for e in events if e["class_uid"] == 2004]
    assert len(findings) == 1
    assert findings[0]["finding_info"]["title"] == "Agent activity missing from hook capture"
    assert findings[0]["evidences"][0]["data"]["missing_tool_calls"] == 2
    for event in events:
        assert_valid_ocsf(event)


def test_calls_before_the_hooks_started_are_not_gaps(tmp_path):
    config = Config(home=tmp_path, detect=False)
    hooks_were_live(config, "c2", since=1758326400500)
    records = [rec("c1", ts=1758326400000), rec("c2", ts=1758326401000)]
    assert common.emit_session(config, "sess-x", records, call_ids_match=True) == (0, 2, 0)


def test_live_hooks_with_no_seen_file_means_every_call_is_a_gap(tmp_path):
    config = Config(home=tmp_path, detect=False)
    hooks_were_live(config)  # state written, but no tool hook ever recorded a call
    assert common.emit_session(config, "sess-x", [rec("c1")], call_ids_match=True) == (1, 0, 1)


def test_session_level_fallback_skips_hook_covered_sessions(tmp_path):
    config = Config(home=tmp_path, detect=False)
    hooks_were_live(config)
    assert common.emit_session(config, "sess-x", [rec("c1")], call_ids_match=False) == (0, 1, 0)


def test_gap_finding_never_carries_an_unredacted_prompt(tmp_path):
    config = Config(home=tmp_path, detect=False)
    hooks_were_live(config)
    common.emit_session(config, "sess-x", [rec("c1", prompt=f"use {SECRET}")], call_ids_match=True)
    assert SECRET not in "".join(p.read_text() for p in tmp_path.glob("events-*.ndjson"))


def test_watermark_round_trips_owner_only(tmp_path):
    config = Config(home=tmp_path)
    assert common.load_watermark(config, "codex") == {}
    common.save_watermark(config, "codex", {"files": {"/a": 10}})
    assert common.load_watermark(config, "codex") == {"files": {"/a": 10}}
    path = tmp_path / "ingest" / "codex.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_settled_means_idle_for_ten_minutes():
    now = 1758326400000
    assert common.settled(now - 10 * 60 * 1000, now)
    assert not common.settled(now - 60 * 1000, now)
    assert not common.settled(None, now)


def test_iso_ms_parses_agent_timestamps():
    assert common.iso_ms("2026-09-20T00:00:00.000Z") == 1789862400000
    assert common.iso_ms("garbage") is None
    assert common.iso_ms(None) is None


def test_seen_file_is_owner_only_and_tolerates_odd_ids(tmp_path):
    config = Config(home=tmp_path)
    state.mark_seen(config, "../../etc/passwd", "id\nwith newline", 5)
    since, ids = state.seen(config, "../../etc/passwd")
    assert since == 5 and ids == {"id with newline"}
    files = list((tmp_path / "seen").iterdir())
    assert len(files) == 1 and stat.S_IMODE(files[0].stat().st_mode) == 0o600


def test_cursor_hook_marks_the_tool_call_as_seen(tmp_path):
    config = Config(home=tmp_path, detect=False)
    cursor.handle(
        {"conversation_id": "conv-1", "hook_event_name": "preToolUse", "tool_name": "shell",
         "tool_input": {"command": "ls"}, "tool_use_id": "toolu_1", "workspace_roots": ["/repo"]},
        config,
    )
    assert state.seen(config, "conv-1")[1] == {"toolu_1"}


def test_codex_hook_marks_the_tool_call_as_seen(tmp_path):
    config = Config(home=tmp_path, detect=False)
    codex.handle(
        {"session_id": "sess-x", "hook_event_name": "PreToolUse", "tool_name": "shell",
         "tool_input": {"command": ["ls"]}, "call_id": "call_1"},
        config,
    )
    assert state.seen(config, "sess-x")[1] == {"call_1"}


class CountingSink:
    def __init__(self):
        self.writes = []

    def write(self, events):
        self.writes.append(list(events))


def test_backfill_writes_a_session_in_one_batch(tmp_path, monkeypatch):
    sink = CountingSink()
    monkeypatch.setattr("stationchief.pipeline.build_sinks", lambda config: [sink])
    config = Config(home=tmp_path, detect=False)
    common.emit_session(config, "sess-x", [rec(f"c{i}") for i in range(5)], call_ids_match=True)
    assert [len(w) for w in sink.writes] == [5]


def test_missed_calls_and_their_gap_finding_are_one_batch(tmp_path, monkeypatch):
    config = Config(home=tmp_path, detect=False)
    hooks_were_live(config, "c1")
    sink = CountingSink()
    monkeypatch.setattr("stationchief.pipeline.build_sinks", lambda config: [sink])
    assert common.emit_session(config, "sess-x", [rec("c1"), rec("c2"), rec("c3")], call_ids_match=True) == (2, 1, 1)
    assert len(sink.writes) == 1
    assert len(sink.writes[0]) == 3
    assert [e["class_uid"] for e in sink.writes[0]].count(2004) == 1
