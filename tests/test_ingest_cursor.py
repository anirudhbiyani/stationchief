import json
import pathlib
import sqlite3

import pytest

from stationchief import state
from stationchief.config import Config
from stationchief.core.mapping import map_record
from stationchief.core.records import ActionKind, Decision
from stationchief.ingest import cursor

FIXTURE = json.loads((pathlib.Path(__file__).parent / "fixtures" / "cursor" / "workspace_trace.json").read_text())
NOW = 1789902000000  # 2026-09-20T11:00Z, an hour after the conversation


def make_user_dir(tmp_path, fixture=FIXTURE, with_headers=True):
    """Build a Cursor user directory with a real state.vscdb in Cursor's layout."""
    user = tmp_path / "Cursor" / "User"
    (user / "globalStorage").mkdir(parents=True)
    workspace = user / "workspaceStorage" / fixture["header"]["workspaceId"]
    workspace.mkdir(parents=True)
    (workspace / "workspace.json").write_text(json.dumps({"folder": fixture["workspace_folder"]}))
    conn = sqlite3.connect(user / "globalStorage" / "state.vscdb")
    conn.execute("CREATE TABLE cursorDiskKV (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB)")
    composer_id = fixture["composer"]["composerId"]
    conn.execute("INSERT INTO cursorDiskKV VALUES (?, ?)", (f"composerData:{composer_id}", json.dumps(fixture["composer"])))
    for bubble_id, bubble in fixture["bubbles"].items():
        conn.execute("INSERT INTO cursorDiskKV VALUES (?, ?)", (f"bubbleId:{composer_id}:{bubble_id}", json.dumps(bubble)))
    if with_headers:
        conn.execute(
            "CREATE TABLE composerHeaders (composerId TEXT PRIMARY KEY, workspaceId TEXT, createdAt INTEGER,"
            " lastUpdatedAt INTEGER, isArchived INTEGER, isSubagent INTEGER, recency INTEGER, checkpointAt INTEGER, value TEXT)"
        )
        conn.execute(
            "INSERT INTO composerHeaders (composerId, workspaceId, lastUpdatedAt) VALUES (?, ?, ?)",
            (composer_id, fixture["header"]["workspaceId"], fixture["header"]["lastUpdatedAt"]),
        )
    conn.commit()
    conn.close()
    return user


def records(tmp_path, monkeypatch, **kwargs):
    """Run a real ingest and return the records it handed to emit_session."""
    config = Config(home=tmp_path / "home", detect=False)
    user = make_user_dir(tmp_path, **kwargs)
    # Fixed identity: goldens must not depend on (or leak) the machine they ran on.
    monkeypatch.setattr(cursor.socket, "gethostname", lambda: "laptop")
    monkeypatch.setattr(cursor.common, "user_name", lambda: "dev")
    captured = []
    original = cursor.common.emit_session

    def capture(config, session_id, recs, *, call_ids_match):
        captured.extend(recs)
        return original(config, session_id, recs, call_ids_match=call_ids_match)

    monkeypatch.setattr(cursor.common, "emit_session", capture)
    cursor.ingest(config, user, now_ms=NOW)
    return captured


def events(home):
    return [json.loads(l) for p in home.glob("events-*.ndjson") for l in p.read_text().splitlines()]


def test_extracts_every_tool_call_and_nothing_else(tmp_path, monkeypatch):
    recs = records(tmp_path, monkeypatch)
    assert [r.posture["tool_call_id"] for r in recs] == ["toolu_1", "toolu_2", "toolu_3", "toolu_4", "toolu_5"]
    assert [r.action.kind for r in recs] == [
        ActionKind.SHELL, ActionKind.FILE_READ, ActionKind.FILE_UPDATE, ActionKind.MCP_CALL, ActionKind.SHELL,
    ]


def test_user_decisions_carry_through(tmp_path, monkeypatch):
    recs = records(tmp_path, monkeypatch)
    assert recs[0].decision == Decision.ALLOWED
    assert recs[1].decision == Decision.OBSERVED
    assert recs[4].decision == Decision.DENIED


def test_prompt_model_workspace_and_sandbox(tmp_path, monkeypatch):
    shell = records(tmp_path, monkeypatch)[0]
    assert shell.prompt == "clean up the build"
    assert shell.turn_id == "b1"
    assert shell.session_id == "conv-1"
    assert shell.actor.model == "claude-opus-5"
    assert shell.cwd == "/repo"
    assert shell.action.input["command"] == "rm -rf build"
    assert shell.posture["sandbox"] == "workspace_readwrite"
    assert shell.posture["capture"] == "transcript"
    assert shell.ts == 1789898405000


def test_relative_paths_resolve_against_the_workspace(tmp_path, monkeypatch):
    recs = records(tmp_path, monkeypatch)
    assert recs[1].action.input["file_path"] == "/repo/src/app.py"
    assert recs[2].action.input["file_path"] == "/repo/src/app.py"


def test_status_error_and_cancelled_are_failures(tmp_path, monkeypatch):
    recs = records(tmp_path, monkeypatch)
    assert recs[2].action.status == "failure"
    assert (recs[4].action.status, recs[4].action.error) == ("failure", "cancelled")


def test_mcp_calls_are_renamed_to_the_shared_convention(tmp_path, monkeypatch):
    mcp = records(tmp_path, monkeypatch)[3]
    assert mcp.action.tool == "mcp__github__create_issue"
    assert mcp.action.input == {"title": "bug"}


def test_goldens(tmp_path, monkeypatch, assert_golden):
    names = ("trace_shell_accepted", "trace_read", "trace_edit_failed", "trace_mcp", "trace_shell_rejected")
    for name, record in zip(names, records(tmp_path, monkeypatch)):
        assert_golden("cursor", name, map_record(record))


def test_ingest_backfills_then_is_idempotent(tmp_path):
    user = make_user_dir(tmp_path)
    config = Config(home=tmp_path / "home", detect=False)
    assert cursor.ingest(config, user, now_ms=NOW) == (5, 0, 0)
    assert cursor.ingest(config, user, now_ms=NOW) == (0, 0, 0)
    assert len(events(config.home)) == 5


def test_a_resumed_conversation_emits_only_new_calls_with_the_old_prompt(tmp_path):
    user = make_user_dir(tmp_path)
    config = Config(home=tmp_path / "home", detect=False)
    cursor.ingest(config, user, now_ms=NOW)
    conn = sqlite3.connect(user / "globalStorage" / "state.vscdb")
    composer = dict(FIXTURE["composer"])
    composer["fullConversationHeadersOnly"] = composer["fullConversationHeadersOnly"] + [{"bubbleId": "b8", "type": 2}]
    conn.execute("INSERT INTO cursorDiskKV VALUES (?, ?)", ("composerData:conv-1", json.dumps(composer)))
    b8 = {"_v": 3, "type": 2, "bubbleId": "b8", "createdAt": "2026-09-20T10:01:00.000Z",
          "toolFormerData": {"name": "run_terminal_command_v2", "toolCallId": "toolu_6", "status": "completed", "params": {"command": "ls"}}}
    conn.execute("INSERT INTO cursorDiskKV VALUES (?, ?)", ("bubbleId:conv-1:b8", json.dumps(b8)))
    conn.commit()
    conn.close()
    assert cursor.ingest(config, user, now_ms=NOW) == (1, 0, 0)
    assert events(config.home)[-1]["message_context"]["prompt_text"] == "clean up the build"


def test_an_active_conversation_is_left_to_the_hooks(tmp_path):
    user = make_user_dir(tmp_path)
    config = Config(home=tmp_path / "home", detect=False)
    assert cursor.ingest(config, user, now_ms=FIXTURE["header"]["lastUpdatedAt"] + 60_000) == (0, 0, 0)


def test_works_without_the_composer_headers_table(tmp_path, monkeypatch):
    recs = records(tmp_path, monkeypatch, with_headers=False)
    assert len(recs) == 5
    assert recs[1].action.input["file_path"] == "src/app.py", "no workspace known, so the path stays relative"


def test_unknown_bubble_versions_are_skipped_and_logged(tmp_path, monkeypatch):
    fixture = json.loads(json.dumps(FIXTURE))
    fixture["bubbles"]["b3"]["_v"] = 99
    recs = records(tmp_path, monkeypatch, fixture=fixture)
    assert "toolu_2" not in [r.posture["tool_call_id"] for r in recs]
    assert "bubble version 99" in (tmp_path / "home" / "errors.log").read_text()


def test_calls_the_hooks_captured_are_not_repeated_and_missed_ones_are_gaps(tmp_path):
    user = make_user_dir(tmp_path)
    config = Config(home=tmp_path / "home", detect=False)
    state.update(config, "conv-1", prompt="clean up the build")
    for call_id in ("toolu_1", "toolu_2", "toolu_3", "toolu_4"):
        state.mark_seen(config, "conv-1", call_id, 0)
    assert cursor.ingest(config, user, now_ms=NOW) == (1, 4, 1)


def test_the_database_is_never_modified(tmp_path):
    user = make_user_dir(tmp_path)
    db = user / "globalStorage" / "state.vscdb"
    before = db.read_bytes()
    cursor.ingest(Config(home=tmp_path / "home", detect=False), user, now_ms=NOW)
    assert db.read_bytes() == before


def test_a_missing_cursor_install_is_not_an_error(tmp_path):
    assert cursor.ingest(Config(home=tmp_path), tmp_path / "nope", now_ms=NOW) == (0, 0, 0)


def test_a_db_with_no_tables_is_logged_and_not_raised(tmp_path):
    user = tmp_path / "Cursor" / "User"
    (user / "globalStorage").mkdir(parents=True)
    sqlite3.connect(user / "globalStorage" / "state.vscdb").close()  # valid, empty sqlite file
    config = Config(home=tmp_path / "home", detect=False)
    assert cursor.ingest(config, user, now_ms=NOW) == (0, 0, 0)
    assert "cannot read" in (tmp_path / "home" / "errors.log").read_text()


def test_a_corrupt_db_file_is_logged_and_not_raised(tmp_path):
    user = tmp_path / "Cursor" / "User"
    (user / "globalStorage").mkdir(parents=True)
    (user / "globalStorage" / "state.vscdb").write_bytes(b"not a database")
    config = Config(home=tmp_path / "home", detect=False)
    assert cursor.ingest(config, user, now_ms=NOW) == (0, 0, 0)
    assert "cannot read" in (tmp_path / "home" / "errors.log").read_text()


def test_a_locked_db_is_logged_and_not_raised(tmp_path):
    user = make_user_dir(tmp_path)
    db_path = user / "globalStorage" / "state.vscdb"
    locker = sqlite3.connect(db_path, isolation_level=None)
    locker.execute("BEGIN EXCLUSIVE")
    try:
        config = Config(home=tmp_path / "home", detect=False)
        assert cursor.ingest(config, user, now_ms=NOW) == (0, 0, 0)
        assert "locked" in (tmp_path / "home" / "errors.log").read_text()
    finally:
        locker.rollback()
        locker.close()


@pytest.mark.parametrize(
    "bubble_name, server",
    # Bubble names seen in a real Cursor store; params name the tool exactly.
    [("mcp_cloud-engineer_list_resources", "cloud-engineer"), ("mcp-cloud-engineer-mcp-set_context", "cloud-engineer-mcp"), ("mcp", "cloud-engineer")],
)
def test_type_19_mcp_calls_are_named_from_params(bubble_name, server):
    from stationchief.ingest.cursor import _tool_call

    tool = {
        "tool": 19,
        "name": bubble_name,
        "params": json.dumps({"tools": [{"name": "list_resources", "serverName": server, "parameters": "{}"}]}),
        "rawArgs": json.dumps({"provider": "aws"}),
    }
    assert _tool_call(tool, "/repo") == (f"mcp__{server}__list_resources", ActionKind.MCP_CALL, {"provider": "aws"})


def test_calls_a_summary_dropped_from_the_headers_are_still_read_and_new_ones_too(tmp_path):
    """Seen on a real store: summarising drops early messages from
    fullConversationHeadersOnly, so the list shrinks while the store grows."""
    user = make_user_dir(tmp_path)
    config = Config(home=tmp_path / "home", detect=False)
    assert cursor.ingest(config, user, now_ms=NOW) == (5, 0, 0)
    conn = sqlite3.connect(user / "globalStorage" / "state.vscdb")
    composer = dict(FIXTURE["composer"])
    b9 = {"_v": 3, "type": 2, "bubbleId": "b9", "createdAt": "2026-09-20T10:02:00.000Z",
          "toolFormerData": {"name": "run_terminal_command_v2", "toolCallId": "toolu_9", "status": "completed", "params": {"command": "make"}}}
    composer["fullConversationHeadersOnly"] = [{"bubbleId": "b9", "type": 2}]  # summarised: one header left
    conn.execute("INSERT INTO cursorDiskKV VALUES (?, ?)", ("composerData:conv-1", json.dumps(composer)))
    conn.execute("INSERT INTO cursorDiskKV VALUES (?, ?)", ("bubbleId:conv-1:b9", json.dumps(b9)))
    conn.commit()
    conn.close()
    assert cursor.ingest(config, user, now_ms=NOW) == (1, 0, 0), "only the new call; the dropped ones were already emitted"
    assert [e["process"]["cmd_line"] for e in events(config.home) if e["class_uid"] == 1007][-1] == "make"


def test_a_conversation_read_only_from_dropped_messages_keeps_the_prompts(tmp_path, monkeypatch):
    fixture = json.loads(json.dumps(FIXTURE))
    fixture["composer"]["fullConversationHeadersOnly"] = []  # everything summarised away
    recs = records(tmp_path, monkeypatch, fixture=fixture)
    assert len(recs) == 5
    assert all(r.prompt for r in recs)
