import json
import pathlib
import subprocess
import sys
import time

import pytest

from stationchief.cli import main


def test_version_prints_the_version(capsys):
    assert main(["version"]) == 0
    assert capsys.readouterr().out.strip() == __import__("stationchief").__version__


def test_hook_reads_stdin_and_writes_a_response(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("STATIONCHIEF_HOME", str(tmp_path))
    payload = json.dumps(
        {
            "session_id": "sess-abc",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
            "cwd": "/repo",
        }
    )
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO(payload))
    assert main(["hook", "claude"]) == 0
    assert json.loads(capsys.readouterr().out) == {"continue": True, "suppressOutput": True}
    assert list(tmp_path.glob("events-*.ndjson"))


def test_hook_exits_zero_on_unparseable_stdin(tmp_path, monkeypatch):
    monkeypatch.setenv("STATIONCHIEF_HOME", str(tmp_path))
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO("{not json"))
    assert main(["hook", "claude"]) == 0


def test_deeply_nested_stdin_is_treated_as_invalid_json_not_a_hook_failure(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("STATIONCHIEF_HOME", str(tmp_path))
    # Deep enough that json.loads raises RecursionError, not ValueError.
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO("[" * 1_000_000 + "]" * 1_000_000))
    assert main(["hook", "claude"]) == 0
    assert json.loads(capsys.readouterr().out) == {"continue": True, "suppressOutput": True}
    log = tmp_path / "errors.log"
    assert "hook claude failed" not in (log.read_text() if log.exists() else "")


def test_install_into_a_non_object_file_fails_cleanly(tmp_path, capsys):
    path = tmp_path / "settings.json"
    path.write_text('{"hooks": []}')
    assert main(["install", "claude", "--config-path", str(path)]) == 1
    err = capsys.readouterr().err
    assert "refusing to overwrite" in err and "Traceback" not in err


def test_hook_exits_zero_on_empty_stdin(tmp_path, monkeypatch):
    monkeypatch.setenv("STATIONCHIEF_HOME", str(tmp_path))
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO(""))
    assert main(["hook", "claude"]) == 0


def test_hook_exits_zero_even_when_the_pipeline_explodes(tmp_path, monkeypatch):
    monkeypatch.setenv("STATIONCHIEF_HOME", str(tmp_path))
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO('{"hook_event_name":"PreToolUse"}'))
    monkeypatch.setattr("stationchief.adapters.claude.emit_checked", lambda *a, **k: 1 / 0)
    assert main(["hook", "claude"]) == 0


def test_codex_hook_response_is_empty(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("STATIONCHIEF_HOME", str(tmp_path))
    monkeypatch.setattr(
        "sys.stdin",
        __import__("io").StringIO('{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"shell","tool_input":{"command":["ls"]}}'),
    )
    assert main(["hook", "codex"]) == 0
    assert json.loads(capsys.readouterr().out) == {}


def test_install_and_uninstall_round_trip(tmp_path, capsys):
    path = tmp_path / "settings.json"
    assert main(["install", "claude", "--config-path", str(path)]) == 0
    assert "installed" in capsys.readouterr().out
    assert main(["uninstall", "claude", "--config-path", str(path)]) == 0
    from stationchief.install import SIGNATURE

    assert SIGNATURE not in path.read_text()


def test_install_accepts_several_agents(tmp_path, capsys):
    assert main(["install", "claude", "cursor", "--config-path", str(tmp_path / "s.json")]) == 0


def test_unknown_agent_is_an_error(tmp_path):
    assert main(["hook", "copilot"]) == 0, "even an unknown agent must not fail a hook"


def test_hook_exits_zero_when_config_building_itself_raises(tmp_path, monkeypatch, capsys):
    fake_home = tmp_path / "fakehome"
    fake_home.mkdir()
    monkeypatch.setenv("STATIONCHIEF_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setattr(
        "sys.stdin",
        __import__("io").StringIO(
            '{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"},"cwd":"/repo"}'
        ),
    )

    def _raise():
        raise RuntimeError("boom")

    monkeypatch.setattr("stationchief.cli._config", _raise)
    assert main(["hook", "claude"]) == 0
    assert json.loads(capsys.readouterr().out) == {}

    # Verify that errors were logged to STATIONCHIEF_HOME, not the real home
    errors_log = tmp_path / "errors.log"
    assert errors_log.exists(), f"errors.log should exist at {errors_log}"
    content = errors_log.read_text()
    assert "boom" in content, f"errors.log should contain 'boom', got: {content}"

    # Verify that the real home's .stationchief directory was NOT created
    real_home_stationchief = fake_home / ".stationchief"
    assert not real_home_stationchief.exists(), f"{real_home_stationchief} should not exist"


def test_ingest_runs_each_requested_agent(tmp_path, monkeypatch, capsys):
    import os
    import shutil

    monkeypatch.setenv("STATIONCHIEF_HOME", str(tmp_path / "home"))
    sessions = tmp_path / "sessions" / "2026" / "09" / "20"
    sessions.mkdir(parents=True)
    rollout = sessions / "rollout-test.jsonl"
    shutil.copy(pathlib.Path(__file__).parent / "fixtures" / "codex" / "rollout_session.jsonl", rollout)
    an_hour_ago = time.time() - 3600
    os.utime(rollout, (an_hour_ago, an_hour_ago))
    code = main(["ingest", "codex", "cursor", "--codex-dir", str(tmp_path / "sessions"), "--cursor-dir", str(tmp_path / "none")])
    out = capsys.readouterr().out
    assert code == 0
    assert "codex: emitted 3" in out
    assert "cursor: emitted 0" in out


@pytest.mark.perf
def test_hook_cold_start_stays_within_the_latency_budget(tmp_path):
    """PreToolUse runs in the agent's critical path. The spec budgets 30-50ms.

    The ceiling here is generous because CI machines are noisy; the point is to
    catch a heavy import sneaking into the hook path, not to benchmark.
    """
    payload = '{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"},"cwd":"/repo"}'
    env = {"STATIONCHIEF_HOME": str(tmp_path), "PATH": "/usr/bin:/bin"}
    durations = []
    for _ in range(5):
        start = time.perf_counter()
        subprocess.run(
            [sys.executable, "-c", "from stationchief.cli import main; main(['hook','claude'])"],
            input=payload,
            text=True,
            capture_output=True,
            env=env,
        )
        durations.append((time.perf_counter() - start) * 1000)
    best = min(durations)
    print(f"\nhook cold start: best {best:.0f}ms of {len(durations)} runs")
    assert best < 250, f"hook cold start regressed to {best:.0f}ms"


def test_installed_hook_command_quotes_an_interpreter_path_with_a_space(tmp_path, monkeypatch):
    import shlex

    interpreter = "/Users/Jane Doe/venv/bin/python"
    monkeypatch.setattr("sys.executable", interpreter)
    path = tmp_path / "settings.json"
    assert main(["install", "claude", "--config-path", str(path)]) == 0
    command = json.loads(path.read_text())["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    argv = shlex.split(command, comments=True)
    assert argv[:5] == [interpreter, "-m", "stationchief.cli", "hook", "claude"]


PRE_TOOL = json.dumps(
    {"session_id": "s", "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "rm -rf /"}}
)


def test_the_stdout_sink_never_corrupts_the_hook_response(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("STATIONCHIEF_HOME", str(tmp_path))
    (tmp_path / "config.json").write_text(json.dumps({"sinks": ["stdout"]}))
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO(PRE_TOOL))
    assert main(["hook", "claude"]) == 0
    captured = capsys.readouterr()
    assert captured.out.count("\n") == 1
    assert json.loads(captured.out) == {"continue": True, "suppressOutput": True}
    # The events still go somewhere visible: stderr.
    assert [json.loads(line)["class_uid"] for line in captured.err.splitlines()]


class BrokenStdout:
    def write(self, text):
        raise BrokenPipeError()

    def flush(self):
        raise BrokenPipeError()

    def fileno(self):
        raise OSError("no fd")


def test_a_broken_pipe_on_the_response_still_exits_zero(tmp_path, monkeypatch):
    monkeypatch.setenv("STATIONCHIEF_HOME", str(tmp_path))
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO(PRE_TOOL))
    monkeypatch.setattr("sys.stdout", BrokenStdout())
    assert main(["hook", "claude"]) == 0


def test_a_broken_pipe_on_the_fallback_response_still_exits_zero(tmp_path, monkeypatch):
    monkeypatch.setenv("STATIONCHIEF_HOME", str(tmp_path))
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO(PRE_TOOL))
    monkeypatch.setattr("stationchief.adapters.claude.handle", lambda *a, **k: 1 / 0)
    monkeypatch.setattr("sys.stdout", BrokenStdout())
    assert main(["hook", "claude"]) == 0
    assert main(["hook", "nosuchagent"]) == 0
