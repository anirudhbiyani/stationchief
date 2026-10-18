import json

from stationchief.adapters import claude, codex, components, cursor
from stationchief.config import Config
from stationchief.core.mapping import map_record
from stationchief.core.records import ActionKind


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))


def claude_home(tmp_path):
    home, repo = tmp_path / "home", tmp_path / "repo"
    write_json(
        home / ".claude.json",
        {
            "mcpServers": {"github": {"command": "npx", "args": ["-y", "@acme/github-mcp"], "env": {"GITHUB_TOKEN": "ghp_leak"}}},
            "projects": {str(repo): {"mcpServers": {"db": {"url": "https://mcp.example.com/db"}}}},
        },
    )
    write_json(repo / ".mcp.json", {"mcpServers": {"linear": {"command": "linear-mcp"}}})
    write_json(home / ".claude" / "settings.json", {"enabledPlugins": {"acme@market": True, "off@market": False}})
    return home, repo


def test_claude_discovers_every_scope_and_only_enabled_plugins(tmp_path):
    home, repo = claude_home(tmp_path)
    found = components.discover("claude", home, str(repo))
    assert {(c["name"], c["kind"], c["scope"]) for c in found} == {
        ("github", "mcp_server", "user"),
        ("db", "mcp_server", "local"),
        ("linear", "mcp_server", "project"),
        ("acme@market", "plugin", "user"),
    }
    github = next(c for c in found if c["name"] == "github")
    assert github["command"] == "npx -y @acme/github-mcp"


def test_env_is_never_read(tmp_path):
    home, repo = claude_home(tmp_path)
    assert "ghp_leak" not in json.dumps(components.discover("claude", home, str(repo)))


def test_cursor_discovers_global_and_workspace_servers(tmp_path):
    home, repo = tmp_path / "home", tmp_path / "repo"
    write_json(home / ".cursor" / "mcp.json", {"mcpServers": {"global": {"command": "g"}}})
    write_json(repo / ".cursor" / "mcp.json", {"mcpServers": {"local": {"command": "l"}}})
    names = {c["name"] for c in components.discover("cursor", home, str(repo))}
    assert names == {"global", "local"}


def test_codex_discovers_servers_from_toml(tmp_path):
    home = tmp_path / "home"
    (home / ".codex").mkdir(parents=True)
    (home / ".codex" / "config.toml").write_text(
        '[mcp_servers.docs]\ncommand = "docs-mcp"\nargs = ["--stdio"]\n[mcp_servers.docs.env]\nKEY = "leak"\n'
    )
    found = components.discover("codex", home, "/repo")
    assert found == [{"name": "docs", "kind": "mcp_server", "scope": "user", "command": "docs-mcp --stdio"}]


def test_missing_and_malformed_configs_yield_nothing_rather_than_raising(tmp_path):
    home = tmp_path / "home"
    write_json(home / ".cursor" / "mcp.json", {"mcpServers": "not a mapping"})
    (home / ".claude.json").write_text("{not json")
    (home / ".codex").mkdir()
    (home / ".codex" / "config.toml").write_text("not = [toml")
    for agent in ("claude", "cursor", "codex", "unknown-agent"):
        assert components.discover(agent, home, str(tmp_path / "nowhere")) == []


def test_records_map_to_valid_6002_events(tmp_path, assert_valid_ocsf):
    home, repo = claude_home(tmp_path)
    found = components.discover("claude", home, str(repo))
    records = components.records(
        found,
        source="claude",
        agent_name="claude-code",
        model_provider="Anthropic",
        session_id="sess-abc",
        cwd=str(repo),
        hostname="laptop",
        user_name="dev",
        session_state={"model": "claude-opus-5", "agent_version": "2.0.1"},
    )
    assert all(r.action.kind == ActionKind.COMPONENT_LOAD for r in records)
    for record in records:
        event = map_record(record)
        assert_valid_ocsf(event)
        assert event["class_uid"] == 6002
        assert event["metadata"]["correlation_uid"] == "sess-abc"
    github = map_record(next(r for r in records if r.action.input["name"] == "github"))
    assert github["enrichments"][0]["data"]["component_command"] == "npx -y @acme/github-mcp"


def emitted(tmp_path):
    return [json.loads(line) for path in tmp_path.glob("events-*.ndjson") for line in path.read_text().splitlines()]


def test_claude_session_start_emits_one_6002_per_component(tmp_path, monkeypatch):
    home, repo = claude_home(tmp_path)
    monkeypatch.setenv("HOME", str(home))
    out = tmp_path / "out"
    claude.handle({"session_id": "s", "hook_event_name": "SessionStart", "cwd": str(repo)}, Config(home=out))
    assert sorted(e["application"]["name"] for e in emitted(out)) == ["acme@market", "db", "github", "linear"]


def test_cursor_session_start_emits_components(tmp_path, monkeypatch):
    home, repo = tmp_path / "home", tmp_path / "repo"
    write_json(home / ".cursor" / "mcp.json", {"mcpServers": {"global": {"command": "g"}}})
    monkeypatch.setenv("HOME", str(home))
    out = tmp_path / "out"
    cursor.handle(
        {"conversation_id": "c", "hook_event_name": "sessionStart", "workspace_roots": [str(repo)]}, Config(home=out)
    )
    assert [e["application"]["name"] for e in emitted(out)] == ["global"]


def test_codex_session_start_emits_components(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".codex").mkdir(parents=True)
    (home / ".codex" / "config.toml").write_text('[mcp_servers.docs]\ncommand = "docs-mcp"\n')
    monkeypatch.setenv("HOME", str(home))
    out = tmp_path / "out"
    codex.handle({"session_id": "s", "hook_event_name": "SessionStart"}, Config(home=out), sessions_dir=tmp_path / "none")
    assert [e["application"]["name"] for e in emitted(out)] == ["docs"]


def test_component_command_secret_never_reaches_the_sink(tmp_path, monkeypatch):
    home, repo = tmp_path / "home", tmp_path / "repo"
    secret = "sk-ant-abcdefgh12345678"
    write_json(
        home / ".claude.json",
        {"mcpServers": {"leaky": {"command": "npx", "args": ["-y", "some-mcp", "--api-key", secret]}}},
    )
    monkeypatch.setenv("HOME", str(home))
    out = tmp_path / "out"
    claude.handle({"session_id": "s", "hook_event_name": "SessionStart", "cwd": str(repo)}, Config(home=out))
    raw = "\n".join(path.read_text() for path in out.glob("events-*.ndjson"))
    assert secret not in raw


class CountingSink:
    def __init__(self):
        self.writes = []

    def write(self, events):
        self.writes.append(list(events))


def test_session_start_with_ten_servers_makes_exactly_one_sink_write(tmp_path, monkeypatch):
    # One write per hook: with the service down, each write can cost a timeout.
    home, repo = tmp_path / "home", tmp_path / "repo"
    write_json(home / ".claude.json", {"mcpServers": {f"s{i}": {"command": f"mcp-{i}"} for i in range(10)}})
    monkeypatch.setenv("HOME", str(home))
    sink = CountingSink()
    monkeypatch.setattr("stationchief.pipeline.build_sinks", lambda config: [sink])
    claude.handle({"session_id": "s", "hook_event_name": "SessionStart", "cwd": str(repo)}, Config(home=tmp_path / "out"))
    assert len(sink.writes) == 1
    assert len(sink.writes[0]) == 10


def test_cursor_and_codex_session_start_also_write_once(tmp_path, monkeypatch):
    home, repo = tmp_path / "home", tmp_path / "repo"
    write_json(home / ".cursor" / "mcp.json", {"mcpServers": {f"s{i}": {"command": "g"} for i in range(3)}})
    (home / ".codex").mkdir(parents=True)
    (home / ".codex" / "config.toml").write_text("".join(f'[mcp_servers.d{i}]\ncommand = "d"\n' for i in range(3)))
    monkeypatch.setenv("HOME", str(home))
    sink = CountingSink()
    monkeypatch.setattr("stationchief.pipeline.build_sinks", lambda config: [sink])
    config = Config(home=tmp_path / "out")
    cursor.handle({"conversation_id": "c", "hook_event_name": "sessionStart", "workspace_roots": [str(repo)]}, config)
    codex.handle({"session_id": "s", "hook_event_name": "SessionStart"}, config, sessions_dir=tmp_path / "none")
    assert [len(w) for w in sink.writes] == [3, 3]
