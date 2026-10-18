import json

import pytest

from stationchief import install


def test_install_creates_the_config_file(tmp_path):
    path = tmp_path / "settings.json"
    assert install.install("claude", config_path=path, command="stationchief hook claude") is True
    settings = json.loads(path.read_text())
    assert "PreToolUse" in settings["hooks"]


def test_installed_command_carries_the_signature(tmp_path):
    path = tmp_path / "settings.json"
    install.install("claude", config_path=path, command="stationchief hook claude")
    serialized = path.read_text()
    assert install.SIGNATURE in serialized


def test_install_is_idempotent(tmp_path):
    path = tmp_path / "settings.json"
    install.install("claude", config_path=path, command="stationchief hook claude")
    first = path.read_text()
    assert install.install("claude", config_path=path, command="stationchief hook claude") is False
    assert path.read_text() == first


def test_install_preserves_unrelated_settings(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"model": "opus", "hooks": {"Stop": [{"hooks": [{"type": "command", "command": "mine.sh"}]}]}}))
    install.install("claude", config_path=path, command="stationchief hook claude")
    settings = json.loads(path.read_text())
    assert settings["model"] == "opus"
    assert any(
        entry["hooks"][0]["command"] == "mine.sh" for entry in settings["hooks"]["Stop"]
    )


def test_uninstall_removes_only_our_hooks(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "mine.sh"}]}]}}))
    install.install("claude", config_path=path, command="stationchief hook claude")
    assert install.uninstall("claude", config_path=path) is True
    settings = json.loads(path.read_text())
    commands = [h["command"] for entry in settings["hooks"]["PreToolUse"] for h in entry["hooks"]]
    assert commands == ["mine.sh"]
    assert install.SIGNATURE not in path.read_text()


def test_uninstall_on_a_clean_config_is_a_no_op(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"model": "opus"}))
    assert install.uninstall("claude", config_path=path) is False
    assert json.loads(path.read_text()) == {"model": "opus"}


def test_install_then_uninstall_restores_the_original_file(tmp_path):
    path = tmp_path / "settings.json"
    # Keys deliberately out of order: the user's layout must survive, byte for byte.
    original = {"model": "opus", "hooks": {"Stop": [{"hooks": [{"type": "command", "command": "mine.sh"}]}]}, "env": {}}
    path.write_text(json.dumps(original, indent=2) + "\n")
    install.install("claude", config_path=path, command="stationchief hook claude")
    install.uninstall("claude", config_path=path)
    assert path.read_text() == json.dumps(original, indent=2) + "\n"


def test_malformed_existing_config_raises_rather_than_silently_overwriting(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text("{not json")
    with pytest.raises(ValueError, match="could not be parsed"):
        install.install("claude", config_path=path, command="stationchief hook claude")


@pytest.mark.parametrize("agent", ["claude", "cursor", "codex"])
def test_every_agent_installs_and_uninstalls_cleanly(agent, tmp_path):
    path = tmp_path / f"{agent}.json"
    assert install.install(agent, config_path=path, command=f"stationchief hook {agent}") is True
    assert install.install(agent, config_path=path, command=f"stationchief hook {agent}") is False
    assert install.uninstall(agent, config_path=path) is True
    assert install.SIGNATURE not in path.read_text()


def test_unknown_agent_is_rejected(tmp_path):
    with pytest.raises(KeyError):
        install.install("copilot", config_path=tmp_path / "x.json", command="x")


def test_cursor_subscribes_only_to_the_generic_hook_pair():
    events = install.AGENTS["cursor"].events
    assert "preToolUse" in events and "postToolUse" in events
    assert "beforeShellExecution" not in events, "granular hooks double-fire; see adapters/cursor.py"


def test_cursor_install_writes_flat_entries_with_version(tmp_path):
    """Cursor's flat hook format with version: 1."""
    path = tmp_path / "cursor.json"
    assert install.install("cursor", config_path=path, command="stationchief hook cursor") is True
    settings = json.loads(path.read_text())
    # Check version is set
    assert settings["version"] == 1
    # Check flat entries (not nested with "hooks" and "type")
    for event in install.AGENTS["cursor"].events:
        assert event in settings["hooks"]
        for entry in settings["hooks"][event]:
            assert "command" in entry
            assert "type" not in entry
            assert "hooks" not in entry
            assert install.SIGNATURE in entry["command"]


def test_cursor_install_preserves_existing_version_and_user_hooks(tmp_path):
    """Cursor should preserve existing version and user's flat entries."""
    path = tmp_path / "cursor.json"
    original = {
        "version": 2,
        "hooks": {
            "preToolUse": [
                {"command": "user_hook.sh"}
            ]
        }
    }
    path.write_text(json.dumps(original, indent=2, sort_keys=True))
    assert install.install("cursor", config_path=path, command="stationchief hook cursor") is True
    settings = json.loads(path.read_text())
    # Version should remain as it was
    assert settings["version"] == 2
    # User hook should still be there
    assert any(
        entry["command"] == "user_hook.sh" for entry in settings["hooks"]["preToolUse"]
    )
    # Our hook should also be there
    assert any(
        install.SIGNATURE in entry["command"] for entry in settings["hooks"]["preToolUse"]
    )


def test_cursor_uninstall_removes_only_our_flat_entries(tmp_path):
    """Cursor uninstall should only remove our flat entries, preserving user's."""
    path = tmp_path / "cursor.json"
    path.write_text(json.dumps({
        "version": 1,
        "hooks": {
            "preToolUse": [
                {"command": "user_hook.sh"}
            ]
        }
    }))
    install.install("cursor", config_path=path, command="stationchief hook cursor")
    assert install.uninstall("cursor", config_path=path) is True
    settings = json.loads(path.read_text())
    # User hook should still be there
    commands = [entry["command"] for entry in settings["hooks"]["preToolUse"]]
    assert commands == ["user_hook.sh"]
    assert install.SIGNATURE not in path.read_text()


def test_codex_install_writes_nested_entries(tmp_path):
    """Codex should write nested hook format like Claude."""
    path = tmp_path / "codex.json"
    assert install.install("codex", config_path=path, command="stationchief hook codex") is True
    settings = json.loads(path.read_text())
    # Check nested format
    for event in install.AGENTS["codex"].events:
        assert event in settings["hooks"]
        for entry in settings["hooks"][event]:
            # Nested format has "hooks" list with "type" and "command"
            assert "hooks" in entry
            for hook in entry["hooks"]:
                assert hook["type"] == "command"
                assert install.SIGNATURE in hook["command"]
    # Codex should not have version at top level (unlike cursor)
    assert "version" not in settings


@pytest.mark.parametrize("agent", ["claude", "cursor", "codex"])
def test_reinstall_with_a_changed_command_replaces_ours_and_keeps_the_users(agent, tmp_path):
    path = tmp_path / "settings.json"
    event = install.AGENTS[agent].events[0]
    user = {"command": "mine.sh"} if install.AGENTS[agent].style == "flat" else {"hooks": [{"type": "command", "command": "mine.sh"}]}
    path.write_text(json.dumps({"hooks": {event: [user]}}))
    install.install(agent, config_path=path, command="/old/python -m stationchief.cli hook x")
    assert install.install(agent, config_path=path, command="/new/python -m stationchief.cli hook x") is True
    text = path.read_text()
    assert "/old/python" not in text
    hooks = json.loads(text)["hooks"]
    for name in install.AGENTS[agent].events:
        commands = [
            e["command"] if "command" in e else h["command"]
            for e in hooks[name]
            for h in (e.get("hooks") or [e])
        ]
        assert sum("/new/python" in c for c in commands) == 1
    assert user in hooks[event]
    assert install.install(agent, config_path=path, command="/new/python -m stationchief.cli hook x") is False


def test_reinstall_keeps_a_users_hook_that_shares_an_entry_with_ours(tmp_path):
    path = tmp_path / "settings.json"
    install.install("claude", config_path=path, command="/old/python hook")
    settings = json.loads(path.read_text())
    settings["hooks"]["Stop"][0]["hooks"].append({"type": "command", "command": "mine.sh"})
    path.write_text(json.dumps(settings))
    install.install("claude", config_path=path, command="/new/python hook")
    commands = [h["command"] for e in json.loads(path.read_text())["hooks"]["Stop"] for h in e["hooks"]]
    assert "mine.sh" in commands
    assert not any("/old/python" in c for c in commands)
    assert sum("/new/python" in c for c in commands) == 1


@pytest.mark.parametrize("content", ["[1, 2]", "null", '{"hooks": []}', '{"hooks": "x"}'])
def test_install_refuses_a_file_whose_shape_is_not_ours_to_guess(tmp_path, content):
    path = tmp_path / "settings.json"
    path.write_text(content)
    with pytest.raises(ValueError, match="refusing to overwrite"):
        install.install("claude", config_path=path, command="stationchief hook claude")
    assert path.read_text() == content


def test_install_writes_atomically_and_keeps_the_file_mode(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text("{}")
    path.chmod(0o600)
    install.install("claude", config_path=path, command="stationchief hook claude")
    assert path.stat().st_mode & 0o777 == 0o600
    assert [p.name for p in tmp_path.iterdir()] == ["settings.json"]  # no temp file left


@pytest.mark.parametrize(
    "agent,event,flag",
    [("claude", "PreToolUse", {"onFailure": "block"}), ("cursor", "preToolUse", {"failClosed": True})],
)
def test_fail_closed_sets_the_agents_own_switch_on_the_pre_tool_hook_only(agent, event, flag, tmp_path):
    path = tmp_path / "settings.json"
    install.install(agent, config_path=path, command="stationchief hook x", fail_closed=True)
    text = path.read_text()
    hooks = json.loads(text)["hooks"]
    pre = hooks[event][0]
    pre = pre["hooks"][0] if "hooks" in pre else pre
    assert flag.items() <= pre.items()
    assert text.count(next(iter(flag))) == 1, "only the pre-tool hook carries it"
    # Toggling it rewrites the entry; repeating it does not.
    assert install.install(agent, config_path=path, command="stationchief hook x", fail_closed=True) is False
    assert install.install(agent, config_path=path, command="stationchief hook x") is True
    assert next(iter(flag)) not in path.read_text()


def test_codex_has_no_fail_closed_switch(tmp_path):
    path = tmp_path / "codex.json"
    install.install("codex", config_path=path, command="stationchief hook codex", fail_closed=True)
    assert "onFailure" not in path.read_text() and "failClosed" not in path.read_text()
