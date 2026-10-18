"""deploy/managed/ must match what the installer writes, so IT never ships a stale hook list."""

import json
import pathlib
import tomllib

import pytest

from stationchief import install

MANAGED = pathlib.Path(__file__).parent.parent / "deploy" / "managed"
PYTHON = "/opt/stationchief/venv/bin/python"


@pytest.mark.parametrize("agent, name", [("claude", "claude-managed-settings.json"), ("cursor", "cursor-hooks.json")])
def test_managed_json_matches_the_installer(agent, name, tmp_path):
    expected = tmp_path / name
    install.install(agent, config_path=expected, command=f"{PYTHON} -m stationchief.cli hook {agent}", fail_closed=True)
    assert json.loads((MANAGED / name).read_text()) == json.loads(expected.read_text())


def test_managed_codex_toml_matches_the_installer(tmp_path):
    expected = tmp_path / "hooks.json"
    install.install("codex", config_path=expected, command=f"{PYTHON} -m stationchief.cli hook codex")
    managed = tomllib.loads((MANAGED / "codex-requirements.toml").read_text())
    assert managed["features"]["hooks"] is True
    assert {event: entries for event, entries in managed["hooks"].items() if event != "managed_dir"} == json.loads(
        expected.read_text()
    )["hooks"]
    assert managed["hooks"]["managed_dir"] == "/opt/stationchief"
