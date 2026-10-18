"""Discover the MCP servers and plugins an agent loads, for OCSF 6002.

No hook payload lists them, so SessionStart reads the agent's own config files.
Every reader returns [] on any failure, since a missing or malformed config is
normal. Only name, command and scope are taken. `env` and `headers`, where MCP
credentials live, are never read.

Known limit: this reports what the config says will load, not what actually connected.
A server that fails to start still appears. That is the right side to err on for
supply-chain visibility.
"""

import json
import pathlib
import time
import tomllib

from stationchief.core.records import Action, ActionKind, ActivityRecord, Actor, Decision


def _json(path) -> dict:
    try:
        data = json.loads(pathlib.Path(path).read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _toml(path) -> dict:
    try:
        return tomllib.loads(pathlib.Path(path).read_text())
    except (OSError, ValueError):
        return {}


def _servers(mapping, scope: str) -> list[dict]:
    if not isinstance(mapping, dict):
        return []
    found = []
    for name, spec in mapping.items():
        spec = spec if isinstance(spec, dict) else {}
        args = spec.get("args") if isinstance(spec.get("args"), list) else []
        command = " ".join(str(part) for part in [spec.get("command") or spec.get("url") or "", *args]).strip()
        found.append({"name": str(name), "kind": "mcp_server", "scope": scope, "command": command})
    return found


def _claude(home: pathlib.Path, cwd: str) -> list[dict]:
    user = _json(home / ".claude.json")
    project_entry = (user.get("projects") or {}).get(cwd) if isinstance(user.get("projects"), dict) else None
    found = _servers(user.get("mcpServers"), "user")
    found += _servers(project_entry.get("mcpServers") if isinstance(project_entry, dict) else None, "local")
    found += _servers(_json(pathlib.Path(cwd) / ".mcp.json").get("mcpServers"), "project")
    plugins = _json(home / ".claude" / "settings.json").get("enabledPlugins")
    if isinstance(plugins, dict):
        found += [
            {"name": str(name), "kind": "plugin", "scope": "user", "command": ""}
            for name, enabled in plugins.items()
            if enabled is True
        ]
    return found


def _cursor(home: pathlib.Path, cwd: str) -> list[dict]:
    return _servers(_json(home / ".cursor" / "mcp.json").get("mcpServers"), "user") + _servers(
        _json(pathlib.Path(cwd) / ".cursor" / "mcp.json").get("mcpServers"), "project"
    )


def _codex(home: pathlib.Path, cwd: str) -> list[dict]:
    return _servers(_toml(home / ".codex" / "config.toml").get("mcp_servers"), "user")


_READERS = {"claude": _claude, "cursor": _cursor, "codex": _codex}


def discover(agent: str, home, cwd: str) -> list[dict]:
    reader = _READERS.get(agent)
    if reader is None:
        return []
    try:
        return reader(pathlib.Path(home), cwd or "")
    except BaseException:
        return []


def records(found, *, source, agent_name, model_provider, session_id, cwd, hostname, user_name, session_state):
    """One COMPONENT_LOAD record per discovered component.

    Kind, scope and command have no ratified field on 6002's `application`
    object, so they ride in the posture enrichment (plan amendment A2).
    """
    model = session_state.get("model")
    actor = Actor(
        user_name=user_name,
        agent_name=agent_name,
        agent_version=session_state.get("agent_version") or "unknown",
        model=model,
        model_provider=model_provider if model else None,
        pid=None,
    )
    now = int(time.time() * 1000)
    base_posture = dict(session_state.get("posture") or {})
    return [
        ActivityRecord(
            source=source,
            session_id=session_id,
            turn_id=None,
            ts=now,
            event="SessionStart",
            actor=actor,
            cwd=cwd,
            hostname=hostname,
            posture={
                **base_posture,
                "component_kind": item["kind"],
                "component_scope": item["scope"],
                "component_command": item["command"],
            },
            prompt=None,
            action=Action(tool=f"{item['kind']}_load", kind=ActionKind.COMPONENT_LOAD, input=dict(item)),
            decision=Decision.OBSERVED,
        )
        for item in found
    ]
