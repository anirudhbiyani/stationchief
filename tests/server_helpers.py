"""Shared by the server tests: a config with one known token."""

from stationchief.server.config import ServerConfig, hash_token

TOKEN = "test-token-not-a-secret"
PRINCIPAL = "laptop-fleet"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


def server_config(**overrides) -> ServerConfig:
    values = {"tokens": {hash_token(TOKEN): PRINCIPAL}}
    values.update(overrides)
    return ServerConfig(**values)


def ocsf_event(session_id="sess-abc", command="ls -la"):
    """A real, schema-valid OCSF event, as a stationchief client would send it."""
    from stationchief.core.mapping import map_record
    from stationchief.core.records import Action, ActionKind, ActivityRecord, Actor, Decision

    return map_record(
        ActivityRecord(
            source="claude",
            session_id=session_id,
            turn_id="turn-1",
            ts=1789898400000,
            event="PreToolUse",
            actor=Actor(user_name="dev", agent_name="claude-code", agent_version="2.0.1"),
            cwd="/repo",
            hostname="laptop",
            posture={"permission_mode": "default"},
            prompt="list files",
            action=Action(tool="Bash", kind=ActionKind.SHELL, input={"command": command}),
            decision=Decision.OBSERVED,
        )
    )


def string_attr(key, value):
    return {"key": key, "value": {"stringValue": str(value)}}


def log_record(name, attributes=None, body=None, time_ms=1789898400000):
    record = {
        "timeUnixNano": str(time_ms * 1_000_000),
        "attributes": [string_attr("event.name", name)] + [string_attr(k, v) for k, v in (attributes or {}).items()],
    }
    if body is not None:
        record["body"] = {"stringValue": body}
    return record


def otlp_payload(records, resource=None):
    return {
        "resourceLogs": [
            {
                "resource": {"attributes": [string_attr(k, v) for k, v in (resource or {"service.name": "stationchief"}).items()]},
                "scopeLogs": [{"scope": {"name": "test"}, "logRecords": records}],
            }
        ]
    }
