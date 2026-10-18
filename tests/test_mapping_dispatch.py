import pytest

from stationchief.core.mapping import map_application_lifecycle, map_record
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
        source="claude",
        session_id="sess-abc",
        turn_id="turn-1",
        ts=1758326400000,
        event="SessionStart",
        actor=ACTOR,
        cwd="/repo",
        hostname="laptop",
        posture={"permission_mode": "default"},
        prompt=None,
        action=action,
        decision=Decision.OBSERVED,
    )


def test_mcp_server_connect_maps_to_application_lifecycle_start(assert_valid_ocsf):
    event = map_application_lifecycle(
        record(
            Action(
                tool="mcp_server_connect",
                kind=ActionKind.COMPONENT_LOAD,
                input={"name": "github", "version": "1.2.3", "transport": "stdio"},
            )
        )
    )
    assert (event["class_uid"], event["category_uid"], event["activity_id"]) == (6002, 6, 3)
    assert_valid_ocsf(event)


def test_uses_application_not_the_deprecated_app_attribute(assert_valid_ocsf):
    event = map_application_lifecycle(
        record(
            Action(
                tool="mcp_server_connect",
                kind=ActionKind.COMPONENT_LOAD,
                input={"name": "github", "version": "1.2.3"},
            )
        )
    )
    assert "app" not in event
    assert event["application"] == {"name": "github", "uid": "github", "version": "1.2.3"}
    assert_valid_ocsf(event)


def test_component_name_becomes_a_resource_uid_observable(assert_valid_ocsf):
    event = map_application_lifecycle(
        record(Action(tool="plugin_load", kind=ActionKind.COMPONENT_LOAD, input={"name": "acme-plugin"}))
    )
    assert {"name": "application.uid", "type_id": 10, "value": "acme-plugin"} in event["observables"]
    assert_valid_ocsf(event)


@pytest.mark.parametrize(
    "kind,class_uid",
    [
        (ActionKind.SHELL, 1007),
        (ActionKind.FILE_READ, 1001),
        (ActionKind.FILE_CREATE, 1001),
        (ActionKind.FILE_UPDATE, 1001),
        (ActionKind.FILE_DELETE, 1001),
        (ActionKind.HTTP, 4002),
        (ActionKind.MCP_CALL, 6003),
        (ActionKind.COMPONENT_LOAD, 6002),
    ],
)
def test_dispatcher_routes_every_kind(kind, class_uid, assert_valid_ocsf):
    event = map_record(record(Action(tool="t", kind=kind, input={"name": "x", "url": "https://a.test/"})))
    assert event["class_uid"] == class_uid
    assert_valid_ocsf(event)


def test_unknown_kind_falls_back_to_api_activity_rather_than_dropping(assert_valid_ocsf):
    event = map_record(record(Action(tool="mystery", kind=ActionKind.UNKNOWN, input={})))
    assert event["class_uid"] == 6003
    assert event["api"]["operation"] == "mystery"
    assert_valid_ocsf(event)


def test_every_kind_is_routable():
    from stationchief.core.mapping import KIND_TO_MAPPER

    assert set(KIND_TO_MAPPER) == set(ActionKind.ALL)
