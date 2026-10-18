import pytest

from stationchief.core.mapping import map_api_activity, map_http_activity
from stationchief.core.records import Action, ActionKind, ActivityRecord, Actor, Decision

ACTOR = Actor(
    user_name="dev",
    agent_name="claude-code",
    agent_version="2.0.1",
    model="claude-opus-5",
    model_provider="Anthropic",
    pid=4242,
)


def record(action, decision=Decision.OBSERVED):
    return ActivityRecord(
        source="claude",
        session_id="sess-abc",
        turn_id="turn-1",
        ts=1758326400000,
        event="PostToolUse",
        actor=ACTOR,
        cwd="/repo",
        hostname="laptop",
        posture={"permission_mode": "default"},
        prompt="check the docs",
        action=action,
        decision=decision,
    )


def test_webfetch_maps_to_http_activity_get(assert_valid_ocsf):
    event = map_http_activity(
        record(Action(tool="WebFetch", kind=ActionKind.HTTP, input={"url": "https://example.com/docs?v=2"}))
    )
    assert (event["class_uid"], event["category_uid"], event["activity_id"]) == (4002, 4, 3)
    assert event["type_uid"] == 400203
    assert_valid_ocsf(event)


def test_url_is_decomposed_into_the_url_object(assert_valid_ocsf):
    event = map_http_activity(
        record(Action(tool="WebFetch", kind=ActionKind.HTTP, input={"url": "https://example.com/docs?v=2"}))
    )
    assert event["http_request"]["url"] == {
        "url_string": "https://example.com/docs?v=2",
        "scheme": "https",
        "hostname": "example.com",
        "path": "/docs",
        "query_string": "v=2",
    }
    assert event["http_request"]["http_method"] == "GET"
    assert_valid_ocsf(event)


def test_url_becomes_an_observable(assert_valid_ocsf):
    event = map_http_activity(
        record(Action(tool="WebFetch", kind=ActionKind.HTTP, input={"url": "https://evil.test/x"}))
    )
    assert {"name": "http_request.url.url_string", "type_id": 6, "value": "https://evil.test/x"} in event["observables"]
    assert_valid_ocsf(event)


def test_http_activity_declares_host_profile_for_device(assert_valid_ocsf):
    event = map_http_activity(
        record(Action(tool="WebFetch", kind=ActionKind.HTTP, input={"url": "https://example.com/"}))
    )
    assert "host" in event["metadata"]["profiles"]
    assert event["device"]["hostname"] == "laptop"
    assert_valid_ocsf(event)


@pytest.mark.parametrize(
    "method,activity_id", [("GET", 3), ("POST", 6), ("PUT", 7), ("DELETE", 2), ("PATCH", 9), ("WAT", 99)]
)
def test_http_method_selects_the_activity_id(method, activity_id, assert_valid_ocsf):
    event = map_http_activity(
        record(
            Action(
                tool="WebFetch",
                kind=ActionKind.HTTP,
                input={"url": "https://example.com/", "method": method},
            )
        )
    )
    assert event["activity_id"] == activity_id
    assert event["type_uid"] == 400200 + activity_id
    assert_valid_ocsf(event)


def test_mcp_tool_call_maps_to_api_activity(assert_valid_ocsf):
    event = map_api_activity(
        record(
            Action(
                tool="mcp__github__create_issue",
                kind=ActionKind.MCP_CALL,
                input={"repo": "acme/app", "title": "bug"},
            )
        )
    )
    assert (event["class_uid"], event["category_uid"]) == (6003, 6)
    assert event["api"]["operation"] == "create_issue"
    assert event["api"]["service"]["name"] == "github"
    assert event["api"]["request"]["data"] == {"repo": "acme/app", "title": "bug"}
    assert_valid_ocsf(event)


def test_api_activity_supplies_the_required_src_endpoint(assert_valid_ocsf):
    event = map_api_activity(
        record(Action(tool="mcp__github__create_issue", kind=ActionKind.MCP_CALL, input={}))
    )
    assert event["src_endpoint"] == {"hostname": "laptop"}
    assert_valid_ocsf(event)


def test_unprefixed_mcp_tool_falls_back_to_the_agent_as_service(assert_valid_ocsf):
    event = map_api_activity(record(Action(tool="some_tool", kind=ActionKind.MCP_CALL, input={})))
    assert event["api"]["operation"] == "some_tool"
    assert event["api"]["service"]["name"] == "claude-code"
    assert_valid_ocsf(event)


def test_websearch_maps_to_api_activity_not_a_fabricated_url(assert_valid_ocsf):
    event = map_api_activity(
        record(Action(tool="WebSearch", kind=ActionKind.MCP_CALL, input={"query": "ocsf ai profile"}))
    )
    assert event["api"]["operation"] == "search"
    assert event["api"]["request"]["data"] == {"query": "ocsf ai profile"}
    assert_valid_ocsf(event)


def test_tool_output_becomes_the_api_response(assert_valid_ocsf):
    event = map_api_activity(
        record(
            Action(
                tool="mcp__github__create_issue",
                kind=ActionKind.MCP_CALL,
                input={},
                output="created issue 12",
                status="success",
            )
        )
    )
    assert event["api"]["response"]["message"] == "created issue 12"
    assert event["status_id"] == 1
    assert_valid_ocsf(event)


@pytest.mark.parametrize("url", ["http://example.com:99999/x", "http://[::1/x", "http://example.com:abc/"])
def test_a_malformed_url_still_maps_with_just_the_url_string(url):
    event = map_http_activity(record(Action(tool="WebFetch", kind=ActionKind.HTTP, input={"url": url})))
    assert event["http_request"]["url"] == {"url_string": url}
