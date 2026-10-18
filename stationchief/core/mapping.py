"""ActivityRecord -> OCSF event. A pure function, and the reason golden-file
tests are the whole test strategy for this layer.

Every action lands on a ratified OCSF class. Nothing here invents schema.
"""

import posixpath
import urllib.parse

from stationchief.core import ocsf
from stationchief.core.records import ActionKind, ActivityRecord

FILE_KIND_TO_ACTIVITY_ID = {
    ActionKind.FILE_CREATE: 1,
    ActionKind.FILE_READ: 2,
    ActionKind.FILE_UPDATE: 3,
    ActionKind.FILE_DELETE: 4,
}

OBSERVABLE_FILE_PATH = 45
OBSERVABLE_COMMAND_LINE = 13


def _first(mapping, *keys, default=None):
    """Agents disagree on argument names for the same concept."""
    for key in keys:
        value = mapping.get(key)
        if value:
            return value
    return default


COMMAND_KEYS = ("command", "cmd", "script")
PATH_KEYS = ("file_path", "path", "filePath", "notebook_path")


def command_of(tool_input) -> str:
    """The shell command in a tool input, under whichever key the agent used.
    Shared with detection so both read the same field."""
    return str(_first(tool_input, *COMMAND_KEYS, default=""))


def path_of(tool_input) -> str | None:
    """The file path in a tool input, under whichever key the agent used."""
    path = _first(tool_input, *PATH_KEYS)
    return str(path) if path else None


def map_process_activity(record: ActivityRecord) -> dict:
    command = command_of(record.action.input)
    event = ocsf.base_event(record, class_uid=1007, category_uid=1, activity_id=1)
    event["actor"] = ocsf.actor(record)
    event["device"] = ocsf.device(record)
    event["process"] = {
        # The agent's tool layer reports intent, not an OS pid; 0 satisfies the
        # process object's at_least_one constraint honestly.
        "pid": 0,
        "cmd_line": command,
        "working_directory": record.cwd,
        "parent_process": {"pid": record.actor.pid or 0, "name": record.actor.agent_name},
    }
    event["observables"] = [
        ocsf.observable("process.cmd_line", OBSERVABLE_COMMAND_LINE, command)
    ]
    return event


def map_file_activity(record: ActivityRecord) -> dict:
    path = path_of(record.action.input)
    activity_id = FILE_KIND_TO_ACTIVITY_ID.get(record.action.kind, 0)
    event = ocsf.base_event(record, class_uid=1001, category_uid=1, activity_id=activity_id)
    event["actor"] = ocsf.actor(record)
    event["device"] = ocsf.device(record)
    if path:
        event["file"] = {"name": posixpath.basename(path) or path, "type_id": 1, "path": path}
        event["observables"] = [ocsf.observable("file.path", OBSERVABLE_FILE_PATH, path)]
    else:
        event["file"] = {"name": "unknown", "type_id": 0}
    return event


HTTP_METHOD_TO_ACTIVITY_ID = {
    "CONNECT": 1,
    "DELETE": 2,
    "GET": 3,
    "HEAD": 4,
    "OPTIONS": 5,
    "POST": 6,
    "PUT": 7,
    "TRACE": 8,
    "PATCH": 9,
}

OBSERVABLE_URL = 6


def _url_object(raw) -> dict:
    raw = str(raw)
    url = {"url_string": raw}
    try:
        parsed = urllib.parse.urlsplit(raw)
        port = parsed.port
    except ValueError:
        # A bad port or an unclosed IPv6 bracket: keep the event, and the raw
        # string, rather than drop the activity.
        return url
    if parsed.scheme:
        url["scheme"] = parsed.scheme
    if parsed.hostname:
        url["hostname"] = parsed.hostname
    if parsed.path:
        url["path"] = parsed.path
    if parsed.query:
        url["query_string"] = parsed.query
    if port:
        url["port"] = port
    return url


def map_http_activity(record: ActivityRecord) -> dict:
    raw_url = str(_first(record.action.input, "url", "uri", default=""))
    method = str(_first(record.action.input, "method", "http_method", default="GET")).upper()
    activity_id = HTTP_METHOD_TO_ACTIVITY_ID.get(method, 99)
    event = ocsf.base_event(record, class_uid=4002, category_uid=4, activity_id=activity_id)
    # actor and device are gated behind the host profile on this class, which
    # ocsf.base_event already declares in metadata.profiles.
    event["actor"] = ocsf.actor(record)
    event["device"] = ocsf.device(record)
    http_request = {"url": _url_object(raw_url)}
    # Only include http_method if it's a valid enum value
    if method in HTTP_METHOD_TO_ACTIVITY_ID:
        http_request["http_method"] = method
    event["http_request"] = http_request
    event["observables"] = [ocsf.observable("http_request.url.url_string", OBSERVABLE_URL, raw_url)]
    return event


def _split_mcp_tool(tool: str, fallback_service: str) -> tuple[str, str]:
    """`mcp__<server>__<operation>` is the convention every agent we support uses."""
    if tool.startswith("mcp__"):
        parts = tool.split("__")
        if len(parts) >= 3:
            return parts[1], "__".join(parts[2:])
    if tool in ("WebSearch", "web_search"):
        return "web_search", "search"
    return fallback_service, tool


def map_api_activity(record: ActivityRecord) -> dict:
    service, operation = _split_mcp_tool(record.action.tool, record.actor.agent_name)
    event = ocsf.base_event(record, class_uid=6003, category_uid=6, activity_id=0)
    event["actor"] = ocsf.actor(record)
    event["device"] = ocsf.device(record)
    # src_endpoint is required on this class; hostname satisfies the object's
    # at_least_one constraint.
    event["src_endpoint"] = {"hostname": record.hostname}
    api = {
        "operation": operation,
        "service": {"name": service},
        "request": {"uid": event["metadata"]["uid"], "data": dict(record.action.input)},
    }
    if record.action.output is not None:
        api["response"] = {"message": record.action.output}
    if record.action.error:
        api.setdefault("response", {})["error_message"] = record.action.error
    event["api"] = api
    return event


OBSERVABLE_RESOURCE_UID = 10

APPLICATION_LIFECYCLE_START = 3


def map_application_lifecycle(record: ActivityRecord) -> dict:
    """MCP server connections and plugin loads: the supply-chain surface."""
    name = _first(record.action.input, "name", "server", "plugin", default="unknown")
    event = ocsf.base_event(
        record, class_uid=6002, category_uid=6, activity_id=APPLICATION_LIFECYCLE_START
    )
    event["actor"] = ocsf.actor(record)
    event["device"] = ocsf.device(record)
    # `app` is deprecated on this class as of 1.9.0; `application` replaces it.
    # The application object has no vendor_name field.
    application = {"name": name, "uid": name}
    version = _first(record.action.input, "version")
    if version:
        application["version"] = version
    event["application"] = application
    event["observables"] = [ocsf.observable("application.uid", OBSERVABLE_RESOURCE_UID, name)]
    return event


KIND_TO_MAPPER = {
    ActionKind.SHELL: map_process_activity,
    ActionKind.FILE_READ: map_file_activity,
    ActionKind.FILE_CREATE: map_file_activity,
    ActionKind.FILE_UPDATE: map_file_activity,
    ActionKind.FILE_DELETE: map_file_activity,
    ActionKind.HTTP: map_http_activity,
    ActionKind.MCP_CALL: map_api_activity,
    ActionKind.COMPONENT_LOAD: map_application_lifecycle,
    # An action we do not recognize is still an action. API Activity is the
    # least-lossy ratified home for it; dropping it would be worse.
    ActionKind.UNKNOWN: map_api_activity,
}


def map_record(record: ActivityRecord) -> dict:
    """The only mapping entry point. Pure: same record in, same event out."""
    return KIND_TO_MAPPER[record.action.kind](record)
