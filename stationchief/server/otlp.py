"""Decode OTLP/HTTP JSON log exports and route each record.

Pure functions, no web framework: the endpoint in app.py hands the parsed
body to `process_logs` and stores what comes back.

Only the JSON encoding of OTLP is supported. Protobuf is refused at the
endpoint with 415; set OTEL_EXPORTER_OTLP_PROTOCOL=http/json on exporters.
"""

import dataclasses
import json
import logging
import time

log = logging.getLogger("stationchief.server")

OCSF_EVENT_NAME = "stationchief.ocsf"
OCSF_VERSION = "1.9.0"
# PII that native agent exporters attach to every record. Dropped before
# anything else sees the attributes. Stable per-person identifiers
# (account/user/org ids) are dropped alongside the email: the authenticated
# principal (not a payload attribute) is the only identity native.py may use.
DROPPED_ATTRIBUTES = frozenset({"user.email", "user.account_uuid", "user.id", "organization.id"})
# Known limit: bound recursion on arrayValue/kvlistValue so a hostile or buggy
# exporter can't blow the interpreter's recursion limit; past this depth the
# nested value is dropped (returns None) instead of crashing the request.
MAX_DEPTH = 16
# Ids (uid, correlation_uid = the session id) longer than this are never
# real ids; the event is rejected rather than stored.
MAX_ID_LENGTH = 256


@dataclasses.dataclass(frozen=True)
class LogRecord:
    name: str
    attributes: dict
    resource: dict
    body: object
    time_ms: int


@dataclasses.dataclass
class Outcome:
    events: list = dataclasses.field(default_factory=list)
    rejected: int = 0
    dropped: int = 0
    errors: list = dataclasses.field(default_factory=list)

    def response(self) -> dict:
        """OTLP ExportLogsServiceResponse: partial success only when rejecting."""
        if not self.rejected:
            return {}
        return {
            "partialSuccess": {
                "rejectedLogRecords": self.rejected,
                "errorMessage": "; ".join(self.errors[:5]),
            }
        }


def any_value(value, _depth=0):
    """OTLP AnyValue -> Python. int64 arrives as a JSON string by spec."""
    if _depth > MAX_DEPTH:
        return None
    if not isinstance(value, dict):
        return None
    if "stringValue" in value:
        return value["stringValue"]
    if "intValue" in value:
        try:
            return int(value["intValue"])
        except (TypeError, ValueError, OverflowError):  # OverflowError: Infinity, 1e999
            return None
    if "doubleValue" in value:
        return value["doubleValue"]
    if "boolValue" in value:
        return value["boolValue"]
    if "arrayValue" in value:
        array = value["arrayValue"]
        items = array.get("values") if isinstance(array, dict) else None
        if not isinstance(items, list):
            items = []
        return [any_value(v, _depth + 1) for v in items]
    if "kvlistValue" in value:
        kvlist = value["kvlistValue"]
        kv_values = kvlist.get("values") if isinstance(kvlist, dict) else None
        return attributes(kv_values, _depth + 1)
    if "bytesValue" in value:
        return value["bytesValue"]
    return None


def attributes(key_values, _depth=0) -> dict:
    result = {}
    if not isinstance(key_values, list):
        key_values = []
    for item in key_values:
        if isinstance(item, dict) and isinstance(item.get("key"), str):
            result[item["key"]] = any_value(item.get("value"), _depth)
    for key in DROPPED_ATTRIBUTES:
        result.pop(key, None)
    return result


def _time_ms(record: dict) -> int:
    for key in ("timeUnixNano", "observedTimeUnixNano"):
        try:
            nanos = int(record.get(key) or 0)
        except (TypeError, ValueError, OverflowError):  # OverflowError: Infinity, 1e999
            nanos = 0
        if nanos:
            return nanos // 1_000_000
    return int(time.time() * 1000)


def iter_log_records(payload: dict):
    """Walk the OTLP envelope, skipping any level that doesn't match its
    expected shape. A hostile or broken exporter can send anything; a
    malformed container is dropped silently, never crashes the request."""
    resource_logs_list = payload.get("resourceLogs")
    if not isinstance(resource_logs_list, list):
        return
    for resource_logs in resource_logs_list:
        if not isinstance(resource_logs, dict):
            continue
        resource_obj = resource_logs.get("resource")
        resource = attributes(resource_obj.get("attributes") if isinstance(resource_obj, dict) else None)
        scope_logs_list = resource_logs.get("scopeLogs")
        if not isinstance(scope_logs_list, list):
            continue
        for scope_logs in scope_logs_list:
            if not isinstance(scope_logs, dict):
                continue
            log_records_list = scope_logs.get("logRecords")
            if not isinstance(log_records_list, list):
                continue
            for record in log_records_list:
                if not isinstance(record, dict):
                    continue
                attrs = attributes(record.get("attributes"))
                name = str(attrs.get("event.name") or record.get("eventName") or attrs.get("name") or "")
                body = any_value(record.get("body"))
                # Claude Code sends event.name "tool_result" with the qualified
                # "claude_code.tool_result" as the body; prefer the qualified one.
                if name and isinstance(body, str) and body.endswith("." + name):
                    name = body
                yield LogRecord(
                    name=name,
                    attributes=attrs,
                    resource=resource,
                    body=body,
                    time_ms=_time_ms(record),
                )


def parse_ocsf_event(body) -> dict:
    """Structural check for an event a stationchief client already mapped.

    Clients run the full schema-validated pipeline; the server checks shape
    only, so a bad record is rejected rather than stored half-understood.
    """
    try:
        event = json.loads(body) if isinstance(body, str) else None
    except ValueError:
        event = None
    if not isinstance(event, dict):
        raise ValueError("body is not a JSON object")
    metadata = event.get("metadata")
    if not isinstance(event.get("class_uid"), int) or isinstance(event.get("class_uid"), bool):
        raise ValueError("class_uid missing or not an integer")
    if not isinstance(metadata, dict) or not isinstance(metadata.get("uid"), str):
        raise ValueError("metadata.uid missing")
    if metadata.get("version") != OCSF_VERSION:
        raise ValueError(f"metadata.version must be {OCSF_VERSION}")
    if not isinstance(event.get("time"), int) or isinstance(event.get("time"), bool):
        raise ValueError("time missing or not an integer")
    if "correlation_uid" in metadata and not isinstance(metadata["correlation_uid"], str):
        raise ValueError("metadata.correlation_uid must be a string")
    for key in ("uid", "correlation_uid"):
        if len(metadata.get(key) or "") > MAX_ID_LENGTH:
            raise ValueError(f"metadata.{key} is longer than {MAX_ID_LENGTH} characters")
    return event


def process_logs(payload: dict, *, native=None, principal: str = "") -> Outcome:
    """Route every log record: stationchief events, native agent events, or drop.

    ``principal`` is the authenticated identity the caller's bearer token
    resolved to (see server/app.py's BearerAuth). It is the only identity
    native.py's per-session cache and mapped events may use; a payload
    attribute is never trusted as identity.
    """
    outcome = Outcome()
    if not isinstance(payload, dict):
        outcome.rejected, outcome.errors = 1, ["request body is not an OTLP JSON object"]
        return outcome
    for record in iter_log_records(payload):
        if record.name == OCSF_EVENT_NAME:
            try:
                outcome.events.append(parse_ocsf_event(record.body))
            except ValueError as error:
                outcome.rejected += 1
                outcome.errors.append(f"{OCSF_EVENT_NAME}: {error}")
        elif native is not None and native.handles(record.name):
            try:
                outcome.events.extend(native.map(record, principal))
            except Exception:  # one bad record must not fail the batch
                # Details (exception type/message) stay server-side; the
                # client only sees that its record could not be mapped.
                log.exception("native mapper failed on record %r", record.name)
                outcome.rejected += 1
                outcome.errors.append(f"{record.name}: could not be mapped")
        else:
            outcome.dropped += 1
    return outcome
