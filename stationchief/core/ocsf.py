"""Shared OCSF construction. Pure: no clock, no I/O, no network.

Agent identity, model, and prompt use the ratified `ai_operation` profile
objects (`ai_agent`, `ai_model`, `message_context`) rather than `enrichments[]`.
`enrichments[]` carries only what OCSF 1.9.0 has no field for: the agent's
permission and sandbox posture, its working directory, and the source hook
event name.

Every class this module serves declares three profiles. Emitting `action_id`
without `security_control`, `device` without `host`, or `ai_agent` without
`ai_operation` is invalid OCSF, not merely unidiomatic.
"""

import hashlib
import json

import stationchief
from stationchief.core.records import ActivityRecord, Decision

OCSF_VERSION = "1.9.0"
PROFILES = ["security_control", "host", "ai_operation"]

# ai_agent.type_id has no value for a third-party coding agent (the enum is
# Native / LangChain / AutoGen / CrewAI), so we emit 99 Other.
AI_AGENT_TYPE_OTHER = 99
AI_ROLE_USER = 1

SEVERITY_INFORMATIONAL = 1

_DECISION_TO_SECURITY_CONTROL = {
    Decision.OBSERVED: (3, None),
    Decision.ALLOWED: (1, 8),
    Decision.DENIED: (2, 2),
    Decision.BLOCKED: (2, 2),
}

_STATUS_TO_ID = {"success": 1, "failure": 2, "unknown": 0}


def product():
    return {
        "name": "stationchief",
        "vendor_name": "StationChief",
        "version": stationchief.__version__,
    }


def event_uid(record: ActivityRecord) -> str:
    """A stable id derived from the record's content, so goldens reproduce."""
    canonical = json.dumps(record.to_dict(), sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()[:32]


def metadata(record: ActivityRecord) -> dict:
    return {
        "version": OCSF_VERSION,
        "product": product(),
        "profiles": list(PROFILES),
        "correlation_uid": record.session_id,
        "uid": event_uid(record),
    }


def actor(record: ActivityRecord) -> dict:
    # The `process` object carries an at_least_one constraint over pid/uid/cpid,
    # so a name alone is invalid. Adapters that cannot supply a pid pass 0.
    return {
        "user": {"name": record.actor.user_name, "type_id": 1},
        "process": {
            "pid": record.actor.pid if record.actor.pid is not None else 0,
            "name": record.actor.agent_name,
        },
    }


def device(record: ActivityRecord) -> dict:
    return {"type_id": 3, "hostname": record.hostname}


def ai_model(record: ActivityRecord) -> dict | None:
    if not record.actor.model:
        return None
    return {
        "name": record.actor.model,
        "ai_provider": record.actor.model_provider or "Unknown",
        "uid": record.actor.model,
    }


def ai_agent(record: ActivityRecord) -> dict:
    agent = {
        "name": record.actor.agent_name,
        "uid": record.actor.agent_name,
        "type_id": AI_AGENT_TYPE_OTHER,
        "version": record.actor.agent_version,
        "instance_uid": record.session_id,
    }
    model = ai_model(record)
    if model:
        agent["ai_model"] = model
    return agent


def message_context(record: ActivityRecord) -> dict | None:
    """The prompt's ratified home. Omitted when the record carries no prompt."""
    if not record.prompt and not record.turn_id:
        return None
    context = {
        "ai_role_id": AI_ROLE_USER,
        # The at_least_one constraint requires application or service.
        "application": {"name": record.actor.agent_name, "uid": record.actor.agent_name},
    }
    if record.turn_id:
        context["uid"] = record.turn_id
    if record.prompt:
        context["prompt_text"] = record.prompt
    return context


def enrichments(record: ActivityRecord) -> list[dict]:
    """Only what OCSF 1.9.0 has no ratified field for."""
    # Posture first: it comes from the agent's payload and must not be able to
    # overwrite the record's own cwd, hook event or source. A missing record
    # field (None) does not clobber a posture value of the same name.
    data = dict(record.posture)
    for key, value in (("cwd", record.cwd), ("hook_event", record.event), ("source", record.source)):
        if value is not None or key not in data:
            data[key] = value
    return [{"name": "agent_posture", "value": record.source, "data": data}]


def observable(name: str, type_id: int, value: str) -> dict:
    return {"name": name, "type_id": type_id, "value": value}


def base_event(
    record: ActivityRecord,
    *,
    class_uid: int,
    category_uid: int,
    activity_id: int,
    severity_id: int = SEVERITY_INFORMATIONAL,
) -> dict:
    action_id, disposition_id = _DECISION_TO_SECURITY_CONTROL[record.decision]
    event = {
        "class_uid": class_uid,
        "category_uid": category_uid,
        "activity_id": activity_id,
        "type_uid": class_uid * 100 + activity_id,
        "severity_id": severity_id,
        "time": record.ts,
        "metadata": metadata(record),
        "ai_agent": ai_agent(record),
        "enrichments": enrichments(record),
        "action_id": action_id,
        "status_id": _STATUS_TO_ID.get(record.action.status, 0),
    }
    if disposition_id is not None:
        event["disposition_id"] = disposition_id
    model = ai_model(record)
    if model:
        event["ai_model"] = model
    context = message_context(record)
    if context:
        event["message_context"] = context
    if record.action.error:
        event["status_detail"] = record.action.error
    return event
