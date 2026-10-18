"""Map native Claude Code and Codex OTLP log events onto ActivityRecords.

This is the zero-install path: point an agent's own OTEL exporter at /otel
and the server does what the hooks do on the laptop: redact, detect, map.

EVERY attribute name below is taken from the agents' published telemetry docs
and must be verified against a real export (plan Task S4, Step 6), exactly as
the hook payload fixtures were. Native exports are coarser than hooks: tool
input arrives only where the agent includes it, and prompts only when the
user opted in to prompt logging.
"""

import collections
import json
import threading

from stationchief.adapters import claude, codex
from stationchief.core.mapping import map_record
from stationchief.core.records import Action, ActivityRecord, Actor, Decision
from stationchief.core.redact import redact_record
from stationchief.detect.rules import findings_for

SESSION_CACHE_SIZE = 10_000

AGENTS = {
    "claude_code": {
        "source": "claude",
        "agent_name": claude.AGENT_NAME,
        "provider": claude.MODEL_PROVIDER,
        "classify": claude.classify,
        "session_key": "session.id",
        "input_key": "tool_parameters",
    },
    "codex": {
        "source": "codex",
        "agent_name": codex.AGENT_NAME,
        "provider": "OpenAI",
        "classify": codex.classify,
        "session_key": "conversation.id",
        "input_key": "arguments",
    },
}

PROMPT_EVENTS = frozenset({"claude_code.user_prompt", "codex.user_prompt"})
SESSION_START_EVENTS = frozenset({"codex.conversation_starts"})
TOOL_EVENTS = frozenset(
    {"claude_code.tool_result", "claude_code.tool_decision", "codex.tool_result", "codex.tool_decision"}
)
HANDLED = PROMPT_EVENTS | SESSION_START_EVENTS | TOOL_EVENTS

APPROVED = frozenset({"accept", "approved", "approved_for_session"})
REJECTED = frozenset({"reject", "denied", "abort"})
# A decision made by static config is not a user approval.
USER_SOURCES = frozenset({"user", "user_temporary", "user_permanent", "user_reject"})


def _truthy(value) -> bool:
    return value is True or str(value).lower() == "true"


def _tool_input(raw) -> dict:
    """Tool parameters arrive as a JSON string; normalise the command key."""
    if isinstance(raw, dict):
        data = dict(raw)
    else:
        try:
            data = json.loads(raw) if raw else {}
        except (TypeError, ValueError):
            data = {"raw": str(raw)}
        if not isinstance(data, dict):
            data = {"raw": str(raw)}
    if "command" not in data:
        for key in ("full_command", "bash_command", "cmd"):
            if data.get(key):
                data["command"] = data[key]
                break
    if isinstance(data.get("command"), list):
        data["command"] = " ".join(str(part) for part in data["command"])
    return data


class NativeMapper:
    """Stateful only for context that arrives on earlier events.

    Known limit: the per-session cache is per process and lost on restart, so
    a tool event after a restart carries no prompt. Move it to the store if
    multiple replicas serve one agent.
    """

    def __init__(self, cache_size: int = SESSION_CACHE_SIZE):
        self._sessions: collections.OrderedDict[tuple, dict] = collections.OrderedDict()
        self._cache_size = cache_size
        # process_logs runs in worker threads; the session cache is shared.
        self._lock = threading.Lock()

    def handles(self, name: str) -> bool:
        return name in HANDLED

    def _session(self, key) -> dict:
        """``key`` is (principal, session_id): a session id is only unique
        per authenticated caller, so two principals reusing the same session
        id (accidentally, or a hostile client replaying another user's id)
        must never share cached prompt/posture state."""
        context = self._sessions.pop(key, None) or {}
        self._sessions[key] = context
        while len(self._sessions) > self._cache_size:
            self._sessions.popitem(last=False)
        return context

    def map(self, record, principal: str = "") -> list[dict]:
        with self._lock:
            return self._map(record, principal)

    def _map(self, record, principal: str) -> list[dict]:
        prefix = record.name.split(".", 1)[0]
        agent = AGENTS[prefix]
        attrs = record.attributes
        session_id = str(attrs.get(agent["session_key"]) or "unknown")
        context = self._session((principal, session_id))

        if record.name in PROMPT_EVENTS:
            if attrs.get("prompt"):
                context["prompt"] = str(attrs["prompt"])
            context["turn_id"] = attrs.get("prompt.id")
            return []
        if record.name in SESSION_START_EVENTS:
            context["model"] = attrs.get("model")
            context["posture"] = {
                "sandbox": attrs.get("sandbox_policy"),
                "approval_policy": attrs.get("approval_policy"),
            }
            return []
        return self._tool_events(record, agent, session_id, context, principal)

    def _tool_events(self, record, agent, session_id, context, principal: str = "") -> list[dict]:
        attrs = record.attributes
        tool = str(attrs.get("tool_name") or "")
        decision = str(attrs.get("decision") or "").lower()
        is_decision = record.name.endswith(".tool_decision")
        if is_decision and decision in REJECTED:
            verdict = Decision.DENIED
        elif is_decision and decision in APPROVED and str(attrs.get("source") or "").lower() in USER_SOURCES:
            verdict = Decision.ALLOWED
        else:
            verdict = Decision.OBSERVED

        status, error = "unknown", None
        if not is_decision:
            status = "success" if _truthy(attrs.get("success")) else "failure"
            error = None if status == "success" else str(attrs.get("error") or "tool reported failure")

        model = attrs.get("model") or context.get("model")
        resource = record.resource
        activity = ActivityRecord(
            source=agent["source"],
            session_id=session_id,
            turn_id=attrs.get("prompt.id") or context.get("turn_id"),
            ts=record.time_ms,
            event=record.name,
            actor=Actor(
                # The authenticated principal, never a payload attribute: a
                # native export's user.account_uuid/user.id is someone else's
                # stable identifier and is dropped before this module ever
                # sees attrs (see otlp.DROPPED_ATTRIBUTES).
                user_name=principal or "unknown",
                agent_name=agent["agent_name"],
                agent_version=str(resource.get("service.version") or attrs.get("app.version") or "unknown"),
                model=model,
                model_provider=agent["provider"] if model else None,
            ),
            cwd="",
            hostname=str(resource.get("host.name") or "unknown"),
            posture={
                **(context.get("posture") or {}),
                "capture": "otel-native",
                "decision_source": attrs.get("source"),
                "tool_call_id": attrs.get("call_id") or attrs.get("tool_use_id"),
            },
            prompt=context.get("prompt"),
            action=Action(
                tool=tool,
                kind=agent["classify"](tool),
                input=_tool_input(attrs.get(agent["input_key"])),
                output=None,
                status=status,
                error=error,
            ),
            decision=verdict,
        )
        cleaned, hits = redact_record(activity)
        return [*findings_for(cleaned, hits), map_record(cleaned)]
