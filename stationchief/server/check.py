"""Policy decisions for /check.

The engine is pluggable. The chosen engine is OPA as a central sidecar
(`OpaEngine` in stationchief/server/policy.py, Rego under policy/). AllowAllEngine
is the default when the server config names no engine: /check is live and
every decision is recorded, but nothing is blocked.
"""

from typing import Protocol

from stationchief.core.records import Action, ActivityRecord, Actor, Decision
from stationchief.core.redact import redact_record
from stationchief.policy import CheckRequest, Verdict


class PolicyEngine(Protocol):
    def decide(self, request: CheckRequest, principal: str | None = None) -> Verdict:
        """Return allow, deny or ask for one pending tool call.

        ``principal`` is the authenticated caller (from the bearer token);
        ``request.user`` is only what the client claims."""


class AllowAllEngine:
    """The default engine: allows everything, attributes nothing."""

    def decide(self, request: CheckRequest, principal: str | None = None) -> Verdict:
        return Verdict(decision="allow", reason="no policy configured", policy=None)


def decision_record(request: CheckRequest, verdict: Verdict, *, now_ms: int, principal: str) -> ActivityRecord:
    """The audit record for one /check decision.

    A deny is the spec's "blocked by our own control" row (action_id 2,
    disposition 2). Allow and ask are recorded as observed: the tool has not
    run yet, and an ask is resolved by the user afterwards.

    ``request.input`` was already redacted by the client; it is run through
    ``redact_record`` again here as defence in depth, so a server-side event
    is never stored on trust in a client's redaction alone.
    """
    record = ActivityRecord(
        source=request.agent,
        session_id=request.session_id,
        turn_id=None,
        ts=now_ms,
        event=request.hook_event,
        actor=Actor(
            # The authenticated principal (as in native.py), never the
            # client-supplied `user`: that is only what the client claims.
            user_name=principal or "unknown",
            agent_name=request.agent,
            agent_version="unknown",
        ),
        cwd=request.cwd,
        hostname=request.hostname or "unknown",
        posture={
            **request.posture,
            "capture": "check",
            "policy_decision": verdict.decision,
            "policy": verdict.policy,
            "redaction_rules": list(request.redaction_rules),
        },
        prompt=None,
        action=Action(tool=request.tool, kind=request.kind, input=dict(request.input)),
        decision=Decision.BLOCKED if verdict.decision == "deny" else Decision.OBSERVED,
    )
    record, _hits = redact_record(record)
    return record
