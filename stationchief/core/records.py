"""The source-agnostic record every adapter produces and the core consumes.

Adapters absorb per-agent quirks and emit one of these. Nothing downstream of
this module knows which agent an event came from.
"""

import dataclasses
from typing import Any


class ActionKind:
    """What the agent did, independent of what any agent calls its tools."""

    SHELL = "shell"
    FILE_READ = "file_read"
    FILE_CREATE = "file_create"
    FILE_UPDATE = "file_update"
    FILE_DELETE = "file_delete"
    HTTP = "http"
    MCP_CALL = "mcp_call"
    COMPONENT_LOAD = "component_load"
    UNKNOWN = "unknown"

    ALL = frozenset(
        {
            SHELL,
            FILE_READ,
            FILE_CREATE,
            FILE_UPDATE,
            FILE_DELETE,
            HTTP,
            MCP_CALL,
            COMPONENT_LOAD,
            UNKNOWN,
        }
    )


class Decision:
    """How the action was permitted. Maps onto OCSF action_id/disposition_id."""

    OBSERVED = "observed"
    ALLOWED = "allowed"
    DENIED = "denied"
    BLOCKED = "blocked"

    ALL = frozenset({OBSERVED, ALLOWED, DENIED, BLOCKED})


@dataclasses.dataclass(frozen=True)
class Actor:
    user_name: str
    agent_name: str
    agent_version: str
    model: str | None = None
    model_provider: str | None = None
    pid: int | None = None


@dataclasses.dataclass(frozen=True)
class Action:
    tool: str
    kind: str
    input: dict[str, Any]
    output: str | None = None
    status: str = "unknown"
    error: str | None = None


@dataclasses.dataclass(frozen=True)
class ActivityRecord:
    source: str
    session_id: str
    turn_id: str | None
    ts: int
    event: str
    actor: Actor
    cwd: str
    hostname: str
    posture: dict[str, Any]
    prompt: str | None
    action: Action
    decision: str

    def __post_init__(self):
        if self.action.kind not in ActionKind.ALL:
            raise ValueError(f"unknown action kind: {self.action.kind!r}")
        if self.decision not in Decision.ALL:
            raise ValueError(f"unknown decision: {self.decision!r}")
        if not isinstance(self.ts, int) or isinstance(self.ts, bool):
            raise ValueError(f"ts must be an int of epoch milliseconds, got {self.ts!r}")

    def to_dict(self):
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, data):
        data = dict(data)
        data["actor"] = Actor(**data["actor"])
        data["action"] = Action(**data["action"])
        return cls(**data)
