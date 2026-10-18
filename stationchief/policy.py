"""The /check wire contract, shared by the hook client and the server.

Stdlib only, so the client imports it without the server's dependencies.
The request carries tool input that the client has already redacted, plus
the names of the redaction rules that matched. The prompt is never sent.
"""

import dataclasses

from stationchief.core.records import ActionKind

DECISIONS = frozenset({"allow", "deny", "ask"})
MAX_STRING = 4096


def _string(data: dict, key: str, *, required: bool = False, default: str = "") -> str:
    value = data.get(key, default)
    if value is None:
        value = default
    if not isinstance(value, str) or len(value) > MAX_STRING:
        raise ValueError(f"{key} must be a string of at most {MAX_STRING} characters")
    if required and not value:
        raise ValueError(f"{key} is required")
    return value


@dataclasses.dataclass(frozen=True)
class CheckRequest:
    agent: str
    session_id: str
    tool: str
    kind: str
    input: dict
    redaction_rules: tuple[str, ...] = ()
    cwd: str = ""
    user: str = ""
    hostname: str = ""
    posture: dict = dataclasses.field(default_factory=dict)
    hook_event: str = "PreToolUse"

    def __post_init__(self):
        if self.kind not in ActionKind.ALL:
            raise ValueError(f"unknown kind {self.kind!r}")

    @classmethod
    def from_json(cls, data) -> "CheckRequest":
        """Validate an untrusted request body. Raises ValueError with a reason."""
        if not isinstance(data, dict):
            raise ValueError("request body must be a JSON object")
        tool_input = data.get("input", {})
        posture = data.get("posture", {})
        rules = data.get("redaction_rules", [])
        if not isinstance(tool_input, dict):
            raise ValueError("input must be an object")
        if not isinstance(posture, dict):
            raise ValueError("posture must be an object")
        if not isinstance(rules, list) or not all(isinstance(r, str) for r in rules):
            raise ValueError("redaction_rules must be a list of strings")
        return cls(
            agent=_string(data, "agent", required=True),
            session_id=_string(data, "session_id", required=True),
            tool=_string(data, "tool", required=True),
            kind=_string(data, "kind", required=True),
            input=tool_input,
            redaction_rules=tuple(rules),
            cwd=_string(data, "cwd"),
            user=_string(data, "user"),
            hostname=_string(data, "hostname"),
            posture=posture,
            hook_event=_string(data, "hook_event", default="PreToolUse") or "PreToolUse",
        )

    def to_json(self) -> dict:
        data = dataclasses.asdict(self)
        data["redaction_rules"] = list(self.redaction_rules)
        return data


@dataclasses.dataclass(frozen=True)
class Verdict:
    decision: str
    reason: str = ""
    policy: str | None = None

    def __post_init__(self):
        if self.decision not in DECISIONS:
            raise ValueError(f"unknown decision {self.decision!r}")

    @classmethod
    def from_json(cls, data) -> "Verdict":
        if not isinstance(data, dict):
            raise ValueError("verdict must be a JSON object")
        policy = data.get("policy")
        return cls(
            decision=data.get("decision"),
            reason=str(data.get("reason") or ""),
            policy=None if policy is None else str(policy),
        )

    def to_json(self) -> dict:
        return dataclasses.asdict(self)
