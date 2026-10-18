"""Configuration from ~/.stationchief/config.json. Every default is the safe one.

A malformed config falls back to defaults rather than raising, because this is
loaded inside a hook on the agent's critical path.
"""

import dataclasses
import json
import pathlib

DEFAULT_HOME = pathlib.Path.home() / ".stationchief"
CONFIG_FILENAME = "config.json"


@dataclasses.dataclass(frozen=True)
class Config:
    home: pathlib.Path = DEFAULT_HOME
    redact: bool = True
    detect: bool = True
    sinks: tuple[str, ...] = ("ndjson",)
    http_url: str | None = None
    http_token: str | None = None
    server_url: str | None = None
    server_token: str | None = None
    check_timeout_ms: int = 750
    fail_closed: bool = False

    @classmethod
    def load(cls, path=None) -> "Config":
        path = pathlib.Path(path) if path else DEFAULT_HOME / CONFIG_FILENAME
        try:
            raw = json.loads(path.read_text())
        except (OSError, ValueError):
            return cls()
        if not isinstance(raw, dict):
            return cls()
        # Each field is validated on its own: a wrongly typed value falls back
        # to that field's default without discarding the valid ones.
        values = {}
        for key, value in raw.items():
            checked = _validate(key, value)
            if checked is not _INVALID:
                values[key] = checked
        try:
            return cls(**values)
        except Exception:
            return cls()


_INVALID = object()
_BOOLS = frozenset({"redact", "detect", "fail_closed"})
_OPTIONAL_STRINGS = frozenset({"http_url", "http_token", "server_url", "server_token"})


def _validate(key: str, value):
    """``value`` converted for field ``key``, or _INVALID. A bool must be a
    real bool: the string "false" is truthy and must not enable fail_closed."""
    if key == "home":
        return pathlib.Path(value) if isinstance(value, str) and value else _INVALID
    if key in _BOOLS:
        return value if isinstance(value, bool) else _INVALID
    if key in _OPTIONAL_STRINGS:
        return value if value is None or isinstance(value, str) else _INVALID
    if key == "sinks":
        if isinstance(value, str):
            return (value,)  # one sink, not one per character
        if isinstance(value, list) and all(isinstance(name, str) for name in value):
            return tuple(value)
        return _INVALID
    if key == "check_timeout_ms":
        valid = isinstance(value, (int, float)) and not isinstance(value, bool) and 0 < value < float("inf")
        return value if valid else _INVALID
    return _INVALID  # unknown keys are ignored
