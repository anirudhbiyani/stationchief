"""Pattern redaction, applied to every record before it reaches any sink.

This is a trust boundary. These records carry prompts and raw tool arguments;
a probe run of an unredacted agent surfaced a user's email address and full
prompt text. Redaction is on by default and disabling it is an explicit,
per-field configuration choice.

Hits are returned rather than swallowed, because "a secret was present" is
itself a detection signal (see stationchief.detect.rules) that no downstream SIEM can
recover once the value is gone.
"""

import dataclasses
import re
from typing import Any

from stationchief.core.records import ActivityRecord

# A secret-named identifier, e.g. AWS_SECRET_ACCESS_KEY, DB_PASSWORD. The
# lookbehind starts matches only at identifier starts, which keeps
# backtracking linear; the lookahead keeps `tokenizer=` and `max_tokens=` out.
SECRET_NAME = (
    r"(?i)(?<![A-Za-z0-9_-])[A-Za-z0-9_-]*?"
    r"(?:password|passwd|secret|token|credentials?|pwd|api[_-]?key|access[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)"
    r"(?![A-Za-z0-9])"
)

# Ordered: the most specific pattern must win, so a GitHub token is not first
# swallowed by the generic assignment rule. The generic rules skip a value
# that an earlier rule already replaced, so one secret is one hit.
PATTERNS: list[tuple[str, re.Pattern]] = [
    # BEGIN to END, or BEGIN to end of text: a key cut short (`head id_rsa`)
    # is still a key. Covers PGP's `PRIVATE KEY BLOCK` armor too.
    (
        "private_key",
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----"
            r"(?:.*?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|.*\Z)",
            re.S,
        ),
    ),
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")),
    ("github_token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}")),
    ("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("slack_token", re.compile(r"\bxox[baprse]-[A-Za-z0-9-]{10,}\b")),
    ("anthropic_api_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,}\b")),
    ("stripe_api_key", re.compile(r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("openai_api_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    # `Authorization: Bearer <value>` / `"Authorization": "Basic <value>"`: the
    # header form needs its `:` or `=`, so prose ("fix authorization handling")
    # stays out.
    (
        "authorization_header",
        re.compile(r"(?i)\bauthorization\b[\"']?\s*[:=]\s*[\"']?(?:bearer\s+|token\s+|basic\s+)?(?!\[REDACTED:)([^\s\"']{8,})"),
    ),
    # A bare `Bearer <value>`; the value must look like a token (a digit or
    # token punctuation), not an English word.
    (
        "authorization_header",
        re.compile(r"(?i)\bbearer\s+(?!\[REDACTED:)(?=[A-Za-z]*[0-9._~+/=-])([A-Za-z0-9._~+/=-]{8,})"),
    ),
    # The password in URL userinfo: scheme://user:PASSWORD@host. The
    # lookbehind and bounded scheme keep a long run of `a.a.a.` linear.
    ("url_password", re.compile(r"(?i)(?<![a-z0-9+.-])[a-z][a-z0-9+.-]{0,31}://[^\s:/@]{1,256}:([^\s@/]{1,256})@")),
    # curl -u user:PASSWORD / --user user:PASSWORD, but not a numeric
    # `uid:gid` (`docker run -u 1000:1000`).
    (
        "cli_user_password",
        re.compile(r"(?<!\S)(?:-u\s*|--user[=\s]+)[\"']?(?![0-9]+:[0-9]+(?:[\s\"']|$))[^\s:\"']+:(?!\[REDACTED:)([^\s\"']+)"),
    ),
    # `--password X` / `--password=X` (not `--password-stdin`), and
    # `docker login -p X`.
    ("cli_password", re.compile(r"(?<!\S)--password(?:=|\s+)[\"']?(?!\[REDACTED:)([^\s\"']+)")),
    (
        "cli_password",
        re.compile(r"(?i)\b(?:docker|podman)\s+login\b[^\n]{0,256}?(?<!\S)-p\s*[\"']?(?!\[REDACTED:)([^\s\"']+)"),
    ),
    # .npmrc: //registry/:_authToken=VALUE
    ("npm_auth_token", re.compile(r"(?i)_authToken\s*=\s*[\"']?(?!\[REDACTED:)([^\s\"']+)")),
    # `PASSWORD='correct horse battery staple'`: a quoted value may hold
    # spaces, so it gets its own rule ahead of the unquoted one below.
    (
        "assigned_secret",
        re.compile(
            SECRET_NAME + r"[\"']?\s*[:=]\s*"
            r"(?:\"(?!\[REDACTED:)([^\"\n]{8,256})\"|'(?!\[REDACTED:)([^'\n]{8,256})')"
        ),
    ),
    (
        # A secret-named key (optionally prefixed, e.g. AWS_SECRET_ACCESS_KEY,
        # DB_PASSWORD, STRIPE_API_KEY) assigned a value.
        "assigned_secret",
        re.compile(SECRET_NAME + r"[\"']?\s*[:=]\s*[\"']?(?!\[REDACTED:)([^\s\"',;]{8,})[\"']?"),
    ),
    # Bounded local part behind a lookbehind (linear on `a.a.a.`); an address
    # followed by `:path` is an scp/git remote (`git@github.com:org/repo`).
    (
        "email",
        re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}\b(?![A-Za-z0-9.-]{0,253}:\S)"),
    ),
]


# Known limit: bound recursion so a deeply nested tool input (hostile or just a
# large JSON blob) can't blow the interpreter's recursion limit; past this
# depth the value can no longer be safely inspected, so it is redacted
# outright rather than passed through or crashing the request.
MAX_DEPTH = 32

# Tool output is capped here, after redaction, never before it: cutting first
# can sever a secret from the markers or prefix its pattern needs, and the
# remainder then passes through as ordinary text.
OUTPUT_LIMIT = 4096


@dataclasses.dataclass(frozen=True)
class Hit:
    rule: str
    path: str


def redact_text(text: str) -> tuple[str, list[Hit]]:
    """Redact every known secret shape in ``text``. Returns the cleaned text and hits."""
    if not text:
        return text, []
    hits: list[Hit] = []
    for rule, pattern in PATTERNS:
        def substitute(match, rule=rule):
            hits.append(Hit(rule=rule, path=""))
            if match.lastindex:
                # Keep the assignment's left-hand side; redact only the value
                # (the group that matched, for a rule with alternatives).
                start, end = match.span(match.lastindex)
                tag = f"[REDACTED:{rule}]"
                return match.group(0)[: start - match.start()] + tag + match.group(0)[end - match.start():]
            return f"[REDACTED:{rule}]"

        text = pattern.sub(substitute, text)
    return text, hits


# A structured key that names a secret: {"password": ...}, {"apiKey": ...},
# {"Authorization": ...}. Matched against the key with camelCase and dashes
# folded to snake_case, and anchored to the key's last word, so `max_tokens`,
# `token_count`, `tokenizer` and `secret_name` stay out. `pwd` is left out on
# purpose: as a key it is almost always the shell's working directory.
SECRET_KEY = re.compile(
    r"(?:^|_)(?:password|passwd|passphrase|secret|token|credentials?|api_?key|access_?key"
    r"|authorization|cookie|private_?key)$"
)


def _is_secret_key(key: Any) -> bool:
    if not isinstance(key, str):
        return False
    return bool(SECRET_KEY.search(re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key).lower().replace("-", "_")))


def _walk(value: Any, path: str, enabled: bool, hits: list[Hit], depth: int = 0) -> Any:
    if depth >= MAX_DEPTH:
        hits.append(Hit(rule="too_deep", path=path))
        return "[REDACTED:too_deep]"
    if isinstance(value, str):
        cleaned, found = redact_text(value)
        hits.extend(dataclasses.replace(hit, path=path) for hit in found)
        return cleaned if enabled else value
    if isinstance(value, dict):
        # env-style pairs: [{"name": "DB_PASSWORD", "value": "..."}]
        named = _is_secret_key(value.get("name")) or _is_secret_key(value.get("key"))
        result = {}
        for key, item in value.items():
            secret = _is_secret_key(key) or (named and key == "value")
            if secret and isinstance(item, (str, int, float)) and not isinstance(item, bool) and item != "":
                hits.append(Hit(rule="assigned_secret", path=f"{path}.{key}"))
                result[key] = "[REDACTED:assigned_secret]" if enabled else item
            else:
                result[key] = _walk(item, f"{path}.{key}", enabled, hits, depth + 1)
        return result
    if isinstance(value, list):
        return [_walk(item, f"{path}[{index}]", enabled, hits, depth + 1) for index, item in enumerate(value)]
    return value


def redact_record(record: ActivityRecord, enabled: bool = True) -> tuple[ActivityRecord, list[Hit]]:
    """Redact the free-text surfaces of ``record``.

    Hits are collected whether or not ``enabled`` is set, so that turning
    redaction off does not also turn detection off.
    """
    hits: list[Hit] = []
    prompt = _walk(record.prompt, "prompt", enabled, hits)
    output = _walk(record.action.output, "action.output", enabled, hits)
    if isinstance(output, str):
        output = output[:OUTPUT_LIMIT]
    action = dataclasses.replace(
        record.action,
        input=_walk(record.action.input, "action.input", enabled, hits),
        output=output,
        error=_walk(record.action.error, "action.error", enabled, hits),
    )
    posture = _walk(record.posture, "posture", enabled, hits)
    return dataclasses.replace(record, prompt=prompt, action=action, posture=posture), hits


__all__ = ["Hit", "OUTPUT_LIMIT", "PATTERNS", "redact_record", "redact_text"]
