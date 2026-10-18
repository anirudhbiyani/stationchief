"""In-process detection, kept deliberately narrow.

Only three things live here, and each one is here for the same reason: a SIEM
structurally cannot compute it downstream.

  - Secret material in a prompt. The value is gone by the time an event is
    written, because redaction removed it. The fact that it was there is not
    recoverable later.
  - Destructive command shapes. A SIEM could do this too; here the finding
    sits next to the event it describes. Blocking is a /check policy decision
    made by the service, not a detector verdict.
  - File access outside the workspace. Requires knowing the workspace root,
    which is agent context, not event content.

Everything correlational - a burst of reads followed by an outbound fetch, an
unfamiliar MCP server appearing mid-session - is a SIEM rule. We ship those as
Sigma examples, not code.
"""

import hashlib
import os
import re

from stationchief.check import NOT_SECRET_RULES
from stationchief.core import ocsf
from stationchief.core.mapping import command_of, path_of
from stationchief.core.records import ActionKind, ActivityRecord

SEVERITY_MEDIUM = 3
SEVERITY_HIGH = 4

DETECTION_FINDING_CREATE = 1
CONFIDENCE_HIGH = 3

# Command-chaining separators. Each pattern below looks within one segment
# (`[^;&|\n]*`), never across `&&`/`;`/`|`, so `rm -rf dist && cd /` is not a
# root delete, and a segment is scanned a bounded number of times.
DESTRUCTIVE_PATTERNS = [
    (
        # The atomic group commits to the segment's first `rm`: the lookaheads
        # from it already cover every later `rm` in the segment, and retrying
        # each one would be quadratic.
        "recursive_root_delete",
        re.compile(
            r"(?:^|[;&|\n])(?>[^;&|\n]*?\brm\b)"
            r"(?=[^;&|\n]*\s(?:-[a-zA-Z]*[rR]|--recursive\b))"
            r"(?=[^;&|\n]*\s(?:~|\$HOME|/[a-z]*)/?\*?(?:\s|[;&|]|$))"
        ),
    ),
    ("raw_device_write", re.compile(r"\bdd\s+.*\bof=/dev/")),
    ("filesystem_format", re.compile(r"\bmkfs(\.\w+)?\s+/dev/")),
    ("fork_bomb", re.compile(r":\(\)\s*\{\s*:\|:&\s*\}\s*;\s*:")),
    ("curl_pipe_shell", re.compile(r"\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z|k|fi)?sh\b")),
    ("world_writable_root", re.compile(r"\bchmod\s+(-R\s+)?777\s+/(\s|$)")),
    # The force flag and the protected branch in either order.
    (
        "force_push_protected",
        re.compile(
            r"(?:^|[;&|\n])(?>[^;&|\n]*?\bgit\s+push\b)"
            r"(?=[^;&|\n]*\s(?:--force\b|-f\b))"
            r"(?=[^;&|\n]*\b(?:main|master|production)\b)"
        ),
    ),
    ("history_wipe", re.compile(r"\bhistory\s+-c\b|(?:^|[;&|\n])(?>[^;&|\n]*?\brm\s)[^;&|\n]*\.(?:bash|zsh)_history\b")),
]

FILE_KINDS = {
    ActionKind.FILE_READ,
    ActionKind.FILE_CREATE,
    ActionKind.FILE_UPDATE,
    ActionKind.FILE_DELETE,
}


def _finding(record: ActivityRecord, *, title, rule, severity_id, evidence) -> dict:
    # Detection Finding 2004 has a different schema than activity events.
    # It doesn't include ai_agent, ai_model, message_context, or action_id fields.
    uid = ocsf.event_uid(record)
    # The finding is its own event: it must not share metadata.uid with the
    # activity event that triggered it, or a store keyed on uid drops one.
    metadata = ocsf.metadata(record)
    metadata["uid"] = hashlib.sha256(f"{uid}:{rule}".encode()).hexdigest()[:32]
    event = {
        "class_uid": 2004,
        "category_uid": 2,
        "activity_id": DETECTION_FINDING_CREATE,
        "type_uid": 2004 * 100 + DETECTION_FINDING_CREATE,
        "severity_id": severity_id,
        "time": record.ts,
        "metadata": metadata,
        "finding_info": {
            "uid": f"{uid}-{rule}",
            "title": title,
            "types": ["AI Agent Activity"],
            "product_uid": "stationchief",
        },
        "confidence_id": CONFIDENCE_HIGH,
        "evidences": [{"data": evidence}],
        "enrichments": ocsf.enrichments(record),
    }
    return event


def _secret_in_prompt(record: ActivityRecord, hits) -> list[dict]:
    # An email address is PII, not a secret; /check skips it for the same reason.
    prompt_hits = [hit for hit in hits if hit.path.startswith("prompt") and hit.rule not in NOT_SECRET_RULES]
    if not prompt_hits:
        return []
    # Evidence names the rule that matched, never the value: the value is the
    # thing we just removed.
    return [
        _finding(
            record,
            title="Secret material present in prompt",
            rule="secret_in_prompt",
            severity_id=SEVERITY_HIGH,
            evidence={"rule": prompt_hits[0].rule, "rules": sorted({h.rule for h in prompt_hits})},
        )
    ]


def _destructive_command(record: ActivityRecord) -> list[dict]:
    if record.action.kind != ActionKind.SHELL:
        return []
    command = command_of(record.action.input)
    for rule, pattern in DESTRUCTIVE_PATTERNS:
        if pattern.search(command):
            return [
                _finding(
                    record,
                    title="Destructive command shape",
                    rule=rule,
                    severity_id=SEVERITY_HIGH,
                    evidence={"rule": rule, "cmd_line": command},
                )
            ]
    return []


def _outside_workspace(record: ActivityRecord) -> list[dict]:
    if record.action.kind not in FILE_KINDS or not record.cwd:
        return []
    path = path_of(record.action.input)
    if not path:
        return []
    workspace = os.path.abspath(record.cwd)
    resolved = os.path.abspath(os.path.join(workspace, str(path)))
    if resolved == workspace or resolved.startswith(workspace + os.sep):
        return []
    return [
        _finding(
            record,
            title="File access outside workspace",
            rule="outside_workspace",
            severity_id=SEVERITY_HIGH,
            evidence={"rule": "outside_workspace", "path": resolved, "workspace": workspace},
        )
    ]


def findings_for(record: ActivityRecord, hits) -> list[dict]:
    """Return zero or more Detection Finding 2004 events for this record."""
    return _secret_in_prompt(record, hits) + _destructive_command(record) + _outside_workspace(record)


def coverage_gap_finding(record: ActivityRecord, missing: int) -> dict:
    """Tool calls in the agent's own transcript that no hook reported.

    Built by ingest, not by findings_for: it needs both capture paths, which
    only exist after the fact. ``record`` is the first missing call, already
    redacted by the caller.
    """
    return _finding(
        record,
        title="Agent activity missing from hook capture",
        rule="hook_coverage_gap",
        severity_id=SEVERITY_MEDIUM,
        evidence={
            "rule": "hook_coverage_gap",
            "missing_tool_calls": missing,
            "first_missing_tool": record.action.tool,
            "first_missing_call_id": record.posture.get("tool_call_id"),
        },
    )

