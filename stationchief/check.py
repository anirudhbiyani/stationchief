"""Ask the stationchief service whether a pending tool call may run (POST /check).

Called from the pre-tool hook, on the agent's critical path, so it has a
hard timeout (config.check_timeout_ms). When the server is slow or down the
answer is config.fail_closed: deny if true, allow (the default) if false.
Only redacted tool input and the names of matched redaction rules are sent;
the prompt never is.

The default opener refuses redirects (and skips proxies for loopback), not
urllib.request.urlopen: the request carries a bearer token, and a token must
never be replayed to wherever a redirect points. A malicious or misconfigured
/check target that answers with a 3xx never gets a second (redirected)
request; ask() treats the refused redirect like any other failure and falls
back to the fail-open/fail-closed verdict.

The timeout is an overall deadline: urlopen's timeout bounds each socket
operation, so a server trickling bytes could hold the hook indefinitely. The
request runs in a daemon thread that ask() waits on for check_timeout_ms.
"""

import json
import threading
import urllib.parse
import urllib.request

from stationchief.policy import CheckRequest, Verdict
from stationchief.sinks.http import default_opener, require_secure_url

CHECK_PATH = "/check"


def configured(config) -> bool:
    return bool(config.server_url and config.server_token)


# PII, not a secret: an email address in a command is not a reason to ask.
NOT_SECRET_RULES = frozenset({"email"})


def _input_secret_rules(hits) -> tuple[str, ...]:
    """Secret rules that matched the tool input itself. The prompt and the
    tool's earlier output are not what this call is about to run."""
    return tuple(
        sorted({hit.rule for hit in hits if hit.path.startswith("action.input") and hit.rule not in NOT_SECRET_RULES})
    )


def request_for(record, hits) -> CheckRequest:
    """``record`` must already be redacted; ``hits`` are its redaction hits."""
    return CheckRequest(
        agent=record.source,
        session_id=record.session_id,
        tool=record.action.tool,
        kind=record.action.kind,
        input=dict(record.action.input),
        redaction_rules=_input_secret_rules(hits),
        cwd=record.cwd,
        user=record.actor.user_name,
        hostname=record.hostname,
        posture=dict(record.posture),
        hook_event=record.event,
    )


def ask(record, hits, config, *, opener=None, log=None) -> Verdict | None:
    """Return the server's verdict, the fail-open/closed fallback, or None
    when no server is configured (the check is skipped entirely)."""
    if not configured(config):
        return None
    try:
        require_secure_url(config.server_url)
        opener = opener or default_opener(urllib.parse.urlsplit(config.server_url))
        body = json.dumps(request_for(record, hits).to_json()).encode()
        request = urllib.request.Request(
            config.server_url.rstrip("/") + CHECK_PATH,
            data=body,
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {config.server_token}"},
            method="POST",
        )
        return Verdict.from_json(_within_deadline(opener, request, config.check_timeout_ms / 1000))
    except Exception as error:
        fallback = "deny" if config.fail_closed else "allow"
        if log is not None:
            log(f"policy check failed ({type(error).__name__}: {error}); falling back to {fallback}")
        return Verdict(decision=fallback, reason=f"policy server unavailable; failing {'closed' if config.fail_closed else 'open'}")


def _within_deadline(opener, request, seconds):
    """The parsed JSON reply, or TimeoutError once ``seconds`` have passed."""
    outcome = {}

    def post():
        try:
            with opener(request, timeout=seconds) as response:
                outcome["reply"] = json.loads(response.read())
        except BaseException as error:
            outcome["error"] = error

    worker = threading.Thread(target=post, daemon=True)
    worker.start()
    worker.join(seconds)
    if worker.is_alive():
        raise TimeoutError(f"no /check verdict within {seconds:g}s")
    if "error" in outcome:
        raise outcome["error"]
    return outcome["reply"]


def emit_checked(record, config, *, pre_tool: bool, ask_blocks: bool = False) -> Verdict | None:
    """Emit ``record``, first asking /check when this is a pre-tool event.

    Redaction always runs before the request leaves the machine, whatever
    config.redact says. A deny is emitted as BLOCKED, the spec's "blocked by
    our own control" row, and so is an ask when ``ask_blocks`` (a caller with
    no human to ask). Returns the verdict, or None when no check ran.
    """
    import dataclasses

    from stationchief.core.records import Decision
    from stationchief.core.redact import redact_record
    from stationchief.pipeline import emit, log_error

    verdict = None
    if pre_tool and configured(config):
        cleaned, hits = redact_record(record, enabled=True)
        verdict = ask(cleaned, hits, config, log=lambda message: log_error(config, message))
        if verdict.decision == "deny" or (ask_blocks and verdict.decision == "ask"):
            record = dataclasses.replace(record, decision=Decision.BLOCKED)
    # The verdict is what keeps a denied call from running: nothing after it
    # may turn a deny into an allow by raising.
    try:
        emit(record, config)
    except BaseException:
        import traceback

        log_error(config, f"emit after /check failed: {traceback.format_exc()}")
    return verdict


def reason_text(verdict: Verdict) -> str:
    return f"Blocked by stationchief policy: {verdict.reason or 'no reason given'}"
