"""HTTP POST sink: Splunk HEC, or any endpoint that accepts NDJSON.

Runs inside the hook, so it uses the stdlib only and a short timeout. A slow
collector costs at most TIMEOUT_SECONDS per tool call and is then logged by the
pipeline. The event is still in NDJSON if that sink is configured too.
TIMEOUT_SECONDS is an overall deadline, not only urllib's per-socket timeout,
so a server that trickles bytes cannot hold the hook either.

These bodies contain prompts, so https is required except to loopback.
"""

import json
import threading
import urllib.parse
import urllib.request

TIMEOUT_SECONDS = 2
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
HEC_PATH = "/services/collector"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect: the https/loopback check covers only the configured URL."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


no_redirect_open = urllib.request.build_opener(_NoRedirect).open
# Loopback traffic never goes through http_proxy: it is plain http, so the
# proxy would see the bearer token and the prompts in clear text.
loopback_open = urllib.request.build_opener(_NoRedirect, urllib.request.ProxyHandler({})).open


def default_opener(parts: urllib.parse.SplitResult):
    return loopback_open if parts.hostname in LOOPBACK_HOSTS else no_redirect_open


def call_with_deadline(function, seconds: float):
    """Run ``function`` on a daemon thread and wait at most ``seconds`` overall.

    urlopen's timeout bounds each socket operation, not the whole request.
    Raises TimeoutError on the deadline (the thread is abandoned and dies with
    the process), otherwise returns or re-raises what ``function`` did."""
    outcome = {}

    def run():
        try:
            outcome["value"] = function()
        except BaseException as error:
            outcome["error"] = error

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(seconds)
    if thread.is_alive():
        raise TimeoutError(f"no complete answer within {seconds} s")
    if "error" in outcome:
        raise outcome["error"]
    return outcome.get("value")


def require_secure_url(url: str) -> urllib.parse.SplitResult:
    """https, or plain http to loopback only. Shared by every sender that
    ships prompts or tool input off the machine."""
    parts = urllib.parse.urlsplit(url)
    secure = parts.scheme == "https" and bool(parts.hostname)
    local = parts.scheme == "http" and parts.hostname in LOOPBACK_HOSTS
    if not (secure or local):
        raise ValueError(f"refusing to send events to {url!r}: https required except to loopback")
    return parts


class HttpSink:
    def __init__(self, url: str, *, token: str | None = None, opener=None):
        parts = require_secure_url(url)
        if opener is None:
            opener = default_opener(parts)
        self._url = url
        self._token = token
        self._open = opener
        # Known limit: HEC is recognised by its fixed endpoint path, not a config flag.
        self._hec = parts.path == HEC_PATH or parts.path.startswith(HEC_PATH + "/")

    def _body(self, events: list[dict]) -> tuple[bytes, str]:
        if self._hec:
            envelopes = (
                json.dumps({"event": e, "sourcetype": "ocsf", "time": e.get("time", 0) / 1000}, sort_keys=True)
                for e in events
            )
            return "\n".join(envelopes).encode(), "application/json"
        return "".join(json.dumps(e, sort_keys=True) + "\n" for e in events).encode(), "application/x-ndjson"

    def write(self, events: list[dict]) -> None:
        if not events:
            return
        body, content_type = self._body(events)
        headers = {"Content-Type": content_type}
        if self._token:
            headers["Authorization"] = f"{'Splunk' if self._hec else 'Bearer'} {self._token}"
        request = urllib.request.Request(self._url, data=body, headers=headers, method="POST")
        # urlopen raises on 4xx/5xx; the pipeline catches and logs it.
        call_with_deadline(lambda: self._post(request), TIMEOUT_SECONDS)

    def _post(self, request) -> None:
        with self._open(request, timeout=TIMEOUT_SECONDS):
            pass
