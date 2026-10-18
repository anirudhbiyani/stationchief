"""Policy engines for /check, and the config that selects one.

OPA runs as a central sidecar next to the stationchief service and owns every
policy decision. The service asks it once per pending tool call:

    POST {url}/v1/data/{path}?provenance   {"input": <CheckRequest> + "principal"}
    ->   {"result": {"decision": "allow"|"deny"|"ask", "reason": "..."}}

Anything else (no result, a non-2xx, a malformed decision, a timeout) raises,
and the /check endpoint answers the server's `on_engine_error` fallback.
Stdlib urllib: OPA is one HTTP call away, and the service already waits on
it in a worker thread. The default opener refuses redirects: the service
talks to a localhost sidecar, and a redirect there is never legitimate.
"""

import json
import urllib.parse
import urllib.request

from stationchief.policy import CheckRequest, Verdict
from stationchief.server.check import AllowAllEngine
from stationchief.sinks.http import default_opener

DEFAULT_OPA_URL = "http://127.0.0.1:8181"
DEFAULT_OPA_PATH = "stationchief/check/decision"
DEFAULT_OPA_TIMEOUT_MS = 250
ENGINE_TYPES = ("allow_all", "opa")


class OpaError(RuntimeError):
    pass


class OpaEngine:
    def __init__(
        self,
        url: str = DEFAULT_OPA_URL,
        path: str = DEFAULT_OPA_PATH,
        timeout_s: float = DEFAULT_OPA_TIMEOUT_MS / 1000,
        opener=None,
    ):
        self._path = path.strip("/")
        # ?provenance adds the loaded bundle revisions to the reply, so every
        # stored decision names the exact policy version that made it.
        self._endpoint = f"{url.rstrip('/')}/v1/data/{self._path}?provenance"
        self._timeout_s = timeout_s
        # The sidecar is plain-http loopback: never route it through http_proxy.
        self._open = opener or default_opener(urllib.parse.urlsplit(url))

    def _policy_name(self, reply: dict) -> str:
        bundles = ((reply.get("provenance") or {}).get("bundles")) or {}
        revisions = sorted(
            f"{name}@{info['revision']}"
            for name, info in bundles.items()
            if isinstance(info, dict) and info.get("revision")
        )
        return f"{self._path} ({', '.join(revisions)})" if revisions else self._path

    def decide(self, request: CheckRequest, principal: str | None = None) -> Verdict:
        # input.principal is the authenticated caller; input.user is only
        # what the client claims, so per-user rules must use principal.
        body = json.dumps({"input": {**request.to_json(), "principal": principal}}).encode()
        http_request = urllib.request.Request(
            self._endpoint, data=body, headers={"Content-Type": "application/json"}, method="POST"
        )
        with self._open(http_request, timeout=self._timeout_s) as response:
            status = getattr(response, "status", 200)
            if status >= 300:
                raise OpaError(f"OPA answered HTTP {status}")
            reply = json.loads(response.read())
        result = reply.get("result") if isinstance(reply, dict) else None
        if not isinstance(result, dict):
            raise OpaError(f"policy {self._path} is undefined for this input")
        # Verdict raises ValueError on anything but allow/deny/ask.
        return Verdict(
            decision=result.get("decision"),
            reason=str(result.get("reason") or ""),
            policy=self._policy_name(reply),
        )


def validate_engine_spec(spec) -> dict:
    spec = {"type": "allow_all"} if spec is None else spec
    if not isinstance(spec, dict) or spec.get("type", "allow_all") not in ENGINE_TYPES:
        raise ValueError(f"engine.type must be one of {ENGINE_TYPES}")
    if spec.get("type") == "opa":
        timeout_ms = spec.get("timeout_ms", DEFAULT_OPA_TIMEOUT_MS)
        if not isinstance(timeout_ms, int) or isinstance(timeout_ms, bool) or not 1 <= timeout_ms <= 10_000:
            raise ValueError("engine.timeout_ms must be an integer between 1 and 10000")
    return spec


def build_engine(spec):
    """Engine from the server config's `engine` object; allow_all by default."""
    spec = validate_engine_spec(spec)
    if spec.get("type", "allow_all") == "allow_all":
        return AllowAllEngine()
    return OpaEngine(
        url=spec.get("url", DEFAULT_OPA_URL),
        path=spec.get("path", DEFAULT_OPA_PATH),
        timeout_s=spec.get("timeout_ms", DEFAULT_OPA_TIMEOUT_MS) / 1000,
    )
