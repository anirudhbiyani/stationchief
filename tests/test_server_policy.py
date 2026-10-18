import io
import json
import os
import pathlib
import shutil
import subprocess
import urllib.error

import pytest

from stationchief.policy import CheckRequest, Verdict
from stationchief.server.check import AllowAllEngine
from stationchief.server.config import ServerConfig, hash_token
from stationchief.server.policy import OpaEngine, OpaError, build_engine
from test_server_check import REQUEST

POLICY_DIR = pathlib.Path(__file__).parent.parent / "policy"


class FakeOpa:
    """Stands in for urllib.request.urlopen; answers with a canned reply."""

    def __init__(self, reply=None, status=200, raises=None):
        self.reply, self.status, self.raises = reply, status, raises
        self.requests = []

    def __call__(self, request, timeout):
        self.requests.append((request, timeout))
        if self.raises is not None:
            raise self.raises
        outer = self

        class Response:
            status = outer.status

            def read(self):
                return json.dumps(outer.reply).encode()

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        return Response()


def engine(opa, **kwargs):
    return OpaEngine(url="http://opa:8181", opener=opa, **kwargs)


def request():
    return CheckRequest.from_json(REQUEST)


@pytest.mark.parametrize("decision", ["allow", "deny", "ask"])
def test_returns_the_policy_decision(decision):
    opa = FakeOpa({"result": {"decision": decision, "reason": "because"}})
    verdict = engine(opa).decide(request())
    assert verdict == Verdict(decision, "because", "stationchief/check/decision")


def test_opa_input_carries_the_authenticated_principal():
    opa = FakeOpa({"result": {"decision": "allow"}})
    engine(opa).decide(request(), principal="laptop-fleet")
    sent = json.loads(opa.requests[0][0].data)["input"]
    assert sent["principal"] == "laptop-fleet"
    assert sent["user"] == REQUEST["user"]  # the client's claim is still there


def test_posts_the_check_request_as_opa_input():
    opa = FakeOpa({"result": {"decision": "allow", "reason": ""}})
    engine(opa, timeout_s=0.25).decide(request())
    http_request, timeout = opa.requests[0]
    assert http_request.full_url == "http://opa:8181/v1/data/stationchief/check/decision?provenance"
    assert http_request.get_method() == "POST"
    assert json.loads(http_request.data) == {"input": {**REQUEST, "principal": None}}
    assert timeout == 0.25


def test_policy_names_the_bundle_revision_when_opa_reports_one():
    reply = {
        "result": {"decision": "deny", "reason": "r"},
        "provenance": {"version": "1.21.0", "bundles": {"stationchief": {"revision": "a1b2c3"}}},
    }
    assert engine(FakeOpa(reply)).decide(request()).policy == "stationchief/check/decision (stationchief@a1b2c3)"


@pytest.mark.parametrize(
    "opa, error",
    [
        (FakeOpa({}), OpaError),  # undefined: no rule produced a result
        (FakeOpa({"result": "allow"}), OpaError),
        (FakeOpa({"result": {"decision": "maybe"}}), ValueError),
        (FakeOpa({"result": {"decision": "allow"}}, status=500), OpaError),
        (FakeOpa(raises=TimeoutError("timed out")), TimeoutError),
        (FakeOpa(raises=urllib.error.URLError("refused")), urllib.error.URLError),
        (FakeOpa(raises=urllib.error.HTTPError("u", 500, "err", {}, io.BytesIO(b""))), urllib.error.HTTPError),
    ],
)
def test_every_failure_raises_so_the_endpoint_fallback_applies(opa, error):
    with pytest.raises(error):
        engine(opa).decide(request())


def test_build_engine_defaults_to_allow_all():
    assert isinstance(build_engine(None), AllowAllEngine)
    assert isinstance(build_engine({"type": "allow_all"}), AllowAllEngine)


def test_build_engine_configures_opa():
    built = build_engine({"type": "opa", "url": "http://opa:8181/", "path": "/team/decision", "timeout_ms": 100})
    assert isinstance(built, OpaEngine)
    assert built._endpoint == "http://opa:8181/v1/data/team/decision?provenance"
    assert built._timeout_s == 0.1


@pytest.mark.parametrize(
    "spec",
    [{"type": "cedar"}, "opa", {"type": "opa", "timeout_ms": 0}, {"type": "opa", "timeout_ms": "250"}],
)
def test_invalid_engine_config_fails_at_load(spec):
    with pytest.raises(ValueError, match="engine"):
        ServerConfig(tokens={hash_token("a"): "p"}, engine=spec)


def test_engine_is_read_from_the_config_file(tmp_path):
    path = tmp_path / "server.json"
    path.write_text(json.dumps({"tokens": {hash_token("a"): "p"}, "engine": {"type": "opa", "url": "http://opa:8181"}}))
    assert ServerConfig.load(path).engine == {"type": "opa", "url": "http://opa:8181"}


def test_rego_policy_unit_tests():
    """Runs the policy's own `opa test` suite when the opa binary is installed."""
    opa = shutil.which("opa") or os.environ.get("STATIONCHIEF_OPA_BIN")
    if not opa:
        pytest.skip("opa binary not installed; run `opa test policy/ -v` where it is")
    result = subprocess.run([opa, "test", str(POLICY_DIR), "-v"], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.opa
def test_against_a_running_opa_server():
    url = os.environ.get("STATIONCHIEF_TEST_OPA_URL")
    if not url:
        pytest.skip("STATIONCHIEF_TEST_OPA_URL not set")
    live = OpaEngine(url=url, timeout_s=2)
    deny = CheckRequest.from_json({**REQUEST, "input": {"command": "rm -rf /"}, "redaction_rules": []})
    allow = CheckRequest.from_json({**REQUEST, "input": {"command": "ls"}, "redaction_rules": []})
    assert live.decide(deny).decision == "deny"
    assert live.decide(allow).decision == "allow"


def test_opa_on_loopback_bypasses_http_proxy():
    from stationchief.sinks import http

    assert OpaEngine(url="http://127.0.0.1:8181")._open is http.loopback_open
    assert OpaEngine(url="https://opa.example")._open is http.no_redirect_open
