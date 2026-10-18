import os
import pathlib
import sys
import tempfile

import pytest

# stationchief.config binds DEFAULT_HOME -- and Config's dataclass default for its
# `home` field -- from $HOME at *import* time. Several test modules import
# stationchief.config at collection time, before any per-test fixture gets to run,
# so HOME must already point somewhere safe by then. Otherwise Config()'s
# frozen default falls back to the developer's real ~/.stationchief for the rest of
# the test session no matter what a later fixture monkeypatches.
os.environ["HOME"] = tempfile.mkdtemp(prefix="stationchief-test-home-")

sys.path.insert(0, str(pathlib.Path(__file__).parent))

from ocsf_check import validate  # noqa: E402


@pytest.fixture(autouse=True)
def _isolate_home(tmp_path_factory, monkeypatch):
    """Set HOME to a per-test tmp dir to prevent writing to the developer's real home."""
    tmp_home = tmp_path_factory.mktemp("home")
    monkeypatch.setenv("HOME", str(tmp_home))
    # DEFAULT_HOME is computed at import time, so we need to monkeypatch it too
    monkeypatch.setattr("stationchief.config.DEFAULT_HOME", tmp_home / ".stationchief")
    # OtlpSink remembers per process that the server is down; tests share one.
    otlp = sys.modules.get("stationchief.sinks.otlp")
    if otlp is not None:
        otlp._unreachable.clear()


FIXTURES = pathlib.Path(__file__).parent / "fixtures"
GOLDEN = pathlib.Path(__file__).parent / "golden"


@pytest.fixture
def assert_valid_ocsf():
    def _assert(event):
        errors = validate(event)
        assert errors == [], "OCSF validation failed:\n  " + "\n  ".join(errors)

    return _assert


@pytest.fixture
def load_fixture():
    def _load(agent, name):
        import json

        return json.loads((FIXTURES / agent / f"{name}.json").read_text())

    return _load


@pytest.fixture
def assert_golden(assert_valid_ocsf):
    """Compare an event against its golden file and validate it.

    Set STATIONCHIEF_UPDATE_GOLDEN=1 to write the golden file instead of comparing.
    """

    def _assert(agent, name, event):
        import json
        import os

        path = GOLDEN / agent / f"{name}.ocsf.json"
        assert_valid_ocsf(event)
        if os.environ.get("STATIONCHIEF_UPDATE_GOLDEN"):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(event, indent=2, sort_keys=True) + "\n")
            return
        assert path.exists(), f"missing golden file {path}; run with STATIONCHIEF_UPDATE_GOLDEN=1"
        assert event == json.loads(path.read_text())

    return _assert
