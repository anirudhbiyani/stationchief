import json

from stationchief.config import Config
from stationchief.core.records import Action, ActionKind, ActivityRecord, Actor, Decision
from stationchief.pipeline import emit

SECRET = "AKIAIOSFODNN7EXAMPLE"


def make_record(prompt=f"deploy using {SECRET}"):
    return ActivityRecord(
        source="claude",
        session_id="sess-abc",
        turn_id="turn-1",
        ts=1758326400000,
        event="PreToolUse",
        actor=Actor(
            user_name="dev",
            agent_name="claude-code",
            agent_version="2.0.1",
            model="claude-opus-5",
            model_provider="Anthropic",
            pid=4242,
        ),
        cwd="/repo",
        hostname="laptop",
        posture={"permission_mode": "default"},
        prompt=prompt,
        action=Action(tool="Bash", kind=ActionKind.SHELL, input={"command": "ls"}),
        decision=Decision.OBSERVED,
    )


def test_emit_writes_a_valid_ocsf_event_to_the_ndjson_sink(tmp_path, assert_valid_ocsf):
    config = Config(home=tmp_path, detect=False)
    events = emit(make_record(), config)
    assert len(events) == 1
    assert_valid_ocsf(events[0])
    written = list(tmp_path.glob("events-*.ndjson"))[0].read_text().splitlines()
    assert json.loads(written[0]) == events[0]


def test_no_secret_reaches_any_sink(tmp_path):
    emit(make_record(), Config(home=tmp_path, detect=False))
    written = list(tmp_path.glob("events-*.ndjson"))[0].read_text()
    assert SECRET not in written


def test_a_failing_sink_does_not_propagate(tmp_path):
    class Exploding:
        def write(self, events):
            raise RuntimeError("disk on fire")

    events = emit(make_record(), Config(home=tmp_path, detect=False), sinks=[Exploding()])
    assert len(events) == 1, "the event is still produced even when a sink fails"


def test_a_failing_sink_is_logged(tmp_path):
    class Exploding:
        def write(self, events):
            raise RuntimeError("disk on fire")

    emit(make_record(), Config(home=tmp_path, detect=False), sinks=[Exploding()])
    assert "disk on fire" in (tmp_path / "errors.log").read_text()


def test_a_misconfigured_sink_does_not_take_ndjson_down(tmp_path):
    config = Config(home=tmp_path, detect=False, sinks=("http", "bogus", "ndjson"))
    emit(make_record(), config)
    assert list(tmp_path.glob("events-*.ndjson")), "ndjson must still be written"
    assert "unconfigured sink 'http'" in (tmp_path / "errors.log").read_text()


def test_detection_findings_are_emitted_alongside_the_activity_event(tmp_path, assert_valid_ocsf):
    config = Config(home=tmp_path)
    events = emit(make_record(prompt=f"deploy using {SECRET}"), config)
    class_uids = [event["class_uid"] for event in events]
    assert class_uids == [2004, 1007]
    for event in events:
        assert_valid_ocsf(event)


def test_detection_can_be_turned_off(tmp_path):
    events = emit(make_record(), Config(home=tmp_path, detect=False))
    assert [event["class_uid"] for event in events] == [1007]


def test_a_failing_http_sink_does_not_log_its_token(tmp_path):
    config = Config(
        home=tmp_path,
        detect=False,
        sinks=("http",),
        http_url="https://127.0.0.1:1/ingest",  # nothing listens on port 1
        http_token="super-secret-token",
    )
    emit(make_record(), config)
    log = (tmp_path / "errors.log").read_text()
    assert "HttpSink" in log
    assert "super-secret-token" not in log


class CountingSink:
    def __init__(self):
        self.writes = []

    def write(self, events):
        self.writes.append(list(events))


def test_emit_many_redacts_each_record_and_writes_once(tmp_path):
    from stationchief.pipeline import emit_many

    sink = CountingSink()
    assert emit_many([make_record(), make_record(prompt="plain")], Config(home=tmp_path), sinks=[sink]) is True
    assert len(sink.writes) == 1
    events = sink.writes[0]
    assert SECRET not in json.dumps(events)
    assert any(e["class_uid"] == 2004 for e in events)  # detection still runs


class FailingSink:
    def write(self, events):
        raise OSError("disk full")


def test_emit_many_reports_whether_any_sink_captured_the_events(tmp_path):
    from stationchief.pipeline import emit_many

    config = Config(home=tmp_path)
    assert emit_many([make_record()], config, sinks=[FailingSink()]) is False
    assert emit_many([make_record()], config, sinks=[FailingSink(), CountingSink()]) is True


def test_emit_many_with_nothing_writes_nothing(tmp_path):
    from stationchief.pipeline import emit_many

    sink = CountingSink()
    assert emit_many([], Config(home=tmp_path), sinks=[sink]) is True
    assert sink.writes == []


def test_errors_log_is_created_0600_in_a_0700_directory(tmp_path):
    import os
    import stat

    from stationchief.pipeline import log_error

    home = tmp_path / "fresh"
    old = os.umask(0)  # prove the modes come from os.open/mkdir, not the umask
    try:
        log_error(Config(home=home), "boom")
    finally:
        os.umask(old)
    assert stat.S_IMODE((home / "errors.log").stat().st_mode) == 0o600
    assert stat.S_IMODE(home.stat().st_mode) == 0o700
    log_error(Config(home=home), "again")
    assert (home / "errors.log").read_text().count("\n") == 2


def test_an_existing_loose_home_is_tightened_to_0700(tmp_path):
    import stat

    from stationchief.pipeline import log_error

    tmp_path.chmod(0o755)
    log_error(Config(home=tmp_path), "boom")
    assert stat.S_IMODE(tmp_path.stat().st_mode) == 0o700
