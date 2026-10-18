import dataclasses

import pytest

from stationchief.adapters.otel import ATTRIBUTE_PREFIX, attributes_to_record
from stationchief.core.records import ActionKind, Decision

CONTEXT = {"hostname": "laptop", "user_name": "dev"}


def attributes(**overrides):
    base = {
        "stationchief.session_id": "sess-otel",
        "stationchief.turn_id": "turn-1",
        "stationchief.agent_name": "our-agent",
        "stationchief.agent_version": "0.3.0",
        "stationchief.model": "claude-opus-5",
        "stationchief.model_provider": "Anthropic",
        "stationchief.tool": "run_shell",
        "stationchief.kind": "shell",
        "stationchief.input": '{"command": "ls -la"}',
        "stationchief.cwd": "/repo",
        "stationchief.prompt": "list the files",
        "stationchief.decision": "observed",
        "stationchief.ts": 1758326400000,
    }
    base.update(overrides)
    return base


def test_attributes_become_a_record():
    record = attributes_to_record(attributes(), **CONTEXT)
    assert record.source == "otel"
    assert record.session_id == "sess-otel"
    assert record.action.kind == ActionKind.SHELL
    assert record.action.input == {"command": "ls -la"}
    assert record.decision == Decision.OBSERVED


def test_record_maps_to_the_same_ocsf_as_a_hook_record(assert_valid_ocsf):
    from stationchief.core.mapping import map_record

    event = map_record(attributes_to_record(attributes(), **CONTEXT))
    assert event["class_uid"] == 1007
    assert event["ai_agent"]["name"] == "our-agent"
    assert event["message_context"]["prompt_text"] == "list the files"
    assert_valid_ocsf(event)


def test_records_without_our_prefix_are_ignored():
    assert attributes_to_record({"http.method": "GET"}, **CONTEXT) is None


def test_missing_required_attribute_is_ignored_rather_than_guessed():
    without_session = {k: v for k, v in attributes().items() if k != "stationchief.session_id"}
    assert attributes_to_record(without_session, **CONTEXT) is None


def test_input_may_be_a_dict_as_well_as_a_json_string():
    record = attributes_to_record(attributes(**{"stationchief.input": {"command": "pwd"}}), **CONTEXT)
    assert record.action.input == {"command": "pwd"}


def test_unparseable_input_becomes_an_empty_dict_not_a_crash():
    record = attributes_to_record(attributes(**{"stationchief.input": "{broken"}), **CONTEXT)
    assert record.action.input == {}


def test_unknown_kind_falls_back_to_unknown():
    record = attributes_to_record(attributes(**{"stationchief.kind": "teleport"}), **CONTEXT)
    assert record.action.kind == ActionKind.UNKNOWN


def test_missing_timestamp_is_supplied_rather_than_rejected():
    without_ts = {k: v for k, v in attributes().items() if k != "stationchief.ts"}
    assert isinstance(attributes_to_record(without_ts, **CONTEXT).ts, int)


def test_prefix_is_exported_for_instrumentors():
    assert ATTRIBUTE_PREFIX == "stationchief."


@pytest.mark.skipif(
    __import__("importlib.util", fromlist=["util"]).find_spec("opentelemetry") is None,
    reason="opentelemetry-sdk not installed",
)
def test_processor_emits_through_the_pipeline(tmp_path):
    from stationchief.adapters.otel import StationChiefLogRecordProcessor
    from stationchief.config import Config

    class FakeLogRecord:
        def __init__(self, attributes):
            self.attributes = attributes

    class FakeLogData:
        def __init__(self, attributes):
            self.log_record = FakeLogRecord(attributes)

    processor = StationChiefLogRecordProcessor(Config(home=tmp_path, detect=False))
    processor.emit(FakeLogData(attributes()))
    assert processor.force_flush()
    assert list(tmp_path.glob("events-*.ndjson"))


class _LogData:
    def __init__(self, attrs):
        self.log_record = type("LogRecord", (), {"attributes": attrs})()


def _processor(tmp_path, **overrides):
    from stationchief.adapters.otel import StationChiefLogRecordProcessor
    from stationchief.config import Config

    return StationChiefLogRecordProcessor(Config(home=tmp_path, detect=False, **overrides))


def test_processor_writes_in_the_background_and_drains_on_shutdown(tmp_path):
    import json

    processor = _processor(tmp_path)
    for n in range(50):
        processor.emit(_LogData(attributes(**{"stationchief.turn_id": f"t{n}"})))
    processor.shutdown()
    lines = [line for f in tmp_path.glob("events-*.ndjson") for line in f.read_text().splitlines()]
    assert len(lines) == 50 and all(json.loads(line)["class_uid"] for line in lines)
    processor.emit(_LogData(attributes()))  # after shutdown: ignored, never raises


def test_a_full_queue_drops_instead_of_blocking_the_caller(tmp_path, monkeypatch):
    import threading
    import time

    from stationchief.adapters.otel import StationChiefLogRecordProcessor

    release = threading.Event()
    monkeypatch.setattr(StationChiefLogRecordProcessor, "QUEUE_SIZE", 2)
    monkeypatch.setattr(StationChiefLogRecordProcessor, "_write", lambda self, batch: release.wait(5))
    processor = _processor(tmp_path)
    start = time.monotonic()
    for _ in range(20):
        processor.emit(_LogData(attributes()))
    assert time.monotonic() - start < 0.5
    assert processor._dropped >= 15
    release.set()
    assert processor.force_flush(5000)
    processor.shutdown()


def test_shutdown_resends_the_spool_when_a_server_is_configured(tmp_path, monkeypatch):
    from stationchief.sinks import otlp

    calls = []
    monkeypatch.setattr(otlp, "flush", lambda sink, spool: calls.append(spool) or (0, 0))
    (tmp_path / "spool").mkdir()
    processor = _processor(tmp_path, sinks=["ndjson"], server_url="https://stationchief.example", server_token="t")
    processor.shutdown()
    assert calls == [tmp_path / "spool"]
