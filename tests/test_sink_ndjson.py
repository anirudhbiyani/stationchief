import datetime
import json
import stat

from stationchief.sinks.ndjson import NdjsonSink

EVENT = {"class_uid": 1007, "time": 1758326400000}


def at(day):
    return lambda: datetime.datetime(2026, 9, day, 12, 0, tzinfo=datetime.timezone.utc)


def test_writes_one_json_object_per_line(tmp_path):
    sink = NdjsonSink(tmp_path, now=at(20))
    sink.write([EVENT, {"class_uid": 1001}])
    path = tmp_path / "events-2026-09-20.ndjson"
    lines = path.read_text().splitlines()
    assert [json.loads(line)["class_uid"] for line in lines] == [1007, 1001]


def test_appends_rather_than_truncating(tmp_path):
    sink = NdjsonSink(tmp_path, now=at(20))
    sink.write([EVENT])
    sink.write([EVENT])
    assert len((tmp_path / "events-2026-09-20.ndjson").read_text().splitlines()) == 2


def test_rotates_by_date(tmp_path):
    NdjsonSink(tmp_path, now=at(20)).write([EVENT])
    NdjsonSink(tmp_path, now=at(21)).write([EVENT])
    assert sorted(p.name for p in tmp_path.iterdir()) == [
        "events-2026-09-20.ndjson",
        "events-2026-09-21.ndjson",
    ]


def test_event_file_is_owner_only(tmp_path):
    sink = NdjsonSink(tmp_path, now=at(20))
    sink.write([EVENT])
    mode = stat.S_IMODE((tmp_path / "events-2026-09-20.ndjson").stat().st_mode)
    assert mode == 0o600, f"expected 0600, got {oct(mode)}"


def test_creates_its_directory_owner_only(tmp_path):
    directory = tmp_path / "nested" / "stationchief"
    NdjsonSink(directory, now=at(20)).write([EVENT])
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700


def test_tightens_permissions_on_a_preexisting_world_readable_file(tmp_path):
    path = tmp_path / "events-2026-09-20.ndjson"
    path.write_text("")
    path.chmod(0o644)
    NdjsonSink(tmp_path, now=at(20)).write([EVENT])
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_empty_write_creates_nothing(tmp_path):
    NdjsonSink(tmp_path, now=at(20)).write([])
    assert list(tmp_path.iterdir()) == []


def test_output_is_single_line_per_event_even_with_newlines_inside(tmp_path):
    sink = NdjsonSink(tmp_path, now=at(20))
    sink.write([{"message": "line one\nline two"}])
    lines = (tmp_path / "events-2026-09-20.ndjson").read_text().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["message"] == "line one\nline two"
