import json

import pytest

from stationchief.config import Config


def test_defaults_are_safe(tmp_path):
    config = Config.load(tmp_path / "missing.json")
    assert config.redact is True
    assert config.detect is True
    assert config.sinks == ("ndjson",)


def test_reads_a_config_file(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"redact": False, "sinks": ["ndjson", "stdout"]}))
    config = Config.load(path)
    assert config.redact is False
    assert config.sinks == ("ndjson", "stdout")


def test_superseded_block_and_s3_settings_are_gone(tmp_path):
    # Blocking is a /check decision (C2); storage is the service's job (A5).
    import stationchief.detect.rules as rules

    assert not {"block", "s3_uri"} & {f for f in Config.__dataclass_fields__}
    assert not hasattr(rules, "should_block")
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"block": True, "s3_uri": "s3://x", "redact": False}))
    assert Config.load(path).redact is False  # old keys are ignored, not fatal


def test_malformed_config_falls_back_to_defaults_rather_than_raising(tmp_path):
    path = tmp_path / "config.json"
    path.write_text("{not json")
    assert Config.load(path).redact is True


def test_unknown_keys_are_ignored(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"redact": True, "future_option": 1}))
    assert Config.load(path).redact is True


def test_home_defaults_under_the_user_directory(tmp_path):
    # Config's `home` field default is bound once, from the user's home
    # directory, when the class is defined -- not re-derived on each call.
    # So the true "user directory" reference here is Config()'s own default,
    # not a fresh pathlib.Path.home() lookup (tests isolate $HOME per-test,
    # which would otherwise make this comparison flaky/wrong).
    assert Config.load(tmp_path / "missing.json").home == Config().home


def test_a_single_sink_given_as_a_string_is_one_sink_not_its_characters(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"sinks": "ndjson"}))
    assert Config.load(path).sinks == ("ndjson",)


def test_a_sinks_value_that_is_neither_string_nor_list_falls_back_to_the_default(tmp_path):
    path = tmp_path / "config.json"
    for bad in (5, {"ndjson": True}, None):
        path.write_text(json.dumps({"sinks": bad}))
        assert Config.load(path).sinks == Config().sinks


@pytest.mark.parametrize(
    "raw, field, expected",
    [
        ({"home": None}, "home", Config().home),
        ({"home": 5}, "home", Config().home),
        ({"sinks": ["ndjson", 3]}, "sinks", ("ndjson",)),
        ({"fail_closed": "false"}, "fail_closed", False),
        ({"fail_closed": 1}, "fail_closed", False),
        ({"redact": None}, "redact", True),
        ({"detect": "no"}, "detect", True),
        ({"check_timeout_ms": 0}, "check_timeout_ms", 750),
        ({"check_timeout_ms": -5}, "check_timeout_ms", 750),
        ({"check_timeout_ms": "500"}, "check_timeout_ms", 750),
        ({"check_timeout_ms": True}, "check_timeout_ms", 750),
        ({"check_timeout_ms": 1500.5}, "check_timeout_ms", 1500.5),
        ({"server_url": 5}, "server_url", None),
    ],
)
def test_a_wrongly_typed_field_falls_back_to_its_default_without_raising(tmp_path, raw, field, expected):
    path = tmp_path / "config.json"
    path.write_text(json.dumps(raw))
    assert getattr(Config.load(path), field) == expected


def test_one_bad_field_keeps_the_valid_security_settings(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"home": None, "fail_closed": True, "check_timeout_ms": 200}))
    config = Config.load(path)
    assert config.fail_closed is True and config.check_timeout_ms == 200
