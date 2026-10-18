import copy

import pytest

from ocsf_check import validate

VALID = {
    "class_uid": 1001,
    "category_uid": 1,
    "activity_id": 2,
    "type_uid": 100102,
    "severity_id": 1,
    "time": 1758326400000,
    "metadata": {
        "version": "1.9.0",
        "product": {"name": "stationchief", "vendor_name": "StationChief"},
        "profiles": ["security_control", "host", "ai_operation"],
    },
    "actor": {"user": {"name": "dev", "type_id": 1}, "process": {"pid": 4242, "name": "claude"}},
    "device": {"type_id": 3, "hostname": "laptop"},
    "file": {"name": "app.py", "type_id": 1, "path": "/repo/app.py"},
    "action_id": 3,
}


def test_valid_event_has_no_errors():
    assert validate(VALID) == []


def test_missing_required_attribute_is_reported():
    event = copy.deepcopy(VALID)
    del event["file"]
    assert any("file: required attribute missing" in e for e in validate(event))


def test_unknown_attribute_is_reported():
    event = copy.deepcopy(VALID)
    event["not_a_field"] = 1
    assert any("not_a_field: unknown attribute" in e for e in validate(event))


def test_profile_gated_attribute_without_declaration_is_reported():
    event = copy.deepcopy(VALID)
    event["metadata"]["profiles"] = ["host", "ai_operation"]
    errors = validate(event)
    assert any("action_id" in e and "security_control" in e for e in errors)


def test_type_uid_mismatch_is_reported():
    event = copy.deepcopy(VALID)
    event["type_uid"] = 100199
    assert any("type_uid" in e for e in validate(event))


def test_at_least_one_constraint_is_enforced():
    event = copy.deepcopy(VALID)
    event["actor"]["process"] = {"name": "claude", "cmd_line": "claude"}
    assert any("at_least_one" in e for e in validate(event))


def test_enum_value_is_checked():
    event = copy.deepcopy(VALID)
    event["file"]["type_id"] = 77
    assert any("file.type_id" in e for e in validate(event))
