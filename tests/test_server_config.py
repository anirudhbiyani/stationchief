import json

import pytest

from stationchief.server.config import ServerConfig, hash_token


def write(tmp_path, data):
    path = tmp_path / "server.json"
    path.write_text(json.dumps(data))
    return path


def test_loads_tokens_as_digests(tmp_path):
    config = ServerConfig.load(write(tmp_path, {"tokens": {hash_token("t0k"): "fleet"}}))
    assert config.principal_for("t0k") == "fleet"
    assert config.principal_for("wrong") is None
    assert config.principal_for("") is None


def test_refuses_to_start_without_tokens(tmp_path):
    with pytest.raises(ValueError, match="no tokens"):
        ServerConfig.load(write(tmp_path, {"tokens": {}}))


def test_rejects_a_config_without_a_tokens_mapping(tmp_path):
    with pytest.raises(ValueError, match="tokens"):
        ServerConfig.load(write(tmp_path, {"storage_url": "s3://x"}))


def test_malformed_json_raises_rather_than_defaulting(tmp_path):
    path = tmp_path / "server.json"
    path.write_text("{not json")
    with pytest.raises(ValueError):
        ServerConfig.load(path)


def test_path_comes_from_the_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("STATIONCHIEF_SERVER_CONFIG", str(write(tmp_path, {"tokens": {hash_token("a"): "p"}})))
    assert ServerConfig.load().principal_for("a") == "p"


def test_storage_url_prefers_the_environment(tmp_path, monkeypatch):
    path = write(tmp_path, {"tokens": {hash_token("a"): "p"}, "storage_url": "s3://file"})
    monkeypatch.setenv("STATIONCHIEF_STORAGE_URL", "gs://env")
    assert ServerConfig.load(path).storage_url == "gs://env"


def test_on_engine_error_is_validated(tmp_path):
    with pytest.raises(ValueError, match="on_engine_error"):
        ServerConfig.load(write(tmp_path, {"tokens": {hash_token("a"): "p"}, "on_engine_error": "maybe"}))


def test_digests_are_matched_case_insensitively(tmp_path):
    config = ServerConfig.load(write(tmp_path, {"tokens": {hash_token("a").upper(): "p"}}))
    assert config.principal_for("a") == "p"
