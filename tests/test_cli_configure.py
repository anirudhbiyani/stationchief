import json
import stat

from stationchief.cli import main
from stationchief.config import Config


def token_file(tmp_path, value="s3cret-token\n"):
    path = tmp_path / "token"
    path.write_text(value)
    return str(path)


def test_configure_writes_an_owner_only_config(tmp_path, monkeypatch, capsys):
    home = tmp_path / "home"
    monkeypatch.setenv("STATIONCHIEF_HOME", str(home))
    assert main(["configure", "--server", "https://stationchief.example.com/", "--token-file", token_file(tmp_path)]) == 0
    path = home / "config.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    config = Config.load(path)
    assert (config.server_url, config.server_token, config.sinks) == ("https://stationchief.example.com", "s3cret-token", ("server",))
    assert "s3cret-token" not in capsys.readouterr().out


def test_keep_ndjson_keeps_the_local_sink(tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("STATIONCHIEF_HOME", str(home))
    main(["configure", "--server", "https://a.example.com", "--token-file", token_file(tmp_path), "--keep-ndjson"])
    assert Config.load(home / "config.json").sinks == ("server", "ndjson")


def test_existing_keys_are_preserved(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    (home / "config.json").write_text(json.dumps({"detect": False, "http_url": "https://splunk.example.com"}))
    monkeypatch.setenv("STATIONCHIEF_HOME", str(home))
    main(["configure", "--server", "https://a.example.com", "--token-file", token_file(tmp_path)])
    data = json.loads((home / "config.json").read_text())
    assert data["detect"] is False and data["http_url"] == "https://splunk.example.com"


def test_preexisting_directory_permissions_are_fixed(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir(mode=0o755)
    monkeypatch.setenv("STATIONCHIEF_HOME", str(home))
    main(["configure", "--server", "https://a.example.com", "--token-file", token_file(tmp_path)])
    assert stat.S_IMODE(home.stat().st_mode) == 0o700


def test_plaintext_servers_are_refused(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("STATIONCHIEF_HOME", str(tmp_path / "home"))
    assert main(["configure", "--server", "http://a.example.com", "--token-file", token_file(tmp_path)]) == 1
    assert "https required" in capsys.readouterr().err
    assert not (tmp_path / "home" / "config.json").exists()


def test_empty_or_missing_token_files_are_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("STATIONCHIEF_HOME", str(tmp_path / "home"))
    assert main(["configure", "--server", "https://a.example.com", "--token-file", token_file(tmp_path, "\n")]) == 1
    assert main(["configure", "--server", "https://a.example.com", "--token-file", str(tmp_path / "nope")]) == 1


def test_flush_without_a_server_is_an_error(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("STATIONCHIEF_HOME", str(tmp_path / "home"))
    assert main(["flush"]) == 1
    assert "stationchief configure" in capsys.readouterr().err


def test_flush_with_nothing_spooled_succeeds(tmp_path, monkeypatch, capsys):
    home = tmp_path / "home"
    monkeypatch.setenv("STATIONCHIEF_HOME", str(home))
    main(["configure", "--server", "https://a.example.com", "--token-file", token_file(tmp_path)])
    assert main(["flush"]) == 0
    assert "sent 0" in capsys.readouterr().out


def test_configure_warns_when_the_existing_config_turns_redaction_off(tmp_path, monkeypatch, capsys):
    home = tmp_path / "home"
    home.mkdir()
    (home / "config.json").write_text(json.dumps({"redact": False}))
    monkeypatch.setenv("STATIONCHIEF_HOME", str(home))
    assert main(["configure", "--server", "https://a.example.com", "--token-file", token_file(tmp_path)]) == 0
    err = capsys.readouterr().err
    assert "redact" in err and "refused" in err


def test_configure_does_not_warn_when_redaction_is_on(tmp_path, monkeypatch, capsys):
    home = tmp_path / "home"
    monkeypatch.setenv("STATIONCHIEF_HOME", str(home))
    main(["configure", "--server", "https://a.example.com", "--token-file", token_file(tmp_path)])
    assert "redact" not in capsys.readouterr().err
