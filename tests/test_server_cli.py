import io
import json

from stationchief.server.cli import main
from stationchief.server.config import hash_token


def test_hash_token_reads_stdin(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("s3cret\n"))
    assert main(["hash-token"]) == 0
    assert capsys.readouterr().out.strip() == hash_token("s3cret")


def test_hash_token_refuses_an_empty_token(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("\n"))
    assert main(["hash-token"]) == 1


def test_serve_refuses_to_start_without_tokens(tmp_path, capsys):
    path = tmp_path / "server.json"
    path.write_text(json.dumps({"tokens": {}}))
    assert main(["--config", str(path), "serve"]) == 1
    assert "no tokens" in capsys.readouterr().err


def test_serve_needs_a_storage_url(tmp_path, monkeypatch):
    monkeypatch.delenv("STATIONCHIEF_STORAGE_URL", raising=False)
    path = tmp_path / "server.json"
    path.write_text(json.dumps({"tokens": {hash_token("a"): "p"}}))
    try:
        main(["--config", str(path), "serve"])
    except SystemExit as exit_:
        assert "storage_url" in str(exit_)
    else:
        raise AssertionError("serve ran without storage")


def test_serve_refuses_an_unsupported_storage_url(tmp_path, capsys):
    path = tmp_path / "server.json"
    path.write_text(json.dumps({"tokens": {hash_token("a"): "p"}, "storage_url": "postgresql://x"}))
    assert main(["--config", str(path), "serve"]) == 1
    assert "s3://" in capsys.readouterr().err
