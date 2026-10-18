from stationchief.config import Config
from stationchief import state


def test_missing_state_reads_as_empty(tmp_path):
    assert state.read(Config(home=tmp_path), "sess-abc") == {}


def test_update_then_read_round_trips(tmp_path):
    config = Config(home=tmp_path)
    state.update(config, "sess-abc", prompt="hello", turn_id="turn-1")
    assert state.read(config, "sess-abc") == {"prompt": "hello", "turn_id": "turn-1"}


def test_update_merges_rather_than_replacing(tmp_path):
    config = Config(home=tmp_path)
    state.update(config, "sess-abc", prompt="hello")
    state.update(config, "sess-abc", model="claude-opus-5")
    assert state.read(config, "sess-abc") == {"prompt": "hello", "model": "claude-opus-5"}


def test_state_file_is_owner_only(tmp_path):
    import stat

    config = Config(home=tmp_path)
    state.update(config, "sess-abc", prompt="secret plan")
    path = tmp_path / "state" / "sess-abc.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_corrupt_state_reads_as_empty_rather_than_raising(tmp_path):
    config = Config(home=tmp_path)
    state.update(config, "sess-abc", prompt="hello")
    (tmp_path / "state" / "sess-abc.json").write_text("{broken")
    assert state.read(config, "sess-abc") == {}


def test_session_id_is_sanitised_into_the_filename(tmp_path):
    config = Config(home=tmp_path)
    state.update(config, "../../escape", prompt="x")
    assert not (tmp_path.parent / "escape.json").exists()
    assert state.read(config, "../../escape") == {"prompt": "x"}


def test_update_replaces_the_file_atomically_instead_of_truncating_it(tmp_path):
    import json

    config = Config(home=tmp_path)
    state.update(config, "s1", prompt="first")
    path = tmp_path / "state" / "s1.json"
    with open(path) as reader:  # a concurrent reader holding the old file
        state.update(config, "s1", model="m")
        assert json.loads(reader.read()) == {"prompt": "first"}
    assert state.read(config, "s1") == {"prompt": "first", "model": "m"}
    assert [p.name for p in (tmp_path / "state").iterdir()] == ["s1.json"]
