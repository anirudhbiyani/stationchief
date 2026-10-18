import gzip
import json
import re
import threading

import pytest

from stationchief.server.store import EventRejected, MemoryStore, ObjectStore, object_key, store_from_url
from server_helpers import ocsf_event


class Bucket:
    """Records every put as (key, decoded lines)."""

    def __init__(self, fail=None):
        self.objects, self.fail = [], fail

    def put(self, key, data):
        if self.fail:
            raise self.fail
        self.objects.append((key, [json.loads(l) for l in gzip.decompress(data).splitlines()]))


def test_memory_store_dedups_on_uid():
    store = MemoryStore()
    event = ocsf_event()
    assert store.write([event, event], "p") == 1
    assert store.write([event], "p") == 0
    assert store.events() == [event]


def test_memory_store_uniqueness_is_per_principal():
    store = MemoryStore()
    event = ocsf_event()
    assert store.write([event], "team-a") == 1
    assert store.write([event], "team-b") == 1
    assert store.write([event], "team-a") == 0


def test_object_store_writes_one_gzip_ndjson_object_with_the_principal():
    bucket = Bucket()
    event = ocsf_event(session_id="sess-9")
    assert ObjectStore(bucket.put, "stationchief/", window_s=0).write([event], "fleet") == 1
    ((key, rows),) = bucket.objects
    assert re.fullmatch(r"stationchief/dt=\d{4}-\d\d-\d\d/hour=\d\d/\d+-[0-9a-f]{32}\.ndjson\.gz", key)
    assert rows[0]["principal"] == "fleet" and rows[0]["event"] == event
    assert isinstance(rows[0]["received_at"], int)


def test_concurrent_writes_in_one_window_share_one_object():
    bucket = Bucket()
    store = ObjectStore(bucket.put, window_s=0.2)
    threads = [threading.Thread(target=store.write, args=([ocsf_event(command=f"ls {i}")], f"p{i}")) for i in range(5)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    ((_, rows),) = bucket.objects
    assert sorted(row["principal"] for row in rows) == [f"p{i}" for i in range(5)]


def test_an_upload_failure_raises_in_every_writer_so_each_gets_a_503():
    store = ObjectStore(Bucket(fail=ConnectionError("s3 down")).put, window_s=0.2)
    errors = []

    def write(i):
        try:
            store.write([ocsf_event(command=f"ls {i}")], "p")
        except Exception as error:
            errors.append(error)

    threads = [threading.Thread(target=write, args=(i,)) for i in range(3)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(errors) == 3 and all(isinstance(e, ConnectionError) for e in errors)
    assert not any(isinstance(e, EventRejected) for e in errors)  # an outage, not bad data


def test_an_unserialisable_event_is_rejected_before_anything_is_uploaded():
    bucket = Bucket()
    event = ocsf_event()
    event["time"] = float("nan")
    with pytest.raises(EventRejected) as info:
        ObjectStore(bucket.put, window_s=0).write([event], "p")
    assert info.value.rejected == 1 and bucket.objects == []


def test_one_bad_event_does_not_cost_the_rest_of_the_batch_a_retry_each():
    from stationchief.server.app import _store_each

    bucket = Bucket()
    bad = ocsf_event(command="bad")
    bad["time"] = float("nan")
    good = [ocsf_event(command=f"ls {i}") for i in range(50)]
    store = ObjectStore(bucket.put, window_s=0.2)
    assert _store_each(store, good + [bad], "p") == (1, False)
    ((_, rows),) = bucket.objects  # one upload, not 51 windows
    assert len(rows) == 50


def test_empty_writes_upload_nothing():
    bucket = Bucket()
    assert ObjectStore(bucket.put, window_s=0).write([], "p") == 0
    assert bucket.objects == []


def test_object_key_without_a_prefix():
    assert object_key("", 0).startswith("dt=1970-01-01/hour=00/0-")


class FakeS3:
    def __init__(self):
        self.calls = []

    def put_object(self, **kwargs):
        self.calls.append(kwargs)


class FakeGcs:
    def __init__(self):
        self.calls = []

    def bucket(self, name):
        client = self

        class Blob:
            def __init__(self, key):
                self.key = key

            def upload_from_string(self, data, **kwargs):
                client.calls.append((name, self.key, data, kwargs))

        class Bucket:
            def blob(self, key):
                return Blob(key)

        return Bucket()


def test_s3_url_puts_to_the_bucket_under_the_prefix():
    s3 = FakeS3()
    store = store_from_url("s3://telemetry/agents", client=s3)
    store._window_s = 0
    store.write([ocsf_event()], "p")
    (call,) = s3.calls
    assert call["Bucket"] == "telemetry" and call["Key"].startswith("agents/dt=")
    assert gzip.decompress(call["Body"]).startswith(b'{"event":')


def test_gcs_url_creates_objects_without_overwriting():
    gcs = FakeGcs()
    store = store_from_url("gs://telemetry/agents", client=gcs)
    store._window_s = 0
    store.write([ocsf_event()], "p")
    ((bucket, key, _, kwargs),) = gcs.calls
    assert bucket == "telemetry" and key.startswith("agents/dt=")
    assert kwargs["if_generation_match"] == 0 and kwargs["timeout"] > 0


@pytest.mark.parametrize("url", ["postgresql://x/y", "s3://", "file:///tmp/x", "telemetry"])
def test_other_storage_urls_are_refused(url):
    with pytest.raises(ValueError, match="storage_url"):
        store_from_url(url, client=object())
