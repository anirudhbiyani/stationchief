"""Append-only NDJSON, rotated by date. The default sink.

These files contain prompts and tool arguments, so the directory is 0700 and
every file is 0600 — enforced on each write, not only at creation, because a
file may predate this code or have been chmodded since.
"""

import datetime
import json
import os
import pathlib
from typing import Callable

DIRECTORY_MODE = 0o700
FILE_MODE = 0o600


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


class NdjsonSink:
    def __init__(self, directory, *, now: Callable[[], datetime.datetime] = _utcnow, prefix: str = "events"):
        self._directory = pathlib.Path(directory)
        self._now = now
        self._prefix = prefix

    def path(self) -> pathlib.Path:
        return self._directory / f"{self._prefix}-{self._now().strftime('%Y-%m-%d')}.ndjson"

    def write(self, events: list[dict]) -> None:
        if not events:
            return
        self._directory.mkdir(parents=True, exist_ok=True, mode=DIRECTORY_MODE)
        os.chmod(self._directory, DIRECTORY_MODE)
        path = self.path()
        # O_CREAT with an explicit mode closes the window where the file exists
        # world-readable between creation and chmod.
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, FILE_MODE)
        try:
            with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
                for event in events:
                    handle.write(json.dumps(event, sort_keys=True) + "\n")
        finally:
            os.chmod(path, FILE_MODE)
