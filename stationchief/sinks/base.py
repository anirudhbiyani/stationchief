"""The sink contract: one method, so adding a destination stays cheap."""

import json
import sys
from typing import Protocol


class Sink(Protocol):
    def write(self, events: list[dict]) -> None:
        """Persist ``events``. Must not raise; a failed sink must not kill a hook."""


class StdoutSink:
    def write(self, events: list[dict]) -> None:
        for event in events:
            sys.stdout.write(json.dumps(event, sort_keys=True) + "\n")
        sys.stdout.flush()
