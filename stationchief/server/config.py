"""Server configuration: which bearer tokens are valid, and who they belong to.

The config file maps sha256(token) to a principal name, so the file itself
holds no usable secret. Generate an entry with `stationchief-server hash-token`.
"""

import dataclasses
import hashlib
import hmac
import json
import os
import pathlib

DEFAULT_MAX_BODY_BYTES = 5 * 1024 * 1024
ENGINE_ERROR_CHOICES = ("allow", "deny")


@dataclasses.dataclass(frozen=True)
class ServerConfig:
    tokens: dict[str, str]
    storage_url: str | None = None
    on_engine_error: str = "allow"
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES
    engine: dict = dataclasses.field(default_factory=lambda: {"type": "allow_all"})

    def __post_init__(self):
        if not self.tokens:
            raise ValueError("no tokens configured; refusing to run an unauthenticated server")
        if self.on_engine_error not in ENGINE_ERROR_CHOICES:
            raise ValueError(f"on_engine_error must be one of {ENGINE_ERROR_CHOICES}")
        from stationchief.server.policy import validate_engine_spec

        validate_engine_spec(self.engine)

    @classmethod
    def load(cls, path=None) -> "ServerConfig":
        """Read the JSON config. Unlike the client config, errors raise: a
        server that silently starts with defaults is a server without auth."""
        path = pathlib.Path(path or os.environ["STATIONCHIEF_SERVER_CONFIG"])
        raw = json.loads(path.read_text())
        if not isinstance(raw, dict) or not isinstance(raw.get("tokens"), dict):
            raise ValueError(f"{path}: expected an object with a 'tokens' mapping")
        return cls(
            tokens={str(k).lower(): str(v) for k, v in raw["tokens"].items()},
            # s3://bucket/prefix or gs://bucket/prefix; the environment wins.
            storage_url=os.environ.get("STATIONCHIEF_STORAGE_URL") or raw.get("storage_url"),
            on_engine_error=raw.get("on_engine_error", "allow"),
            max_body_bytes=int(raw.get("max_body_bytes", DEFAULT_MAX_BODY_BYTES)),
            engine=raw.get("engine") or {"type": "allow_all"},
        )

    def principal_for(self, token: str) -> str | None:
        """Constant-time lookup: every configured digest is compared."""
        digest = hash_token(token)
        found = None
        for known, principal in self.tokens.items():
            if hmac.compare_digest(known, digest):
                found = principal
        return found


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
