"""`stationchief-server`: serve, hash-token."""

import argparse
import logging
import sys

from stationchief.server.config import ServerConfig, hash_token


def _store(config: ServerConfig, memory: bool):
    if memory:
        from stationchief.server.store import MemoryStore

        logging.getLogger("stationchief.server").warning("--memory: events are lost on restart")
        return MemoryStore()
    if not config.storage_url:
        raise SystemExit("no storage_url (or STATIONCHIEF_STORAGE_URL) configured; use --memory for local testing")
    from stationchief.server.store import store_from_url

    return store_from_url(config.storage_url)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="stationchief-server")
    parser.add_argument("--config", default=None, help="server config JSON (default: $STATIONCHIEF_SERVER_CONFIG)")
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve", help="run the HTTP service")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument("--memory", action="store_true", help="in-memory store, for local testing only")
    sub.add_parser("hash-token", help="read a token on stdin, print its config-file digest")
    args = parser.parse_args(argv)

    if args.command == "hash-token":
        token = sys.stdin.readline().strip()
        if not token:
            print("hash-token: empty token on stdin", file=sys.stderr)
            return 1
        print(hash_token(token))
        return 0

    try:
        config = ServerConfig.load(args.config)
    except (KeyError, OSError, ValueError) as error:
        print(f"stationchief-server: cannot load config: {error}", file=sys.stderr)
        return 1

    try:
        store = _store(config, args.memory)
    except ValueError as error:
        print(f"stationchief-server: {error}", file=sys.stderr)
        return 1
    import uvicorn

    from stationchief.server.app import create_app

    logging.basicConfig(level=logging.INFO)
    uvicorn.run(create_app(config, store), host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
