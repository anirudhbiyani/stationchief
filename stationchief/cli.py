"""Command-line entry point.

`stationchief hook <agent>` runs inside the agent's critical path on every tool call,
so imports here stay lazy: the adapters and the pipeline are imported inside
the handler, not at module scope. See the perf test in tests/test_cli.py.

The hook subcommand always exits 0. A non-zero exit from a hook disrupts the
developer's session, which is a worse outcome than losing one event.
"""

import argparse
import json
import os
import pathlib
import sys

import stationchief

ADAPTERS = ("claude", "cursor", "codex")
INGESTERS = ("cursor", "codex")


def _config():
    from stationchief.config import Config

    home = os.environ.get("STATIONCHIEF_HOME")
    config = Config.load(pathlib.Path(home) / "config.json" if home else None)
    if home:
        import dataclasses

        config = dataclasses.replace(config, home=pathlib.Path(home))
    return config


def _respond(text: str) -> None:
    """Write the hook's one-line response. Never raises: if the agent has
    closed the pipe, stdout is pointed at /dev/null so the interpreter's own
    flush at exit cannot fail either."""
    try:
        sys.stdout.write(text + "\n")
        sys.stdout.flush()
    except BaseException:
        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
        except BaseException:
            pass


def _hook(agent: str) -> int:
    import contextlib

    config = None
    response = {}
    try:
        config = _config()
        if agent not in ADAPTERS:
            from stationchief.pipeline import log_error

            log_error(config, f"unknown agent {agent!r}")
        else:
            from importlib import import_module

            module = import_module(f"stationchief.adapters.{agent}")
            try:
                payload = json.loads(sys.stdin.read() or "{}")
            except (ValueError, RecursionError):
                # Deeply nested JSON raises RecursionError: it is invalid
                # input like any other, not a reason to skip the adapter.
                payload = {}
            # stdout carries the agent's JSON response and nothing else: the
            # stdout sink (or any stray print) goes to stderr during the hook.
            with contextlib.redirect_stdout(sys.stderr):
                response = module.handle(payload, config)
    except BaseException:
        import traceback

        response = {}
        try:
            from stationchief.config import Config
            from stationchief.pipeline import log_error

            stationchief_home = os.environ.get("STATIONCHIEF_HOME")
            fallback_config = config or (
                Config(home=pathlib.Path(stationchief_home)) if stationchief_home else Config()
            )
            log_error(fallback_config, f"hook {agent} failed: {traceback.format_exc()}")
        except BaseException:
            pass
    try:
        text = json.dumps(response)
    except BaseException:
        text = "{}"
    _respond(text)
    return 0


def _ingest(agents, cursor_dir, codex_dir) -> int:
    from importlib import import_module

    config = _config()
    sources = {"cursor": cursor_dir, "codex": codex_dir}
    status = 0
    for agent in agents:
        try:
            emitted, skipped, gaps = import_module(f"stationchief.ingest.{agent}").ingest(config, sources[agent])
            print(f"{agent}: emitted {emitted}, skipped {skipped} already captured by hooks, {gaps} coverage gap finding(s)")
        except Exception as error:
            print(f"{agent}: ingest failed: {error}", file=sys.stderr)
            status = 1
    return status


def _install(agents, config_path, remove: bool) -> int:
    import shlex

    from stationchief import install as installer
    from stationchief.config import Config

    fail_closed = Config.load().fail_closed

    # Quoted: an interpreter under "/Users/Jane Doe/..." must stay one word.
    command_base = f"{shlex.quote(sys.executable)} -m stationchief.cli hook"
    for agent in agents:
        try:
            if remove:
                changed = installer.uninstall(agent, config_path=config_path)
                print(f"{agent}: {'uninstalled' if changed else 'nothing to remove'}")
            else:
                changed = installer.install(
                    agent, config_path=config_path, command=f"{command_base} {agent}", fail_closed=fail_closed
                )
                print(f"{agent}: {'installed' if changed else 'already installed'}")
        except (KeyError, ValueError, OSError) as error:
            print(f"{agent}: {error}", file=sys.stderr)
            return 1
    return 0


def _configure(server_url: str, token_file: str, keep_ndjson: bool) -> int:
    """Point this machine at a stationchief service. The token is read from a file,
    never from argv, where it would land in shell history and `ps` output."""
    from stationchief.sinks.http import require_secure_url

    try:
        require_secure_url(server_url)
    except ValueError as error:
        print(f"configure: {error}", file=sys.stderr)
        return 1
    try:
        token = pathlib.Path(token_file).read_text().strip()
    except OSError as error:
        print(f"configure: cannot read token file: {error}", file=sys.stderr)
        return 1
    if not token:
        print("configure: token file is empty", file=sys.stderr)
        return 1

    home = _config().home
    path = home / "config.json"
    try:
        existing = json.loads(path.read_text())
    except (OSError, ValueError):
        existing = {}
    if not isinstance(existing, dict):
        existing = {}
    existing.update(
        {
            "server_url": server_url.rstrip("/"),
            "server_token": token,
            "sinks": ["server", "ndjson"] if keep_ndjson else ["server"],
        }
    )
    home.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(home, 0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(existing, handle, indent=2, sort_keys=True)
    os.chmod(path, 0o600)
    print(f"configured {path}: events go to {server_url.rstrip('/')}/otel, policy checks to /check")
    if existing.get("redact") is False:
        print(
            f"configure: warning: {path} has \"redact\": false, so the server sink will be refused "
            "and no events will reach the service. Remove that setting to send events.",
            file=sys.stderr,
        )
    return 0


def _flush() -> int:
    from stationchief.sinks.otlp import OtlpSink, flush

    config = _config()
    if not (config.server_url and config.server_token):
        print("flush: no server configured; run `stationchief configure` first", file=sys.stderr)
        return 1
    sink = OtlpSink(config.server_url, config.server_token, spool_dir=config.home / "spool")
    sent, waiting = flush(sink, config.home / "spool")
    print(f"flush: sent {sent} event(s); {waiting} spool file(s) still waiting")
    return 1 if waiting else 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="stationchief", description=stationchief.__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    hook = sub.add_parser("hook", help="handle one hook payload on stdin")
    hook.add_argument("agent")

    for name in ("install", "uninstall"):
        command = sub.add_parser(name, help=f"{name} hooks for one or more agents")
        command.add_argument("agents", nargs="+", choices=list(ADAPTERS))
        command.add_argument("--config-path", default=None)

    configure = sub.add_parser("configure", help="send events and policy checks to a stationchief service")
    configure.add_argument("--server", required=True, help="service base URL, e.g. https://stationchief.example.com")
    configure.add_argument("--token-file", required=True, help="file holding the bearer token")
    configure.add_argument("--keep-ndjson", action="store_true", help="also keep the local NDJSON files")

    sub.add_parser("flush", help="resend events spooled while the service was unreachable")
    ingest = sub.add_parser("ingest", help="read agent transcripts at rest: backfill and hook coverage check")
    ingest.add_argument("agents", nargs="+", choices=list(INGESTERS))
    ingest.add_argument("--cursor-dir", default=None, help="Cursor user directory (default: platform location)")
    ingest.add_argument("--codex-dir", default=None, help="Codex sessions directory (default: ~/.codex/sessions)")

    sub.add_parser("version", help="print the version")

    args = parser.parse_args(argv)
    if args.command == "hook":
        return _hook(args.agent)
    if args.command in ("install", "uninstall"):
        return _install(args.agents, args.config_path, remove=args.command == "uninstall")
    if args.command == "configure":
        return _configure(args.server, args.token_file, args.keep_ndjson)
    if args.command == "flush":
        return _flush()
    if args.command == "ingest":
        return _ingest(args.agents, args.cursor_dir, args.codex_dir)
    print(stationchief.__version__)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
