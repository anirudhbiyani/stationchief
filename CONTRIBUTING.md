# Contributing

Thanks for helping. StationChief is in beta, so open an issue to discuss anything larger than a small fix before you start. `docs/roadmap.md` lists the planned work, each item with a design and a definition of done.

## Setup

You need Python 3.14 or later, [uv](https://docs.astral.sh/uv/) and [OPA](https://www.openpolicyagent.org/docs/latest/#running-opa).

```bash
uv venv --python 3.14
uv pip install -e '.[dev,server,otel]'
.venv/bin/pytest -q          # the full suite
opa test policy/ -v          # the Rego policy tests
```

CI runs both on Linux and macOS for every push and pull request.

## Rules every change follows

- **The client stays standard-library only.** Anything outside `stationchief/server/` may import only the standard library; `tests/test_no_third_party_imports.py` enforces this. Hooks run inside the agent's critical path on every developer's machine.
- **Test against a real agent, not only its documentation.** Each adapter has had at least one bug that only real data revealed. When you add or change an adapter:
  1. Capture a real payload or export.
  2. Replace every personal value (emails, usernames, hostnames, account, organisation and session IDs, home paths) with a placeholder.
  3. Commit it as a fixture next to the test, like the `*_0158.json` and `*_real_export.json` fixtures.
- **Every OCSF event is schema-checked.** Use the `assert_valid_ocsf` fixture. A new OCSF class goes into `KEEP` in `tools/fetch_schema.py`, and the bundled schema is regenerated.
- **Golden files** in `tests/golden/` are regenerated with `STATIONCHIEF_UPDATE_GOLDEN=1 .venv/bin/pytest -q`. Review the diff: only the fields you meant to change should move.
- **Keep `deploy/managed/` in sync** when hook events or commands change; `tests/test_deploy_managed.py` fails otherwise.
- **No real secrets in tests.** Use recognisably fake values, such as AWS's documented example key `AKIAIOSFODNN7EXAMPLE`.

## License

By contributing, you agree that your contribution is licensed under the project's license, [AGPL-3.0-or-later](LICENSE).
