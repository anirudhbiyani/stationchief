#!/bin/sh
# Runs once per developer, as that developer (Jamf: run as current user; Intune: user context).
# STATIONCHIEF_TOKEN is this developer's own bearer token, from your MDM's secret store.
set -eu
umask 077
PY=/opt/stationchief/venv/bin/python
SERVER=https://stationchief.example.com
FAIL_CLOSED=false   # true: block tool calls when the StationChief service is unreachable

mkdir -p "$HOME/.stationchief"
token_file=$(mktemp "$HOME/.stationchief/token.XXXXXX")
trap 'rm -f "$token_file"' EXIT
printf '%s' "$STATIONCHIEF_TOKEN" > "$token_file"
"$PY" -m stationchief.cli configure --server "$SERVER" --token-file "$token_file"
"$PY" - "$FAIL_CLOSED" <<'PYEOF'
import json, pathlib, sys
path = pathlib.Path.home() / ".stationchief" / "config.json"
config = json.loads(path.read_text())
config["fail_closed"] = sys.argv[1] == "true"
path.write_text(json.dumps(config, indent=2, sort_keys=True))
PYEOF
