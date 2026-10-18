# Roadmap: closing the gaps

This is the plan for StationChief's known gaps, ordered so the next few releases can pick items from the top. It comes from a comparison with commercial AI coding agent security tools (Pillar, CrowdStrike, Microsoft Defender, Noma, Zenity and others) and open-source ones (Perplexity Numbat, Gen Digital Sage, agent-chaperone), and from what live testing against Claude Code, Codex and Cursor showed.

StationChief's differentiators, which every item below should protect rather than dilute:
- **OCSF-native events** in the classes a SIEM already understands.
- **Policy-as-code**: OPA/Rego for blocking, Sigma for detection.
- **Fail-closed** where the agent allows it.
- **Self-hosted**, with redaction on the laptop and a client that needs only Python's standard library.

Each item lists the problem, a design that names the files to change, what "done" means (the tests that prove it), and a rough size: **S** is about 1–2 days, **M** about 3–5 days, **L** a week or more.

## Summary

| # | Item | Why it matters | Size | Depends on |
|---|---|---|---|---|
| 1 | [OCSF 1.1 export for Amazon Security Lake](#1-ocsf-11-export-for-amazon-security-lake) | Security Lake and many SIEM integrations expect OCSF 1.1, not 1.9 | M | — |
| 2 | [Tamper and coverage monitoring](#2-tamper-and-coverage-monitoring) | Detect machines where StationChief's hooks were removed or never loaded | M | — |
| 3 | [Posture findings and `stationchief scan`](#3-posture-findings-and-stationchief-scan) | Risky agent configuration is a top buying criterion; StationChief only inventories it today | M | — |
| 4 | [`install --managed` and a system-wide client config](#4-install---managed-and-a-system-wide-client-config) | Rollout today needs hand-copied files and a per-user script | M | — |
| 5 | [More agents: Gemini CLI and GitHub Copilot CLI](#5-more-agents-gemini-cli-and-github-copilot-cli) | 3 agents against competitors' 8 to 26 | M each | — |
| 6 | [Cursor CLI history ingest](#6-cursor-cli-history-ingest) | The Cursor CLI's own chats are not backfilled | S | — |
| 7 | [Structured shell policy](#7-structured-shell-policy) | Policy matches command text, so simple rewording slips past | M | — |
| 8 | [Native OTel noise reduction](#8-native-otel-noise-reduction) | Codex code mode and approval-only events add noise | S | — |
| 9 | [SIEM content pack](#9-siem-content-pack) | Teams need ready queries, duplicate removal and Sigma conversions on day one | M | 1 |
| 10 | [Windows support](#10-windows-support) | Paths and file permissions are untested on Windows | L | 4 |
| 11 | [Typed business actions for custom agents](#11-typed-business-actions-for-custom-agents) | Non-coding agents' email, payment and database actions are all `unknown` | M | — |

Suggested release grouping:
- **0.2:** items 1, 2, 3, 8. Mostly server-side; strengthens the SIEM story.
- **0.3:** items 4, 6, 7, 9. Easier rollout and stronger enforcement.
- **0.4 and later:** items 5, 10, 11. Breadth.

## Ground rules for every item

- **No new third-party dependencies on the client.** `tests/test_no_third_party_imports.py` enforces this; server-only dependencies stay under `stationchief/server/`.
- **Verify against a real agent before calling it done.** Every adapter so far had at least one bug that only real data revealed: Claude Code's OTel event names, Codex's `Bash` tool name and code mode, Cursor's summarised conversations. Capture a real payload, sanitise it, and commit it as a fixture next to the test, as the `*_0158.json` and `*_real_export.json` fixtures do.
- **New OCSF classes:** add the class to `KEEP` in `tools/fetch_schema.py`, regenerate `tests/schema/ocsf-1.9.0-pruned.json`, and validate every new event with the `assert_valid_ocsf` fixture.
- **Keep `deploy/managed/` in sync** whenever hook events or commands change. `tests/test_deploy_managed.py` fails otherwise.

---

## 1. OCSF 1.1 export for Amazon Security Lake

**Problem.** StationChief emits OCSF 1.9.0. Amazon Security Lake custom sources, and integrations built on it such as Elastic's, follow OCSF 1.1.0. Several 1.9 fields don't exist in 1.1, including the `ai_agent` and `ai_model` objects and the `ai_operation` profile, so events fail validation or lose their agent attribution.

**Design.**
- **Where to convert:** in the **server**, at storage time, not on the client. Clients keep emitting 1.9, so their events stay rich and a single conversion point controls what's stored.
- **Configuration:** a new `ocsf_version` setting in the server config, `"1.9.0"` (default) or `"1.1.0"`.
- **Converter:** add `stationchief/server/ocsf_compat.py` with `downgrade(event, target) -> event`. It:
  - sets `metadata.version`;
  - drops profiles the target lacks;
  - moves `ai_agent`, `ai_model` and `message_context` into `unmapped.stationchief.*`, so attribution survives in a documented place;
  - maps or drops any field missing from the 1.1 schema.
- **Where it's called:** in `stationchief/server/store.py` just before serialising, so both `/otel` events and `/check` decision events go through it.
- **Parquet:** Security Lake ingests Parquet, partitioned by source, region, account and date. Add a Parquet writer as an optional server extra (`pyarrow`), alongside the gzip NDJSON one, plus a short note in `docs/rollout.md` on registering StationChief as a Security Lake custom source.

**Done when:**
- every golden event, once downgraded, validates against a pruned 1.1.0 schema (add a `--version` option to `tools/fetch_schema.py`, which today fetches 1.9.0 only);
- a round-trip test shows agent name, model and session survive under `unmapped.stationchief`;
- one real event file is ingested by Security Lake (a manual check, written up in the PR).

**Size:** M. The converter is small; most of the work is the schema mapping table and its tests.

---

## 2. Tamper and coverage monitoring

**Problem.** A machine where StationChief's hooks were deleted, never trusted (Codex), or overridden by a higher-ranked managed source looks exactly like a machine with no agent activity. Transcript ingest catches *missed calls* after the fact, but only on machines where ingest runs.

**Design.**
- **Use Claude Code's own telemetry.** Its native OTel export already reports `claude_code.managed_settings_resolved` (which managed sources applied, or `refused`) and `claude_code.hook_registered` (one per hook). Both were seen in a real export. Map them in `stationchief/server/native.py`, adding them to `HANDLED`. Raise a **Detection Finding** (2004) when:
  - a session starts with **no StationChief hook registered** for `PreToolUse`, matched on the `stationchief.cli hook` command or the `# stationchief-managed` tag;
  - managed settings were `refused`, or the source behaviour means the StationChief policy file was skipped (the "first-wins" problem described in `docs/rollout.md`).
- **Heartbeat from the hooks.** The `SessionStart` hook already runs on every session. Have it emit a small heartbeat event recording the StationChief version, the agent, whether fail-closed is on, and whether the hook came from managed settings or the user's own files.
- **Silent-machine rule.** Add a Sigma rule `sigma/agent_hooks_silent.yml`: a host with agent activity in native OTel but no StationChief heartbeat in the last N hours.

**Done when:**
- sanitised real exports, with and without the StationChief hook registered, produce the right findings;
- the heartbeat is covered by a golden test;
- the new Sigma rule passes `tests/test_sigma.py`.

**Size:** M.

---

## 3. Posture findings and `stationchief scan`

**Problem.** StationChief already lists the MCP servers and plugins an agent loads, emitting an Application Lifecycle (6002) event from `stationchief/adapters/components.py` at session start. What it doesn't do is say whether a configuration is **risky**, and it only looks when a session starts.

**Design.**
- **New command:** `stationchief scan [claude|cursor|codex ...]`. It reads each agent's user, project and managed config with the existing readers in `components.py`, and emits one **Compliance Finding** (OCSF 2003, added to `KEEP`) per risky setting.
- **First checks**, each a small pure function with its own tests:
  - permission bypass: Claude Code `bypassPermissions` or `--dangerously-skip-permissions` aliases, Codex `danger-full-access` or `approval_policy = "never"`, Cursor "run everything";
  - MCP servers not on the approved list. Reuse `policy/data.json` `approved_mcp_tools`, so policy and posture share one list;
  - StationChief hooks missing, or not from a managed source;
  - hooks from unexpected sources, such as project-level `.claude/settings.json` or `.cursor/hooks.json`. Live research showed attackers using hook files as a way in;
  - `disableAllHooks` set at user level, which doesn't affect managed hooks but shows intent.
- **Scheduling:** run `scan` from the same cron or MDM schedule as `stationchief ingest`, and from the `SessionStart` hook at low cost.

**Done when:**
- each check has a passing and a failing fixture;
- `stationchief scan` exits 0 and prints a one-line summary per finding;
- findings validate as OCSF 2003.

**Size:** M.

---

## 4. `install --managed` and a system-wide client config

**Problem.** Rollout today means copying files from `deploy/managed/` and running `stationchief-user-setup.sh` for every developer, because:
- `install` writes only JSON, so it can't write Codex's `requirements.toml`;
- the client reads only `~/.stationchief/config.json`.

**Design.**
- **`stationchief install <agent> --managed`.** It writes the agent's managed location: `managed-settings.d/50-stationchief.json`, `/etc/codex/requirements.toml`, or the Cursor enterprise `hooks.json`.
  - It requires root and refuses to write a file it can't make `644`.
  - For Codex, it adds a minimal TOML writer for the `[hooks]` tables only (the standard library reads TOML but can't write it). It merges into an existing `requirements.toml` instead of overwriting it.
  - `deploy/managed/` becomes the output of `install --managed --print`, so the drift test compares against the same code path.
- **A `--fail-closed` flag on `install`**, so the fail-closed switch no longer depends on the caller's own config.
- **System-wide client config.** `Config.load()` reads `/etc/stationchief/config.json` (on Windows, `%ProgramData%\StationChief\config.json`) and then the user file on top. Admin-owned keys (`fail_closed`, `server_url`) can be locked with a `"locked": [...]` list, so a developer's file can't turn fail-closed off.
- **Per-developer tokens** stay in the user file. Optionally, a `token_command` key, like `otelHeadersHelper`, fetches the token from a keychain or secrets manager.

**Done when:**
- `install --managed` round-trips: `uninstall --managed` restores the original bytes;
- the Codex TOML it writes is accepted by a real Codex CLI;
- locked keys are honoured, with a test that a user file can't override them;
- `docs/rollout.md` steps 3 and 4 shrink to one command each.

**Size:** M.

---

## 5. More agents: Gemini CLI and GitHub Copilot CLI

**Problem.** StationChief covers 3 agents. Both of these expose pre-tool hooks, and they're the next most common in enterprise use.

**Design**, per agent. This is the pattern Codex and Cursor followed:
- an adapter `stationchief/adapters/<agent>.py` with `to_record`, `classify` and a verdict response in the agent's own format;
- an `AgentSpec` in `stationchief/install.py`: config path, events, style, and fail-closed switch if the agent has one;
- native OTel support in `server/native.py` if the agent exports it;
- a managed-config entry in `deploy/managed/` and `docs/rollout.md`;
- **real-payload fixtures captured first**, then the code. Don't build from documentation alone.

**Done when:**
- a live headless run of each agent allows `echo` and blocks `curl … | sh`;
- install and uninstall restore the original config byte for byte;
- the goldens are generated from real payloads.

**Size:** M per agent.

---

## 6. Cursor CLI history ingest

**Problem.** `stationchief ingest cursor` reads the Cursor **app's** database. The Cursor **CLI** keeps its chats elsewhere, in `~/.cursor/chats/<hash>/<id>/store.db` plus `meta.json`, so there's no backfill or coverage-gap check for CLI sessions.

**Design.**
- Add a second reader to `stationchief/ingest/cursor.py` for that store, reusing `_tool_call` and the watermark of emitted IDs.
- Reverse-engineer the schema from a real store first, read-only, and document it in the module docstring, as was done for the app store.

**Done when:**
- a real CLI session's tool calls are all emitted once, and a second run emits nothing;
- CLI sessions that the hooks captured are not repeated.

**Size:** S.

---

## 7. Structured shell policy

**Problem.** `policy/stationchief/check.rego` matches the command **string**. Its own header says shell tricks can get past it: `eval`, variables, wrappers, `xargs`, subshells. Competitors claim deeper analysis.

**Design.**
- **Parse on the client, decide in the policy.** In `stationchief/check.py`, before calling `/check`, split the command into pipeline segments with `shlex`. Record each segment's program, normalised by basename, its arguments and its redirections. Mark constructs that can't be analysed safely (`eval`, `$(…)`, backticks, `bash -c` with a variable) as `opaque: true`.
- **Send the parsed form with the raw string** in `CheckRequest`, as a new optional `input.shell` field. Existing policies keep working.
- **Rewrite the Rego rules over that structure.** For example: "any segment whose program is a shell, piped from a segment whose program is `curl` or `wget`". Add one ask rule: **opaque commands ask** rather than allow, configurable in `policy/data.json`.

**Done when:**
- every bypass example in the Rego header is caught or asked about, with `opa test` cases for each;
- no rule that existed before regresses;
- the parser has unit tests against real commands taken from the ingested histories.

**Size:** M.

---

## 8. Native OTel noise reduction

**Problem.**
- **Codex code mode** reports both the outer `exec` wrapper and the inner `exec_command` call, so every shell command appears twice: once as a generic API event and once as a process event.
- **`tool_decision` events** carry an approval but no command.

**Design.** In `stationchief/server/native.py`:
- **The `exec` wrapper:** drop `codex.tool_result` and `tool_decision` events for the wrapper when an inner tool call exists in the same conversation and turn. Otherwise keep it, so nothing is lost.
- **`tool_decision` events:** fold each into the matching `tool_result` by `call_id` / `tool_use_id`, carrying the decision as `action_id` / `disposition_id`, instead of emitting a separate empty event. That requires holding a decision briefly. Reuse the existing per-session cache in `NativeMapper` and bound it.

**Done when:**
- the real Codex and Claude Code export fixtures produce exactly one process event per command, carrying its approval decision;
- the event count in `test_real_*_export_is_mapped` drops accordingly.

**Size:** S.

---

## 9. SIEM content pack

**Problem.** StationChief ships 3 Sigma rules, and the README documents duplicates. A security team adopting it needs ready-made queries on day one.

**Design.** Add `content/`, with:
- **Queries** for Athena, BigQuery and Splunk:
  - removing duplicates on `(principal, metadata.uid)`, so the README's SQL becomes runnable files;
  - blocked actions by user;
  - MCP servers seen across the fleet;
  - the commands in a session (a replay timeline);
  - coverage-gap and tamper findings from items 2 and 3.
- **Sigma conversions** of the rules in `sigma/` with `sigma-cli`, checked into `content/` for the common backends and regenerated in CI. `sigma-cli` is a development dependency only.
- **New Sigma rules** for items 2 and 3, and one for an "unapproved MCP server first seen".
- **A one-page "first day with StationChief in your SIEM"** in `docs/`.

**Done when:**
- every query runs against the sample events in `tests/golden/`, using DuckDB in CI as a stand-in for Athena;
- CI fails if a Sigma conversion is stale.

**Size:** M.

---

## 10. Windows support

**Problem.** Windows is untested. Known risks:
- POSIX-only modes (`os.chmod` to `600`/`700`) and `os.O_*` flags in `pipeline.log_error` and the sinks;
- `shlex.quote` for the hook command in `cli._install`, which isn't valid for `cmd.exe` or PowerShell;
- managed paths under `C:\Program Files` and `%ProgramData%`;
- Codex's `command_windows` field.

**Design.**
- Add `windows-latest` to the CI matrix first, to surface failures.
- Then fix them behind small helpers: file permissions through ACLs, or documented as best effort; a hook command built from `subprocess.list2cmdline`; `command_windows` in the Codex managed TOML.

**Done when:**
- CI is green on Windows;
- a live Claude Code run on Windows allows and blocks as on macOS;
- the beta banner's "tested on macOS" covers Windows too.

**Size:** L. It depends on item 4 for the system-wide config path.

---

## 11. Typed business actions for custom agents

**Problem.** The Python decorator (`stationchief/adapters/agent.py`) records an email, payment or database action as `unknown`, which maps to the generic API Activity. Detections can't tell a refund from a search.

**Design.**
- **New action kinds**, starting with `email_send`, `db_query` and `payment`, in `stationchief/core/records.py`. Map them in `stationchief/core/mapping.py` to OCSF classes that fit: Email Activity (4009) for email, and API Activity with a typed `api.operation` for database and payment actions until OCSF has better classes.
- **Business fields in policy.** The decorator takes optional extractors, `@agent.tool(kind="payment", amount=lambda args: args["amount"])`, so Rego can write rules such as "ask above $500".
- **Real-framework checks:** add example agents, kept out of the core package, that run the decorator inside the OpenAI Agents SDK and LangChain in CI. That confirms tool schemas still build and `ToolBlocked` reaches the model.

**Done when:**
- each new kind maps to a valid OCSF event;
- a Rego test shows an amount-based rule working;
- both framework examples pass in CI.

**Size:** M.

---

## Not planned, and why

- **A web dashboard.** StationChief's position is "your SIEM is the dashboard". Item 9's content pack covers investigations. Revisit only if users without a SIEM ask for it.
- **Fail-closed for Codex.** Codex has no switch for it, and it can't be added from outside. The README and rollout guide say so. Revisit if OpenAI adds one.
- **Exactly-once delivery.** At-least-once with duplicates removed on read (item 9) is simpler and already documented. Exactly-once would need server-side state the object-store design deliberately avoids.
