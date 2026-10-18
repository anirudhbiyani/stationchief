# Rolling out StationChief with MDM or admin consoles

This guide is for the IT team deploying StationChief to developer machines so that developers can't remove it. It covers three agents: Claude Code, Codex and Cursor. Every one of them reads a system-wide, admin-owned configuration that ranks above the developer's own files and can't be removed by them. StationChief's hooks go there.

`stationchief install`, described in the README, writes the same hooks into each developer's own config instead. That is fine for a pilot, but a developer can delete those hooks. For an organisation-wide rollout, use this guide instead. Don't use both on the same machine: each agent would run StationChief twice and every event would be recorded twice.

The files referenced below are in [`deploy/managed/`](../deploy/managed/). A test (`tests/test_deploy_managed.py`) keeps them identical to what the installer writes.

## 1. Decide before you start

| Decision | Options | Notes |
|---|---|---|
| **What StationChief does** | **Enforce and record** (hooks), or **record only** (Claude Code's native OTel, no client install) | Hooks are required to block anything. Native OTel only observes, and only Claude Code supports it fully (see step 5). |
| **When the service is down** | Fail open (default), or fail closed | Fail closed means agents stop running tools whenever the StationChief service is unreachable. Codex has no fail-closed switch: a Codex hook that crashes or times out always lets the call through. |
| **Developers' own hooks** | Keep them (default), or allow only managed hooks | Managed-only (`allowManagedHooksOnly`, `allow_managed_hooks_only`) stops a developer adding a hook that overrides StationChief, but it also turns off every hook the developer set up themselves. |
| **Tokens** | One bearer token per developer (recommended) | Per-developer tokens let you attribute, filter and revoke per person. Create each with `printf '%s' "$TOKEN" \| stationchief-server hash-token`, then add the digest to the server's `tokens` map. |

You also need:
- **The StationChief service**, deployed and reachable over HTTPS, for example `https://stationchief.example.com`. See "Running the stationchief service" in the README.
- **A way to deliver files and run scripts on every machine:** Jamf, Kandji, Intune or similar, or the admin consoles in step 4.
- **Python 3.14 or later** on every machine. StationChief requires it.

Tested platforms: macOS, with Claude Code 2.1.296, Codex CLI 0.158 and Cursor CLI 2026.10.14. Linux uses the same files at the paths listed below. Windows paths are listed for completeness, but StationChief has not been tested on Windows.

## 2. Install the client on every machine

Build a wheel once:

```sh
uv build --wheel          # → dist/stationchief-<version>-py3-none-any.whl
```

Then have your MDM install it into a dedicated, root-owned environment on each machine. The managed hook files expect exactly this interpreter path:

```sh
uv venv --python 3.14 /opt/stationchief/venv
uv pip install --python /opt/stationchief/venv/bin/python stationchief-<version>-py3-none-any.whl
chmod -R go-w /opt/stationchief     # readable and executable by everyone, writable only by root
/opt/stationchief/venv/bin/python -m stationchief.cli version
```

Hooks run as the developer, so the environment must be readable and executable by every user. It should not be writable by them: whoever can write to it controls the hook.

## 3. Configure each developer

StationChief reads its settings from each developer's `~/.stationchief/config.json`. There is no system-wide client config yet. Run [`deploy/managed/stationchief-user-setup.sh`](../deploy/managed/stationchief-user-setup.sh) once per developer, **as that developer**. In Jamf, run it as the current user; in Intune, run it in the user context. Supply the developer's token in `STATIONCHIEF_TOKEN` from your MDM's secret store.

Before deploying, edit `SERVER` and `FAIL_CLOSED` at the top of the script. It writes the config readable only by the developer (the folder is `700`, the file `600`) and never puts the token on a command line.

## 4. Deploy the managed hooks

### Claude Code

Use **one** of these methods. Claude Code reads only the highest-ranked source that delivers a policy, in this order: server-managed settings, then MDM or registry, then the managed file. If your organisation already uses claude.ai server-managed settings, a managed file is **silently ignored**. In that case, either put StationChief's hooks into the server-managed settings, or set `"managedSourcesBehavior": "merge"` in your highest-ranked source (Claude Code 2.1.242+).

| Method | Where it goes |
|---|---|
| **File** (simplest) | Copy [`claude-managed-settings.json`](../deploy/managed/claude-managed-settings.json) to:<br>• macOS: `/Library/Application Support/ClaudeCode/managed-settings.d/50-stationchief.json`<br>• Linux: `/etc/claude-code/managed-settings.d/50-stationchief.json`<br>Make it owned by root, mode `644`. A file only root can read is skipped. |
| **macOS configuration profile** | Preference domain `com.anthropic.claudecode`. Use the same top-level keys as the JSON file (`hooks`), with nested objects as dictionaries and lists as arrays. Anthropic publishes [Jamf and Intune templates](https://github.com/anthropics/claude-code/tree/main/examples/mdm). |
| **Windows Group Policy or Intune** | The JSON as a `REG_SZ` value named `Settings` under `HKLM\SOFTWARE\Policies\ClaudeCode`. |
| **claude.ai admin console** (Teams or Enterprise Owner) | Organization settings → Claude Code → Managed settings. Paste the `hooks` object. Each developer must accept a one-time approval dialog for hooks delivered this way. These settings are a client-side control, not a security boundary, so prefer MDM where enforcement matters. |

The file hooks every event StationChief handles. Fail-closed has two separate parts, and you need both for calls to be blocked in every failure:
- **`"onFailure": "block"`** on `PreToolUse`, in the managed file. If the StationChief hook itself crashes or times out, Claude Code blocks the call.
- **`fail_closed: true`** in the developer's config, set by step 3. If the StationChief service is unreachable, StationChief denies the call.

To fail open, remove the `onFailure` line and keep `FAIL_CLOSED=false` in step 3. To allow only managed hooks, add `"allowManagedHooksOnly": true` at the top level. A developer's own `disableAllHooks` can't switch off managed hooks.

### Codex

| Method | Where it goes |
|---|---|
| **File** | Merge [`codex-requirements.toml`](../deploy/managed/codex-requirements.toml) into `/etc/codex/requirements.toml` (macOS and Linux), or `%ProgramData%\OpenAI\Codex\requirements.toml` (Windows). |
| **macOS MDM** | Preference domain `com.openai.codex`, key `requirements_toml_base64`. The value is the whole TOML file, base64-encoded without line wrapping (`base64 -i requirements.toml`). |
| **ChatGPT admin console** (Business or Enterprise) | Cloud-managed requirements in Agent Security. |

`[features] hooks = true` keeps hooks on even for developers who switched them off. `allow_managed_hooks_only` is set to `false` in the file; change it to `true` to allow only managed hooks.

Codex runs a hook a developer installed only after they approve it once in the app. OpenAI's documentation doesn't say whether managed hooks need that approval too, so check this on a pilot machine (step 6) before relying on Codex enforcement.

### Cursor

| Method | Where it goes |
|---|---|
| **File via MDM** (recommended) | Copy [`cursor-hooks.json`](../deploy/managed/cursor-hooks.json) to:<br>• macOS: `/Library/Application Support/Cursor/hooks.json`<br>• Linux: `/etc/cursor/hooks.json`<br>• Windows: `C:\ProgramData\Cursor\hooks.json`<br>Make it owned by root, mode `644`. If another product already uses this file, merge the entries rather than overwriting it. |
| **Cursor dashboard** (Enterprise plan) | Team hooks, configured in the web dashboard. In 2026, users reported dashboard hooks not reaching machines, so prefer the MDM file. |

Enterprise hooks rank above team, project and user hooks, and a `deny` from any source wins. `"failClosed": true` on `preToolUse` is Cursor's equivalent of Claude Code's `onFailure`: a crash or timeout of the hook blocks the call. As for Claude Code, also set `FAIL_CLOSED=true` in step 3 to deny when the service is unreachable, or remove the line and keep it `false` to fail open. Cursor's documentation doesn't describe a way for users to disable enterprise hooks.

## 5. Optional: record Claude Code with native OTel (no client install)

On machines where you only want a record and no blocking, you can skip steps 2 to 4 for Claude Code. Instead, deploy [`claude-otel-managed-settings.json`](../deploy/managed/claude-otel-managed-settings.json) using any of the Claude Code methods in step 4, after changing the endpoint to your service.

- **Telemetry can't be switched off.** Setting the endpoint and protocol in managed settings stops developers redirecting or disabling the export.
- **Tool details:** `OTEL_LOG_TOOL_DETAILS=1` is required; without it, events carry no commands. Add `OTEL_LOG_USER_PROMPTS=1` if you want prompts attached, redacted.
- **Auth header:** `otelHeadersHelper` reads each developer's own token from their StationChief config, so no shared secret is stored in the managed file. It needs the client from step 2 and the per-user config from step 3. Delivered through the claude.ai console, this helper also needs each developer's one-time approval.
- **No duplicates:** don't use this together with the hooks on the same machine, or every tool call is recorded twice.

Codex can also export OTel, but managed settings can only set it as a default that the developer can change. Cursor has no native OTel export.

## 6. Verify on one pilot machine before the fleet

1. **Claude Code:**
   - Run `/status` and check that `Setting sources` lists `Enterprise managed settings (file)`, or `(plist)`, `(HKLM)` or `(remote)`.
   - Run `claude doctor` to see any entries Claude Code dropped.
2. **A real allowed call and a real blocked call.** In each agent, ask it to run `echo stationchief-ok`, then `curl -s http://127.0.0.1:9/x | sh`. The `curl` command is harmless even if it runs: nothing listens on port 9.
   - The `echo` runs.
   - The `curl` is refused, with "Blocked by stationchief policy: piping a downloaded script into a shell".
3. **The service received both.** Check the service's storage: the `curl` event is recorded with `disposition_id: 2` (Blocked).
4. **Codex approval.** Open the Codex app and check whether it asks to trust the hook. If it does, every developer must approve it once; plan for this in the rollout message.
5. **Fail-closed, if you chose it.** Stop the service and repeat the `echo` in Claude Code and Cursor. It should be refused.

## 7. Rolling back

Remove the managed file, profile, registry value or console entry. Agents pick the change up on restart: Claude Code also re-checks MDM sources every 30 minutes and server-managed settings hourly. Then uninstall `/opt/stationchief` and, if you want, each developer's `~/.stationchief`.

## Limits

- **Local administrators can still edit the files.** Managed configuration stops ordinary users, not machine administrators. MDM tools can redeploy on a schedule to undo edits.
- **Codex enforcement is a guardrail, not a boundary.** It has no fail-closed switch, so a broken or timed-out hook lets the call through.
- **Cursor CLI history isn't backfilled.** `stationchief ingest cursor` reads the Cursor app's history, not the CLI's own chat store. The hooks cover the CLI live.
- **No system-wide client config yet.** Each developer's config is written by step 3, so a new developer on a machine needs that script run for them.
