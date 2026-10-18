# Security policy

StationChief is a security tool, so reports about its own weaknesses are especially welcome.

## Reporting a vulnerability

**Don't open a public issue.** Report it privately through GitHub instead: on the repository's **Security** tab, choose **Report a vulnerability**. Please include:

- what an attacker can do, and what they need first (local access, a malicious repository, a compromised MCP server, network position);
- the StationChief version, or commit, and the agent and version involved;
- steps or a proof of concept that reproduces it.

This is a beta project maintained by one person. Expect an acknowledgement within a few days and a fix or a plan within a few weeks, depending on severity. Fixes go into the latest version only.

## In scope

Anything that makes StationChief's guarantees false, for example:
- a secret that leaves the machine unredacted;
- a policy decision bypassed **through StationChief's own code**, not through a limit listed below;
- authentication on the service bypassed, or one principal reading or writing another's data;
- a hook that crashes or hangs the agent;
- telemetry silently lost without being spooled or reported.

## Known limits (not vulnerabilities)

These are documented trade-offs. Ideas for improving them are welcome as normal issues:
- **Shell policy matches the command text.** Indirection such as `eval`, variables, wrappers or subshells can build a command the starter policy doesn't recognise. See the header of `policy/stationchief/check.rego` and item 7 of `docs/roadmap.md`.
- **Codex can't fail closed.** A Codex hook that crashes or times out lets the call through.
- **Fail-open is the default.** Fail-closed is opt-in.
- **Local administrators can edit or remove managed configuration.**
- **Delivery is at-least-once,** so events can be stored twice. Remove duplicates on read, as the README describes.
