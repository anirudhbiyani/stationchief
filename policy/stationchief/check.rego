# stationchief starter policy for POST /check.
#
# The stationchief service sends {"input": <CheckRequest>} and reads
# data.stationchief.check.decision: {"decision": "allow"|"deny"|"ask", "reason": str}.
# Precedence: any deny beats any ask beats allow.
#
# input.input is tool input the client has already redacted; input.redaction_rules
# names the secret patterns that matched before redaction. The prompt is never sent.
#
# This is a STARTER policy based on matching the literal command string, not
# a sandbox: it is defence in depth against the obvious cases (a bare `rm -rf
# /`, a plain `curl | sh`), not a guarantee against a determined attacker.
# Shell indirection — `eval`, variable expansion built up across several
# commands, shell functions/aliases, a wrapper script, `xargs`, `find -exec`,
# a subshell — can construct a dangerous command this policy never sees as
# such. Treat every rule here as one layer, not the only layer.
package stationchief.check

import rego.v1

decision := {"decision": "deny", "reason": concat("; ", sort(deny))} if {
	count(deny) > 0
} else := {"decision": "ask", "reason": concat("; ", sort(ask))} if {
	count(ask) > 0
} else := {"decision": "allow", "reason": "no policy rule matched"}

shell if input.kind == "shell"

# Lower-cased command string; "" when the tool carries no string command.
command := lower(c) if {
	c := input.input.command
	is_string(c)
} else := ""

# A direct path, not object.get(data, ...): reading all of `data` would make
# every rule depend on every package, including the tests.
approved_mcp_tools := data.stationchief.approved_mcp_tools if {
	is_array(data.stationchief.approved_mcp_tools)
} else := []

deny contains "recursive force delete of a root or home path" if {
	shell
	dangerous_rm
}

# `rm` invocations are checked segment by segment (split on `;`, `&`, `|`,
# newline) so `echo hi; rm -rf /` is still caught, and by argv rather than a
# single regex: option tokens are read from anywhere in the call (`rm / -rf`,
# `rm -rf --no-preserve-root /`, `rm --recursive --force /`) and every operand
# is checked, so `rm -rf ./build ~` is caught as well as `rm -rf ~`.
dangerous_targets := {"/", "/*", "~", "~/", "~/*", "$home", "$home/", "$home/*"}

dangerous_rm if {
	some segment in regex.split(`[;&|\n]`, command)
	tokens := rm_argv(segment)
	opts := [t | some t in tokens; startswith(t, "-")]
	recursive_flag(opts)
	force_flag(opts)
	some target in tokens
	not startswith(target, "-")
	normalize_target(target) in dangerous_targets
}

# The argv of an `rm` call within one command segment, with any leading
# `NAME=value` assignments and wrapper commands (see `strip_one_round`)
# stripped, and any leading path recognised by basename (`/bin/rm`,
# `/usr/bin/rm`, `./rm`); undefined when the segment isn't an `rm` call.
rm_argv(segment) := tokens if {
	no_prefix := strip_prefix_commands(trim_space(segment))
	regex.match(`^(\S*/)?rm(\s|$)`, no_prefix)
	rest := trim_space(regex.replace(no_prefix, `^(\S*/)?rm\s*`, ""))
	tokens := [t | some t in regex.split(`\s+`, rest); t != ""]
}

# One round of prefix stripping: a leading backslash (`\rm` skips an alias),
# leading `NAME=value` assignments (`FOO=1 BAR=2 rm ...`, and `env`'s own
# `env FOO=1 rm ...`), then a leading `sudo` (its options, and the argument
# of a short or long option that takes one: `-u root`, `--user root`), then
# `nice` (and `-n N`), `timeout` (its options and the duration), and
# `env`/`command`/`exec`/`nohup`/`time` (their options). Each stage is a no-op
# (returns its input unchanged) when its prefix isn't present;
# `regex.replace` never fails. `command` is already lower-cased, so patterns
# are all lower-case.
strip_one_round(s) := out if {
	unescaped := regex.replace(s, `^\\+`, "")
	assignments_stripped := regex.replace(unescaped, `^([a-z_][a-z0-9_]*=\S*\s+)+`, "")
	sudo_stripped := regex.replace(assignments_stripped, sudo_prefix, "")
	nice_stripped := regex.replace(sudo_stripped, `^nice(\s+(-n\s+\S+|--adjustment\s+\S+|-\S+))*\s+`, "")
	timeout_stripped := regex.replace(nice_stripped, `^timeout(\s+(-[sk]\s+\S+|--(signal|kill-after)\s+\S+|-\S+))*\s+\S+\s+`, "")
	out := regex.replace(timeout_stripped, `^(env|command|exec|nohup|time)(\s+-\S+)*\s+`, "")
}

sudo_value_options := `-[ugcdhprt]\s+\S+|--(user|group|close-from|chdir|chroot|host|prompt|role|type|command-timeout|other-user)\s+\S+`

sudo_prefix := concat("", [`^sudo(\s+(`, sudo_value_options, `|-\S+))*\s+`])

# `strip_one_round` applied repeatedly, so a chain like `sudo env FOO=1
# rm ...` — sudo, then env, then env's own assignment — is fully unwound:
# each round can reveal a new prefix for the next round to strip, and
# extra rounds beyond what a segment needs are harmless no-ops.
strip_prefix_commands(s) := out if {
	round1 := strip_one_round(s)
	round2 := strip_one_round(round1)
	round3 := strip_one_round(round2)
	round4 := strip_one_round(round3)
	round5 := strip_one_round(round4)
	round6 := strip_one_round(round5)
	round7 := strip_one_round(round6)
	out := strip_one_round(round7)
}

# One pair of surrounding `"` or `'` stripped from a target operand, and the
# brace form of $HOME normalised to the same spelling as the bare variable,
# so `"$home"`, `'/'`, `${home}` and `${home}/` all compare equal to the
# plain form.
strip_matching_quotes(t) := out if {
	count(t) >= 2
	q := substring(t, 0, 1)
	q == substring(t, count(t) - 1, 1)
	q in {"\"", "'"}
	out := substring(t, 1, count(t) - 2)
} else := t

normalize_target(t) := replace(strip_matching_quotes(t), "${home}", "$home")

recursive_flag(opts) if {
	some opt in opts
	opt == "--recursive"
}

recursive_flag(opts) if {
	some opt in opts
	startswith(opt, "-")
	not startswith(opt, "--")
	contains(opt, "r")
}

force_flag(opts) if {
	some opt in opts
	opt == "--force"
}

force_flag(opts) if {
	some opt in opts
	startswith(opt, "-")
	not startswith(opt, "--")
	contains(opt, "f")
}

deny contains "piping a downloaded script into a shell" if {
	shell
	regex.match(`\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b`, command)
}

# Only real MCP tools (`mcp__<server>__<op>`): a built-in web search is also
# classified mcp_call, and asking before every search helps no one.
ask contains sprintf("MCP tool %s is not on the approved list", [input.tool]) if {
	input.kind == "mcp_call"
	is_string(input.tool)
	startswith(lower(input.tool), "mcp__")
	not input.tool in approved_mcp_tools
}

ask contains "shell command after secret material was detected in its input" if {
	shell
	count(object.get(input, "redaction_rules", [])) > 0
}
