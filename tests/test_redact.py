import dataclasses
import json

import pytest

from stationchief.core.records import Action, ActionKind, ActivityRecord, Actor, Decision
from stationchief.core.redact import OUTPUT_LIMIT, redact_record, redact_text

SECRETS = [
    ("aws_access_key_id", "AKIAIOSFODNN7EXAMPLE"),
    ("github_token", "ghp_" + "a" * 36),
    ("slack_token", "xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwx"),
    ("anthropic_api_key", "sk-ant-api03-" + "b" * 32),
    ("openai_api_key", "sk-proj-" + "c" * 40),
    ("private_key", "-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n-----END RSA PRIVATE KEY-----"),
    ("jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r0"),
    ("assigned_secret", 'password = "hunter2correcthorse"'),
    ("email", "dev@example.com"),
]


@pytest.mark.parametrize("rule,secret", SECRETS, ids=[r for r, _ in SECRETS])
def test_each_pattern_is_redacted(rule, secret):
    cleaned, hits = redact_text(f"prefix {secret} suffix")
    assert secret not in cleaned
    assert cleaned.startswith("prefix ") and cleaned.endswith(" suffix")
    assert rule in {hit.rule for hit in hits}


def test_clean_text_is_untouched_and_reports_no_hits():
    cleaned, hits = redact_text("git commit -m 'refactor the parser'")
    assert cleaned == "git commit -m 'refactor the parser'"
    assert hits == []


def make_record(prompt, command):
    return ActivityRecord(
        source="claude",
        session_id="sess-abc",
        turn_id="turn-1",
        ts=1758326400000,
        event="PreToolUse",
        actor=Actor(user_name="dev", agent_name="claude-code", agent_version="2.0.1", pid=4242),
        cwd="/repo",
        hostname="laptop",
        posture={},
        prompt=prompt,
        action=Action(tool="Bash", kind=ActionKind.SHELL, input={"command": command}),
        decision=Decision.OBSERVED,
    )


def test_secret_in_prompt_never_survives_to_the_record():
    secret = "AKIAIOSFODNN7EXAMPLE"
    cleaned, hits = redact_record(make_record(f"deploy with {secret}", "ls"))
    assert secret not in json.dumps(cleaned.to_dict())
    assert [hit.path for hit in hits] == ["prompt"]


def test_secret_in_nested_tool_input_never_survives():
    secret = "ghp_" + "a" * 36
    record = make_record("hi", f"curl -H 'Authorization: token {secret}' https://api.github.com")
    cleaned, hits = redact_record(record)
    assert secret not in json.dumps(cleaned.to_dict())
    assert [hit.path for hit in hits] == ["action.input.command"]


def test_disabling_redaction_is_explicit_and_reports_hits_anyway():
    secret = "AKIAIOSFODNN7EXAMPLE"
    record = make_record(f"deploy with {secret}", "ls")
    cleaned, hits = redact_record(record, enabled=False)
    assert cleaned.prompt == record.prompt
    assert [hit.rule for hit in hits] == ["aws_access_key_id"]


def make_posture_record(posture):
    return ActivityRecord(
        source="claude",
        session_id="sess-abc",
        turn_id=None,
        ts=1758326400000,
        event="SessionStart",
        actor=Actor(user_name="dev", agent_name="claude-code", agent_version="2.0.1"),
        cwd="/repo",
        hostname="laptop",
        posture=posture,
        prompt=None,
        action=Action(tool="mcp_server_load", kind=ActionKind.COMPONENT_LOAD, input={}),
        decision=Decision.OBSERVED,
    )


def test_secret_in_posture_never_survives_to_the_record():
    secret = "sk-ant-abcdefgh12345678"
    record = make_posture_record(
        {"component_command": f"npx -y some-mcp --api-key {secret}", "sandbox": "workspace-write"}
    )
    cleaned, hits = redact_record(record)
    assert secret not in json.dumps(cleaned.to_dict())
    assert any(hit.path.startswith("posture") for hit in hits)
    assert cleaned.posture["sandbox"] == "workspace-write"


def test_disabling_redaction_leaves_posture_unchanged_but_reports_the_hit():
    secret = "sk-ant-abcdefgh12345678"
    record = make_posture_record(
        {"component_command": f"npx -y some-mcp --api-key {secret}", "sandbox": "workspace-write"}
    )
    cleaned, hits = redact_record(record, enabled=False)
    assert cleaned.posture == record.posture
    assert any(hit.path.startswith("posture") for hit in hits)


def test_json_quoted_password_key_is_redacted():
    """Security fix: JSON-quoted keys like {"password": "..."} must be caught."""
    test_json = '{"password": "hunter2correcthorse", "user": "dev"}'
    cleaned, hits = redact_text(test_json)
    assert "hunter2correcthorse" not in cleaned
    assert '"user": "dev"' in cleaned
    assert len(hits) == 1
    assert hits[0].rule == "assigned_secret"


def test_single_quoted_api_key_is_redacted():
    """Security fix: Single-quoted keys like {'api_key': '...'} must be caught."""
    test_input = "{'api_key': 'abcd1234efgh5678'}"
    cleaned, hits = redact_text(test_input)
    assert "abcd1234efgh5678" not in cleaned
    assert len(hits) == 1
    assert hits[0].rule == "assigned_secret"


def test_bare_token_in_json_is_redacted():
    """Security fix: Bare 'token' keyword must be caught in JSON."""
    test_json = '{"token": "abcdef1234567890"}'
    cleaned, hits = redact_text(test_json)
    assert "abcdef1234567890" not in cleaned
    assert len(hits) == 1
    assert hits[0].rule == "assigned_secret"


def test_assignment_preserves_trailing_quote():
    """Verify that trailing quotes are preserved in assignment redaction."""
    test_input = 'password = "hunter2correcthorse"'
    cleaned, hits = redact_text(test_input)
    assert cleaned == 'password = "[REDACTED:assigned_secret]"'
    assert len(hits) == 1


def test_nested_json_string_with_bare_token_is_redacted():
    """Nested JSON strings with bare token keyword must be redacted."""
    record = ActivityRecord(
        source="claude",
        session_id="sess-abc",
        turn_id="turn-1",
        ts=1758326400000,
        event="PreToolUse",
        actor=Actor(user_name="dev", agent_name="claude-code", agent_version="2.0.1", pid=4242),
        cwd="/repo",
        hostname="laptop",
        posture={},
        prompt="send request",
        action=Action(
            tool="HTTP",
            kind=ActionKind.HTTP,
            input={"body": '{"token": "abcdef1234567890"}'},
        ),
        decision=Decision.OBSERVED,
    )
    cleaned, hits = redact_record(record)
    assert "abcdef1234567890" not in json.dumps(cleaned.to_dict())
    assert any(hit.rule == "assigned_secret" for hit in hits)


def test_nested_json_string_in_action_input_is_redacted():
    """JSON strings nested in action input fields must be redacted."""
    record = ActivityRecord(
        source="claude",
        session_id="sess-abc",
        turn_id="turn-1",
        ts=1758326400000,
        event="PreToolUse",
        actor=Actor(user_name="dev", agent_name="claude-code", agent_version="2.0.1", pid=4242),
        cwd="/repo",
        hostname="laptop",
        posture={},
        prompt="send request",
        action=Action(
            tool="HTTP",
            kind=ActionKind.HTTP,
            input={"body": '{"api_key": "abcdef1234567890"}'},
        ),
        decision=Decision.OBSERVED,
    )
    cleaned, hits = redact_record(record)
    assert "abcdef1234567890" not in json.dumps(cleaned.to_dict())
    assert any(hit.rule == "assigned_secret" for hit in hits)


def _nest(depth, leaf):
    """Build a dict nested ``depth`` levels deep, bottom-up (iteratively, so
    building the fixture itself never risks a recursion error)."""
    value = leaf
    for _ in range(depth):
        value = {"child": value}
    return value


def test_a_deeply_nested_action_input_does_not_crash_and_is_redacted():
    record = make_record("hi", "ls")
    record = dataclasses.replace(
        record, action=dataclasses.replace(record.action, input={"tree": _nest(3000, "leaf")})
    )
    cleaned, hits = redact_record(record)
    dumped = json.dumps(cleaned.to_dict())
    assert "[REDACTED:too_deep]" in dumped
    assert any(hit.rule == "too_deep" for hit in hits)


def test_a_secret_at_depth_5_is_still_redacted_normally():
    secret = "AKIAIOSFODNN7EXAMPLE"
    record = make_record("hi", "ls")
    record = dataclasses.replace(
        record, action=dataclasses.replace(record.action, input={"tree": _nest(5, secret)})
    )
    cleaned, hits = redact_record(record)
    dumped = json.dumps(cleaned.to_dict())
    assert secret not in dumped
    assert "[REDACTED:too_deep]" not in dumped
    assert any(hit.rule == "aws_access_key_id" for hit in hits)
    assert not any(hit.rule == "too_deep" for hit in hits)


def test_client_secret_and_credentials_are_redacted():
    """Test client_secret and credentials keywords are caught."""
    # Test client_secret assignment
    test_client_secret = "client_secret=abcdefgh12345678"
    cleaned_cs, hits_cs = redact_text(test_client_secret)
    assert "abcdefgh12345678" not in cleaned_cs
    assert len(hits_cs) == 1
    assert hits_cs[0].rule == "assigned_secret"

    # Test credentials JSON
    test_credentials = '{"credentials": "abcdefgh12345678"}'
    cleaned_cr, hits_cr = redact_text(test_credentials)
    assert "abcdefgh12345678" not in cleaned_cr
    assert len(hits_cr) == 1
    assert hits_cr[0].rule == "assigned_secret"


SHAPES = [
    ("export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ("DB_PASSWORD=hunter2hunter2 ./run.sh", "hunter2hunter2"),
    ("export STRIPE_API_KEY=rk_live_abcdefghijklmnop1234", "rk_live_abcdefghijklmnop1234"),
    ('{"DATABASE_PASSWORD": "hunter2hunter2"}', "hunter2hunter2"),
    ("export GITHUB_TOKEN=github_pat_11ABCDEFG0123456789abcdefghijklmnopqrstuvwxyz", "github_pat_11ABCDEFG0123456789abcdefghijklmnopqrstuvwxyz"),
    ('curl -H "Authorization: Bearer abcdef0123456789abcdef"', "abcdef0123456789abcdef"),
    ("curl -u admin:S3cr3tP4ss https://x", "S3cr3tP4ss"),
    ("//registry.npmjs.org/:_authToken=npm_abcdefghijklmnopqrstuvwxyz0123456789", "npm_abcdefghijklmnopqrstuvwxyz0123456789"),
    ("postgresql://admin:pw12345678@db:5432/x", "pw12345678"),
    ("export PASSWORD='correct horse battery staple'", "correct horse battery staple"),
    ('DB_PASSWORD="correct horse battery staple"', "correct horse battery staple"),
    ("mysqladmin --password s3cr3tpw status", "s3cr3tpw"),
    ("tool --password=s3cr3tpw", "s3cr3tpw"),
    ("docker login -u ci -p hunter2xyz registry.example.com", "hunter2xyz"),
    ("STRIPE=sk_live_abcdefghijklmnopqrstuvwx", "sk_live_abcdefghijklmnopqrstuvwx"),
]


@pytest.mark.parametrize("text,secret", SHAPES, ids=[s for _, s in SHAPES])
def test_common_secret_shapes_are_redacted(text, secret):
    cleaned, hits = redact_text(text)
    assert secret not in cleaned
    assert hits


@pytest.mark.parametrize(
    "text",
    ["load the tokenizer", "passwordless login", "tokenizer=bert-base-uncased", "max_tokens=4096", "sudo -u root rm -rf build"],
)
def test_ordinary_words_are_not_redacted(text):
    assert redact_text(text) == (text, [])


def test_npm_token_and_curl_user_rules_are_named():
    assert "npm_token" in {h.rule for h in redact_text("npm_abcdefghijklmnopqrstuvwxyz0123456789")[1]}
    assert "github_token" in {h.rule for h in redact_text("github_pat_11ABCDEFG0123456789abcdefghij")[1]}


def test_redaction_stays_fast_on_a_long_identifier():
    import time

    start = time.perf_counter()
    redact_text("a_" * 20000)
    assert time.perf_counter() - start < 1


@pytest.mark.parametrize(
    "text", ["a." * 50000, "ab-" * 33000, "a@" * 50000, "x:" * 50000], ids=["dots", "kebab", "at", "colon"]
)
def test_redaction_is_linear_on_hostile_input(text):
    import time

    start = time.perf_counter()
    redact_text(text)
    assert time.perf_counter() - start < 0.2


@pytest.mark.parametrize(
    "text",
    [
        "fix authorization handling in the router",
        "the bearer instrument is transferable",
        "docker run -u 1000:1000 alpine id",
        "git clone git@github.com:org/repo.git",
        "ssh deploy@build.example.com:/srv/app",
        "echo $PW | docker login --password-stdin -u ci",
        "ls -p /tmp",
    ],
)
def test_known_false_positives_are_not_redacted(text):
    assert redact_text(text) == (text, [])


def test_email_followed_by_prose_colon_is_still_redacted():
    cleaned, hits = redact_text("contact dev@example.com: thanks")
    assert cleaned == "contact [REDACTED:email]: thanks"


def test_hook_never_writes_an_exported_aws_secret_to_ndjson(tmp_path):
    from stationchief.adapters import claude
    from stationchief.config import Config

    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    payload = {
        "hook_event_name": "PreToolUse",
        "session_id": "s1",
        "cwd": str(tmp_path),
        "tool_name": "Bash",
        "tool_input": {"command": f"export AWS_SECRET_ACCESS_KEY={secret} && aws s3 ls"},
    }
    claude.handle(payload, Config(home=tmp_path))
    written = "".join(p.read_text() for p in tmp_path.glob("events-*.ndjson"))
    assert "AWS_SECRET_ACCESS_KEY" in written
    assert secret not in written


KEY_BODY = "\n".join("MIIJKAIBAAKCAgEA" + str(i).zfill(48) for i in range(60))


def test_private_key_without_end_marker_is_redacted():
    out, hits = redact_text("head -20 id_rsa\n-----BEGIN OPENSSH PRIVATE KEY-----\n" + KEY_BODY)
    assert "MIIJKAIBAAKCAgEA" not in out
    assert out.startswith("head -20 id_rsa\n")
    assert [h.rule for h in hits] == ["private_key"]


def test_pgp_private_key_block_is_redacted():
    text = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQOYBFabc\n-----END PGP PRIVATE KEY BLOCK-----\nafter"
    out, hits = redact_text(text)
    assert "lQOYBFabc" not in out and out.endswith("\nafter")
    assert [h.rule for h in hits] == ["private_key"]


def test_output_is_capped_after_redaction_so_a_straddling_key_never_leaks():
    key = f"-----BEGIN RSA PRIVATE KEY-----\n{KEY_BODY}\n-----END RSA PRIVATE KEY-----"
    output = "x" * 3000 + key + "tail" * 2000
    record = make_record("hi", "ls")
    record = dataclasses.replace(record, action=dataclasses.replace(record.action, output=output))
    cleaned, hits = redact_record(record)
    assert "MIIJKAIBAAKCAgEA" not in cleaned.action.output
    assert "[REDACTED:private_key]tail" in cleaned.action.output
    assert len(cleaned.action.output) == OUTPUT_LIMIT
    assert [h.rule for h in hits] == ["private_key"]


def test_hook_redacts_a_key_that_straddles_the_output_cap(tmp_path):
    from stationchief.adapters import claude
    from stationchief.config import Config

    key = f"-----BEGIN RSA PRIVATE KEY-----\n{KEY_BODY}\n-----END RSA PRIVATE KEY-----"
    payload = {
        "hook_event_name": "PostToolUse",
        "session_id": "s1",
        "cwd": str(tmp_path),
        "tool_name": "Grep",
        "tool_input": {"pattern": "KEY"},
        "tool_response": "x" * 1500 + key,
    }
    claude.handle(payload, Config(home=tmp_path))
    written = "".join(p.read_text() for p in tmp_path.glob("events-*.ndjson"))
    assert "REDACTED:private_key" in written
    assert "MIIJKAIBAAKCAgEA" not in written


def make_input_record(tool_input):
    record = make_record("hi", "ls")
    return dataclasses.replace(record, action=dataclasses.replace(record.action, input=tool_input))


@pytest.mark.parametrize(
    "tool_input",
    [
        {"password": "hunter2correcthorse"},
        {"headers": {"Authorization": "Basic hunter2correcthorse"}},
        {"env": [{"name": "DB_PASSWORD", "value": "hunter2correcthorse"}]},
        {"connection": {"apiKey": "hunter2correcthorse"}},
        {"client_secret": "hunter2correcthorse", "accessToken": "hunter2correcthorse"},
    ],
)
def test_structured_secret_fields_are_redacted(tool_input):
    cleaned, hits = redact_record(make_input_record(tool_input))
    assert "hunter2correcthorse" not in json.dumps(cleaned.to_dict())
    assert hits and all(h.rule == "assigned_secret" and h.path.startswith("action.input") for h in hits)


def test_structured_secret_is_reported_but_kept_when_redaction_is_disabled():
    record = make_input_record({"password": "hunter2correcthorse"})
    cleaned, hits = redact_record(record, enabled=False)
    assert cleaned.action.input == {"password": "hunter2correcthorse"}
    assert [(h.rule, h.path) for h in hits] == [("assigned_secret", "action.input.password")]


def test_token_counting_fields_are_not_secrets():
    tool_input = {
        "max_tokens": 4096, "maxTokens": 10, "tokenizer": "cl100k", "token_count": 12,
        "input_tokens": 3, "pwd": "/repo", "secret_name": "prod-db", "has_password": True,
        "env": [{"name": "HOME", "value": "/home/dev"}],
    }
    cleaned, hits = redact_record(make_input_record(tool_input))
    assert cleaned.action.input == tool_input
    assert hits == []
