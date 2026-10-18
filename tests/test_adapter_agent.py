import asyncio
import inspect

import pytest

from stationchief.adapters import agent as agent_module
from stationchief.adapters.agent import Agent, ToolBlocked
from stationchief.config import Config
from stationchief.core.records import ActionKind, Decision
from stationchief.policy import Verdict


@pytest.fixture
def emitted(monkeypatch):
    records = []
    monkeypatch.setattr("stationchief.pipeline.emit", lambda record, config: records.append(record))
    monkeypatch.setattr(agent_module, "emit", lambda record, config: records.append(record))
    return records


def checked_agent(monkeypatch, tmp_path, decision="allow", **config):
    seen = []

    def ask(record, hits, config, **kwargs):
        seen.append(record)
        return Verdict(decision=decision, reason="refunds over $500 need a human")

    monkeypatch.setattr("stationchief.check.ask", ask)
    cfg = Config(home=tmp_path, server_url="https://fd.example.com", server_token="t", **config)
    return Agent("support-bot", version="1.4.0", model="gpt-5", model_provider="OpenAI", config=cfg), seen


def test_allowed_call_runs_and_records_before_and_after(monkeypatch, tmp_path, emitted):
    agent, seen = checked_agent(monkeypatch, tmp_path)

    @agent.tool(kind=ActionKind.HTTP)
    def refund(order_id: str, amount: float) -> dict:
        """Refund an order."""
        return {"ok": True}

    assert refund("A-1", amount=20.0) == {"ok": True}
    assert seen[0].action.input == {"order_id": "A-1", "amount": 20.0}
    before, after = emitted
    assert (before.event, after.event) == ("PreToolUse", "PostToolUse")
    assert before.source == after.actor.agent_name == "support-bot"
    assert after.action.status == "success" and after.action.output == '{"ok": true}'
    # Frameworks build the tool schema from these.
    assert refund.__name__ == "refund" and refund.__doc__ == "Refund an order."
    assert list(inspect.signature(refund).parameters) == ["order_id", "amount"]


@pytest.mark.parametrize("decision", ["deny", "ask"])
def test_deny_or_ask_blocks_without_running(monkeypatch, tmp_path, emitted, decision):
    agent, _ = checked_agent(monkeypatch, tmp_path, decision=decision)
    ran = []

    @agent.tool
    def refund(order_id, amount):
        ran.append(order_id)

    with pytest.raises(ToolBlocked, match="need a human"):
        refund("A-1", 900)
    assert ran == []
    assert [r.decision for r in emitted] == [Decision.BLOCKED]


def test_tool_error_is_recorded_and_reraised(monkeypatch, tmp_path, emitted):
    agent, _ = checked_agent(monkeypatch, tmp_path)

    @agent.tool(name="lookup_customer")
    def lookup(email):
        raise LookupError("no such customer")

    with pytest.raises(LookupError):
        lookup("a@example.com")
    after = emitted[-1]
    assert after.action.tool == "lookup_customer"
    assert after.action.status == "failure" and "no such customer" in after.action.error


def test_async_tools_are_checked_too(monkeypatch, tmp_path, emitted):
    agent, _ = checked_agent(monkeypatch, tmp_path, decision="deny")

    @agent.tool
    async def send_email(to, body):
        return "sent"

    with pytest.raises(ToolBlocked):
        asyncio.run(send_email("ceo@example.com", "hi"))


def test_check_failure_follows_fail_closed(monkeypatch, tmp_path, emitted):
    def broken(*args, **kwargs):
        raise RuntimeError("bug")

    for fail_closed, blocked in ((False, False), (True, True)):
        agent, _ = checked_agent(monkeypatch, tmp_path, fail_closed=fail_closed)
        monkeypatch.setattr(agent_module, "emit_checked", broken)

        @agent.tool
        def noop():
            return "ran"

        if blocked:
            with pytest.raises(ToolBlocked, match="failing closed"):
                noop()
        else:
            assert noop() == "ran"


def test_without_a_server_calls_are_only_recorded(tmp_path, emitted):
    agent = Agent("crew", config=Config(home=tmp_path))

    @agent.tool
    def search(query):
        return ["result"]

    assert search("q") == ["result"]
    assert [r.event for r in emitted] == ["PreToolUse", "PostToolUse"]


def test_records_map_to_valid_ocsf(tmp_path, emitted, assert_valid_ocsf):
    from stationchief.core.mapping import map_record

    agent = Agent("crew", config=Config(home=tmp_path))

    @agent.tool
    def create_ticket(title):
        return 42

    create_ticket("printer on fire")
    for record in emitted:
        assert_valid_ocsf(map_record(record))


def test_unknown_kind_is_rejected_at_decoration():
    with pytest.raises(ValueError):
        Agent("x", config=Config()).tool(kind="email")
