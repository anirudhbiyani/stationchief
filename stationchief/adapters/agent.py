"""Any Python agent: wrap its tool functions with ``Agent.tool``.

Framework-agnostic on purpose. LangChain, CrewAI, the OpenAI Agents SDK, the
Claude Agent SDK's custom tools and hand-written loops all end up calling one
Python function per tool, so that function is the one seam they share:

    from stationchief.adapters.agent import Agent, ToolBlocked

    agent = Agent("support-bot", version="1.4.0", model="gpt-5", model_provider="OpenAI")

    @agent.tool(kind="http")
    def refund(order_id: str, amount: float) -> str: ...

Put a framework's own decorator outside this one (``@function_tool`` above
``@agent.tool``): functools.wraps keeps the name, docstring and signature the
framework reads to build the tool schema.

Before the call the arguments go through /check, exactly as a coding agent's
pre-tool hook does; after it the outcome is emitted. A deny raises ToolBlocked
instead of running the function, and so does an ask, because there is no
human in the loop to answer it. Frameworks hand a tool's exception back to
the model as the tool result, so the agent sees the reason and carries on.

Unlike the hooks, stationchief failures here follow config.fail_closed: an
error building or checking the record blocks the call when it is set, and is
logged and ignored when it is not. Emitting the outcome never raises.
"""

import asyncio
import functools
import getpass
import inspect
import json
import socket
import time
import traceback
import uuid

from stationchief.check import emit_checked
from stationchief.config import Config
from stationchief.core.records import Action, ActionKind, ActivityRecord, Actor, Decision
from stationchief.pipeline import emit, log_error


class ToolBlocked(PermissionError):
    """The policy refused this tool call; the function did not run."""

    def __init__(self, tool: str, reason: str):
        super().__init__(f"Blocked by stationchief policy: {reason or 'no reason given'}")
        self.tool = tool
        self.reason = reason


class Agent:
    """One running agent. ``session_id`` defaults to a fresh id per instance;
    set ``prompt`` to the current task to have it recorded (it is never sent
    to /check)."""

    def __init__(self, name, *, version="unknown", model=None, model_provider=None, session_id=None, cwd="", config=None):
        self.name = name
        self.version = version
        self.model = model
        self.model_provider = model_provider
        self.session_id = session_id or uuid.uuid4().hex
        self.cwd = cwd
        self.prompt = None
        self.config = config or Config.load()
        self._hostname = socket.gethostname()
        try:
            self._user_name = getpass.getuser()
        except BaseException:
            self._user_name = "unknown"

    def tool(self, fn=None, *, name=None, kind=ActionKind.UNKNOWN):
        """Decorator, bare (``@agent.tool``) or with options. ``kind`` is the
        ActionKind the policy and OCSF mapping use; business actions with no
        better fit stay ``unknown`` and map to API Activity."""
        if kind not in ActionKind.ALL:
            raise ValueError(f"unknown action kind {kind!r}; use one of {sorted(ActionKind.ALL)}")

        def wrap(fn):
            tool_name = name or fn.__name__
            signature = inspect.signature(fn)

            if inspect.iscoroutinefunction(fn):

                @functools.wraps(fn)
                async def run_async(*args, **kwargs):
                    tool_input = _input(signature, args, kwargs)
                    # The check blocks for up to check_timeout_ms; keep it off the event loop.
                    await asyncio.to_thread(self._before, tool_name, kind, tool_input)
                    try:
                        result = await fn(*args, **kwargs)
                    except BaseException as error:
                        await asyncio.to_thread(self._after, tool_name, kind, tool_input, None, error)
                        raise
                    await asyncio.to_thread(self._after, tool_name, kind, tool_input, result, None)
                    return result

                return run_async

            @functools.wraps(fn)
            def run(*args, **kwargs):
                tool_input = _input(signature, args, kwargs)
                self._before(tool_name, kind, tool_input)
                try:
                    result = fn(*args, **kwargs)
                except BaseException as error:
                    self._after(tool_name, kind, tool_input, None, error)
                    raise
                self._after(tool_name, kind, tool_input, result, None)
                return result

            return run

        return wrap if fn is None else wrap(fn)

    def _record(self, event, tool, kind, tool_input, *, output=None, status="unknown", error=None):
        return ActivityRecord(
            source=self.name,
            session_id=self.session_id,
            turn_id=None,
            ts=int(time.time() * 1000),
            event=event,
            actor=Actor(
                user_name=self._user_name,
                agent_name=self.name,
                agent_version=self.version,
                model=self.model,
                model_provider=self.model_provider,
                pid=None,
            ),
            cwd=self.cwd,
            hostname=self._hostname,
            posture={},
            prompt=self.prompt,
            action=Action(tool=tool, kind=kind, input=tool_input, output=output, status=status, error=error),
            decision=Decision.OBSERVED,
        )

    def _before(self, tool, kind, tool_input):
        try:
            record = self._record("PreToolUse", tool, kind, tool_input)
            verdict = emit_checked(record, self.config, pre_tool=True, ask_blocks=True)
        except Exception:
            log_error(self.config, f"agent adapter pre-tool check failed: {traceback.format_exc()}")
            if self.config.fail_closed:
                raise ToolBlocked(tool, "policy check failed; failing closed") from None
            return
        if verdict is not None and verdict.decision != "allow":
            raise ToolBlocked(tool, verdict.reason)

    def _after(self, tool, kind, tool_input, result, error):
        try:
            if error is None:
                record = self._record("PostToolUse", tool, kind, tool_input, output=_text(result), status="success")
            else:
                record = self._record(
                    "PostToolUse", tool, kind, tool_input, status="failure", error=f"{type(error).__name__}: {error}"
                )
            emit(record, self.config)
        except BaseException:
            log_error(self.config, f"agent adapter emit failed: {traceback.format_exc()}")


def _input(signature, args, kwargs) -> dict:
    """The call's arguments by parameter name, as plain JSON values (anything
    else becomes its str()). ``self`` and ``cls`` are left out."""
    try:
        bound = signature.bind_partial(*args, **kwargs).arguments
        named = {key: value for key, value in bound.items() if key not in ("self", "cls")}
    except TypeError:
        named = {"args": list(args), "kwargs": kwargs}
    return json.loads(json.dumps(named, default=str))


def _text(result):
    if result is None or isinstance(result, str):
        return result
    try:
        return json.dumps(result, default=str)
    except (TypeError, ValueError):
        return str(result)
