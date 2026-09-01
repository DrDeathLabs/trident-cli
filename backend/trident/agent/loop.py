"""The expert agent loop: explore with tools, then commit to a structured verdict.

Flow (native OpenAI tool-calling, supported by the council models — verified on
gemma4:31b-cloud, gpt-oss:120b-cloud, and glm-5.2:cloud):
  1. The model is given the finding/task and the workspace tool schemas.
  2. While it emits tool_calls (and the step budget allows), we dispatch each
     call, feed the result back, and let it keep exploring.
  3. When it stops calling tools (or the budget is hit), we ask once more for a
     schema-validated verdict (no tools) via chat_structured.

DB-free and side-effect-free, so it runs safely inside the deliberation thread
pool. Returns the same StructuredResult the single-shot path returns, plus a
`trace` of tool calls and the number of LLM calls made (for budgeting + the UI).
"""

from __future__ import annotations

import json
from typing import TypeVar

from loguru import logger
from pydantic import BaseModel

from trident.agent.tools import WorkspaceTools
from trident.reliability.structured import StructuredResult, chat_structured
from trident.llm.base import ChatMessage, llm

T = TypeVar("T", bound=BaseModel)

_MAX_TOOL_RESULT_CHARS = 4000


def _parse_tool_call(tc: dict) -> tuple[str, dict, str]:
    fn = (tc or {}).get("function", {}) or {}
    name = fn.get("name", "")
    raw = fn.get("arguments")
    if isinstance(raw, dict):
        args = raw
    elif isinstance(raw, str):
        try:
            args = json.loads(raw or "{}")
        except json.JSONDecodeError:
            args = {}
    else:
        args = {}
    call_id = tc.get("id") or f"call_{name}"
    return name, args, call_id


def run_agent(
    system_prompt: str,
    task_prompt: str,
    tools: WorkspaceTools,
    model_cls: type[T],
    *,
    model: str,
    max_steps: int,
    final_instruction: str,
    temperature: float = 0.1,
    budget=None,
) -> StructuredResult[T]:
    """Run a tool-using exploration then extract a validated `model_cls` verdict.

    If a budget is given, each exploration step takes 1 from it before running;
    when the budget is spent the agent stops exploring and commits to a verdict —
    so a per-job cap actually bounds agentic cost (thousands of calls otherwise).
    """
    messages = [ChatMessage("system", system_prompt), ChatMessage("user", task_prompt)]
    trace: list[dict] = []
    calls = 0

    for _step in range(max_steps):
        if budget is not None and not budget.take(1):
            break  # out of budget — stop exploring, go straight to the verdict
        resp = llm().chat(messages, model=model, tools=tools.schemas, temperature=temperature)
        calls += 1
        tcs = resp.tool_calls or []
        if not tcs:
            if resp.content:
                messages.append(ChatMessage("assistant", resp.content))
            break
        # Record the assistant's tool-call turn, then answer each call.
        messages.append(ChatMessage("assistant", resp.content or "", tool_calls=tcs))
        for tc in tcs:
            name, args, call_id = _parse_tool_call(tc)
            result = tools.dispatch(name, args)
            trace.append({"tool": name, "args": args, "result_preview": result[:300]})
            messages.append(ChatMessage(
                "tool", result[:_MAX_TOOL_RESULT_CHARS], tool_call_id=call_id,
            ))
    else:
        logger.debug(f"agent hit max_steps={max_steps} with {len(trace)} tool calls")

    # Commit to a schema-validated verdict (no tools). This is essential, so it
    # is charged (counted) rather than gated.
    messages.append(ChatMessage("user", final_instruction))
    result = chat_structured(messages, model_cls, model=model, temperature=0.0)
    if budget is not None:
        budget.charge(getattr(result, "llm_calls", 1))
    return StructuredResult(
        result.obj, result.response, result.error,
        trace=trace, llm_calls=calls + getattr(result, "llm_calls", 1),
    )
