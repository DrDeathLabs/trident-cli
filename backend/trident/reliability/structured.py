"""Schema-constrained LLM calls for the council.

`chat_structured` is the single entry point every expert/judge/red-team call
should use. It:
  1. asks the model for JSON matching a Pydantic schema (via response_format),
  2. validates the response against that schema,
  3. on validation failure, retries ONCE with the error fed back as a repair
     instruction,
  4. returns a StructuredResult whose `.obj` is None iff parsing truly failed.

A None result is a *parse failure*, which the caller must record as such
(never as a verdict) so garbage output cannot masquerade as disagreement.

Whether the backend honors response_format is probed once and cached; if it is
unsupported the layer degrades to plain prompting (validation still applies).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Generic, TypeVar

from loguru import logger
from pydantic import BaseModel

from trident.reliability.parse import parse_validated
from trident.llm.base import ChatMessage, LLMError, LLMResponse, LLMUnavailable, llm

T = TypeVar("T", bound=BaseModel)

# None = unknown (probe on first use), True/False = observed capability.
_RESPONSE_FORMAT_SUPPORTED: bool | None = None


@dataclass
class StructuredResult(Generic[T]):
    obj: T | None
    response: LLMResponse
    error: str | None = None
    trace: list = field(default_factory=list)  # agent tool-call trace, if any
    llm_calls: int = 1                          # LLM calls this result cost

    @property
    def ok(self) -> bool:
        return self.obj is not None


def _response_format_for(model_cls: type[BaseModel]) -> dict:
    return {
        "type": "json_schema",
        "json_schema": {
            "name": model_cls.__name__,
            "schema": model_cls.model_json_schema(),
            "strict": False,
        },
    }


def _raw_chat(messages, model, temperature, rf):
    """One LLM call, degrading gracefully if response_format is unsupported."""
    global _RESPONSE_FORMAT_SUPPORTED
    if rf is not None and _RESPONSE_FORMAT_SUPPORTED is not False:
        try:
            resp = llm().chat(messages, model=model, temperature=temperature, response_format=rf)
            _RESPONSE_FORMAT_SUPPORTED = True
            return resp
        except LLMUnavailable:
            raise
        except LLMError as e:
            # Endpoint rejected response_format — degrade and don't try it again.
            logger.warning(f"response_format unsupported; degrading to plain prompting ({e})")
            _RESPONSE_FORMAT_SUPPORTED = False
    return llm().chat(messages, model=model, temperature=temperature)


def chat_structured(
    messages: list[ChatMessage],
    model_cls: type[T],
    *,
    model: str,
    temperature: float = 0.2,
) -> StructuredResult[T]:
    """Call the LLM and validate the result against `model_cls`, with one repair retry."""
    rf = _response_format_for(model_cls)

    resp = _raw_chat(messages, model, temperature, rf)
    obj, err = parse_validated(resp.content, model_cls)
    if obj is not None:
        return StructuredResult(obj, resp, llm_calls=1)

    # Repair attempt: show the model its output and the validation error.
    logger.warning(f"{model_cls.__name__} validation failed ({err}); attempting repair")
    repair_msgs = list(messages) + [
        ChatMessage("assistant", resp.content[:4000]),
        ChatMessage(
            "user",
            f"Your previous response was not valid. Error: {err}. "
            f"Reply with ONLY a single JSON object matching the required schema — "
            f"no markdown, no prose, no code fences.",
        ),
    ]
    resp2 = _raw_chat(repair_msgs, model, 0.0, rf)
    obj2, err2 = parse_validated(resp2.content, model_cls)
    if obj2 is not None:
        return StructuredResult(obj2, resp2, llm_calls=2)
    return StructuredResult(None, resp2, err2, llm_calls=2)
