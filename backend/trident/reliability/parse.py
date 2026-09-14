"""Shared helpers for experts (JSON parsing + validation of LLM output)."""

from __future__ import annotations

import json
from typing import Any, TypeVar

from loguru import logger
from pydantic import BaseModel, ValidationError

T = TypeVar("T", bound=BaseModel)


def parse_llm_json(content: str) -> dict[str, Any]:
    """Parse exactly one JSON object or one fenced JSON object.

    Model output is security decision input.  Do not search arbitrary prose for
    a nested object: that can accept an unrelated or attacker-controlled JSON
    fragment as the decision.  Repair is handled by the structured layer.
    """
    if not content:
        return {}
    text = content.strip()
    if text.startswith("```") and text.endswith("```"):
        lines = text.splitlines()
        if len(lines) < 3 or not lines[0].strip().startswith("```") or lines[-1].strip() != "```":
            return {}
        language = lines[0].strip()[3:].strip().lower()
        if language not in {"", "json"}:
            return {}
        text = "\n".join(lines[1:-1]).strip()
    try:
        value = json.loads(text)
        if isinstance(value, dict):
            return value
        logger.warning("LLM response was valid JSON but not an object")
    except json.JSONDecodeError as e:
        logger.warning(f"Failed to parse LLM JSON: {e}")
    return {}


def parse_validated(content: str, model: type[T]) -> tuple[T | None, str | None]:
    """Parse + validate LLM output against a Pydantic model.

    Returns (instance, None) on success or (None, error_message) on failure.
    An empty/garbage response is a failure — never a silently-defaulted object —
    so callers can distinguish a parse failure from a genuine verdict.
    """
    data = parse_llm_json(content)
    if not data:
        return None, "no JSON object found in response"
    try:
        return model.model_validate(data), None
    except ValidationError as e:
        return None, "; ".join(
            f"{'.'.join(str(p) for p in err['loc'])}: {err['msg']}" for err in e.errors()[:5]
        )
