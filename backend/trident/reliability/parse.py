"""Shared helpers for experts (JSON parsing + validation of LLM output)."""

from __future__ import annotations

import json
import re
from typing import Any, TypeVar

from loguru import logger
from pydantic import BaseModel, ValidationError

T = TypeVar("T", bound=BaseModel)


def parse_llm_json(content: str) -> dict[str, Any]:
    """Parse a JSON object from LLM output, tolerating code fences and prose."""
    if not content:
        return {}
    # Strip code fences if present
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", content, re.DOTALL)
    text = m.group(1) if m else content
    # Try direct parse first
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Find the first {...} block
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end > start:
        chunk = text[start : end + 1]
        try:
            return json.loads(chunk)
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