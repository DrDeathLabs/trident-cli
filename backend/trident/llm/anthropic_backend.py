"""Anthropic LLM backend — uses the Anthropic Messages API via httpx."""

from __future__ import annotations

import os
from typing import Any

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from trident.llm.base import (
    ChatMessage,
    LLMBackend,
    LLMError,
    LLMResponse,
    LLMUnavailable,
)

_ANTHROPIC_BASE = "https://api.anthropic.com/v1"
_DEFAULT_MODEL = "claude-sonnet-5"
_API_VERSION = "2023-06-01"


class AnthropicBackend(LLMBackend):
    """Anthropic backend using the Messages API."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        timeout: int = 300,
        max_retries: int = 3,
    ):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.default_model = model or os.environ.get("EXPERT_MODEL") or _DEFAULT_MODEL
        self.timeout = timeout
        self.max_retries = max_retries
        self.client = httpx.Client(
            timeout=timeout,
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": _API_VERSION,
                "Content-Type": "application/json",
            },
        )

    @retry(
        reraise=True,
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=2, min=2, max=20),
    )
    def _post(self, url: str, payload: dict) -> dict:
        try:
            r = self.client.post(url, json=payload)
            r.raise_for_status()
            return r.json()
        except httpx.ConnectError as e:
            raise LLMUnavailable(f"Anthropic unreachable: {e}") from e
        except (httpx.ReadTimeout, httpx.TimeoutException) as e:
            raise LLMUnavailable(f"Anthropic timed out after {self.timeout}s: {e}") from e
        except httpx.HTTPStatusError as e:
            status = e.response.status_code
            body = e.response.text[:500]
            if status in (401, 403):
                raise LLMError(f"Anthropic auth error {status}: check ANTHROPIC_API_KEY") from e
            raise LLMError(f"Anthropic HTTP {status}: {body}") from e

    def _convert_messages(self, messages: list[ChatMessage]) -> tuple[str | None, list[dict]]:
        """Split system message from the rest; return (system, messages)."""
        system: str | None = None
        converted: list[dict] = []
        for m in messages:
            if m.role == "system":
                system = m.content
            else:
                converted.append({
                    "role": m.role,
                    "content": [{"type": "text", "text": m.content}],
                })
        return system, converted

    def chat(
        self,
        messages: list[ChatMessage],
        *,
        model: str,
        temperature: float = 0.2,
        tools: list[dict] | None = None,
        response_format: dict | None = None,
    ) -> LLMResponse:
        system, converted = self._convert_messages(messages)
        payload: dict[str, Any] = {
            "model": model or self.default_model,
            "max_tokens": 8192,
            "messages": converted,
            "temperature": temperature,
        }
        if system:
            payload["system"] = system
        if tools:
            payload["tools"] = [
                {
                    "name": t.get("function", {}).get("name", t.get("name", "")),
                    "description": t.get("function", {}).get("description", t.get("description", "")),
                    "input_schema": t.get("function", {}).get("parameters", t.get("input_schema", {})),
                }
                for t in tools
            ]

        data = self._post(f"{_ANTHROPIC_BASE}/messages", payload)
        content_blocks = data.get("content", [])
        text_content = " ".join(
            b.get("text", "") for b in content_blocks if b.get("type") == "text"
        )
        tool_use_blocks = [b for b in content_blocks if b.get("type") == "tool_use"]
        tool_calls = None
        if tool_use_blocks:
            tool_calls = [
                {
                    "id": b.get("id"),
                    "type": "function",
                    "function": {"name": b.get("name"), "arguments": str(b.get("input", {}))},
                }
                for b in tool_use_blocks
            ]
        return LLMResponse(content=text_content, tool_calls=tool_calls, raw=data)

    def embed(self, texts: list[str], *, model: str) -> list[list[float]]:
        # Anthropic does not yet expose a public embeddings endpoint.
        # Return zero vectors as a no-op fallback so the triage pipeline doesn't crash.
        return [[0.0] * 64 for _ in texts]

    def health(self) -> dict:
        try:
            r = self.client.get(f"{_ANTHROPIC_BASE}/models", timeout=10)
            r.raise_for_status()
            models = [m["id"] for m in r.json().get("data", [])]
            return {
                "status": "ok",
                "host": _ANTHROPIC_BASE,
                "models": models[:20],
                "expert_model_available": self.default_model in models,
            }
        except Exception as e:
            return {"status": "down", "host": _ANTHROPIC_BASE, "error": str(e)}
