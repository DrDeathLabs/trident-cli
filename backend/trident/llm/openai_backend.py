"""OpenAI LLM backend — uses the OpenAI Chat Completions API via httpx."""

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

_OPENAI_BASE = "https://api.openai.com/v1"
_DEFAULT_MODEL = "gpt-4o"


class OpenAIBackend(LLMBackend):
    """OpenAI backend using the Chat Completions API."""

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        timeout: int = 300,
        max_retries: int = 3,
    ):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self.base_url = (base_url or _OPENAI_BASE).rstrip("/")
        self.default_model = model or os.environ.get("EXPERT_MODEL") or _DEFAULT_MODEL
        self.timeout = timeout
        self.max_retries = max_retries
        self.client = httpx.Client(
            timeout=timeout,
            headers={
                "Authorization": f"Bearer {self.api_key}",
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
            raise LLMUnavailable(f"OpenAI unreachable: {e}") from e
        except (httpx.ReadTimeout, httpx.TimeoutException) as e:
            raise LLMUnavailable(f"OpenAI timed out after {self.timeout}s: {e}") from e
        except httpx.HTTPStatusError as e:
            status = e.response.status_code
            body = e.response.text[:500]
            if status in (401, 403):
                raise LLMError(f"OpenAI auth error {status}: check OPENAI_API_KEY") from e
            raise LLMError(f"OpenAI HTTP {status}: {body}") from e

    @staticmethod
    def _msg_to_dict(m: ChatMessage) -> dict:
        d: dict[str, Any] = {"role": m.role, "content": m.content}
        if m.tool_calls:
            d["tool_calls"] = m.tool_calls
        if m.tool_call_id:
            d["tool_call_id"] = m.tool_call_id
        return d

    def chat(
        self,
        messages: list[ChatMessage],
        *,
        model: str,
        temperature: float = 0.2,
        tools: list[dict] | None = None,
        response_format: dict | None = None,
    ) -> LLMResponse:
        payload: dict[str, Any] = {
            "model": model or self.default_model,
            "messages": [self._msg_to_dict(m) for m in messages],
            "temperature": temperature,
        }
        if tools:
            payload["tools"] = tools
        if response_format:
            payload["response_format"] = response_format

        data = self._post(f"{self.base_url}/chat/completions", payload)
        choice = (data.get("choices") or [{}])[0]
        msg = choice.get("message", {})
        content = msg.get("content", "") or ""
        tool_calls = msg.get("tool_calls")
        return LLMResponse(content=content, tool_calls=tool_calls, raw=data)

    def embed(self, texts: list[str], *, model: str) -> list[list[float]]:
        if not texts:
            return []
        embed_model = model or "text-embedding-3-small"
        data = self._post(
            f"{self.base_url}/embeddings",
            {"model": embed_model, "input": texts},
        )
        items = sorted(data.get("data", []), key=lambda x: x.get("index", 0))
        return [item["embedding"] for item in items]

    def health(self) -> dict:
        try:
            r = self.client.get(f"{self.base_url}/models", timeout=10)
            r.raise_for_status()
            models = [m["id"] for m in r.json().get("data", [])]
            return {
                "status": "ok",
                "host": self.base_url,
                "models": models[:20],
                "expert_model_available": self.default_model in models,
            }
        except Exception as e:
            return {"status": "down", "host": self.base_url, "error": str(e)}
