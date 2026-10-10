"""OpenAI LLM backend — uses the OpenAI Chat Completions API via httpx."""

from __future__ import annotations

import os
import ipaddress
from typing import Any
from urllib.parse import urlsplit

import httpx

from trident.llm.base import (
    ChatMessage,
    LLMBackend,
    LLMError,
    LLMResponse,
    LLMUnavailable,
)

_OPENAI_BASE = "https://api.openai.com/v1"
_DEFAULT_MODEL = "gpt-4o"


def _validate_base_url(base_url: str) -> str:
    """Reject URL forms that can disclose bearer credentials or route them
    over cleartext transport. Local HTTP is useful for loopback gateways.
    """
    normalized = base_url.rstrip("/")
    parsed = urlsplit(normalized)
    if (
        parsed.scheme not in {"https", "http"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("OpenAI-compatible base URL must be an HTTPS URL without credentials or query")
    if parsed.scheme == "http":
        hostname = parsed.hostname.rstrip(".").lower()
        is_loopback = hostname == "localhost"
        try:
            is_loopback = is_loopback or ipaddress.ip_address(hostname).is_loopback
        except ValueError:
            pass
        if not is_loopback:
            raise ValueError("OpenAI-compatible HTTP is allowed only for a loopback gateway; use HTTPS")
    return normalized


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
        self.base_url = _validate_base_url(base_url or _OPENAI_BASE)
        self.default_model = model or os.environ.get("EXPERT_MODEL") or _DEFAULT_MODEL
        self.timeout = timeout
        self.max_retries = max_retries
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        self.client = httpx.Client(
            timeout=timeout,
            headers=headers,
            follow_redirects=False,
        )

    def _post(self, url: str, payload: dict) -> dict:
        attempts = max(1, self.max_retries + 1)
        for attempt in range(attempts):
            try:
                response = self.client.post(url, json=payload)
                response.raise_for_status()
                data = response.json()
                if not isinstance(data, dict):
                    raise LLMError("OpenAI-compatible endpoint returned a non-object JSON response")
                return data
            except httpx.ConnectError as exc:
                if attempt + 1 == attempts:
                    raise LLMUnavailable("OpenAI-compatible endpoint is unreachable") from exc
            except httpx.ConnectTimeout as exc:
                if attempt + 1 == attempts:
                    raise LLMUnavailable("OpenAI-compatible endpoint is unreachable") from exc
            except httpx.TimeoutException as exc:
                if attempt + 1 == attempts:
                    raise LLMUnavailable(
                        f"OpenAI-compatible endpoint timed out after {self.timeout}s"
                    ) from exc
            except httpx.HTTPStatusError as exc:
                status = exc.response.status_code
                if status in (401, 403):
                    raise LLMError(
                        f"OpenAI-compatible authentication error {status}: check the API key"
                    ) from exc
                raise LLMError(f"OpenAI-compatible HTTP {status}") from exc
            except ValueError as exc:
                raise LLMError("OpenAI-compatible endpoint returned malformed JSON") from exc
            if attempt + 1 < attempts:
                import time

                time.sleep(min(0.1 * (2 ** attempt), 1.0))
        raise LLMUnavailable("OpenAI-compatible endpoint request failed")

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
        choices = data.get("choices")
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
            raise LLMError("OpenAI-compatible endpoint returned an invalid chat completion")
        msg = choices[0].get("message")
        if not isinstance(msg, dict):
            raise LLMError("OpenAI-compatible endpoint returned an invalid chat message")
        content = msg.get("content", "") or ""
        if not isinstance(content, str):
            raise LLMError("OpenAI-compatible endpoint returned non-text message content")
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
        items = data.get("data")
        if not isinstance(items, list):
            raise LLMError("OpenAI-compatible endpoint returned invalid embeddings")
        try:
            ordered = sorted(items, key=lambda item: item.get("index", 0))
            return [item["embedding"] for item in ordered]
        except (AttributeError, KeyError, TypeError) as exc:
            raise LLMError("OpenAI-compatible endpoint returned invalid embeddings") from exc

    def health(self) -> dict:
        try:
            r = self.client.get(f"{self.base_url}/models", timeout=10)
            r.raise_for_status()
            data = r.json()
            if not isinstance(data, dict) or not isinstance(data.get("data", []), list):
                raise LLMError("OpenAI-compatible endpoint returned an invalid model list")
            models = [m["id"] for m in data.get("data", []) if isinstance(m, dict) and m.get("id")]
            return {
                "status": "ok",
                "host": self.base_url,
                "models": models[:20],
                "expert_model_available": self.default_model in models,
            }
        except Exception as e:
            # Avoid exposing response bodies, request headers, or credentials in
            # health output. The configured URL is already credential-free.
            return {
                "status": "down",
                "host": self.base_url,
                "error": f"{type(e).__name__}: OpenAI-compatible health check failed",
            }
