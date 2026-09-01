"""LLM backend abstraction.

Single Ollama backend. The council model is configurable (default
gemma4:31b-cloud) with optional per-role and per-job overrides. There is no
fallback model: if the configured model is unreachable, the job fails clearly.
"""

from __future__ import annotations

import json
import os
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

import httpx
from loguru import logger
from tenacity import retry, stop_after_attempt, wait_exponential

from trident.config import settings


@dataclass
class ChatMessage:
    role: str  # "system" | "user" | "assistant" | "tool"
    content: str
    tool_calls: list[dict] | None = None
    tool_call_id: str | None = None


@dataclass
class LLMResponse:
    content: str
    thinking: str | None = None
    tool_calls: list[dict] | None = None
    raw: dict | None = None


class LLMError(RuntimeError):
    pass


class LLMUnavailable(LLMError):
    """Raised when the model endpoint is unreachable after retries — no fallback."""


class LLMBackend(ABC):
    """Abstract LLM backend."""

    @abstractmethod
    def chat(
        self,
        messages: list[ChatMessage],
        *,
        model: str,
        temperature: float = 0.2,
        tools: list[dict] | None = None,
        response_format: dict | None = None,
    ) -> LLMResponse:
        ...

    @abstractmethod
    def embed(self, texts: list[str], *, model: str) -> list[list[float]]:
        ...

    @abstractmethod
    def health(self) -> dict:
        ...


class OllamaBackend(LLMBackend):
    """Ollama backend using the OpenAI-compatible /v1 endpoint.

    Serves both local and cloud models (e.g. glm-5.2:cloud) transparently.
    """

    def __init__(self, host: str | None = None, timeout: int | None = None):
        self.host = (host or settings.llm.ollama_host).rstrip("/")
        self.timeout = timeout or settings.llm.request_timeout
        self.client = httpx.Client(timeout=self.timeout)

    def _v1_url(self, path: str) -> str:
        return f"{self.host}{path}"

    @retry(
        reraise=True,
        stop=stop_after_attempt(settings.llm.max_retries),
        wait=wait_exponential(multiplier=2, min=2, max=20),
    )
    def _post(self, url: str, payload: dict) -> dict:
        try:
            r = self.client.post(url, json=payload)
            r.raise_for_status()
            return r.json()
        except httpx.ConnectError as e:
            raise LLMUnavailable(f"Ollama unreachable at {self.host}: {e}") from e
        except (httpx.ReadTimeout, httpx.TimeoutException) as e:
            raise LLMUnavailable(f"Ollama timed out at {self.host} after {self.timeout}s: {e}") from e
        except httpx.HTTPStatusError as e:
            raise LLMError(f"Ollama HTTP {e.response.status_code}: {e.response.text[:500]}") from e

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
            "model": model,
            "messages": [self._msg_to_dict(m) for m in messages],
            "temperature": temperature,
            "stream": False,
        }
        if tools:
            payload["tools"] = tools
        if response_format:
            payload["response_format"] = response_format

        data = self._post(self._v1_url("/v1/chat/completions"), payload)

        choice = (data.get("choices") or [{}])[0]
        msg = choice.get("message", {})
        content = msg.get("content", "") or ""
        thinking = msg.get("thinking") or msg.get("reasoning_content")
        tool_calls = msg.get("tool_calls")
        return LLMResponse(content=content, thinking=thinking, tool_calls=tool_calls, raw=data)

    def embed(self, texts: list[str], *, model: str) -> list[list[float]]:
        if not texts:
            return []
        # Prefer the batched /api/embed endpoint (one round-trip for the whole list).
        try:
            data = self._post(
                self._v1_url("/api/embed"),
                {"model": model, "input": texts},
            )
            embs = data.get("embeddings")
            if isinstance(embs, list) and len(embs) == len(texts):
                return embs
        except LLMError:
            pass  # fall back to per-text below
        # Fallback: legacy single-prompt endpoint, one call per text.
        out: list[list[float]] = []
        for text in texts:
            data = self._post(
                self._v1_url("/api/embeddings"),
                {"model": model, "prompt": text},
            )
            out.append(data.get("embedding", []))
        return out

    def health(self) -> dict:
        try:
            r = self.client.get(f"{self.host}/api/tags", timeout=10)
            r.raise_for_status()
            tags = r.json().get("models", [])
            names = [m.get("name") for m in tags]
            return {
                "status": "ok",
                "host": self.host,
                "models": names,
                "expert_model_available": settings.llm.default_model in names,
            }
        except Exception as e:
            return {"status": "down", "host": self.host, "error": str(e)}


# A JSON superset covering every council schema's fields. Because all schemas
# ignore extra fields, this one object validates against ReviewVerdict,
# JudgeVerdict, NovelFindingList, AttackPathList, and ChatAnswer alike — so the
# mock produces schema-valid output for every structured call without knowing
# which one it is. Tests can override behavior via set_mock_handler().
_MOCK_SUPERSET = {
    "thinking": "mock reasoning",
    "verdict": "confirmed", "confidence": 0.9,
    "severity": "high", "cwe": None, "owasp": None,
    "narrative": "mock narrative", "remediation": "mock remediation",
    "exploit_scenario": None, "novel_findings": [],
    "final_verdict": "confirmed", "final_confidence": 0.9, "final_severity": "high",
    "reasoning": "mock reasoning", "false_positive_reason": None,
    "attack_paths": [], "answer": "mock answer", "citations": [],
}

# Optional test hook: fn(messages, model) -> dict, merged over the superset.
_mock_handler = None


def set_mock_handler(fn) -> None:
    """Install a test handler that returns a dict merged over the mock superset."""
    global _mock_handler
    _mock_handler = fn


class MockLLMBackend(LLMBackend):
    """Deterministic mock for tests — no network, no API spend, always schema-valid."""

    def chat(
        self,
        messages: list[ChatMessage],
        *,
        model: str,
        temperature: float = 0.2,
        tools: list[dict] | None = None,
        response_format: dict | None = None,
    ) -> LLMResponse:
        if _mock_handler is not None:
            try:
                h = _mock_handler(messages, model)
            except Exception as e:  # pragma: no cover - test hook safety
                logger.warning(f"mock handler error: {e}")
                h = None
            # A str return simulates an unparseable (non-JSON) response.
            if isinstance(h, str):
                return LLMResponse(content=h, raw={})
            data = dict(_MOCK_SUPERSET)
            if h:
                data.update(h)
            # A handler may drive tool-calling by returning {"_tool_calls": [...]}.
            tool_calls = data.pop("_tool_calls", None)
            if tool_calls:
                return LLMResponse(content="", tool_calls=tool_calls, raw={})
            return LLMResponse(content=json.dumps(data), thinking=data.get("thinking"), raw={})
        return LLMResponse(content=json.dumps(_MOCK_SUPERSET), thinking="mock reasoning", raw={})

    def embed(self, texts: list[str], *, model: str) -> list[list[float]]:
        # Deterministic hashing bag-of-words so cosine ~ token overlap: similar
        # texts embed close, different texts embed far (unlike a constant vector).
        import hashlib
        dim = 64
        out: list[list[float]] = []
        for t in texts:
            vec = [0.0] * dim
            for tok in (t or "").lower().split():
                h = int(hashlib.md5(tok.encode()).hexdigest(), 16)
                vec[h % dim] += 1.0
            out.append(vec)
        return out

    def health(self) -> dict:
        return {"status": "ok", "host": "mock", "models": ["mock"], "expert_model_available": True}


def get_llm_backend(backend_override: str | None = None) -> LLMBackend:
    """Return the configured LLM backend.

    Priority: explicit override → TRIDENT_LLM_MOCK env → LLM_BACKEND config → ollama.
    """
    if os.environ.get("TRIDENT_LLM_MOCK") == "1":
        return MockLLMBackend()

    backend = (backend_override or settings.llm.backend).lower()

    if backend == "mock":
        return MockLLMBackend()

    if backend == "openai":
        from trident.llm.openai_backend import OpenAIBackend
        return OpenAIBackend(timeout=settings.llm.request_timeout, max_retries=settings.llm.max_retries)

    if backend == "anthropic":
        from trident.llm.anthropic_backend import AnthropicBackend
        return AnthropicBackend(timeout=settings.llm.request_timeout, max_retries=settings.llm.max_retries)

    return OllamaBackend()


# Convenience: the single backend instance (lazy, thread-safe init)
_llm: LLMBackend | None = None
_llm_lock = threading.Lock()


def llm() -> LLMBackend:
    global _llm
    if _llm is None:
        with _llm_lock:
            if _llm is None:
                _llm = get_llm_backend()
    return _llm