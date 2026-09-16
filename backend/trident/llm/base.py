"""LLM backend abstraction.

Single Ollama backend. The council model is configurable (default
gemma4:31b-cloud) with optional per-role and per-job overrides. There is no
fallback model: if the configured model is unreachable, the job fails clearly.
"""

from __future__ import annotations

import json
import os
import random
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

import httpx
from loguru import logger
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
    metadata: dict | None = None


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
    """Ollama native API backend for local-gateway and direct-cloud modes.

    Cloud models are accessed through Ollama's native ``/api/chat`` contract.
    The cloud service does not support the Ollama ``format`` schema feature,
    so schema enforcement belongs to ``reliability.structured`` instead.
    """

    def __init__(self, host: str | None = None, timeout: int | None = None,
                 mode: str | None = None):
        self.mode = (mode or settings.llm.ollama_mode).strip().lower()
        if self.mode not in {"local_gateway", "direct_cloud"}:
            raise LLMError(f"unsupported Ollama mode: {self.mode}")
        configured_host = host or (
            settings.llm.ollama_cloud_host
            if self.mode == "direct_cloud" else settings.llm.ollama_host
        )
        self.host = configured_host.rstrip("/")
        self.timeout = float(timeout or settings.llm.response_timeout)
        self.connect_timeout = settings.llm.connect_timeout
        self.deadline = settings.llm.request_deadline
        self.max_retries = max(0, settings.llm.max_retries)
        self.client = httpx.Client(
            timeout=httpx.Timeout(self.timeout, connect=self.connect_timeout),
        )
        self._ready = False
        self._ready_lock = threading.Lock()

    def _url(self, path: str) -> str:
        return f"{self.host}{path}"

    def _headers(self) -> dict[str, str]:
        if self.mode == "direct_cloud":
            key = os.environ.get("OLLAMA_API_KEY", "")
            if not key:
                raise LLMUnavailable("OLLAMA_API_KEY is required for direct_cloud mode")
            return {"Authorization": f"Bearer {key}"}
        return {}

    @staticmethod
    def _transient_status(status: int) -> bool:
        return status in {408, 429, 500, 502, 503, 504}

    def _post(self, path: str, payload: dict) -> tuple[dict, dict]:
        """POST JSON with bounded retries for transient transport failures."""
        started = time.monotonic()
        attempts = 0
        last_error: Exception | None = None
        for attempt in range(self.max_retries + 1):
            attempts = attempt + 1
            if time.monotonic() - started > self.deadline:
                raise LLMUnavailable(f"Ollama request deadline exceeded after {self.deadline}s")
            try:
                response = self.client.post(
                    self._url(path), json=payload, headers=self._headers(),
                    timeout=httpx.Timeout(self.timeout, connect=self.connect_timeout),
                )
                if response.status_code >= 400:
                    if self._transient_status(response.status_code) and attempt < self.max_retries:
                        delay = min(20.0, 2.0 ** attempt) + random.uniform(0, 0.5)
                        time.sleep(delay)
                        continue
                    if response.status_code in {401, 403}:
                        raise LLMUnavailable(
                            f"Ollama authentication failed ({response.status_code}); "
                            "check Ollama sign-in or OLLAMA_API_KEY"
                        )
                    raise LLMError(f"Ollama HTTP {response.status_code}: {response.text[:500]}")
                data = response.json()
                return data, {
                    "attempts": attempts, "status_code": response.status_code,
                    "latency_ms": round((time.monotonic() - started) * 1000, 2),
                }
            except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout,
                    httpx.WriteTimeout, httpx.PoolTimeout, httpx.NetworkError) as exc:
                last_error = exc
                if attempt >= self.max_retries:
                    break
                delay = min(20.0, 2.0 ** attempt) + random.uniform(0, 0.5)
                time.sleep(delay)
        if isinstance(last_error, (httpx.ReadTimeout, httpx.TimeoutException)):
            raise LLMUnavailable(
                f"Ollama timed out at {self.host} after {self.timeout}s"
            ) from last_error
        raise LLMUnavailable(f"Ollama unreachable at {self.host}: {last_error}") from last_error

    def _get(self, path: str) -> tuple[dict, int]:
        try:
            response = self.client.get(
                self._url(path), headers=self._headers(),
                timeout=httpx.Timeout(10.0, connect=self.connect_timeout),
            )
            if response.status_code in {401, 403}:
                raise LLMUnavailable("Ollama authentication failed during capability check")
            response.raise_for_status()
            return response.json(), response.status_code
        except LLMUnavailable:
            raise
        except (httpx.ConnectError, httpx.TimeoutException, httpx.NetworkError) as exc:
            raise LLMUnavailable(f"Ollama capability check failed at {self.host}") from exc

    @staticmethod
    def _model_equivalent(requested: str, actual: str | None) -> bool:
        """Accept an Ollama cloud tag only for its exact native model name.

        Ollama's cloud gateway may echo ``gemma4:31b`` for a request sent as
        ``gemma4:31b-cloud`` (or the older ``name:cloud`` spelling).  That is
        an alias representation, not permission to use an arbitrary model.
        Keep the mapping one-way: a native request must not be satisfied by a
        cloud-tagged or otherwise different model.
        """
        requested_name = (requested or "").strip()
        actual_name = (actual or "").strip()
        if not requested_name or not actual_name:
            return False
        if requested_name == actual_name:
            return True
        for cloud_suffix in ("-cloud", ":cloud"):
            if requested_name.endswith(cloud_suffix):
                return actual_name == requested_name[: -len(cloud_suffix)]
        return False

    def ensure_ready(self, model: str) -> dict:
        with self._ready_lock:
            if self._ready:
                return {"status": "ok", "model_requested": model, "cached": True}
            result = self.health(model=model)
            if result.get("status") != "ok":
                raise LLMUnavailable(result.get("error", "Ollama unavailable"))
            if not result.get("model_available", True):
                raise LLMUnavailable(
                    f"configured Ollama model {model!r} is unavailable at {self.host}; "
                    "refusing silent model substitution"
                )
            self._ready = True
            return result

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
        capability = self.ensure_ready(model)
        payload: dict[str, Any] = {
            "model": model,
            "messages": [self._msg_to_dict(m) for m in messages],
            "temperature": temperature,
            "stream": False,
        }
        if tools:
            payload["tools"] = tools
        # Native Ollama API intentionally does not receive response_format:
        # Ollama Cloud does not support server-enforced structured outputs.
        think = settings.llm.think.strip().lower()
        if think and think != "auto":
            payload["think"] = {
                "true": True, "false": False,
            }.get(think, settings.llm.think)
        data, transport = self._post("/api/chat", payload)
        actual_model = data.get("model")
        if not self._model_equivalent(model, actual_model):
            raise LLMError(
                f"Ollama returned model {actual_model!r}, requested {model!r}; "
                "refusing silent model substitution"
            )
        msg = data.get("message", {})
        content = msg.get("content", "") or ""
        thinking = msg.get("thinking") or msg.get("reasoning_content")
        tool_calls = msg.get("tool_calls")
        return LLMResponse(
            content=content, thinking=thinking, tool_calls=tool_calls, raw=data,
            metadata={
                "backend": "ollama", "mode": self.mode, "endpoint": self._url("/api/chat"),
                # Preserve both identities.  The actual response value must
                # not be replaced with the requested alias in audit records.
                "model_requested": model, "model_actual": actual_model,
                "thinking_enabled": think not in {"", "auto", "false"},
                "capability": capability, "transport": transport,
                "prompt_eval_count": data.get("prompt_eval_count"),
                "eval_count": data.get("eval_count"),
            },
        )

    def embed(self, texts: list[str], *, model: str) -> list[list[float]]:
        if not texts:
            return []
        # Prefer the batched /api/embed endpoint (one round-trip for the whole list).
        try:
            data, _ = self._post("/api/embed", {"model": model, "input": texts})
            embs = data.get("embeddings")
            if isinstance(embs, list) and len(embs) == len(texts):
                return embs
        except LLMError:
            pass  # fall back to per-text below
        # Fallback: legacy single-prompt endpoint, one call per text.
        out: list[list[float]] = []
        for text in texts:
            data, _ = self._post("/api/embeddings", {"model": model, "prompt": text})
            out.append(data.get("embedding", []))
        return out

    def health(self, model: str | None = None) -> dict:
        try:
            version, _ = self._get("/api/version")
            tags, _ = self._get("/api/tags")
            tag_models = tags.get("models", [])
            names = [m.get("name") for m in tag_models if m.get("name")]
            requested = model or settings.llm.default_model
            return {
                "status": "ok",
                "host": self.host,
                "mode": self.mode,
                "version": version.get("version"),
                "models": names,
                "model_requested": requested,
                "model_available": any(self._model_equivalent(requested, name) for name in names),
                # Backward-compatible key used by existing status consumers.
                "expert_model_available": any(
                    self._model_equivalent(requested, name) for name in names
                ),
                "auth": "api_key" if self.mode == "direct_cloud" else "local_ollama_session",
            }
        except Exception as e:
            return {"status": "down", "host": self.host, "mode": self.mode, "error": str(e)}


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
