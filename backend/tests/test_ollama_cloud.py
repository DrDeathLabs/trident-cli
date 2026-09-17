"""Native Ollama Cloud contract tests; no network and no response shim."""

from __future__ import annotations

import httpx
import pytest

from trident.llm.base import LLMError, LLMUnavailable, OllamaBackend
from trident.llm.base import set_mock_handler
from trident.reliability.parse import parse_validated
from trident.reliability.schemas import ReviewVerdict
from trident.reliability.structured import chat_structured
from trident.llm.base import ChatMessage


def test_native_chat_uses_api_chat_and_keeps_thinking_separate(monkeypatch):
    seen = {}

    def handler(request: httpx.Request):
        seen["path"] = request.url.path
        seen["payload"] = request.read()
        return httpx.Response(200, json={
            "model": "nemotron-3-super",
            "message": {"role": "assistant", "thinking": "private reasoning", "content": '{"ok":true}'},
            "prompt_eval_count": 4,
            "eval_count": 2,
        })

    backend = OllamaBackend(host="http://ollama.test", timeout=2, mode="local_gateway")
    backend.client = httpx.Client(transport=httpx.MockTransport(handler))
    monkeypatch.setattr(backend, "ensure_ready", lambda model: {"status": "ok"})
    response = backend.chat([], model="nemotron-3-super:cloud", response_format={"type": "json_schema"})

    assert seen["path"] == "/api/chat"
    assert b'"format"' not in seen["payload"]
    assert response.content == '{"ok":true}'
    assert response.thinking == "private reasoning"
    assert response.metadata["model_actual"] == "nemotron-3-super"


def test_cloud_alias_accepts_exact_native_identity_and_records_both(monkeypatch):
    seen_paths = []

    def handler(request: httpx.Request):
        seen_paths.append(request.url.path)
        if request.url.path == "/api/version":
            return httpx.Response(200, json={"version": "0.33.3"})
        if request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [{"name": "gemma4:31b"}]})
        return httpx.Response(200, json={
            "model": "gemma4:31b",
            "message": {"role": "assistant", "content": "{}"},
        })

    backend = OllamaBackend(host="http://ollama.test", timeout=2, mode="local_gateway")
    backend.client = httpx.Client(transport=httpx.MockTransport(handler))
    response = backend.chat([], model="gemma4:31b-cloud")

    assert seen_paths == ["/api/version", "/api/tags", "/api/chat"]
    assert response.metadata["model_requested"] == "gemma4:31b-cloud"
    assert response.metadata["model_actual"] == "gemma4:31b"


def test_direct_cloud_requires_key_without_logging_or_substitution(monkeypatch):
    monkeypatch.delenv("OLLAMA_API_KEY", raising=False)
    backend = OllamaBackend(host="https://ollama.com", mode="direct_cloud")
    result = backend.health(model="nemotron-3-super:cloud")
    assert result["status"] == "down"
    with pytest.raises(LLMUnavailable):
        backend.ensure_ready("nemotron-3-super:cloud")


def test_unrelated_returned_model_is_rejected(monkeypatch):
    backend = OllamaBackend(host="http://ollama.test", timeout=2, mode="local_gateway")
    backend.client = httpx.Client(transport=httpx.MockTransport(
        lambda request: httpx.Response(200, json={
            "model": "another-model", "message": {"content": "{}"},
        })
    ))
    monkeypatch.setattr(backend, "ensure_ready", lambda model: {"status": "ok"})
    with pytest.raises(LLMError, match="model"):
        backend.chat([], model="nemotron-3-super:cloud")


def test_unrelated_available_model_does_not_silently_fallback():
    calls = []

    def handler(request: httpx.Request):
        calls.append(request.url.path)
        if request.url.path == "/api/version":
            return httpx.Response(200, json={"version": "0.33.3"})
        return httpx.Response(200, json={"models": [{"name": "another-model"}]})

    backend = OllamaBackend(host="http://ollama.test", timeout=2, mode="local_gateway")
    backend.client = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(LLMUnavailable, match="unavailable"):
        backend.ensure_ready("gemma4:31b-cloud")
    assert calls == ["/api/version", "/api/tags"]


def test_ollama_timeout_preserves_transport_attempt_metadata():
    def handler(request: httpx.Request):
        raise httpx.ReadTimeout("synthetic timeout", request=request)

    backend = OllamaBackend(host="http://ollama.test", timeout=0.1, mode="local_gateway")
    backend.max_retries = 1
    backend.client = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(LLMUnavailable) as caught:
        backend._post("/api/chat", {"model": "nemotron-3-super:cloud"})
    details = caught.value.transport
    assert details["attempts"] == 2
    assert details["configured_max_retries"] == 1
    assert details["attempt_timeout_seconds"] == 0.1
    assert details["failure_reason"] == "request_timeout"
    assert details["final_exception"] == "synthetic timeout"


def test_application_repair_is_bounded_and_accepts_only_valid_retry():
    calls = {"n": 0}

    def handler(messages, model):
        calls["n"] += 1
        if calls["n"] == 1:
            return "Here is the answer: {\"verdict\":\"confirmed\"}"
        return {"verdict": "confirmed", "confidence": 0.9, "narrative": "source evidence supports it"}

    set_mock_handler(handler)
    result = chat_structured(
        [ChatMessage("user", "Review the supplied finding")], ReviewVerdict, model="mock"
    )
    assert result.ok
    assert result.llm_calls == 2
    assert parse_validated("prefix {\"verdict\":\"confirmed\"}", ReviewVerdict)[0] is None
