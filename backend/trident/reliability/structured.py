"""Typed, fail-closed model execution for security decisions.

Ollama Cloud does not provide server-enforced JSON schemas. This module is the
application enforcement boundary: it prompts for one JSON object, validates it
locally, performs bounded repair, and records the decision lifecycle.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import threading
from dataclasses import dataclass, field
from typing import Any, Generic, TypeVar

from loguru import logger
from pydantic import BaseModel

from trident.config import settings
from trident.llm.base import ChatMessage, LLMError, LLMResponse, LLMUnavailable, llm
from trident.reliability.parse import parse_validated

T = TypeVar("T", bound=BaseModel)
_PROMPT_VERSION = "cloud-typed-v1"
_ledger_lock = threading.Lock()
_ledger_factory = None


def _ledger_session_factory():
    """Use a dedicated SQLite ledger when configured to avoid scan write locks."""
    global _ledger_factory
    if _ledger_factory is not None:
        return _ledger_factory
    with _ledger_lock:
        if _ledger_factory is not None:
            return _ledger_factory
        ledger_path = os.environ.get("TRIDENT_LLM_LEDGER_PATH")
        if ledger_path:
            from sqlalchemy import create_engine, event
            from sqlalchemy.orm import sessionmaker
            from trident.models import Base
            ledger_engine = create_engine(
                f"sqlite:///{ledger_path}", pool_pre_ping=True,
                connect_args={"check_same_thread": False, "timeout": 30},
            )
            @event.listens_for(ledger_engine, "connect")
            def _ledger_pragmas(conn, _record):
                cur = conn.cursor()
                cur.execute("PRAGMA journal_mode=WAL")
                cur.execute("PRAGMA busy_timeout=30000")
                cur.close()
            Base.metadata.create_all(ledger_engine)
            _ledger_factory = sessionmaker(bind=ledger_engine, autoflush=False, expire_on_commit=False)
        else:
            from trident.db import SessionLocal
            _ledger_factory = SessionLocal
    return _ledger_factory


def _ledger_context():
    from contextlib import contextmanager
    @contextmanager
    def managed():
        session = _ledger_session_factory()()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
    return managed()


@dataclass
class StructuredResult(Generic[T]):
    obj: T | None
    response: LLMResponse
    error: str | None = None
    trace: list = field(default_factory=list)
    llm_calls: int = 1
    status: str = "completed"
    validation_errors: list[str] = field(default_factory=list)
    semantic_errors: list[str] = field(default_factory=list)
    request_id: str | None = None
    replay_source: str | None = None

    @property
    def ok(self) -> bool:
        return self.status == "completed" and self.obj is not None


def _response_format_for(model_cls: type[BaseModel]) -> dict:
    """Return the contract for diagnostics; never send it to Ollama Cloud."""
    return {"type": "json_schema", "json_schema": {
        "name": model_cls.__name__, "schema": model_cls.model_json_schema(), "strict": False,
    }}


def _contract(messages: list[ChatMessage], model_cls: type[BaseModel]) -> list[ChatMessage]:
    schema = json.dumps(model_cls.model_json_schema(), sort_keys=True, separators=(",", ":"))
    instruction = (
        "\n\nOUTPUT CONTRACT (application-enforced): Return exactly one JSON object, "
        "with no prose or markdown. It must validate against this schema. Do not "
        "invent evidence, reachability, exploitability, or citations; use only "
        "evidence supplied in the request. If evidence is insufficient, use the "
        "schema's uncertain/disputed form.\nSCHEMA=" + schema
    )
    result = list(messages)
    # Keep the caller's final instruction byte-for-byte intact. Agent/tool
    # loops and deterministic replay use it as a stable request marker.
    result.append(ChatMessage("user", instruction))
    return result


def _semantic_validate(obj: BaseModel, context: dict[str, Any] | None) -> list[str]:
    """Reject typed objects that still cannot safely represent a decision."""
    data = obj.model_dump()
    errors: list[str] = []
    verdict = data.get("verdict") or data.get("final_verdict")
    confidence = data.get("confidence", data.get("final_confidence"))
    rationale = any(str(data.get(k) or "").strip() for k in (
        "rationale", "reasoning", "narrative", "false_positive_reason",
    ))
    if verdict in {"confirmed", "refuted"} and not rationale:
        errors.append("security verdict requires a non-empty rationale or reasoning")
    if confidence is not None:
        try:
            if not 0 <= float(confidence) <= 1:
                errors.append("confidence must be between 0 and 1 after schema coercion")
        except (TypeError, ValueError):
            errors.append("confidence is not numeric")
    # Context is deliberately retained for ledger/guard consumers. Report-only
    # evidence is never upgraded here into source-derived exploitability.
    return errors


def _request_identity(messages: list[ChatMessage], model: str, context: dict[str, Any]) -> tuple[str, str, str]:
    canonical = {
        "run_id": context.get("run_id"), "finding_id": context.get("finding_id"),
        "task_type": context.get("task_type", "structured"),
        "role": context.get("council_role"), "iteration": context.get("iteration", 0),
        "model": model, "messages": [
            {"role": m.role, "content": m.content, "tool_calls": m.tool_calls,
             "tool_call_id": m.tool_call_id} for m in messages
        ],
    }
    raw = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(raw.encode()).hexdigest()
    input_hash = hashlib.sha256((messages[-1].content if messages else "").encode()).hexdigest()
    return digest, digest, input_hash


def _ledger_start(request_id: str, request_hash: str, input_hash: str, model: str, context: dict[str, Any]):
    try:
        from trident.models import LLMRequest
        with _ledger_context() as db:
            row = db.get(LLMRequest, request_id)
            if row is None:
                db.add(LLMRequest(
                    request_id=request_id, request_hash=request_hash, input_hash=input_hash,
                    run_id=context.get("run_id"), finding_id=context.get("finding_id"),
                    task_type=context.get("task_type", "structured"),
                    council_role=context.get("council_role"), iteration=int(context.get("iteration", 0)),
                    prompt_template_version=context.get("prompt_template_version", _PROMPT_VERSION),
                    schema_version=context.get("schema_version", "v1"), model=model,
                    endpoint_mode=settings.llm.ollama_mode, request_settings={
                        "temperature": context.get("temperature"),
                        "max_repair_retries": settings.llm.max_repair_retries,
                        "think": settings.llm.think,
                    }, status="started",
                ))
            else:
                row.status = "started"
    except Exception as exc:
        logger.warning(f"could not start LLM request ledger entry: {exc}")


def _ledger_attempt(request_id: str, attempt: int, status: str, response: LLMResponse | None,
                    error: str | None, latency: float):
    try:
        from trident.models import LLMRequestAttempt
        with _ledger_context() as db:
            db.add(LLMRequestAttempt(
                request_id=request_id, attempt=attempt, transport_status=status,
                raw_response=response.content if response else None, error=(error or "")[:2000] or None,
                latency_ms=round(latency * 1000, 2),
                response_metadata=(response.metadata or {}) if response else {},
            ))
    except Exception as exc:
        logger.warning(f"could not persist LLM request attempt: {exc}")


def _ledger_finish(request_id: str, result: StructuredResult, response: LLMResponse | None):
    try:
        from trident.models import LLMRequest
        with _ledger_context() as db:
            row = db.get(LLMRequest, request_id)
            if row is None:
                return
            row.raw_response = response.content if response else None
            row.parsed_response = result.obj.model_dump(mode="json") if result.obj else None
            row.validation_errors = result.validation_errors
            row.semantic_validation_errors = result.semantic_errors
            row.retry_count = max(0, result.llm_calls - 1)
            row.transport_status = "ok" if response else "error"
            row.response_metadata = response.metadata or {} if response else {}
            row.latency_ms = ((response.metadata or {}).get("transport", {}).get("latency_ms")
                              if response else None)
            row.final_accepted_decision = result.obj.model_dump(mode="json") if result.ok else None
            row.status = result.status
            row.replay_source = result.replay_source
    except Exception as exc:
        logger.warning(f"could not finish LLM request ledger entry: {exc}")


def _raw_chat(messages, model, temperature):
    # No response_format argument: cloud support is explicitly absent and the
    # local typed validator above is the enforcement point.
    return llm().chat(messages, model=model, temperature=temperature)


def _load_replay(path: str) -> list[dict[str, Any]]:
    with open(path, encoding="utf-8") as handle:
        payload = json.load(handle)
    if payload.get("format") != "trident-llm-decision-replay":
        raise ValueError("unsupported LLM replay artifact")
    return payload.get("decisions") or []


def _replay_decision(model_cls: type[T], response: LLMResponse, *, request_id: str,
                     decisions: list[dict[str, Any]], context: dict[str, Any],
                     mode: str) -> StructuredResult[T]:
    match = next((item for item in decisions if item.get("request_id") == request_id), None)
    if match is None:
        match = next((item for item in decisions
                      if item.get("finding_id") == context.get("finding_id")
                      and item.get("task_type") == context.get("task_type", "structured")
                      and item.get("role") == context.get("council_role")
                      and int(item.get("iteration", 0)) == int(context.get("iteration", 0))
                      and item.get("model") == context.get("model")), None)
    if match is None:
        return StructuredResult(
            None, response, "no matching decision in replay artifact", llm_calls=0,
            status="unresolved_replay_missing", request_id=request_id,
            replay_source=mode,
        )
    if mode == "parsed":
        data = match.get("accepted_decision")
        raw = json.dumps(data, sort_keys=True) if data is not None else ""
    else:
        attempts = match.get("attempts") or []
        raw = next((a.get("raw_response") for a in attempts if a.get("raw_response")), "")
        data = None
    replay_response = LLMResponse(content=raw, metadata={"replay": mode, "source_request_id": match.get("request_id")})
    if data is not None:
        try:
            obj = model_cls.model_validate(data)
            semantic_errors = _semantic_validate(obj, context)
            if semantic_errors:
                return StructuredResult(None, replay_response, "; ".join(semantic_errors), llm_calls=0,
                                        status="unresolved_semantic", semantic_errors=semantic_errors,
                                        request_id=request_id, replay_source=mode)
            return StructuredResult(obj, replay_response, llm_calls=0, request_id=request_id,
                                    replay_source=mode)
        except Exception as exc:
            return StructuredResult(None, replay_response, str(exc), llm_calls=0,
                                    status="unresolved_parse", validation_errors=[str(exc)],
                                    request_id=request_id, replay_source=mode)
    obj, error = parse_validated(raw, model_cls)
    if obj is not None:
        semantic_errors = _semantic_validate(obj, context)
        if not semantic_errors:
            return StructuredResult(obj, replay_response, llm_calls=0, request_id=request_id,
                                    replay_source=mode)
    else:
        semantic_errors = []
    return StructuredResult(None, replay_response, error or "; ".join(semantic_errors), llm_calls=0,
                            status="unresolved_semantic" if semantic_errors else "unresolved_parse",
                            validation_errors=[error] if error else [], semantic_errors=semantic_errors,
                            request_id=request_id, replay_source=mode)


def chat_structured(messages: list[ChatMessage], model_cls: type[T], *, model: str,
                    temperature: float = 0.2, context: dict[str, Any] | None = None) -> StructuredResult[T]:
    """Call, parse, repair, and fail closed for a typed model response."""
    context = dict(context or {})
    prepared = _contract(messages, model_cls)
    request_id = request_hash = input_hash = None
    if context.get("run_id") and os.environ.get("TRIDENT_LLM_MOCK") != "1":
        request_id, request_hash, input_hash = _request_identity(prepared, model, context)
        _ledger_start(request_id, request_hash, input_hash, model, {**context, "temperature": temperature})

    replay_path = os.environ.get("TRIDENT_LLM_REPLAY_PATH")
    replay_mode = os.environ.get("TRIDENT_LLM_REPLAY_MODE", "exact").strip().lower()
    if replay_path and request_id and replay_mode in {"exact", "parsed"}:
        try:
            replayed = _replay_decision(
                model_cls, LLMResponse(content=""), request_id=request_id,
                decisions=_load_replay(replay_path), context={**context, "model": model},
                mode=replay_mode,
            )
        except Exception as exc:
            replayed = StructuredResult(None, LLMResponse(content=""), str(exc), llm_calls=0,
                                        status="unresolved_replay_error", request_id=request_id,
                                        replay_source=replay_mode)
        if request_id:
            _ledger_finish(request_id, replayed, replayed.response)
        return replayed

    attempts = 0
    validation_errors: list[str] = []
    semantic_errors: list[str] = []
    response = LLMResponse(content="")
    last_error: str | None = None
    current = prepared
    max_repairs = max(0, settings.llm.max_repair_retries)
    while attempts <= max_repairs:
        attempts += 1
        started = time.monotonic()
        try:
            response = _raw_chat(current, model, temperature if attempts == 1 else 0.0)
            if request_id:
                _ledger_attempt(request_id, attempts, "response", response, None, time.monotonic() - started)
        except (LLMUnavailable, LLMError) as exc:
            last_error = str(exc)
            if request_id:
                _ledger_attempt(request_id, attempts, "transport_error", None, last_error, time.monotonic() - started)
            result = StructuredResult(None, response, last_error, llm_calls=attempts,
                                      status="unresolved_model_error", request_id=request_id)
            if request_id:
                _ledger_finish(request_id, result, None)
            return result

        obj, error = parse_validated(response.content, model_cls)
        if obj is not None:
            semantic_errors = _semantic_validate(obj, context)
            if not semantic_errors:
                result = StructuredResult(obj, response, llm_calls=attempts,
                                          validation_errors=validation_errors, request_id=request_id)
                if request_id:
                    _ledger_finish(request_id, result, response)
                return result
            last_error = "; ".join(semantic_errors)
        else:
            last_error = error or "schema validation failed"
            validation_errors.append(last_error)
        if attempts > max_repairs:
            break
        logger.warning(f"{model_cls.__name__} validation failed ({last_error}); attempting bounded repair")
        current = list(prepared) + [
            ChatMessage("assistant", response.content[:4000]),
            ChatMessage("user", f"Your previous response failed application validation: {last_error}. "
                        "Return ONLY one JSON object matching the schema already provided. "
                        "Do not include prose, markdown, or a verdict without rationale."),
        ]

    result = StructuredResult(
        None, response, last_error, llm_calls=attempts,
        status="unresolved_semantic" if semantic_errors else "unresolved_parse",
        validation_errors=validation_errors, semantic_errors=semantic_errors,
        request_id=request_id,
    )
    if request_id:
        _ledger_finish(request_id, result, response)
    return result
