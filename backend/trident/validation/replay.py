"""Frozen scanner-corpus and model-decision replay helpers.

The corpus is a signed-by-hash, scanner-only envelope. Replaying it never
launches scanner subprocesses; it restores the scanner evidence and, when a
decision ledger is supplied, restores accepted typed decisions exactly.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from trident.clock import utcnow
from trident.models import Finding, Job, LLMRequest, LLMRequestAttempt


def _finding_record(f: Finding) -> dict[str, Any]:
    return {
        "id": f.id, "hash": f.hash, "correlation_key": f.correlation_key,
        "tool": f.tool, "rule_id": f.rule_id, "severity": f.severity,
        "scanner_severity": f.scanner_severity or f.severity,
        "title": f.title, "description": f.description, "file": f.file,
        "line_start": f.line_start, "line_end": f.line_end, "snippet": f.snippet,
        "cwe": f.cwe, "owasp": f.owasp, "recommendation": f.recommendation,
        "raw_outputs": f.raw_outputs or {},
    }


def export_corpus(db, job_id: str, output: str | Path) -> dict:
    job = db.get(Job, job_id)
    if job is None:
        raise ValueError(f"job not found: {job_id}")
    records = [_finding_record(f) for f in db.query(Finding).filter(Finding.job_id == job_id).all()]
    payload = {
        "format": "trident-frozen-scanner-corpus",
        "schema_version": "1",
        "created_at": utcnow().isoformat() + "Z",
        "source": {"job_id": job_id, "target": job.target_name, "commit_hash": job.commit_hash,
                   "source_ref": job.source_ref, "record_count": len(records)},
        "scanner_subprocesses": "not launched during replay",
        "records": records,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    payload["corpus_sha256"] = hashlib.sha256(raw.encode()).hexdigest()
    Path(output).write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return payload


def load_corpus(path: str | Path) -> dict:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if payload.get("format") != "trident-frozen-scanner-corpus":
        raise ValueError("unsupported frozen corpus format")
    if not isinstance(payload.get("records"), list):
        raise ValueError("frozen corpus records must be a list")
    return payload


def restore_corpus(db, path: str | Path, *, target_name: str | None = None) -> Job:
    payload = load_corpus(path)
    source = payload.get("source") or {}
    job = Job(target_name=target_name or source.get("target") or "frozen corpus",
              source_type="frozen_corpus", source_ref=str(Path(path).resolve()),
              workspace_path="", status="complete", commit_hash=source.get("commit_hash"),
              profile={"replay_mode": "scanner_corpus", "scanner_subprocesses": False,
                       "corpus_sha256": payload.get("corpus_sha256")})
    db.add(job)
    db.flush()
    for record in payload["records"]:
        values = {k: record.get(k) for k in (
            "id", "hash", "correlation_key", "tool", "rule_id", "severity",
            "scanner_severity", "title", "description", "file", "line_start", "line_end",
            "snippet", "cwe", "owasp", "recommendation", "raw_outputs",
        )}
        values.update(job_id=job.id, status="raw", confidence=0.5,
                      remediation=None, narrative=None, exploit_scenario=None,
                      attack_paths=[], triage={}, iteration=0)
        db.add(Finding(**values))
    db.commit()
    db.refresh(job)
    return job


def replay_decisions(path: str | Path) -> dict:
    """Validate a decision replay artifact without invoking a model."""
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if payload.get("format") not in {"trident-llm-decision-replay", "trident-frozen-scanner-corpus"}:
        raise ValueError("unsupported replay artifact format")
    decisions = payload.get("decisions") or []
    accepted = [d for d in decisions if d.get("status") == "completed" and d.get("accepted_decision") is not None]
    unresolved = [d for d in decisions if d not in accepted]
    return {"format": payload.get("format"), "total": len(decisions),
            "accepted": len(accepted), "unresolved": len(unresolved),
            "scanner_subprocesses": False}


def export_decisions(db, run_id: str, output: str | Path) -> dict:
    rows = db.query(LLMRequest).filter(LLMRequest.run_id == run_id).all()
    close_ledger = None
    if not rows and os.environ.get("TRIDENT_LLM_LEDGER_PATH"):
        # Production scans use a separate WAL-enabled ledger so model audit
        # writes cannot contend with the scan/job database.  Export remains
        # convenient from the normal CLI database session by falling back to
        # that configured ledger when the run is not present in the primary DB.
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from trident.models import Base

        ledger_engine = create_engine(
            f"sqlite:///{os.environ['TRIDENT_LLM_LEDGER_PATH']}",
            connect_args={"check_same_thread": False, "timeout": 30},
        )
        Base.metadata.create_all(ledger_engine)
        ledger_session = sessionmaker(bind=ledger_engine, autoflush=False,
                                      expire_on_commit=False)()
        rows = ledger_session.query(LLMRequest).filter(LLMRequest.run_id == run_id).all()
        close_ledger = ledger_session
    decisions = []
    for row in rows:
        attempts = db.query(LLMRequestAttempt).filter(
            LLMRequestAttempt.request_id == row.request_id
        ).order_by(LLMRequestAttempt.attempt.asc()).all()
        decisions.append({
            "request_id": row.request_id, "run_id": row.run_id, "finding_id": row.finding_id,
            "task_type": row.task_type, "role": row.council_role, "iteration": row.iteration,
            "model": row.model, "endpoint_mode": row.endpoint_mode,
            "request_hash": row.request_hash, "input_hash": row.input_hash,
            "status": row.status, "validation_errors": row.validation_errors or [],
            "semantic_validation_errors": row.semantic_validation_errors or [],
            "retry_count": row.retry_count, "accepted_decision": row.final_accepted_decision,
            "attempts": [{"attempt": a.attempt, "transport_status": a.transport_status,
                          "raw_response": a.raw_response, "error": a.error,
                          "latency_ms": a.latency_ms} for a in attempts],
        })
    payload = {"format": "trident-llm-decision-replay", "schema_version": "1",
               "run_id": run_id, "decisions": decisions}
    Path(output).write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    if close_ledger is not None:
        close_ledger.close()
    return payload
