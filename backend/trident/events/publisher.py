"""Event publisher + schemas for the live streaming pipeline.

Docker mode: the worker publishes events to Redis pubsub (channel
job:{id}:events); the backend subscribes and fans out to WebSocket clients.
Desktop mode (`settings.task_backend == "inprocess"`): no Redis at all — an
in-process queue-based bus (`inprocess_bus.py`) does the same fan-out within
one process. Either way, events are also persisted to job_events for replay.
"""

from __future__ import annotations

import json
import os
import threading
from typing import Any

from sqlalchemy.orm import Session

from trident.config import settings
from trident.clock import utcnow
from trident.models import JobEvent

# SQLite never populates JobEvent.seq (no CREATE SEQUENCE equivalent — see
# models.py). Without it, the WS reconnect protocol's `since_seq` filter
# degrades to "replay the entire job history on every reconnect", which for
# a long-running job floods the client with thousands of events per retry.
# This in-memory counter fills the same monotonic role for desktop's
# single-process in-process mode; Postgres/Celery mode is unaffected since
# evt.seq is already populated by the DB sequence there.
_seq_lock = threading.Lock()
_seq_counters: dict[str, int] = {}


def _next_inprocess_seq(job_id: str) -> int:
    with _seq_lock:
        n = _seq_counters.get(job_id, 0) + 1
        _seq_counters[job_id] = n
        return n

# Redis is only constructed in Celery/Docker mode — desktop mode never touches
# it (matters for the eventual PyInstaller freeze: no need to bundle redis).
_redis = None
if settings.task_backend == "celery":
    import redis
    # Bounded timeouts so a slow/dead Redis can never stall a scan on publish.
    _redis = redis.Redis.from_url(
        settings.redis.url, decode_responses=True,
        socket_connect_timeout=1, socket_timeout=1,
    )

# Tests set this to avoid any external Redis dependency (events still persist).
_EVENTS_DISABLED = os.environ.get("TRIDENT_DISABLE_EVENTS") == "1"


def channel_for(job_id: str) -> str:
    return f"job:{job_id}:events"


def publish_event(
    db: Session,
    job_id: str,
    event_type: str,
    payload: dict[str, Any] | None = None,
    *,
    persist: bool = True,
) -> dict[str, Any]:
    """Publish an event (Redis pubsub or the in-process bus) + persist to DB
    for replay."""
    payload = payload or {}
    payload["type"] = event_type
    payload["job_id"] = job_id
    payload["ts"] = utcnow().isoformat() + "Z"

    if persist:
        evt = JobEvent(job_id=job_id, type=event_type, payload=payload)
        db.add(evt)
        db.flush()
        if evt.seq is None:
            evt.seq = _next_inprocess_seq(job_id)
            db.flush()
        payload["event_id"] = evt.id
        payload["seq"] = evt.seq

    if not _EVENTS_DISABLED:
        try:
            if settings.task_backend == "celery":
                _redis.publish(channel_for(job_id), json.dumps(payload))
            else:
                from trident.events.inprocess_bus import publish as publish_inprocess
                publish_inprocess(job_id, payload)
        except Exception:
            # Fan-out failure must not crash a scan; event still persisted.
            pass
    return payload


def get_events(db: Session, job_id: str, since_seq: int | None = None, limit: int = 500) -> list[dict]:
    """Return persisted events in monotonic order. Paginates by `seq` (Postgres);
    falls back to created_at when seq is unavailable (e.g. SQLite in tests)."""
    q = db.query(JobEvent).filter(JobEvent.job_id == job_id)
    if since_seq is not None:
        q = q.filter(JobEvent.seq > since_seq)
    q = q.order_by(JobEvent.seq.asc().nulls_last(), JobEvent.created_at.asc())
    rows = q.limit(limit).all()
    out = []
    for r in rows:
        p = dict(r.payload or {})
        p["type"] = r.type
        p["job_id"] = job_id
        p["event_id"] = r.id
        p["seq"] = r.seq
        p["ts"] = r.created_at.isoformat() + "Z" if r.created_at else None
        out.append(p)
    return out


# Event type constants (taxonomy referenced by the UI)
class EventType:
    JOB_STARTED = "job.started"
    JOB_INGEST_PROGRESS = "job.ingest.progress"
    JOB_INGEST_COMPLETE = "job.ingest.complete"
    JOB_ITERATION_START = "job.iteration.start"
    JOB_ITERATION_COMPLETE = "job.iteration.complete"
    JOB_COMPLETE = "job.complete"
    JOB_FAILED = "job.failed"

    SCAN_TOOLS_START = "scan.tools.start"
    SCAN_CORRELATE_START = "scan.correlate.start"
    SCAN_EXPERTS_START = "scan.experts.start"
    SCAN_DEBATE_START = "scan.debate.start"
    SCAN_REDTEAM_START = "scan.redteam.start"

    CORRELATE_COMPLETE = "correlate.complete"

    TOOL_STARTED = "tool.started"
    TOOL_STDOUT = "tool.stdout"
    TOOL_FINDING = "tool.finding"
    TOOL_COMPLETE = "tool.complete"
    TOOL_ERROR = "tool.error"

    FINDING_RAW = "finding.raw"
    FINDING_CONFIRMED = "finding.confirmed"
    FINDING_REFUTED = "finding.refuted"
    FINDING_NOVEL = "finding.novel"
    FINDING_DUPLICATE = "finding.duplicate"
    FINDING_PARSE_ERROR = "finding.parse_error"

    DEBATE_MESSAGE = "debate.message"
    DEBATE_CROSS_EXAM = "debate.cross_exam"
    JUDGE_VERDICT = "judge.verdict"
    REDTEAM_CHAIN = "redteam.chain"

    CONVERGENCE_CHECK = "convergence.check"
    BUDGET_EXHAUSTED = "budget.exhausted"

    AGENT_ENABLED = "agent.enabled"
    AGENT_STEP = "agent.step"

    TRIAGE_START = "triage.start"
    TRIAGE_COMPLETE = "triage.complete"
