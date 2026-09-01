"""Task bodies — the actual ingest/scan/triage work, as plain functions.

Kept separate from dispatch mechanism (Celery in `celery_app.py`, in-process
in `runner.py`) so both share this one implementation. Nothing in here is
Celery-specific; each function opens its own DB session and is safe to call
from a worker thread (desktop/in-process mode) or a Celery worker process
(Docker mode) identically.
"""

from __future__ import annotations

from loguru import logger

from trident.db import db_session


def ingest_job_body(job_id: str, source_type: str, source_ref: str, target_name: str,
                    is_scored: bool, target_id: str | None, profile: dict) -> bool:
    """Ingest the source. Returns True if ingest succeeded (caller should then
    dispatch the scan), False if it failed (job already marked failed)."""
    from trident.maintenance import maybe_cleanup_workspaces
    from trident.models import Job, JobStatus
    from trident.ingest.pipeline import ingest
    with db_session() as db:
        job = db.get(Job, job_id)
        if job is None:
            logger.error(f"Job {job_id} not found for ingest")
            return False
        # Cheap, self-throttled sweep of old terminal jobs' workspaces —
        # piggybacks on every ingest instead of running a standing beat
        # service; a no-op most calls (see maintenance.py).
        maybe_cleanup_workspaces(db)
        try:
            job.status = JobStatus.ingesting.value
            db.commit()
            ws, languages, commit_hash = ingest(db, job_id, source_type, source_ref)
            job.workspace_path = ws
            job.languages = languages
            job.commit_hash = commit_hash
            db.commit()
            return True
        except Exception as e:
            logger.exception(f"Ingest failed for job {job_id}")
            job.status = JobStatus.failed.value
            job.error = f"Ingest failed: {e}"
            db.commit()
            return False


def scan_job_body(job_id: str) -> None:
    """Run the full iterative scan for a job."""
    from trident.models import Job
    from trident.orchestrator import run_scan
    with db_session() as db:
        job = db.get(Job, job_id)
        if job is None:
            logger.error(f"Job {job_id} not found for scan")
            return
        run_scan(job, db)
        db.commit()


def triage_job_body(job_id: str) -> None:
    """Prioritize a job's confirmed findings into P0..P4."""
    from trident.triage import run_triage
    with db_session() as db:
        run_triage(db, job_id)


def corpus_refresh_body(sources: list[str] | None = None, force: bool = False) -> dict:
    """Refresh corpus feeds, rebuild profiles, retrain model."""
    from trident.calibration.feeds import refresh_all
    from trident.calibration.corpus.db import get_db, init_schema
    from trident.calibration.corpus.build import build_corpus
    from trident.calibration.model import train
    results = refresh_all(sources=sources, force=force)
    conn = get_db()
    init_schema(conn)
    profile_count = build_corpus(conn)
    model_stats = train(conn)
    conn.close()
    return {"feeds": results, "profile_count": profile_count, "model": model_stats}
