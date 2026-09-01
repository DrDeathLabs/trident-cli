"""Workspace retention — sweeps on-disk source copies for old terminal jobs.

Findings, verdicts, and history all live in Postgres; only the *extracted
source* under `/workspaces/<job_id>` is disk, and nothing ever cleaned it up
except an explicit job delete. On a long-running instance that's an unbounded
disk leak. This does a cheap, self-scheduling sweep instead of adding a
standing Celery-beat service: each ingest checks a marker file's mtime and
only actually sweeps every `_CHECK_INTERVAL_S`.
"""

from __future__ import annotations

import time
from datetime import timedelta
from pathlib import Path

from loguru import logger
from sqlalchemy.orm import Session

from trident.config import settings
from trident.clock import utcfromtimestamp, utcnow
from trident.models import Job, JobStatus

_TERMINAL = {JobStatus.complete.value, JobStatus.failed.value, JobStatus.cancelled.value}
_CHECK_INTERVAL_S = 6 * 3600  # don't re-sweep more often than this
_SKIP_NAMES = {"uploads", ".last_cleanup"}


def _should_run(marker: Path) -> bool:
    try:
        return not marker.exists() or (time.time() - marker.stat().st_mtime) >= _CHECK_INTERVAL_S
    except OSError:
        return True


def maybe_cleanup_workspaces(db: Session) -> None:
    """Cheap, self-throttling entry point — call this from ingest, not a cron."""
    if settings.workspace_retention_days <= 0:
        return
    marker = settings.workspaces_dir / ".last_cleanup"
    if not _should_run(marker):
        return
    try:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.touch()
    except OSError:
        return  # can't write the marker; skip this round rather than sweep every call
    try:
        cleanup_stale_workspaces(db)
    except Exception:
        logger.exception("workspace cleanup failed")


def cleanup_stale_workspaces(db: Session) -> int:
    """Remove on-disk workspaces for terminal jobs past retention, plus orphan
    directories with no matching Job row. Returns the count removed."""
    ws_root = settings.workspaces_dir
    if not ws_root.is_dir():
        return 0
    cutoff = utcnow() - timedelta(days=settings.workspace_retention_days)
    removed = 0

    for entry in ws_root.iterdir():
        if not entry.is_dir() or entry.name in _SKIP_NAMES:
            continue
        job = db.get(Job, entry.name)
        if job is not None:
            if job.status not in _TERMINAL:
                continue  # never touch an active job's workspace
            ref_time = job.completed_at or job.created_at
            if ref_time and ref_time > cutoff:
                continue
        else:
            # Orphan directory (crash before a Job row existed, or the row was
            # deleted some other way) — fall back to filesystem mtime.
            try:
                mtime = utcfromtimestamp(entry.stat().st_mtime)
            except OSError:
                continue
            if mtime > cutoff:
                continue
        _rmtree_safe(entry)
        removed += 1
        if job is not None:
            job.workspace_path = ""

    # Stray uploaded zips that never got extracted+removed (e.g. a crash
    # between save and extract) — same retention window.
    uploads_dir = ws_root / "uploads"
    if uploads_dir.is_dir():
        for f in uploads_dir.iterdir():
            if not f.is_file():
                continue
            try:
                mtime = utcfromtimestamp(f.stat().st_mtime)
            except OSError:
                continue
            if mtime <= cutoff:
                try:
                    f.unlink()
                except OSError:
                    pass

    if removed:
        db.commit()
        logger.info(f"workspace cleanup: removed {removed} stale workspace(s) "
                    f"older than {settings.workspace_retention_days}d")
    return removed


def _rmtree_safe(path: Path) -> None:
    import shutil
    shutil.rmtree(path, ignore_errors=True)
