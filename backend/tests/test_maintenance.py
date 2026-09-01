"""Workspace retention — cleans up on-disk source for old terminal jobs."""

from __future__ import annotations

import os
from datetime import timedelta

from trident.config import settings
from trident.maintenance import cleanup_stale_workspaces, maybe_cleanup_workspaces
from trident.clock import utcnow
from trident.models import Job


def _mkws(root, name, mtime_days_ago=None):
    d = os.path.join(root, name)
    os.makedirs(d, exist_ok=True)
    if mtime_days_ago is not None:
        t = (utcnow() - timedelta(days=mtime_days_ago)).timestamp()
        os.utime(d, (t, t))
    return d


def _mkjob(db, id_, status, completed_at=None, workspace_path=""):
    j = Job(id=id_, target_name="t", source_type="demo", source_ref="",
            workspace_path=workspace_path, status=status, completed_at=completed_at)
    db.add(j)
    db.commit()
    return j


def test_terminal_job_past_retention_is_removed(db, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "workspaces_dir", tmp_path)
    monkeypatch.setattr(settings, "workspace_retention_days", 14)
    ws = _mkws(tmp_path, "old1")
    _mkjob(db, "old1", "complete", completed_at=utcnow() - timedelta(days=30), workspace_path=ws)

    removed = cleanup_stale_workspaces(db)

    assert removed == 1
    assert not os.path.exists(ws)
    assert db.get(Job, "old1").workspace_path == ""


def test_recent_terminal_job_is_kept(db, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "workspaces_dir", tmp_path)
    monkeypatch.setattr(settings, "workspace_retention_days", 14)
    ws = _mkws(tmp_path, "recent1")
    _mkjob(db, "recent1", "complete", completed_at=utcnow() - timedelta(days=1), workspace_path=ws)

    removed = cleanup_stale_workspaces(db)

    assert removed == 0
    assert os.path.exists(ws)


def test_active_job_is_never_touched_even_if_old(db, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "workspaces_dir", tmp_path)
    monkeypatch.setattr(settings, "workspace_retention_days", 14)
    ws = _mkws(tmp_path, "running1")
    _mkjob(db, "running1", "scanning", completed_at=None, workspace_path=ws)
    # created_at defaults to now, so even the created_at fallback wouldn't trip this

    removed = cleanup_stale_workspaces(db)

    assert removed == 0
    assert os.path.exists(ws)


def test_orphan_directory_swept_by_mtime(db, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "workspaces_dir", tmp_path)
    monkeypatch.setattr(settings, "workspace_retention_days", 14)
    ws = _mkws(tmp_path, "no-such-job", mtime_days_ago=30)

    removed = cleanup_stale_workspaces(db)

    assert removed == 1
    assert not os.path.exists(ws)


def test_recent_orphan_directory_kept(db, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "workspaces_dir", tmp_path)
    monkeypatch.setattr(settings, "workspace_retention_days", 14)
    ws = _mkws(tmp_path, "no-such-job-2", mtime_days_ago=1)

    removed = cleanup_stale_workspaces(db)

    assert removed == 0
    assert os.path.exists(ws)


def test_stray_upload_zip_swept(db, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "workspaces_dir", tmp_path)
    monkeypatch.setattr(settings, "workspace_retention_days", 14)
    uploads = tmp_path / "uploads"
    uploads.mkdir()
    stale_zip = uploads / "stale.zip"
    stale_zip.write_bytes(b"x")
    old_t = (utcnow() - timedelta(days=30)).timestamp()
    os.utime(stale_zip, (old_t, old_t))
    fresh_zip = uploads / "fresh.zip"
    fresh_zip.write_bytes(b"x")

    cleanup_stale_workspaces(db)

    assert not stale_zip.exists()
    assert fresh_zip.exists()


def test_retention_disabled_when_zero(db, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "workspaces_dir", tmp_path)
    monkeypatch.setattr(settings, "workspace_retention_days", 0)
    ws = _mkws(tmp_path, "old-but-disabled")
    _mkjob(db, "old-but-disabled", "complete",
           completed_at=utcnow() - timedelta(days=999), workspace_path=ws)

    maybe_cleanup_workspaces(db)  # the throttled entry point respects the 0 = off switch

    assert os.path.exists(ws)


def test_maybe_cleanup_throttles_repeat_calls(db, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "workspaces_dir", tmp_path)
    monkeypatch.setattr(settings, "workspace_retention_days", 14)
    ws1 = _mkws(tmp_path, "old-a")
    _mkjob(db, "old-a", "complete", completed_at=utcnow() - timedelta(days=30), workspace_path=ws1)
    maybe_cleanup_workspaces(db)
    assert not os.path.exists(ws1)

    # A second job appears right after; the marker file is fresh, so this
    # round must NOT sweep yet even though the new job also qualifies.
    ws2 = _mkws(tmp_path, "old-b")
    _mkjob(db, "old-b", "complete", completed_at=utcnow() - timedelta(days=30), workspace_path=ws2)
    maybe_cleanup_workspaces(db)
    assert os.path.exists(ws2)
