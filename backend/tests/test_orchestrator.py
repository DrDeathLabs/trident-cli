"""Whole-loop integration test for run_scan (mock LLM, no real scanners).

This is the safety net for the structural refactor: it exercises the full
orchestrator pipeline (tools phase → correlate → review → convergence → complete)
end to end. Tools are disabled via an empty profile so no scanner subprocesses
run; raw findings are seeded to stand in for the tool phase.
"""

from __future__ import annotations

from trident.models import Finding, Job, JobEvent
from trident.orchestrator import run_scan
from tests.conftest import make_finding


def _make_job(db, workspace, **profile):
    prof = {"tools": [], "max_iterations": 1}
    prof.update(profile)
    j = Job(id="scanjob", target_name="t", source_type="demo", source_ref="",
            workspace_path=workspace, profile=prof, status="queued")
    db.add(j)
    db.commit()
    return j


def test_run_scan_completes_and_confirms(db, workspace):
    job = _make_job(db, workspace)
    # Stand in for the (disabled) tool phase.
    make_finding(db, job_id="scanjob", id="f1", file="app/main.py", cwe="CWE-89",
                 title="SQL injection", description="sqli", status="raw")
    make_finding(db, job_id="scanjob", id="f2", file="app/main.py", line_start=20,
                 cwe="CWE-78", title="Command injection", description="cmd", status="raw")

    run_scan(job, db)

    assert job.status == "complete"
    confirmed = db.query(Finding).filter(
        Finding.job_id == "scanjob", Finding.status == "confirmed"
    ).count()
    assert confirmed >= 1, "the council should confirm the seeded findings"
    assert db.query(JobEvent).filter(
        JobEvent.job_id == "scanjob", JobEvent.type == "job.complete"
    ).count() == 1


def test_run_scan_no_findings_still_completes(db, workspace):
    """An empty target must still converge and complete cleanly."""
    job = _make_job(db, workspace)
    run_scan(job, db)
    assert job.status == "complete"
