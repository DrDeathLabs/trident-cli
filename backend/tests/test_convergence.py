"""WS5: convergence based on unresolved work; entropy is a metric, never a stop condition."""

from __future__ import annotations

from trident.convergence import compute_entropy, evaluate_convergence
from trident.models import FindingVerdict
from tests.conftest import make_finding


def test_stops_when_no_unresolved_work(db, job):
    make_finding(db, status="confirmed")
    make_finding(db, status="false_positive")
    res = evaluate_convergence(db, "job1", iteration=0, max_iterations=3,
                               min_new_findings=2, prev_disputed=0)
    assert res.converged is True
    assert "resolved" in res.reason


def test_keeps_going_while_raw_remain(db, job):
    make_finding(db, status="raw")
    res = evaluate_convergence(db, "job1", iteration=0, max_iterations=3,
                               min_new_findings=2, prev_disputed=0)
    assert res.converged is False


def test_high_disagreement_does_not_stop(db, job):
    # A pile of disputed findings (max disagreement) must NOT trigger convergence
    # on iteration 0 — the old entropy stop-condition bug.
    for _ in range(5):
        make_finding(db, status="disputed")
    res = evaluate_convergence(db, "job1", iteration=0, max_iterations=3,
                               min_new_findings=2, prev_disputed=0)
    assert res.converged is False


def test_budget_exhausted_stops(db, job):
    make_finding(db, status="raw")
    res = evaluate_convergence(db, "job1", iteration=0, max_iterations=3,
                               min_new_findings=2, prev_disputed=0, budget_exhausted=True)
    assert res.converged is True
    assert "budget" in res.reason


def test_entropy_metric_reflects_disagreement(db, job):
    f = make_finding(db, status="disputed")
    for expert, verdict in [("injection", "confirmed"), ("auth", "refuted")]:
        db.add(FindingVerdict(job_id="job1", finding_id=f.id, expert=expert,
                              verdict=verdict, confidence=0.7, iteration=0))
    db.commit()
    ent = compute_entropy(db, "job1", 0)
    assert ent > 0.5  # split verdicts -> high entropy


def test_entropy_zero_on_agreement(db, job):
    f = make_finding(db, status="confirmed")
    for expert in ("injection", "auth"):
        db.add(FindingVerdict(job_id="job1", finding_id=f.id, expert=expert,
                              verdict="confirmed", confidence=0.9, iteration=0))
    db.commit()
    assert compute_entropy(db, "job1", 0) == 0.0
