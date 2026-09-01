"""Convergence detection for the iterative refinement loop.

The loop stops when there is no unresolved work left, or a hard cap is hit —
NOT when disagreement is low. Disagreement (entropy) is a *reported* metric:
high disagreement is a reason to keep going, not to stop.

Unresolved = findings still needing attention (raw / disputed / unreviewed).
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass

from sqlalchemy.orm import Session

from trident.events.publisher import EventType, publish_event
from trident.models import Finding, FindingVerdict

_UNRESOLVED = ("raw", "disputed", "unreviewed")


@dataclass
class ConvergenceResult:
    converged: bool
    reason: str
    new_confirmed: int
    disputed: int
    unresolved: int
    entropy: float


def count_confirmed(db: Session, job_id: str) -> int:
    return db.query(Finding).filter(
        Finding.job_id == job_id, Finding.status == "confirmed"
    ).count()


def get_iteration_recall(db: Session, job_id: str) -> dict[int, int]:
    """Confirmed findings bucketed by the iteration they were created — for the eval curve."""
    rows = db.query(Finding).filter(
        Finding.job_id == job_id, Finding.status == "confirmed"
    ).all()
    out: dict[int, int] = {}
    for f in rows:
        out[f.iteration] = out.get(f.iteration, 0) + 1
    return out


def compute_entropy(db: Session, job_id: str, iteration: int) -> float:
    """Mean normalized entropy of expert verdicts over findings reviewed this iteration.

    0 = experts agree; 1 = maximally split across confirmed/refuted/disputed.
    Computed from FindingVerdict rows (parse errors excluded) — the *actual*
    disagreement, not a proxy over finding statuses.
    """
    rows = db.query(FindingVerdict).filter(
        FindingVerdict.job_id == job_id,
        FindingVerdict.iteration == iteration,
        FindingVerdict.expert != "judge",
        FindingVerdict.verdict != "parse_error",
    ).all()
    by_finding: dict[str, list[str]] = {}
    for r in rows:
        by_finding.setdefault(r.finding_id, []).append(r.verdict)

    entropies: list[float] = []
    for labels in by_finding.values():
        if len(labels) <= 1:
            entropies.append(0.0)
            continue
        counts = Counter(labels)
        total = len(labels)
        ent = -sum((n / total) * math.log(n / total, 3) for n in counts.values())
        entropies.append(ent)
    return round(sum(entropies) / len(entropies), 4) if entropies else 0.0


def evaluate_convergence(
    db: Session, job_id: str, iteration: int, max_iterations: int,
    min_new_findings: int, prev_disputed: int, budget_exhausted: bool = False,
) -> ConvergenceResult:
    """Decide whether to stop, and always publish the metrics."""
    new_confirmed = get_iteration_recall(db, job_id).get(iteration, 0)
    disputed = db.query(Finding).filter(
        Finding.job_id == job_id, Finding.status == "disputed"
    ).count()
    unresolved = db.query(Finding).filter(
        Finding.job_id == job_id, Finding.status.in_(_UNRESOLVED)
    ).count()
    entropy = compute_entropy(db, job_id, iteration)

    if budget_exhausted:
        converged, reason = True, "LLM budget exhausted"
    elif unresolved == 0:
        converged, reason = True, "all findings resolved (no raw/disputed/unreviewed remain)"
    elif iteration >= max_iterations:
        converged, reason = True, f"max_iterations ({max_iterations}) reached"
    elif iteration > 0 and new_confirmed < min_new_findings and disputed >= prev_disputed:
        converged, reason = True, (
            f"diminishing returns ({new_confirmed} new confirmed, "
            f"disputed not shrinking: {prev_disputed}->{disputed})"
        )
    else:
        converged, reason = False, "continuing"

    # Always emit — the UI gauge must fill on the terminating iteration too.
    publish_event(db, job_id, EventType.CONVERGENCE_CHECK, {
        "iteration": iteration, "converged": converged, "reason": reason,
        "new_confirmed": new_confirmed, "disputed": disputed,
        "unresolved": unresolved, "entropy": entropy,
    })
    return ConvergenceResult(converged, reason, new_confirmed, disputed, unresolved, entropy)
