"""Detect systematic gaps between LLM triage priority and corpus expectations."""

from __future__ import annotations

from collections import Counter

from sqlalchemy.orm import Session

from trident.models import Finding
from trident.calibration.corpus.db import get_db

_TIER_INT = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}
_INT_TIER = {v: k for k, v in _TIER_INT.items()}
_MIN_GROUP = 3
_DIRECTION_THRESHOLD = 0.70


def detect_gaps(job_id: str, db_session: Session) -> list[dict]:
    """Return list of CWE groups with systematic LLM triage gaps vs corpus."""
    findings = (
        db_session.query(Finding)
        .filter(
            Finding.job_id == job_id,
            Finding.status == "confirmed",
            Finding.priority.isnot(None),
            Finding.cwe.isnot(None),
        )
        .all()
    )

    # Group by CWE
    groups: dict[str, list[Finding]] = {}
    for f in findings:
        groups.setdefault(f.cwe, []).append(f)

    corpus_conn = get_db()
    results = []

    try:
        for cwe, group in groups.items():
            if len(group) < _MIN_GROUP:
                continue

            dist = Counter(f.priority for f in group)
            modal_priority = dist.most_common(1)[0][0]
            llm_tier_int = _TIER_INT.get(modal_priority)
            if llm_tier_int is None:
                continue

            row = corpus_conn.execute(
                "SELECT * FROM cwe_profiles WHERE cwe=?", (cwe,)
            ).fetchone()

            if row is None:
                continue

            expected_tier = row["expected_tier"]
            expected_int = _TIER_INT.get(expected_tier)
            if expected_int is None:
                continue

            gap = llm_tier_int - expected_int  # negative = under-escalated, positive = over-escalated
            # Wait — P0=0, P4=4; LLM said P0(0), expected P2(2) → gap = 0-2 = -2 (under int)
            # "over-escalated" = LLM said higher severity (lower int) than expected
            # gap positive means LLM said P4(4) where expected P2(2) → under-escalated
            # Spec says: gap positive = LLM over-escalated (said P0, expected P2 → gap=2)
            # So gap = expected_int - llm_tier_int to match spec semantics
            gap = expected_int - llm_tier_int

            if abs(gap) < 1:
                continue

            direction = "over" if gap > 0 else "under"

            # Check if ≥70% of findings have the same direction
            over_count = sum(
                1 for f in group
                if _TIER_INT.get(f.priority, 4) < expected_int
            )
            under_count = sum(
                1 for f in group
                if _TIER_INT.get(f.priority, 4) > expected_int
            )
            total = len(group)
            dominant_frac = max(over_count, under_count) / total
            systematic = dominant_frac >= _DIRECTION_THRESHOLD

            results.append({
                "cwe": cwe,
                "finding_count": total,
                "llm_modal_tier": modal_priority,
                "expected_tier": expected_tier,
                "gap": gap,
                "direction": direction,
                "systematic": systematic,
                "llm_dist": dict(dist),
                "corpus_evidence": {
                    "cve_count": row["cve_count"],
                    "median_cvss": row["median_cvss"],
                    "mean_epss": row["mean_epss"],
                    "kev_rate": row["kev_rate"],
                    "exploit_rate": row["exploit_rate"],
                },
            })
    finally:
        corpus_conn.close()

    return results
