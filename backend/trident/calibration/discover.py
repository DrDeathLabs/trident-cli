"""Shape-only calibration detector — Phase 1.

Reads historical Finding data across all jobs, groups by CWE and rule_id,
and flags classes with a barbell P0+P4 distribution (the signature of LLM
over-escalation). No LLM calls; purely descriptive.

Minimum thresholds are intentionally conservative given the current eval fleet
(VulnBank + PyGoat + Juice Shop). `sample_adequate` and `cross_target_ok` are
surfaced per-candidate so the UI can show warnings rather than hide candidates.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from sqlalchemy.orm import Session

from trident.models import Finding, TriageOverride

_MIN_SAMPLE = 10   # flag honestly when below this
_MIN_TARGETS = 2   # must appear in ≥2 distinct jobs to be considered cross-target
_BARBELL_THRESHOLD = 0.50  # (P0+P4)/total must exceed this to be flagged

_TIERS = ["P0", "P1", "P2", "P3", "P4"]


@dataclass
class GuardCandidate:
    group_key: str           # e.g. "cwe:CWE-89" or "rule:sql-injection"
    group_type: str          # "cwe" | "rule_id"
    group_value: str
    total: int
    priority_dist: dict[str, int]
    barbell_pct: float       # (P0+P4) / total
    p0_pct: float
    p4_pct: float
    target_count: int        # distinct job_ids
    # Override signal from Phase 0 data (None = no overrides recorded yet)
    override_count: int
    downgrade_pct: float | None   # fraction of overrides that lowered priority
    # Validity flags
    sample_adequate: bool    # total >= _MIN_SAMPLE
    cross_target_ok: bool    # target_count >= _MIN_TARGETS
    # Corpus augmentation (Phase 2+)
    corpus_expected_tier: str | None = None
    corpus_evidence: dict | None = None


def detect_candidates(
    db: Session,
    min_sample: int = _MIN_SAMPLE,
    min_targets: int = _MIN_TARGETS,
    barbell_threshold: float = _BARBELL_THRESHOLD,
) -> list[GuardCandidate]:
    """Return finding classes flagged as potential over-escalation candidates."""
    findings = (
        db.query(Finding)
        .filter(Finding.status == "confirmed", Finding.priority.isnot(None))
        .all()
    )

    # Build override lookup: finding_id → TriageOverride
    override_rows = db.query(TriageOverride).all()
    overrides: dict[str, TriageOverride] = {o.finding_id: o for o in override_rows}

    # Collect into groups keyed by (group_type, value)
    groups: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    for f in findings:
        if f.cwe:
            groups[("cwe", f.cwe)].append(f)
        rule = (f.triage or {}).get("rule_id") if isinstance(f.triage, dict) else None
        if rule:
            groups[("rule_id", rule)].append(f)

    candidates: list[GuardCandidate] = []
    for (gtype, gvalue), group in groups.items():
        dist: dict[str, int] = defaultdict(int)
        jobs: set[str] = set()
        for f in group:
            dist[f.priority] += 1
            jobs.add(f.job_id)

        total = len(group)
        p0 = dist.get("P0", 0)
        p4 = dist.get("P4", 0)
        barbell = (p0 + p4) / total

        if barbell < barbell_threshold:
            continue

        # Override signal
        group_overrides = [overrides[f.id] for f in group if f.id in overrides]
        downgrade_pct = None
        if group_overrides:
            # Downgrade: human moved priority to a less-urgent tier (P0→P2: "P2" > "P0" lexically)
            downgrades = sum(
                1 for o in group_overrides
                if o.override_priority > o.original_priority
            )
            downgrade_pct = round(downgrades / len(group_overrides), 3)

        candidates.append(GuardCandidate(
            group_key=f"{gtype}:{gvalue}",
            group_type=gtype,
            group_value=gvalue,
            total=total,
            priority_dist={t: dist.get(t, 0) for t in _TIERS},
            barbell_pct=round(barbell, 3),
            p0_pct=round(p0 / total, 3),
            p4_pct=round(p4 / total, 3),
            target_count=len(jobs),
            override_count=len(group_overrides),
            downgrade_pct=downgrade_pct,
            sample_adequate=total >= min_sample,
            cross_target_ok=len(jobs) >= min_targets,
        ))

    candidates.sort(key=lambda c: (-c.barbell_pct, -c.total))
    return candidates


def detect_candidates_with_corpus(db: Session) -> list[GuardCandidate]:
    """Like detect_candidates but augments each CWE candidate with corpus data."""
    candidates = detect_candidates(db)

    from trident.calibration.corpus.db import get_db
    conn = get_db()
    try:
        for c in candidates:
            if c.group_type != "cwe":
                continue
            row = conn.execute(
                "SELECT * FROM cwe_profiles WHERE cwe=?", (c.group_value,)
            ).fetchone()
            if row is None:
                continue
            c.corpus_expected_tier = row["expected_tier"]
            c.corpus_evidence = {
                "cve_count": row["cve_count"],
                "median_cvss": row["median_cvss"],
                "p25_cvss": row["p25_cvss"],
                "p75_cvss": row["p75_cvss"],
                "mean_epss": row["mean_epss"],
                "p90_epss": row["p90_epss"],
                "kev_rate": row["kev_rate"],
                "exploit_rate": row["exploit_rate"],
                "modal_attack_vector": row["modal_attack_vector"],
                "modal_impact": row["modal_impact"],
                "built_at": row["built_at"],
            }
    finally:
        conn.close()

    return candidates
