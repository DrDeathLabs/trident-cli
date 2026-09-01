"""Cross-tool correlation & dedupe.

Runs after the deterministic tools and before expert review. Two tools flagging
the same vulnerability (same file, same CWE, adjacent lines) currently produce
two independent Finding rows that get debated twice and both counted — inflating
cost and deflating precision. This collapses each cluster to one *canonical*
finding; the rest are marked `duplicate` and point at it via `canonical_id`.

Corroboration is signal: a cluster backed by two independent tools is more
likely real, so the canonical's confidence is nudged up.

Deliberately embedding-free — clustering is deterministic (file + normalized CWE
+ line proximity), so it adds no LLM cost to the scan.
"""

from __future__ import annotations

from loguru import logger
from sqlalchemy.orm import Session

from trident.events.publisher import EventType, publish_event
from trident.models import (
    Finding, SEVERITY_RANK, _norm_cwe, _norm_path, correlation_key,
)

LINE_WINDOW = 3  # lines of slack when deciding two findings are "the same place"

# Substrings identifying a dependency manifest/lockfile.
_MANIFEST_HINTS = (
    "requirements", "package.json", "package-lock", "yarn.lock", "pnpm-lock",
    "go.mod", "go.sum", "gemfile", "pipfile", "poetry.lock", "pom.xml",
    "build.gradle", "composer.lock", "cargo.lock",
)


def _dep_package(f: Finding) -> str:
    """Extract the vulnerable package name from a dependency finding's raw output."""
    raw = (f.raw_outputs or {}).get("raw") or {}
    for k in ("PkgName", "pkgName", "PackageName", "package", "name"):
        if raw.get(k):
            return str(raw[k]).strip().lower()
    art = raw.get("artifact") or {}  # grype shape
    if isinstance(art, dict) and art.get("name"):
        return str(art["name"]).strip().lower()
    return ""


def _is_dep_finding(f: Finding) -> bool:
    """A vulnerable-dependency finding (as opposed to a code/config finding)."""
    fl = (f.file or "").lower()
    if any(h in fl for h in _MANIFEST_HINTS):
        return True
    return bool(_dep_package(f))


def _collapse_dependencies(db: Session, raw: list[Finding]) -> tuple[list[Finding], int, int]:
    """Collapse dependency CVEs to one canonical per (file, package).

    A single vulnerable pin (e.g. requests 2.2.1) yields dozens of individual CVE
    findings; deliberating each with the full council is wasteful and drowns the
    precision signal. One canonical per package carries the count forward; the
    rest are marked `duplicate`.
    Returns (remaining_non_dep_findings, canonicals_made, duplicates_made).
    """
    dep_groups: dict[tuple[str, str], list[Finding]] = {}
    rest: list[Finding] = []
    for f in raw:
        pkg = _dep_package(f)
        if _is_dep_finding(f) and pkg:
            dep_groups.setdefault((_norm_path(f.file), pkg), []).append(f)
        else:
            rest.append(f)

    canon_made = 0
    dupes = 0
    for (path, pkg), members in dep_groups.items():
        canonical = min(members, key=_canonical_rank)
        cve_ids = sorted({m.rule_id for m in members if m.rule_id})
        version = ((canonical.raw_outputs or {}).get("raw") or {}).get("InstalledVersion", "")
        n = len(members)
        canonical.title = f"Vulnerable dependency: {pkg}" + (f" {version}" if version else "")
        canonical.description = (
            f"The dependency '{pkg}'{(' ' + version) if version else ''} has {n} known "
            f"vulnerability advisory(ies): {', '.join(cve_ids[:12])}"
            f"{' …' if len(cve_ids) > 12 else ''}."
        )
        canonical.correlation_key = correlation_key(canonical.file, 0, f"dep:{pkg}", pkg)
        canonical.corroborating_tools = sorted({m.tool for m in members})
        canon_made += 1
        for m in members:
            if m.id == canonical.id:
                continue
            m.status = "duplicate"
            m.canonical_id = canonical.id
            m.correlation_key = canonical.correlation_key
            dupes += 1
            publish_event(db, m.job_id, EventType.FINDING_DUPLICATE, {
                "finding_id": m.id, "canonical_id": canonical.id,
            })
    return rest, canon_made, dupes


def _bucket_key(f: Finding) -> tuple[str, str]:
    """Coarse cluster bucket: same file + same normalized CWE (or title fallback)."""
    cwe = _norm_cwe(f.cwe) or (f.title or "").strip().lower()[:40]
    return (_norm_path(f.file), cwe)


def _canonical_rank(f: Finding) -> tuple:
    """Sort key to choose the canonical finding of a cluster (best first).

    Prefer more severe, then higher confidence, then a deterministic tool over an
    expert-proposed one, then the earliest line for stability.
    """
    sev = SEVERITY_RANK.get(f.severity, 99)          # ascending: 0 = critical
    is_expert = 1 if str(f.tool).startswith("expert:") else 0
    return (sev, -float(f.confidence or 0.0), is_expert, f.line_start or 0)


def correlate_findings(db: Session, job_id: str) -> dict:
    """Cluster the job's raw findings, keep one canonical per cluster, dedupe the rest."""
    raw = db.query(Finding).filter(
        Finding.job_id == job_id, Finding.status == "raw"
    ).all()

    # First collapse dependency CVEs to one canonical per package, then run the
    # generic (file, cwe, line) clustering on everything else.
    rest, dep_canon, dep_dupes = _collapse_dependencies(db, raw)

    # Group by (file, cwe), then split each group into line-proximity clusters.
    buckets: dict[tuple[str, str], list[Finding]] = {}
    for f in rest:
        buckets.setdefault(_bucket_key(f), []).append(f)

    clusters: list[list[Finding]] = []
    for members in buckets.values():
        members.sort(key=lambda f: f.line_start or 0)
        cur: list[Finding] = []
        cur_max = None
        for f in members:
            ls = f.line_start or 0
            if cur and cur_max is not None and ls - cur_max > LINE_WINDOW:
                clusters.append(cur)
                cur = []
            cur.append(f)
            cur_max = max(cur_max or ls, f.line_end or ls)
        if cur:
            clusters.append(cur)

    n_dupes = 0
    for cluster in clusters:
        canonical = min(cluster, key=_canonical_rank)
        tools = sorted({f.tool for f in cluster})
        key = correlation_key(canonical.file, canonical.line_start, canonical.cwe, canonical.title)
        canonical.correlation_key = key
        canonical.corroborating_tools = tools
        # Corroboration bump: each extra independent tool adds a little confidence.
        n_tools = len({t for t in tools if not str(t).startswith("expert:")}) or len(tools)
        if n_tools > 1:
            canonical.confidence = min(1.0, float(canonical.confidence or 0.5) + 0.10 * (n_tools - 1))
        for f in cluster:
            if f.id == canonical.id:
                continue
            f.status = "duplicate"
            f.canonical_id = canonical.id
            f.correlation_key = key
            n_dupes += 1
            publish_event(db, job_id, EventType.FINDING_DUPLICATE, {
                "finding_id": f.id, "canonical_id": canonical.id,
            })
    db.flush()

    stats = {
        "raw": len(raw),
        "clusters": len(clusters),
        "duplicates": n_dupes + dep_dupes,
        "dep_packages": dep_canon,
        "dep_cves_collapsed": dep_dupes,
    }
    logger.info(f"correlate[{job_id}]: {stats}")
    publish_event(db, job_id, EventType.CORRELATE_COMPLETE, stats)
    return stats
