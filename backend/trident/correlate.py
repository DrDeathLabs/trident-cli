"""Cross-tool correlation, exact dedupe, and remediation grouping.

Runs after the deterministic tools and before expert review. Two tools flagging
the same vulnerability (same file, same CWE, adjacent lines) currently produce
two independent Finding rows that get debated twice and both counted. This
collapses each cluster to one *canonical* remediation finding. Exact repeated
records are marked `duplicate`; distinct evidence in the same remediation group
is marked `related`. Both point at the canonical row via `canonical_id`.

Corroboration is signal: a cluster backed by two independent tools is more
likely real, so the canonical's confidence is nudged up.

Deliberately embedding-free — clustering is deterministic (file + normalized CWE
+ line proximity), so it adds no LLM cost to the scan.
"""

from __future__ import annotations

import hashlib
import json

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


def _dep_version(f: Finding) -> str:
    """Return imported dependency version for identity-safe grouping.

    Native scanner correlation keeps its historical package/file grouping.  In
    report-import mode, however, two records for the same package and file can
    describe different installed versions, so they must not be collapsed into
    one remediation occurrence.
    """
    raw = (f.raw_outputs or {}).get("raw") or {}
    if raw.get("import_format") == "dependency-check":
        return str(raw.get("InstalledVersion") or "unknown-version").strip().lower()
    return ""


def _record_fingerprint(f: Finding) -> str:
    """Identify an exact scanner record, separate from its remediation group.

    A package and file identify a remediation target, not necessarily one
    vulnerability. The original structured record is therefore required before
    a member is called an exact duplicate. Native findings without a structured
    record use the stable finding hash as their fallback identity.
    """
    raw = (f.raw_outputs or {}).get("raw") or {}
    record = raw.get("record") if isinstance(raw, dict) else None
    if record is None:
        return f"hash:{f.hash}"
    encoded = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _group_metadata(
    canonical: Finding,
    members: list[Finding],
    duplicate_count: int,
    related_count: int,
    aggregation_basis: str,
) -> None:
    """Persist aggregation facts needed by report consumers."""
    raw_outputs = dict(canonical.raw_outputs or {})
    member_rule_ids = sorted({m.rule_id for m in members if m.rule_id})
    raw_outputs["correlation"] = {
        "group_size": len(members),
        "duplicate_count": duplicate_count,
        "related_count": related_count,
        "unique_record_count": len(members) - duplicate_count,
        "aggregation_basis": aggregation_basis,
        "member_finding_ids": [m.id for m in members],
        "member_rule_ids": member_rule_ids,
        # Keep the original name for consumers that already use it. It contains
        # every rule represented in the remediation group, including the
        # canonical record, so it is not an exact-duplicate list.
        "related_rule_ids": member_rule_ids,
    }
    kev_evidence = []
    for member in members:
        raw = (member.raw_outputs or {}).get("raw") or {}
        kev = raw.get("kev") or {}
        identity = raw.get("cpe_identity") or {}
        if kev.get("listed") and identity.get("status") == "match":
            kev_evidence.append({
                "finding_id": member.id,
                "rule_id": member.rule_id,
                "kev": kev,
                "identity": identity,
            })
    if kev_evidence:
        raw_outputs["correlation"]["kev_floor_evidence"] = kev_evidence
    canonical.raw_outputs = raw_outputs


def _collapse_dependencies(
    db: Session, raw: list[Finding],
) -> tuple[list[Finding], int, int, int]:
    """Collapse dependency CVEs to one canonical per (file, package, version).

    A single vulnerable pin (e.g. requests 2.2.1) yields dozens of individual CVE
    findings; deliberating each with the full council is wasteful and drowns the
    precision signal. One canonical per package/version carries the count forward; the
    Exact repeats are marked `duplicate`; distinct advisories for the same
    package and file are marked `related`.
    Returns (remaining_non_dep_findings, canonicals_made, duplicates_made,
    related_made).
    """
    dep_groups: dict[tuple[str, str, str], list[Finding]] = {}
    rest: list[Finding] = []
    for f in raw:
        pkg = _dep_package(f)
        if _is_dep_finding(f) and pkg:
            dep_groups.setdefault((_norm_path(f.file), pkg, _dep_version(f)), []).append(f)
        else:
            rest.append(f)

    canon_made = 0
    dupes = 0
    related = 0
    for (path, pkg, version), members in dep_groups.items():
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
        group_dupes = 0
        group_related = 0
        seen_records = {_record_fingerprint(canonical)}
        for m in members:
            if m.id == canonical.id:
                continue
            fingerprint = _record_fingerprint(m)
            if fingerprint in seen_records:
                m.status = "duplicate"
                dupes += 1
                group_dupes += 1
            else:
                m.status = "related"
                related += 1
                group_related += 1
                seen_records.add(fingerprint)
            m.canonical_id = canonical.id
            m.correlation_key = canonical.correlation_key
            publish_event(db, m.job_id, (
                EventType.FINDING_DUPLICATE
                if m.status == "duplicate" else EventType.FINDING_RELATED
            ), {
                "finding_id": m.id, "canonical_id": canonical.id,
                "relation": m.status,
            })
        _group_metadata(
            canonical, members, group_dupes, group_related,
            "same normalized dependency package, version, and artifact path"
            if version else "same normalized dependency package and artifact path",
        )
    return rest, canon_made, dupes, related


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
    rest, dep_canon, dep_dupes, dep_related = _collapse_dependencies(db, raw)

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
    n_related = dep_related
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
        cluster_dupes = 0
        cluster_related = 0
        seen_records = {_record_fingerprint(canonical)}
        for f in cluster:
            if f.id == canonical.id:
                continue
            fingerprint = _record_fingerprint(f)
            if fingerprint in seen_records:
                f.status = "duplicate"
                n_dupes += 1
                cluster_dupes += 1
            else:
                f.status = "related"
                n_related += 1
                cluster_related += 1
                seen_records.add(fingerprint)
            f.canonical_id = canonical.id
            f.correlation_key = key
            publish_event(db, job_id, (
                EventType.FINDING_DUPLICATE
                if f.status == "duplicate" else EventType.FINDING_RELATED
            ), {
                "finding_id": f.id, "canonical_id": canonical.id,
                "relation": f.status,
            })
        _group_metadata(
            canonical, cluster, cluster_dupes, cluster_related,
            "same normalized file and CWE/title bucket within three lines",
        )
    db.flush()

    stats = {
        "raw": len(raw),
        "clusters": len(clusters),
        "duplicates": n_dupes + dep_dupes,
        "related": n_related,
        "dep_packages": dep_canon,
        "dep_records_collapsed": sum(
            1 for f in raw if _is_dep_finding(f) and _dep_package(f)
        ) - dep_canon,
        "dep_exact_duplicates": dep_dupes,
    }
    logger.info(f"correlate[{job_id}]: {stats}")
    publish_event(db, job_id, EventType.CORRELATE_COMPLETE, stats)
    return stats
