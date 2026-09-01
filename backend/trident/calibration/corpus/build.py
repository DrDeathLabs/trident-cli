"""Build cwe_profiles from raw feed tables."""

from __future__ import annotations

import sqlite3
from collections import Counter
from datetime import datetime, timezone
from statistics import median


def _percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    sorted_vals = sorted(values)
    k = (len(sorted_vals) - 1) * p / 100
    lo = int(k)
    hi = lo + 1
    if hi >= len(sorted_vals):
        return sorted_vals[lo]
    return sorted_vals[lo] + (k - lo) * (sorted_vals[hi] - sorted_vals[lo])


def _modal(values: list) -> str | None:
    if not values:
        return None
    return Counter(v for v in values if v is not None).most_common(1)[0][0]


def _impact_label(confidentiality: str | None, integrity: str | None,
                  availability: str | None, scope: str | None) -> str:
    c = (confidentiality or "").upper()
    i = (integrity or "").upper()
    a = (availability or "").upper()
    s = (scope or "").upper()

    if c == "HIGH" and i == "HIGH":
        return "rce" if s == "CHANGED" else "data_tampering"
    if c == "HIGH" or i == "HIGH":
        return "data_exposure"
    if a == "HIGH":
        return "dos"
    return "other"


def _tier(score: float | None) -> str:
    if score is None:
        return "P4"
    if score >= 9:
        return "P0"
    if score >= 7:
        return "P1"
    if score >= 4:
        return "P2"
    if score >= 1:
        return "P3"
    return "P4"


def _load_cwe_data(conn: sqlite3.Connection) -> dict[str, dict]:
    """Load per-CWE raw rows for Python-side aggregation."""
    rows = conn.execute("""
        SELECT
            n.cwe,
            n.cve_id,
            n.base_score,
            n.attack_vector,
            n.confidentiality,
            n.integrity,
            n.availability,
            n.scope,
            e.epss_score,
            CASE WHEN k.cve_id IS NOT NULL THEN 1 ELSE 0 END AS in_kev,
            CASE WHEN x.cve_id IS NOT NULL THEN 1 ELSE 0 END AS in_exploitdb,
            CASE WHEN v.exploitation = 'active' THEN 1 ELSE 0 END AS actively_exploited,
            COALESCE(o.ecosystem_count, 0) AS ecosystem_count
        FROM nvd_cve n
        LEFT JOIN epss e ON e.cve_id = n.cve_id
        LEFT JOIN kev k ON k.cve_id = n.cve_id
        LEFT JOIN exploitdb x ON x.cve_id = n.cve_id
        LEFT JOIN vulnrichment v ON v.cve_id = n.cve_id
        LEFT JOIN osv_cve o ON o.cve_id = n.cve_id
        WHERE n.cwe IS NOT NULL AND n.cwe != ''
    """).fetchall()

    groups: dict[str, dict] = {}
    seen_cves: dict[str, set] = {}

    for row in rows:
        cwe = row["cwe"]
        cve_id = row["cve_id"]

        if cwe not in groups:
            groups[cwe] = {
                "scores": [],
                "epss": [],
                "kev_cves": set(),
                "exploit_cves": set(),
                "active_exploit_cves": set(),
                "ecosystem_counts": [],
                "attack_vectors": [],
                "impacts": [],
                "all_cves": set(),
            }
            seen_cves[cwe] = set()

        g = groups[cwe]
        g["all_cves"].add(cve_id)

        if row["base_score"] is not None:
            g["scores"].append(row["base_score"])

        if row["epss_score"] is not None:
            g["epss"].append(row["epss_score"])

        if row["in_kev"]:
            g["kev_cves"].add(cve_id)

        if row["in_exploitdb"]:
            g["exploit_cves"].add(cve_id)

        if row["actively_exploited"]:
            g["active_exploit_cves"].add(cve_id)

        ec = row["ecosystem_count"]
        if ec and ec > 0:
            g["ecosystem_counts"].append(ec)

        if row["attack_vector"]:
            g["attack_vectors"].append(row["attack_vector"])

        label = _impact_label(
            row["confidentiality"], row["integrity"],
            row["availability"], row["scope"]
        )
        g["impacts"].append(label)

    return groups


def _load_cwe_tree(conn: sqlite3.Connection) -> dict[str, str | None]:
    return {
        row["cwe_id"]: row["parent_cwe"]
        for row in conn.execute("SELECT cwe_id, parent_cwe FROM cwe_tree").fetchall()
    }


def _build_profile(cwe: str, g: dict, now: str) -> dict:
    scores = g["scores"]
    epss_vals = g["epss"]
    total = len(g["all_cves"])

    med_cvss = median(scores) if scores else None
    p25 = _percentile(scores, 25) if scores else None
    p75 = _percentile(scores, 75) if scores else None
    p90_epss = _percentile(epss_vals, 90) if epss_vals else 0.0
    mean_epss = sum(epss_vals) / len(epss_vals) if epss_vals else 0.0

    kev_rate = len(g["kev_cves"]) / total if total else 0.0
    exploit_rate = len(g["exploit_cves"]) / total if total else 0.0
    active_exploit_rate = len(g["active_exploit_cves"]) / total if total else 0.0
    ec = g["ecosystem_counts"]
    osv_ecosystem_breadth = sum(ec) / len(ec) if ec else 0.0

    return {
        "cwe": cwe,
        "cve_count": total,
        "median_cvss": med_cvss,
        "p25_cvss": p25,
        "p75_cvss": p75,
        "mean_epss": mean_epss,
        "p90_epss": p90_epss,
        "kev_rate": kev_rate,
        "exploit_rate": exploit_rate,
        "active_exploit_rate": active_exploit_rate,
        "osv_ecosystem_breadth": osv_ecosystem_breadth,
        "modal_attack_vector": _modal(g["attack_vectors"]),
        "modal_impact": _modal(g["impacts"]),
        "expected_tier": _tier(med_cvss),
        "built_at": now,
    }


def build_corpus(conn: sqlite3.Connection) -> int:
    """Build cwe_profiles table. Returns number of profiles written."""
    from trident.calibration.corpus.db import set_meta

    now = datetime.now(timezone.utc).isoformat()
    groups = _load_cwe_data(conn)
    cwe_tree = _load_cwe_tree(conn)

    profiles: dict[str, dict] = {}
    for cwe, g in groups.items():
        profiles[cwe] = _build_profile(cwe, g, now)

    # Sparse fallback: inherit parent stats for CWEs with < 15 CVEs
    for cwe, profile in list(profiles.items()):
        if profile["cve_count"] < 15:
            parent = cwe_tree.get(cwe)
            if parent and parent in profiles:
                parent_p = profiles[parent]
                for field in (
                    "median_cvss", "p25_cvss", "p75_cvss", "mean_epss",
                    "p90_epss", "kev_rate", "exploit_rate",
                    "active_exploit_rate", "osv_ecosystem_breadth",
                    "modal_attack_vector", "modal_impact", "expected_tier",
                ):
                    profiles[cwe][field] = parent_p[field]

    conn.execute("DELETE FROM cwe_profiles")
    conn.executemany(
        "INSERT INTO cwe_profiles("
        "cwe, cve_count, median_cvss, p25_cvss, p75_cvss, mean_epss, p90_epss, "
        "kev_rate, exploit_rate, active_exploit_rate, osv_ecosystem_breadth, "
        "modal_attack_vector, modal_impact, expected_tier, built_at"
        ") VALUES("
        ":cwe, :cve_count, :median_cvss, :p25_cvss, :p75_cvss, :mean_epss, :p90_epss, "
        ":kev_rate, :exploit_rate, :active_exploit_rate, :osv_ecosystem_breadth, "
        ":modal_attack_vector, :modal_impact, :expected_tier, :built_at"
        ")",
        list(profiles.values()),
    )
    conn.commit()

    count = len(profiles)
    set_meta(conn, "cwe_profile_count", str(count))
    set_meta(conn, "corpus_built_at", now)
    return count
