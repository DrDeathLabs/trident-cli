"""Reporters - SARIF, JSON, HTML, PDF export of job findings.

Only *confirmed* findings are exported in the actionable list by default.
For imported reports, confirmed means retained for remediation work. Rejected,
duplicate, related, suppressed, and unreviewed records remain in disposition
and evidence sections rather than being discarded.
"""

from __future__ import annotations

import hashlib
from html import escape
from collections import Counter

from sqlalchemy import case
from sqlalchemy.orm import Session

from trident import __version__
from trident.clock import utcnow
from trident.evidence import (
    build_evidence_payload,
    disposition_for_status,
    evidence_basis,
    evidence_summary,
    imported_format,
    imported_metadata,
    raw_evidence,
)
from trident.models import AttackChain, Finding, Job, TriageOverride
from trident.triage import PLAYBOOK, TIERS

_REPORTABLE = ("confirmed",)

_TIER_LEVEL: dict[str, str] = {
    "P0": "error", "P1": "error",
    "P2": "warning",
    "P3": "note", "P4": "note",
}

_PRIORITY_ORDER = case({t: i for i, t in enumerate(TIERS)}, value=Finding.priority, else_=99)

_SEV_COLORS = {
    "critical": ("#7f1d1d", "#fca5a5"),
    "high":     ("#7c2d12", "#fdba74"),
    "medium":   ("#78350f", "#fcd34d"),
    "low":      ("#0c4a6e", "#7dd3fc"),
    "info":     ("#1e293b", "#94a3b8"),
}

_TIER_COLORS = {
    "P0": ("#7f1d1d", "#fca5a5"),
    "P1": ("#7c2d12", "#fdba74"),
    "P2": ("#78350f", "#fcd34d"),
    "P3": ("#0c4a6e", "#7dd3fc"),
    "P4": ("#1e293b", "#94a3b8"),
}

_FACTOR_LABELS = {
    "remote_unauth": "Remote (no auth)", "remote_auth": "Remote (auth req.)",
    "adjacent": "Adjacent", "local": "Local", "physical": "Physical",
    "rce": "RCE", "auth_bypass": "Auth Bypass", "data_exposure": "Data Exposure",
    "data_tampering": "Data Tampering", "ssrf": "SSRF", "injection": "Injection",
    "dos": "DoS", "info_disclosure": "Info Disclosure", "other": "Other",
    "trivial": "Trivial", "moderate": "Moderate", "difficult": "Difficult",
    "involved": "Involved",
    "reachable": "Reachable", "unreachable": "Unreachable", "unknown": "Unknown reach",
}

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def _reportable(db: Session, job_id: str) -> list[Finding]:
    return db.query(Finding).filter(
        Finding.job_id == job_id, Finding.status.in_(_REPORTABLE)
    ).all()


def _job_workspace(job: Job | None) -> str:
    """Return the workspace used for evidence classification in a report."""
    if not job:
        return ""
    if job.workspace_path:
        return job.workspace_path
    return str((job.profile or {}).get("source_context") or "")


def _import_metadata(job: Job | None) -> dict | None:
    if not job or not (job.profile or {}).get("import_mode"):
        return None
    profile = job.profile or {}
    return {
        "mode": "import",
        "inputs": profile.get("import_inputs", []),
        "source_context": profile.get("source_context"),
        "discover_novel": bool(profile.get("discover_novel")),
    }


def _review_payload(f: Finding) -> dict:
    """Expose decision provenance without exposing private model thinking."""
    return {
        "verdicts": [
            {
                "expert": v.expert,
                "persona": v.persona,
                "verdict": v.verdict,
                "confidence": v.confidence,
                "rationale": v.rationale,
                "model": v.model,
                "iteration": v.iteration,
            }
            for v in f.verdicts
        ],
        "debate": [
            {
                "speaker": message.speaker,
                "role": message.role,
                "content": message.content,
                "confidence": message.confidence,
            }
            for message in f.debate
        ],
    }


def _action_key(f: Finding) -> tuple[str, str]:
    raw = raw_evidence(f)
    if f.tool == "dependency-check" and raw.get("package"):
        return (
            "dependency",
            f"{str(raw.get('package')).strip().lower()}|"
            f"{str(raw.get('InstalledVersion') or 'unknown-version').strip().lower()}",
        )
    # Code/config findings have no package/version remediation target. Keep one
    # action per canonical finding rather than merging unrelated occurrences.
    return ("finding", f.id)


def _action_id(f: Finding) -> str:
    return "action-" + hashlib.sha256("|".join(_action_key(f)).encode()).hexdigest()[:16]


def _remediation_actions(
    db: Session, job_id: str, findings: list[Finding] | None = None,
) -> list[dict]:
    """Roll up retained findings into stable package/version work items.

    The flat finding list remains the compatibility surface. This additional
    layer gives dependency consumers one action per package/version while
    retaining every canonical, related, and duplicate record as an occurrence.
    """
    if findings is None:
        findings = _reportable(db, job_id)
    job = db.get(Job, job_id)
    workspace = _job_workspace(job)
    all_rows = db.query(Finding).filter(Finding.job_id == job_id).all()
    by_canonical: dict[str, list[Finding]] = {}
    for row in all_rows:
        by_canonical.setdefault(row.canonical_id or row.id, []).append(row)

    grouped: dict[tuple[str, str], dict] = {}
    for finding in findings:
        key = _action_key(finding)
        raw_finding = raw_evidence(finding)
        action = grouped.setdefault(key, {
            "action_id": _action_id(finding),
            "kind": key[0],
            "package": raw_finding.get("package") if key[0] == "dependency" else None,
            "version": raw_finding.get("InstalledVersion") if key[0] == "dependency" else None,
            "finding_ids": [], "occurrences": [], "files": [], "rules": [],
            "priorities": [], "highest_priority": None, "kev_listed": False,
            "kev_records": [], "evidence_bases": [], "evidence_references": [],
            "rationale_references": [], "identity_statuses": [],
            "duplicate_records": 0, "related_records": 0,
        })
        members = by_canonical.get(finding.id, [finding])
        action["finding_ids"].append(finding.id)
        action["evidence_bases"].append(evidence_basis(finding, workspace))
        action["evidence_references"].append({
            "finding_id": finding.id,
            "basis": evidence_basis(finding, workspace),
            "record_preserved": bool(raw_finding.get("record")),
            "import_format": imported_format(finding),
        })
        action["rationale_references"].append({
            "finding_id": finding.id,
            "review_verdict_count": len(finding.verdicts),
            "triage_rationale_present": bool((finding.triage or {}).get("rationale")),
        })
        for member in members:
            raw = raw_evidence(member)
            action["occurrences"].append({
                "finding_id": member.id,
                "canonical_id": member.canonical_id,
                "status": member.status,
                "file": member.file,
                "line_start": member.line_start,
                "line_end": member.line_end,
                "rule_id": member.rule_id,
            })
            if member.file:
                action["files"].append(member.file)
            if member.rule_id:
                action["rules"].append(member.rule_id)
            if member.status == "duplicate":
                action["duplicate_records"] += 1
            elif member.status == "related":
                action["related_records"] += 1
            if (raw.get("kev") or {}).get("listed"):
                action["kev_listed"] = True
                kev = raw.get("kev") or {}
                if kev not in action["kev_records"]:
                    action["kev_records"].append(kev)
            identity_status = (raw.get("cpe_identity") or {}).get("status")
            if identity_status:
                action["identity_statuses"].append(identity_status)
        if finding.priority:
            action["priorities"].append(finding.priority)

    priority_rank = {tier: i for i, tier in enumerate(TIERS)}
    for action in grouped.values():
        action["finding_ids"] = sorted(set(action["finding_ids"]))
        action["files"] = sorted(set(action["files"]))
        action["rules"] = sorted(set(action["rules"]))
        action["priorities"] = sorted(set(action["priorities"]), key=priority_rank.get)
        action["highest_priority"] = min(
            action["priorities"], key=priority_rank.get, default=None,
        )
        action["evidence_bases"] = sorted(set(action["evidence_bases"]))
        action["evidence_basis"] = (
            action["evidence_bases"][0]
            if len(action["evidence_bases"]) == 1
            else "mixed"
        ) if action["evidence_bases"] else None
        action["kev_sources"] = sorted({
            str(item.get("source")) for item in action["kev_records"]
            if item.get("source")
        })
        action["kev_dates"] = sorted({
            str(item.get("date_added")) for item in action["kev_records"]
            if item.get("date_added")
        })
        action["identity_statuses"] = sorted(set(action["identity_statuses"]))
        action["identity_status"] = (
            "conflict" if "conflict" in action["identity_statuses"]
            else ("match" if "match" in action["identity_statuses"] else "unknown")
        )
        action["occurrence_count"] = len(action["occurrences"])
    return sorted(
        grouped.values(),
        key=lambda item: (priority_rank.get(item["highest_priority"], 99), item["action_id"]),
    )


def _triaged_findings(db: Session, job_id: str):
    rows = (
        db.query(Finding)
        .filter(Finding.job_id == job_id, Finding.status.in_(_REPORTABLE))
        .order_by(_PRIORITY_ORDER)
        .all()
    )
    overrides = {
        o.finding_id: o
        for o in db.query(TriageOverride).filter_by(job_id=job_id).all()
    }
    return rows, overrides


def _triage_overview(db: Session, job_id: str, findings: list[Finding] | None = None) -> dict:
    """Return the compact triage summary shared by scan-level exporters."""
    if findings is None:
        findings = _reportable(db, job_id)
    all_records = db.query(Finding).filter(Finding.job_id == job_id).all()
    by_tier = {t: 0 for t in TIERS}
    for finding in findings:
        if finding.priority in by_tier:
            by_tier[finding.priority] += 1
    untriaged = sum(1 for finding in findings if finding.priority not in by_tier)
    false_positives = db.query(Finding).filter(
        Finding.job_id == job_id, Finding.status == "false_positive"
    ).count()
    out_of_scope = db.query(Finding).filter(
        Finding.job_id == job_id, Finding.status == "out_of_scope"
    ).count()
    duplicate_records = db.query(Finding).filter(
        Finding.job_id == job_id, Finding.status == "duplicate"
    ).count()
    related_records = db.query(Finding).filter(
        Finding.job_id == job_id, Finding.status == "related"
    ).count()
    reviewed_statuses = {
        "confirmed", "false_positive", "duplicate", "related", "suppressed",
        "disputed", "out_of_scope", "parse_error",
    }
    reviewed_records = sum(
        1 for finding in all_records if finding.status in reviewed_statuses
    )
    priority_assigned = len(findings) - untriaged
    actions = _remediation_actions(db, job_id, findings)
    return {
        "summary": {
            "total_confirmed": len(findings),
            "accounted_records": len(all_records),
            "reviewed_records": reviewed_records,
            "triage_candidates": len(findings),
            "triaged": len(findings) - untriaged,
            "priority_assigned": priority_assigned,
            "retained_for_remediation": len(findings),
            "false_positives": false_positives,
            "out_of_scope": out_of_scope,
            "duplicate_records": duplicate_records,
            "related_records": related_records,
            "remediation_groups": len(actions),
            "remediation_occurrences": sum(a["occurrence_count"] for a in actions),
            "by_tier": by_tier,
        },
        "tiers": [
            {"tier": t, **PLAYBOOK[t], "count": by_tier[t]}
            for t in TIERS
        ],
        "untriaged": untriaged,
    }


def _disposition_report(db: Session, job_id: str, job: Job | None) -> dict:
    """Return non-actionable records with their disposition and evidence trail."""
    workspace = _job_workspace(job)
    rows = db.query(Finding).filter(
        Finding.job_id == job_id, Finding.status != "confirmed"
    ).all()
    counts = Counter(f.status or "unknown" for f in rows)
    records = []
    for f in rows:
        raw = (f.raw_outputs or {}).get("correlation") or {}
        records.append({
            "id": f.id,
            "status": f.status,
            "disposition": disposition_for_status(f.status),
            "tool": f.tool,
            "rule_id": f.rule_id,
            "title": f.title,
            "file": f.file,
            "line_start": f.line_start,
            "line_end": f.line_end,
            "canonical_id": f.canonical_id,
            "correlation": raw,
            "review": _review_payload(f),
            "evidence": build_evidence_payload(f, workspace),
            "scanner_severity": f.scanner_severity or f.severity,
            "model_severity": f.model_severity,
            "import_metadata": imported_metadata(f),
            "remediation_action_id": _action_id(f),
        })
    return {
        "counts": dict(sorted(counts.items())),
        "records": records,
    }


def _sarif_level(severity: str) -> str:
    return {"critical": "error", "high": "error", "medium": "warning",
            "low": "note", "info": "none"}.get(severity, "warning")


def _fl(v: str | None) -> str:
    if not v:
        return ""
    return _FACTOR_LABELS.get(v, v.replace("_", " ").title())


def _badge(text: str, bg: str, color: str = "#fff") -> str:
    return (f'<span style="background:{bg};color:{color};padding:2px 8px;border-radius:4px;'
            f'font-size:11px;font-weight:700;white-space:nowrap">{escape(text)}</span>')


def _tier_badge(tier: str) -> str:
    bg, color = _TIER_COLORS.get(tier, ("#334155", "#cbd5e1"))
    return _badge(tier, bg, color)


def _sev_badge(sev: str) -> str:
    bg, color = _SEV_COLORS.get(sev or "info", ("#1e293b", "#94a3b8"))
    return _badge((sev or "info").upper(), bg, color)


def _factor_chip(label: str, value: str | None) -> str:
    if not value:
        return ""
    return (f'<span style="font-size:11px;color:#64748b">{escape(label)}:</span> '
            f'<b style="font-size:11px">{escape(_fl(value))}</b>')


# ── Shared CSS ────────────────────────────────────────────────────────────────

_BASE_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
  color: #0f172a; background: #fff;
}
a { color: inherit; text-decoration: none; }
a:hover { text-decoration: underline; }
.report-layout { display: flex; min-height: 100vh; }
.sidebar {
  width: 240px; min-width: 240px; position: sticky; top: 0; height: 100vh;
  overflow-y: auto; background: #f8fafc; border-right: 1px solid #e2e8f0;
  padding: 16px 0; font-size: 12px;
}
.sidebar-section { padding: 0 12px 8px; }
.sidebar-title {
  font-size: 10px; font-weight: 800; text-transform: uppercase;
  letter-spacing: .1em; color: #94a3b8; padding: 0 12px 6px; margin-top: 8px;
}
.sidebar-group { margin-bottom: 2px; }
.sidebar-group > a {
  display: flex; align-items: center; justify-content: space-between;
  padding: 5px 8px; border-radius: 4px; color: #334155; font-weight: 600;
}
.sidebar-group > a:hover { background: #e2e8f0; text-decoration: none; }
.sidebar-sub { padding-left: 8px; margin-top: 1px; }
.sidebar-sub a {
  display: block; padding: 3px 8px; border-radius: 3px;
  color: #64748b; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.sidebar-sub a:hover { background: #e2e8f0; color: #0f172a; text-decoration: none; }
.count-badge {
  background: #e2e8f0; color: #475569; padding: 1px 6px;
  border-radius: 10px; font-size: 10px; font-weight: 700;
}
.main-content { flex: 1; padding: 2rem; max-width: 900px; }
.back-top {
  position: fixed; bottom: 24px; right: 24px;
  background: #0f172a; color: #fff; border: none; border-radius: 50%;
  width: 40px; height: 40px; font-size: 18px; cursor: pointer;
  display: flex; align-items: center; justify-content: center;
  box-shadow: 0 4px 12px rgba(0,0,0,.2); text-decoration: none;
}
.back-top:hover { background: #1e40af; text-decoration: none; }
.finding-card {
  border: 1px solid #e2e8f0; border-radius: 8px;
  margin-bottom: 20px; overflow: hidden;
}
.finding-card-head {
  background: #f8fafc; padding: 12px 16px;
  border-bottom: 1px solid #e2e8f0;
}
.finding-card-body { padding: 14px 16px; }
.section-header {
  padding: 14px 20px; border-radius: 8px 8px 0 0; margin-bottom: 0;
}
.callout-orange {
  margin-top: 12px; background: #fff7ed;
  border-left: 3px solid #fb923c; padding: 10px 14px;
  border-radius: 0 4px 4px 0;
}
.callout-green {
  margin-top: 12px; background: #f0fdf4;
  border-left: 3px solid #4ade80; padding: 10px 14px;
  border-radius: 0 4px 4px 0;
}
.callout-label {
  font-size: 10px; font-weight: 700; text-transform: uppercase;
  letter-spacing: .06em; margin-bottom: 4px;
}
.callout-text { font-size: 13px; color: #334155; line-height: 1.6; }
.factor-row { display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 10px; }
.meta-row { font-size: 11px; color: #94a3b8; margin-bottom: 8px; }
.desc-block { font-size: 13px; color: #334155; line-height: 1.6; margin-top: 10px; }
.narrative-block {
  margin-top: 12px; background: #f8fafc;
  border-left: 3px solid #94a3b8; padding: 10px 14px;
  border-radius: 0 4px 4px 0;
}
.narrative-label {
  font-size: 10px; font-weight: 700; text-transform: uppercase;
  letter-spacing: .06em; color: #64748b; margin-bottom: 4px;
}
.toc-page-ref::after { content: target-counter(attr(href), page); }
@media print {
  .sidebar { display: none; }
  .back-top { display: none; }
  .main-content { padding: 0; max-width: 100%; }
  .report-layout { display: block; }
  .finding-card { break-inside: avoid; page-break-inside: avoid; }
  section { break-inside: avoid; page-break-inside: avoid; }
}
"""

def _html_shell(title: str, sidebar: str, body: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escape(title)}</title>
<style>{_BASE_CSS}</style>
</head>
<body id="top">
<div class="report-layout">
  <nav class="sidebar">
    {sidebar}
  </nav>
  <main class="main-content">
    {body}
  </main>
</div>
<a class="back-top" href="#top" title="Back to top">↑</a>
</body>
</html>"""


# ── Generic (scan-level) exporters ───────────────────────────────────────────

def to_sarif(db: Session, job_id: str) -> dict:
    job = db.get(Job, job_id)
    workspace = _job_workspace(job)
    findings = _reportable(db, job_id)
    triage_overview = _triage_overview(db, job_id, findings)
    rules: dict[str, dict] = {}
    for f in findings:
        if f.rule_id in rules:
            continue
        tags = ["security"]
        if f.cwe:
            tags.append(f"external/cwe/{f.cwe.lower()}")
        rules[f.rule_id] = {
            "id": f.rule_id, "name": f.rule_id,
            "shortDescription": {"text": (f.title or f.rule_id)[:120]},
            "properties": {"tags": tags, "cwe": f.cwe},
        }
    rule_index = {rid: i for i, rid in enumerate(rules)}

    results = []
    for f in findings:
        triage = f.triage or {}
        correlation = (f.raw_outputs or {}).get("correlation") or {}
        guard_notes = [n for n in (triage.get("corpus_guard"), triage.get("guard"), triage.get("reach_guard")) if n]
        msg_text = f.title or f.rule_id
        if guard_notes:
            msg_text += "\n\nTriage adjustments:\n" + "\n".join(f"• {n}" for n in guard_notes)
        results.append({
            "ruleId": f.rule_id,
            "ruleIndex": rule_index.get(f.rule_id, 0),
            "level": _TIER_LEVEL.get(f.priority or "", _sarif_level(f.severity)),
            "message": {"markdown": msg_text, "text": f.title or f.rule_id},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.file},
                "region": {"startLine": max(1, f.line_start or 1),
                           "endLine": max(1, f.line_end or f.line_start or 1)},
            }}],
            "partialFingerprints": {"primaryLocationLineHash": f.hash},
            "properties": {
                "priority": f.priority, "tool": f.tool, "severity": f.severity,
                "scanner_severity": f.scanner_severity or f.severity,
                "model_severity": f.model_severity,
                "remediation_action_id": _action_id(f),
                "import_metadata": imported_metadata(f),
                "confidence": f.confidence, "cwe": f.cwe, "owasp": f.owasp,
                "status": f.status, "iteration": f.iteration,
                "corroborating_tools": f.corroborating_tools or [],
                "narrative": f.narrative, "remediation": f.remediation,
                "exploit_scenario": f.exploit_scenario, "attack_paths": f.attack_paths or [],
                "canonical_id": f.canonical_id,
                "correlation": correlation,
                "disposition": disposition_for_status(f.status),
                "review": _review_payload(f),
                "evidence": build_evidence_payload(f, workspace),
                "triage": {
                    "impact": triage.get("impact"),
                    "attack_vector": triage.get("attack_vector"),
                    "exploitability": triage.get("exploitability"),
                    "fix_effort": triage.get("fix_effort"),
                    "rationale": triage.get("rationale"),
                     "model_impact": triage.get("model_impact"),
                     "model_attack_vector": triage.get("model_attack_vector"),
                     "reported_attack_vector": imported_metadata(f).get("reported_attack_vector"),
                    "in_chain": triage.get("in_chain", False),
                    "reachability": triage.get("reachability"),
                    "contested": triage.get("contested", False),
                    "guard": triage.get("guard"),
                    "class_guard": triage.get("guard"),
                    "corpus_guard": triage.get("corpus_guard"),
                    "reach_guard": triage.get("reach_guard"),
                    "import_evidence_conflict": triage.get("import_evidence_conflict"),
                    "evidence_basis": triage.get("evidence_basis") or evidence_basis(f, workspace),
                    "chain_basis": triage.get("chain_basis"),
                    "chain_member_count": triage.get("chain_member_count", 0),
                    "chain_priority_eligible": triage.get("chain_priority_eligible", False),
                    "chain_priority_suppressed_reason": triage.get("chain_priority_suppressed_reason"),
                    "kev_floor": triage.get("kev_floor"),
                },
            },
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {
            "name": "Trident", "version": __version__,
            "rules": list(rules.values()),
        }}, "results": results, "properties": {
            "triage": triage_overview,
            "remediation_actions": _remediation_actions(db, job_id, findings),
            "import": _import_metadata(job),
            "dispositions": _disposition_report(db, job_id, job),
        }}],
    }


def _finding_dict(f: Finding, job: Job | None = None) -> dict:
    triage = f.triage or {}
    correlation = (f.raw_outputs or {}).get("correlation") or {}
    workspace = _job_workspace(job)
    return {
        "id": f.id, "priority": f.priority, "tool": f.tool, "rule_id": f.rule_id,
        "severity": f.severity, "confidence": f.confidence, "title": f.title,
        "description": f.description, "file": f.file, "line_start": f.line_start,
        "line_end": f.line_end, "cwe": f.cwe, "owasp": f.owasp, "status": f.status,
        "iteration": f.iteration, "corroborating_tools": f.corroborating_tools or [],
        "canonical_id": f.canonical_id,
        "correlation": correlation,
        "narrative": f.narrative, "remediation": f.remediation,
        "exploit_scenario": f.exploit_scenario, "attack_paths": f.attack_paths or [],
        "disposition": disposition_for_status(f.status),
        "review": _review_payload(f),
        "evidence": build_evidence_payload(f, workspace),
        "scanner_severity": f.scanner_severity or f.severity,
        "model_severity": f.model_severity,
        "import_metadata": imported_metadata(f),
        "remediation_action_id": _action_id(f),
        "triage": {
            "impact": triage.get("impact"),
            "attack_vector": triage.get("attack_vector"),
            "exploitability": triage.get("exploitability"),
            "fix_effort": triage.get("fix_effort"),
            "rationale": triage.get("rationale"),
             "model_impact": triage.get("model_impact"),
             "model_attack_vector": triage.get("model_attack_vector"),
             "reported_attack_vector": imported_metadata(f).get("reported_attack_vector"),
            "in_chain": triage.get("in_chain", False),
            "reachability": triage.get("reachability"),
            "contested": triage.get("contested", False),
            "guard": triage.get("guard"),
            "class_guard": triage.get("guard"),
            "corpus_guard": triage.get("corpus_guard"),
            "reach_guard": triage.get("reach_guard"),
            "import_evidence_conflict": triage.get("import_evidence_conflict"),
            "evidence_basis": triage.get("evidence_basis") or evidence_basis(f, workspace),
            "chain_basis": triage.get("chain_basis"),
            "chain_member_count": triage.get("chain_member_count", 0),
            "chain_priority_eligible": triage.get("chain_priority_eligible", False),
            "chain_priority_suppressed_reason": triage.get("chain_priority_suppressed_reason"),
            "kev_floor": triage.get("kev_floor"),
        },
    }


def to_json(db: Session, job_id: str) -> dict:
    job = db.get(Job, job_id)
    findings = _reportable(db, job_id)
    triage_overview = _triage_overview(db, job_id, findings)
    chains = (
        db.query(AttackChain)
        .filter(AttackChain.job_id == job_id)
        .order_by(AttackChain.iteration.asc(), AttackChain.created_at.asc())
        .all()
    )
    return {
        "job": {
            "id": job_id, "target": job.target_name, "status": job.status,
            "languages": job.languages, "iterations": job.current_iteration,
            "started_at": job.started_at.isoformat() if job.started_at else None,
            "completed_at": job.completed_at.isoformat() if job.completed_at else None,
        },
        "import": _import_metadata(job),
        "findings": [_finding_dict(f, job) for f in findings],
        "remediation_actions": _remediation_actions(db, job_id, findings),
        "attack_chains": [
            {
                "id": c.id, "goal": c.goal, "steps": c.steps or [],
                "likelihood": c.likelihood, "iteration": c.iteration,
                "finding_ids": [f.id for f in c.findings],
            }
            for c in chains
        ],
        "triage": triage_overview,
        "dispositions": _disposition_report(db, job_id, job),
    }


def _scan_finding_card(f: Finding) -> str:
    sev = f.severity or "info"
    sev_bg, sev_color = _SEV_COLORS.get(sev, ("#1e293b", "#94a3b8"))
    anchor = f'id="finding-{f.id}"'

    corroborating = ""
    if f.corroborating_tools:
        tools_list = ", ".join(escape(t) for t in f.corroborating_tools)
        corroborating = (f'<div class="meta-row" style="margin-top:4px">'
                         f'Also flagged by: {tools_list}</div>')

    desc_block = ""
    if f.description:
        desc_block = f'<div class="desc-block">{escape(f.description)}</div>'

    narrative_block = ""
    if f.narrative:
        narrative_block = (
            '<div class="narrative-block">'
            '<div class="narrative-label">Analysis</div>'
            f'<div class="callout-text">{escape(f.narrative)}</div>'
            '</div>'
        )

    exploit_block = ""
    if f.exploit_scenario:
        exploit_block = (
            '<div class="callout-orange">'
            '<div class="callout-label" style="color:#92400e">How It Could Be Exploited</div>'
            f'<div class="callout-text">{escape(f.exploit_scenario)}</div>'
            '</div>'
        )

    remediation_block = ""
    if f.remediation:
        remediation_block = (
            '<div class="callout-green">'
            '<div class="callout-label" style="color:#166534">Remediation</div>'
            f'<div class="callout-text">{escape(f.remediation)}</div>'
            '</div>'
        )

    attack_paths_block = ""
    if f.attack_paths:
        items = "".join(
            f'<li style="font-size:13px;color:#334155;margin-bottom:4px">{escape(str(p))}</li>'
            for p in f.attack_paths
        )
        attack_paths_block = (
            '<div style="margin-top:12px">'
            '<div class="callout-label" style="color:#64748b">Attack Paths</div>'
            f'<ol style="padding-left:20px;margin-top:4px">{items}</ol>'
            '</div>'
        )

    cwe_owasp = " &nbsp;·&nbsp; ".join(filter(None, [
        f'CWE: {escape(f.cwe)}' if f.cwe else "",
        f'OWASP: {escape(f.owasp)}' if f.owasp else "",
        f'Rule: <code style="font-size:11px">{escape(f.rule_id or "")}</code>' if f.rule_id else "",
    ]))

    return f"""
<div class="finding-card" {anchor}>
  <div class="finding-card-head">
    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:6px">
      {_sev_badge(sev)}
      <span style="font-size:14px;font-weight:600;color:#0f172a">{escape(f.title or "")}</span>
    </div>
    <div style="font-size:12px;color:#64748b;font-family:monospace">
      {escape(f.file or "")}:{f.line_start}{'–' + str(f.line_end) if f.line_end and f.line_end != f.line_start else ''}
      &nbsp;·&nbsp; {escape(f.tool or "")}
      {f'&nbsp;·&nbsp; conf: {escape(str(f.confidence))}' if f.confidence else ''}
    </div>
    {f'<div class="meta-row" style="margin-top:6px">{cwe_owasp}</div>' if cwe_owasp else ''}
  </div>
  <div class="finding-card-body">
    {corroborating}
    {desc_block}
    {narrative_block}
    {exploit_block}
    {remediation_block}
    {attack_paths_block}
  </div>
</div>"""


def to_html(db: Session, job_id: str) -> str:
    job = db.get(Job, job_id)
    findings = _reportable(db, job_id)
    target = job.target_name or job_id
    generated = utcnow().strftime("%Y-%m-%d %H:%M UTC")

    # Group by severity
    by_sev: dict[str, list[Finding]] = {s: [] for s in _SEV_ORDER}
    for f in findings:
        key = f.severity if f.severity in by_sev else "info"
        by_sev[key].append(f)

    sev_counts = {s: len(v) for s, v in by_sev.items()}

    # Sidebar
    sidebar_groups = ""
    for sev in _SEV_ORDER:
        items = by_sev[sev]
        if not items:
            continue
        bg, color = _SEV_COLORS[sev]
        sub_links = "".join(
            f'<a href="#finding-{f.id}">{escape((f.title or f.rule_id or "")[:45])}</a>'
            for f in items
        )
        sidebar_groups += f"""
<div class="sidebar-group">
  <a href="#sev-{sev}" style="color:{color};background:{bg}">
    {sev.upper()}
    <span class="count-badge" style="background:rgba(255,255,255,.15);color:#fff">{len(items)}</span>
  </a>
  <div class="sidebar-sub">{sub_links}</div>
</div>"""

    sidebar = f"""
<div style="padding:12px 16px;border-bottom:1px solid #e2e8f0;margin-bottom:8px">
  <div style="font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:.1em;color:#94a3b8">Trident</div>
  <div style="font-weight:700;font-size:13px;color:#0f172a;margin-top:2px">{escape(target)}</div>
  <div style="font-size:11px;color:#94a3b8;margin-top:2px">Scan Report</div>
</div>
<div class="sidebar-title">Severity</div>
{sidebar_groups}
<div style="padding:16px 12px 0;border-top:1px solid #e2e8f0;margin-top:12px">
  <a href="#top" style="font-size:11px;color:#94a3b8">↑ Top</a>
</div>"""

    # Cover
    sev_table_rows = ""
    for sev in _SEV_ORDER:
        cnt = sev_counts[sev]
        if not cnt:
            continue
        bg, color = _SEV_COLORS[sev]
        sev_table_rows += (
            f'<tr><td style="padding:8px 12px;border:1px solid #e2e8f0">'
            f'{_sev_badge(sev)}</td>'
            f'<td style="padding:8px 12px;border:1px solid #e2e8f0;font-weight:700;text-align:center">{cnt}</td></tr>\n'
        )

    cover = f"""
<header style="border-bottom:3px solid #0f172a;padding-bottom:24px;margin-bottom:32px">
  <div style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:16px">
    <div>
      <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:#64748b;margin-bottom:4px">Security Scan Report</div>
      <h1 class="cover-title" style="font-size:28px;font-weight:900;color:#0f172a">{escape(target)}</h1>
      <p style="color:#475569;margin-top:4px;font-size:14px">
        {len(findings)} confirmed finding{'s' if len(findings) != 1 else ''} &nbsp;·&nbsp; Generated {generated}
      </p>
    </div>
    <div style="text-align:right">
      <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:#64748b">Powered by</div>
      <div style="font-size:18px;font-weight:900;color:#0f172a">Trident</div>
    </div>
  </div>
  <table style="margin-top:20px;border-collapse:collapse">
    <thead>
      <tr>
        <th style="text-align:left;padding:8px 12px;background:#f1f5f9;font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:#64748b;border:1px solid #e2e8f0">Severity</th>
        <th style="text-align:center;padding:8px 12px;background:#f1f5f9;font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:#64748b;border:1px solid #e2e8f0">Count</th>
      </tr>
    </thead>
    <tbody>{sev_table_rows}</tbody>
  </table>
</header>"""

    # Sections
    sections = ""
    for sev in _SEV_ORDER:
        items = by_sev[sev]
        if not items:
            continue
        bg, color = _SEV_COLORS[sev]
        cards = "".join(_scan_finding_card(f) for f in items)
        sections += f"""
<section id="sev-{sev}" style="margin-bottom:40px">
  <div class="section-header" style="background:{bg};color:{color}">
    <span style="font-size:20px;font-weight:900">{sev.upper()}</span>
    <span style="margin-left:12px;font-size:14px;font-weight:600;opacity:.9">{len(items)} finding{'s' if len(items) != 1 else ''}</span>
  </div>
  <div style="padding:16px 0">{cards}</div>
</section>"""

    footer = f"""
<footer style="border-top:1px solid #e2e8f0;padding-top:16px;margin-top:32px;
               font-size:11px;color:#94a3b8;display:flex;justify-content:space-between">
  <span>Generated by Trident · {generated}</span>
  <span>Job {escape(job_id)}</span>
</footer>"""

    body = cover + sections + footer
    return _html_shell(f"Trident Scan Report — {target}", sidebar, body)


# ── Triage-specific exporters ─────────────────────────────────────────────────

def _triage_finding_dict(
    f: Finding, override: TriageOverride | None, job: Job | None = None,
) -> dict:
    triage = f.triage or {}
    d = _finding_dict(f, job)
    d["triage"].update({
        "fix_effort": triage.get("fix_effort"),
        "rationale": triage.get("rationale"),
        "model_impact": triage.get("model_impact"),
        "model_attack_vector": triage.get("model_attack_vector"),
    })
    d["human_override"] = {
        "original_priority": override.original_priority,
        "override_priority": override.override_priority,
        "rationale": override.rationale,
    } if override else None
    return d


def to_triage_json(db: Session, job_id: str) -> dict:
    job = db.get(Job, job_id)
    findings, overrides = _triaged_findings(db, job_id)
    overview = _triage_overview(db, job_id, findings)
    by_tier: dict[str, list] = {t: [] for t in TIERS}
    untriaged = []
    for f in findings:
        fd = _triage_finding_dict(f, overrides.get(f.id), job)
        if f.priority in by_tier:
            by_tier[f.priority].append(fd)
        else:
            untriaged.append(fd)
    tiers_out = [
        {"tier": t, **PLAYBOOK[t], "count": len(by_tier[t]), "findings": by_tier[t]}
        for t in TIERS if by_tier[t]
    ]
    return {
        "report_type": "triage",
        "generated_at": utcnow().isoformat() + "Z",
        "job": {
            "id": job_id, "target": job.target_name, "status": job.status,
            "languages": job.languages, "iterations": job.current_iteration,
            "started_at": job.started_at.isoformat() if job.started_at else None,
            "completed_at": job.completed_at.isoformat() if job.completed_at else None,
        },
        "import": _import_metadata(job),
        "summary": overview["summary"],
        "remediation_actions": _remediation_actions(db, job_id, findings),
        "tiers": tiers_out,
        "untriaged": untriaged,
        "dispositions": _disposition_report(db, job_id, job),
    }


def to_triage_table(db: Session, job_id: str) -> str:
    """Render the worked triage queue for terminal use."""
    job = db.get(Job, job_id)
    workspace = _job_workspace(job)
    findings, overrides = _triaged_findings(db, job_id)
    by_tier: dict[str, list[tuple[Finding, TriageOverride | None]]] = {
        t: [] for t in TIERS
    }
    untriaged: list[tuple[Finding, TriageOverride | None]] = []
    for finding in findings:
        pair = (finding, overrides.get(finding.id))
        if finding.priority in by_tier:
            by_tier[finding.priority].append(pair)
        else:
            untriaged.append(pair)

    false_positives = db.query(Finding).filter(
        Finding.job_id == job_id, Finding.status == "false_positive"
    ).count()
    target = job.target_name if job else job_id
    dispositions = _disposition_report(db, job_id, job)
    disposition_text = ", ".join(
        f"{status}={count}" for status, count in dispositions["counts"].items()
    ) or "none"
    lines = [
        f"Trident Triage - {target}",
        "=" * 78,
        f"Confirmed: {len(findings)} | False positives: {false_positives} | "
        f"Untriaged: {len(untriaged)}",
        f"Non-actionable dispositions: {disposition_text}",
        "Original report records are retained in JSON/SARIF/sidecar evidence fields.",
        "",
    ]
    actions = _remediation_actions(db, job_id, findings)
    lines.append(f"Remediation actions: {len(actions)}")
    for action in actions:
        label = " ".join(filter(None, [action.get("package"), action.get("version")]))
        label = label or action["action_id"]
        kev_detail = "no"
        if action.get("kev_listed"):
            kev_detail = "yes"
            if action.get("kev_sources"):
                kev_detail += f" source={','.join(action['kev_sources'])}"
            if action.get("kev_dates"):
                kev_detail += f" added={','.join(action['kev_dates'])}"
        lines.append(
            f"  {action['action_id']} | {action.get('highest_priority') or 'untriaged'} | "
            f"{label} | occurrences={action['occurrence_count']} | "
            f"KEV={kev_detail} | identity={action['identity_status']} | "
            f"evidence={action.get('evidence_basis') or 'unknown'}"
        )
    lines.append("")
    import_info = _import_metadata(job)
    if import_info:
        for item in import_info["inputs"]:
            lines.append(
                f"Input: {item.get('path')} | format={item.get('format')} | "
                f"sha256={item.get('sha256')} | records={item.get('records')}"
            )
        lines.append(
            f"Source context: {import_info.get('source_context') or 'none'} | "
            f"novel discovery={'enabled' if import_info.get('discover_novel') else 'disabled'}"
        )
        lines.append("")

    for tier in TIERS:
        items = by_tier[tier]
        playbook = PLAYBOOK[tier]
        lines.extend([
            f"{tier} ({len(items)}) - {playbook['label']}",
            f"  SLA: {playbook['sla']}",
            f"  Action: {playbook['how']}",
        ])
        for finding, override in items:
            triage = finding.triage or {}
            location = f"{finding.file or '?'}:{finding.line_start or 0}"
            factors = ", ".join(filter(None, [
                f"impact={_fl(triage.get('impact'))}" if triage.get("impact") else None,
                f"vector={_fl(triage.get('attack_vector'))}"
                if triage.get("attack_vector") else None,
                f"exploitability={_fl(triage.get('exploitability'))}"
                if triage.get("exploitability") else None,
                f"fix={_fl(triage.get('fix_effort'))}"
                if triage.get("fix_effort") else None,
                 f"reachability={_fl(triage.get('reachability'))}"
                 if triage.get("reachability") else None,
                 f"scanner-severity={finding.scanner_severity or finding.severity}"
                 if finding.scanner_severity or finding.severity else None,
                 f"model-severity={finding.model_severity}" if finding.model_severity else None,
                 "attack-chain" if triage.get("in_chain") else None,
                f"chain-basis={triage.get('chain_basis')}" if triage.get("chain_basis") else None,
            ]))
            title = finding.title or finding.rule_id or "untitled finding"
            lines.append(
                f"  - {finding.severity or 'unknown'} | {location} | {title} | "
                f"action={_action_id(finding)}"
            )
            if factors:
                lines.append(f"    {factors}")
            if finding.cwe:
                lines.append(f"    {finding.cwe} | source={finding.tool or '?'}")
            lines.append(f"    evidence: {evidence_summary(finding, workspace)}")
            if triage.get("rationale"):
                lines.append(f"    rationale: {triage['rationale']}")
            if override and override.original_priority != override.override_priority:
                lines.append(
                    f"    analyst override: {override.original_priority} -> "
                    f"{override.override_priority}"
                    + (f" ({override.rationale})" if override.rationale else "")
                )
        lines.append("")

    if untriaged:
        lines.append("Confirmed - Not Yet Triaged")
        for finding, _ in untriaged:
            lines.append(
                f"  - {finding.file or '?'}:{finding.line_start or 0} | "
                f"{finding.title or finding.rule_id or 'untitled finding'}"
            )

    return "\n".join(lines).rstrip() + "\n"


def to_triage_sarif(db: Session, job_id: str) -> dict:
    job = db.get(Job, job_id)
    workspace = _job_workspace(job)
    findings, overrides = _triaged_findings(db, job_id)
    triage_overview = _triage_overview(db, job_id, findings)
    rules: dict[str, dict] = {}
    for f in findings:
        if f.rule_id in rules:
            continue
        tags = ["security"]
        if f.cwe:
            tags.append(f"external/cwe/{f.cwe.lower()}")
        rules[f.rule_id] = {
            "id": f.rule_id, "name": f.rule_id,
            "shortDescription": {"text": (f.title or f.rule_id)[:120]},
            "properties": {"tags": tags, "cwe": f.cwe},
        }
    rule_index = {rid: i for i, rid in enumerate(rules)}

    results = []
    for f in findings:
        triage = f.triage or {}
        override = overrides.get(f.id)
        msg_parts = [f.title or f.rule_id]
        if triage.get("rationale"):
            msg_parts.append(f"\n\n**Council Rationale:** {triage['rationale']}")
        if triage.get("fix_effort"):
            msg_parts.append(f"\n\n**Fix effort:** {triage['fix_effort']}")
        guard_notes = [n for n in (triage.get("corpus_guard"), triage.get("guard"), triage.get("reach_guard")) if n]
        if guard_notes:
            msg_parts.append("\n\n**Triage adjustments:**\n" + "\n".join(f"• {n}" for n in guard_notes))
        if override and override.original_priority != override.override_priority:
            msg_parts.append(
                f"\n\n⚠ **Analyst override:** {override.original_priority} → "
                f"{override.override_priority}"
                + (f": {override.rationale}" if override.rationale else "")
            )
        results.append({
            "ruleId": f.rule_id,
            "ruleIndex": rule_index.get(f.rule_id, 0),
            "level": _TIER_LEVEL.get(f.priority or "", _sarif_level(f.severity)),
            "message": {"markdown": "".join(msg_parts), "text": f.title or f.rule_id},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.file},
                "region": {"startLine": max(1, f.line_start or 1),
                           "endLine": max(1, f.line_end or f.line_start or 1)},
            }}],
            "partialFingerprints": {"primaryLocationLineHash": f.hash},
            "properties": {
                "priority": f.priority, "tool": f.tool, "severity": f.severity,
                "scanner_severity": f.scanner_severity or f.severity,
                "model_severity": f.model_severity,
                "remediation_action_id": _action_id(f),
                "import_metadata": imported_metadata(f),
                "confidence": f.confidence, "cwe": f.cwe, "owasp": f.owasp,
                "status": f.status, "iteration": f.iteration,
                "corroborating_tools": f.corroborating_tools or [],
                "narrative": f.narrative, "remediation": f.remediation,
                "exploit_scenario": f.exploit_scenario, "attack_paths": f.attack_paths or [],
                "canonical_id": f.canonical_id,
                "correlation": (f.raw_outputs or {}).get("correlation") or {},
                "disposition": disposition_for_status(f.status),
                "review": _review_payload(f),
                "evidence": build_evidence_payload(f, workspace),
                "triage": {
                    "impact": triage.get("impact"),
                    "attack_vector": triage.get("attack_vector"),
                    "exploitability": triage.get("exploitability"),
                    "fix_effort": triage.get("fix_effort"),
                    "rationale": triage.get("rationale"),
                    "model_impact": triage.get("model_impact"),
                    "model_attack_vector": triage.get("model_attack_vector"),
                    "in_chain": triage.get("in_chain", False),
                    "reachability": triage.get("reachability"),
                    "contested": triage.get("contested", False),
                    "guard": triage.get("guard"),
                    "class_guard": triage.get("guard"),
                    "corpus_guard": triage.get("corpus_guard"),
                    "reach_guard": triage.get("reach_guard"),
                    "import_evidence_conflict": triage.get("import_evidence_conflict"),
                    "evidence_basis": triage.get("evidence_basis") or evidence_basis(f, workspace),
                    "chain_basis": triage.get("chain_basis"),
                    "chain_member_count": triage.get("chain_member_count", 0),
                    "chain_priority_eligible": triage.get("chain_priority_eligible", False),
                    "chain_priority_suppressed_reason": triage.get("chain_priority_suppressed_reason"),
                    "kev_floor": triage.get("kev_floor"),
                },
                "human_override": {
                    "original_priority": override.original_priority,
                    "override_priority": override.override_priority,
                    "rationale": override.rationale,
                } if override else None,
            },
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {
            "name": "Trident (triage)", "version": __version__,
            "rules": list(rules.values()),
        }}, "results": results, "properties": {
            "triage": triage_overview,
            "remediation_actions": _remediation_actions(db, job_id, findings),
            "import": _import_metadata(job),
            "dispositions": _disposition_report(db, job_id, job),
        }}],
    }


def _triage_finding_card(f: Finding, t: str, override) -> str:
    triage = f.triage or {}
    sev_bg, _ = _SEV_COLORS.get(f.severity or "info", ("#1e293b", "#94a3b8"))

    factors = " &nbsp;|&nbsp; ".join(filter(None, [
        _factor_chip("Vector", triage.get("attack_vector")),
        _factor_chip("Impact", triage.get("impact")),
        _factor_chip("Exploitability", triage.get("exploitability")),
        _factor_chip("Fix effort", triage.get("fix_effort")),
        _factor_chip("Reachability", triage.get("reachability")),
    ]))

    cwe_owasp = " &nbsp;·&nbsp; ".join(filter(None, [
        f'<span style="color:#475569">CWE: {escape(f.cwe)}</span>' if f.cwe else "",
        f'<span style="color:#475569">OWASP: {escape(f.owasp)}</span>' if f.owasp else "",
        f'<span style="color:#475569">Rule: <code>{escape(f.rule_id or "")}</code></span>' if f.rule_id else "",
    ]))

    rationale_block = ""
    if triage.get("rationale"):
        rationale_block = (
            '<div style="margin-top:12px">'
            '<div style="font-size:10px;font-weight:700;text-transform:uppercase;'
            'letter-spacing:.06em;color:#64748b;margin-bottom:4px">Council Rationale</div>'
            f'<p style="font-size:13px;color:#334155;line-height:1.6;margin:0">'
            f'{escape(triage["rationale"])}</p></div>'
        )

    exploit_block = ""
    if f.exploit_scenario:
        exploit_block = (
            '<div class="callout-orange">'
            '<div class="callout-label" style="color:#92400e">How It Could Be Exploited</div>'
            f'<div class="callout-text">{escape(f.exploit_scenario)}</div>'
            '</div>'
        )

    remediation_block = ""
    if f.remediation:
        remediation_block = (
            '<div class="callout-green">'
            '<div class="callout-label" style="color:#166534">Remediation</div>'
            f'<div class="callout-text">{escape(f.remediation)}</div>'
            '</div>'
        )

    chain_block = ""
    if triage.get("in_chain"):
        chain_block = (
            '<div style="margin-top:10px">'
            '<span style="background:#ede9fe;color:#5b21b6;padding:3px 10px;'
            'border-radius:4px;font-size:11px;font-weight:700">⛓ Attack chain member — bumped one tier</span>'
            '</div>'
        )

    override_block = ""
    if override and override.original_priority != override.override_priority:
        note = f": {escape(override.rationale)}" if override.rationale else ""
        override_block = (
            f'<div style="margin-top:10px;background:#fefce8;border:1px solid #fde047;'
            f'padding:8px 12px;border-radius:4px;font-size:12px;color:#713f12">'
            f'⚠ <b>Analyst override:</b> {escape(override.original_priority)} → '
            f'{escape(override.override_priority)}{note}</div>'
        )

    return f"""
<div class="finding-card" id="finding-{f.id}">
  <div class="finding-card-head">
    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:6px">
      {_tier_badge(t)}
      {_sev_badge(f.severity or "info")}
      <span style="font-size:14px;font-weight:600;color:#0f172a">{escape(f.title or "")}</span>
    </div>
    <div style="font-size:12px;color:#64748b;font-family:monospace">
      {escape(f.file or "")}:{f.line_start}{'–' + str(f.line_end) if f.line_end and f.line_end != f.line_start else ''}
      &nbsp;·&nbsp; {escape(f.tool or "")}
    </div>
  </div>
  <div class="finding-card-body">
    <div class="factor-row">{factors}</div>
    {f'<div class="meta-row">{cwe_owasp}</div>' if cwe_owasp else ''}
    {rationale_block}{exploit_block}{remediation_block}{chain_block}{override_block}
  </div>
</div>"""


def to_triage_html(db: Session, job_id: str) -> str:
    job = db.get(Job, job_id)
    findings, overrides = _triaged_findings(db, job_id)

    by_tier: dict[str, list[tuple]] = {t: [] for t in TIERS}
    untriaged = []
    for f in findings:
        pair = (f, overrides.get(f.id))
        if f.priority in by_tier:
            by_tier[f.priority].append(pair)
        else:
            untriaged.append(pair)

    target = escape(job.target_name or job_id)
    generated = utcnow().strftime("%Y-%m-%d %H:%M UTC")
    total = len(findings)

    # Sidebar
    sidebar_groups = ""
    for t in TIERS:
        items = by_tier[t]
        if not items:
            continue
        bg, color = _TIER_COLORS[t]
        sub_links = "".join(
            f'<a href="#finding-{f.id}">{escape((f.title or f.rule_id or "")[:45])}</a>'
            for f, _ in items
        )
        sidebar_groups += f"""
<div class="sidebar-group">
  <a href="#tier-{t}" style="color:{color};background:{bg}">
    {t}
    <span class="count-badge" style="background:rgba(255,255,255,.15);color:#fff">{len(items)}</span>
  </a>
  <div class="sidebar-sub">{sub_links}</div>
</div>"""

    sidebar = f"""
<div style="padding:12px 16px;border-bottom:1px solid #e2e8f0;margin-bottom:8px">
  <div style="font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:.1em;color:#94a3b8">Trident</div>
  <div style="font-weight:700;font-size:13px;color:#0f172a;margin-top:2px">{target}</div>
  <div style="font-size:11px;color:#94a3b8;margin-top:2px">Triage Report</div>
</div>
<div class="sidebar-title">Priority Tier</div>
{sidebar_groups}
<div style="padding:16px 12px 0;border-top:1px solid #e2e8f0;margin-top:12px">
  <a href="#top" style="font-size:11px;color:#94a3b8">↑ Top</a>
</div>"""

    # Cover summary table
    summary_rows = ""
    for t in TIERS:
        cnt = len(by_tier[t])
        if not cnt:
            continue
        pb = PLAYBOOK[t]
        summary_rows += (
            f'<tr><td style="padding:8px 12px;border:1px solid #e2e8f0">{_tier_badge(t)}</td>'
            f'<td style="padding:8px 12px;border:1px solid #e2e8f0;font-weight:600">{escape(pb["label"])}</td>'
            f'<td style="padding:8px 12px;border:1px solid #e2e8f0;color:#475569">{escape(pb["sla"])}</td>'
            f'<td style="padding:8px 12px;border:1px solid #e2e8f0;font-weight:700;text-align:center">{cnt}</td></tr>\n'
        )

    cover = f"""
<header style="border-bottom:3px solid #0f172a;padding-bottom:24px;margin-bottom:32px">
  <div style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:16px">
    <div>
      <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:#64748b;margin-bottom:4px">Security Triage Report</div>
      <h1 class="cover-title" style="font-size:28px;font-weight:900;color:#0f172a">{target}</h1>
      <p style="color:#475569;margin-top:4px;font-size:14px">
        {total} confirmed finding{'s' if total != 1 else ''} &nbsp;·&nbsp; Generated {generated}
      </p>
    </div>
    <div style="text-align:right">
      <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:#64748b">Powered by</div>
      <div style="font-size:18px;font-weight:900;color:#0f172a">Trident</div>
    </div>
  </div>
  <table style="margin-top:20px;border-collapse:collapse;width:100%">
    <thead>
      <tr>
        <th style="text-align:left;padding:8px 12px;background:#f1f5f9;font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:#64748b;border:1px solid #e2e8f0">Tier</th>
        <th style="text-align:left;padding:8px 12px;background:#f1f5f9;font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:#64748b;border:1px solid #e2e8f0">Label</th>
        <th style="text-align:left;padding:8px 12px;background:#f1f5f9;font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:#64748b;border:1px solid #e2e8f0">SLA</th>
        <th style="text-align:center;padding:8px 12px;background:#f1f5f9;font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:#64748b;border:1px solid #e2e8f0">Count</th>
      </tr>
    </thead>
    <tbody>{summary_rows}</tbody>
  </table>
</header>"""

    # Tier sections
    tier_sections = ""
    for t in TIERS:
        items = by_tier[t]
        if not items:
            continue
        bg, color = _TIER_COLORS[t]
        pb = PLAYBOOK[t]
        cards = "".join(_triage_finding_card(f, t, override) for f, override in items)
        tier_sections += f"""
<section id="tier-{t}" style="margin-bottom:40px">
  <div class="section-header" style="background:{bg};color:{color}">
    <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px">
      <div>
        <span style="font-size:22px;font-weight:900">{t}</span>
        <span style="font-size:16px;font-weight:600;margin-left:12px">{escape(pb['label'])}</span>
      </div>
      <span style="font-size:12px;opacity:.8">SLA: {escape(pb['sla'])} &nbsp;·&nbsp; {len(items)} finding{'s' if len(items) != 1 else ''}</span>
    </div>
    <p style="font-size:12px;margin:8px 0 0;opacity:.85">▸ {escape(pb['how'])}</p>
  </div>
  <div style="padding:16px 0">{cards}</div>
</section>"""

    # Untriaged
    untriaged_section = ""
    if untriaged:
        rows = "".join(
            f'<tr><td style="font-size:12px;font-family:monospace;color:#64748b;padding:8px;border:1px solid #e2e8f0">'
            f'{escape(f.file or "")}:{f.line_start}</td>'
            f'<td style="font-size:13px;padding:8px;border:1px solid #e2e8f0">{escape(f.title or "")}</td></tr>'
            for f, _ in untriaged
        )
        untriaged_section = f"""
<section style="margin-bottom:40px">
  <h2 style="color:#64748b;border-bottom:1px solid #e2e8f0;padding-bottom:8px;margin-bottom:12px">
    Confirmed — Not Yet Triaged ({len(untriaged)})
  </h2>
  <table style="width:100%;border-collapse:collapse">
    <tr>
      <th style="text-align:left;padding:8px;background:#f1f5f9;font-size:12px;border:1px solid #e2e8f0">Location</th>
      <th style="text-align:left;padding:8px;background:#f1f5f9;font-size:12px;border:1px solid #e2e8f0">Title</th>
    </tr>
    {rows}
  </table>
</section>"""

    footer = f"""
<footer style="border-top:1px solid #e2e8f0;padding-top:16px;margin-top:32px;
               font-size:11px;color:#94a3b8;display:flex;justify-content:space-between">
  <span>Generated by Trident · {generated}</span>
  <span>Job {escape(job_id)}</span>
</footer>"""

    body = cover + tier_sections + untriaged_section + footer
    return _html_shell(f"Trident Triage Report — {target}", sidebar, body)


# ── PDF exporters ─────────────────────────────────────────────────────────────

def to_pdf(db: Session, job_id: str) -> bytes:
    from trident.reporters.pdf_builder import build_scan_pdf  # noqa: PLC0415
    job = db.get(Job, job_id)
    findings = _reportable(db, job_id)
    return build_scan_pdf(job, findings)


def to_triage_pdf(db: Session, job_id: str) -> bytes:
    from trident.reporters.pdf_builder import build_triage_pdf  # noqa: PLC0415
    job = db.get(Job, job_id)
    findings, overrides = _triaged_findings(db, job_id)
    return build_triage_pdf(job, findings, overrides)
