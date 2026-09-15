"""Reporting — confirmed-only exports, HTML escaping, SARIF rules, priority fields."""

from __future__ import annotations

from trident.reporters.exporters import (
    to_html,
    to_json,
    to_sarif,
    to_triage_json,
    to_triage_sarif,
    to_triage_table,
)
from tests.conftest import make_finding


def test_reports_exclude_false_positives(db, job):
    make_finding(db, status="confirmed", title="real sqli")
    make_finding(db, status="false_positive", title="refuted noise")
    make_finding(db, status="raw", title="unreviewed")

    sarif = to_sarif(db, "job1")
    titles = {r["message"]["text"] for r in sarif["runs"][0]["results"]}
    assert titles == {"real sqli"}

    js = to_json(db, "job1")
    assert [f["title"] for f in js["findings"]] == ["real sqli"]


def test_html_escapes_llm_authored_title(db, job):
    make_finding(db, status="confirmed", title="<script>alert(1)</script>", file="a.py")
    html = to_html(db, "job1")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_sarif_has_rules_catalog_with_cwe_tags(db, job):
    make_finding(db, status="confirmed", rule_id="py.sqli", cwe="CWE-89")
    sarif = to_sarif(db, "job1")
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    assert any(r["id"] == "py.sqli" for r in rules)
    assert any("external/cwe/cwe-89" in r["properties"]["tags"] for r in rules)


# ---------------------------------------------------------------------------
# Priority in SARIF level
# ---------------------------------------------------------------------------

def test_sarif_level_uses_priority_over_severity(db, job):
    # P2 finding with critical severity: level must be "warning" (from P2), not "error"
    make_finding(db, status="confirmed", severity="critical", priority="P2")
    result = to_sarif(db, "job1")["runs"][0]["results"][0]
    assert result["level"] == "warning"


def test_sarif_level_p0_is_error(db, job):
    make_finding(db, status="confirmed", severity="low", priority="P0")
    result = to_sarif(db, "job1")["runs"][0]["results"][0]
    assert result["level"] == "error"


def test_sarif_level_p4_is_note(db, job):
    make_finding(db, status="confirmed", severity="high", priority="P4")
    result = to_sarif(db, "job1")["runs"][0]["results"][0]
    assert result["level"] == "note"


def test_sarif_level_falls_back_to_severity_when_no_priority(db, job):
    make_finding(db, status="confirmed", severity="critical", priority=None)
    result = to_sarif(db, "job1")["runs"][0]["results"][0]
    assert result["level"] == "error"   # critical severity → error


# ---------------------------------------------------------------------------
# Guard notes in SARIF message
# ---------------------------------------------------------------------------

def test_sarif_guard_notes_appear_in_message_markdown(db, job):
    make_finding(db, status="confirmed", triage={
        "corpus_guard": "↑ CWE-89 population median is P1; raised from P3",
        "guard": None,
        "reach_guard": "reachability: no call path from HTTP entry point — capped to local",
        "impact": "data_exposure", "attack_vector": "local",
        "exploitability": "moderate", "in_chain": False, "reachability": "unreachable",
    })
    result = to_sarif(db, "job1")["runs"][0]["results"][0]
    md = result["message"]["markdown"]
    assert "CWE-89" in md
    assert "reachability" in md


def test_sarif_no_guard_note_section_when_no_guards_fired(db, job):
    make_finding(db, status="confirmed", triage={
        "corpus_guard": None, "guard": None, "reach_guard": None,
        "impact": "rce", "attack_vector": "remote_unauth",
        "exploitability": "trivial", "in_chain": False, "reachability": "reachable",
    })
    result = to_sarif(db, "job1")["runs"][0]["results"][0]
    assert "Triage adjustments" not in result["message"]["markdown"]


# ---------------------------------------------------------------------------
# Priority in JSON output
# ---------------------------------------------------------------------------

def test_json_includes_priority(db, job):
    make_finding(db, status="confirmed", priority="P1")
    data = to_json(db, "job1")
    assert data["findings"][0]["priority"] == "P1"


def test_json_triage_block_present(db, job):
    make_finding(db, status="confirmed", priority="P2", triage={
        "impact": "rce", "attack_vector": "remote_unauth", "exploitability": "trivial",
        "guard": "hygiene-class: best-practice", "corpus_guard": None,
        "reach_guard": None, "in_chain": False, "reachability": "unknown",
    })
    finding = to_json(db, "job1")["findings"][0]
    assert finding["triage"]["impact"] == "rce"
    assert finding["triage"]["guard"] == "hygiene-class: best-practice"
    assert finding["triage"]["class_guard"] == "hygiene-class: best-practice"
    assert finding["triage"]["corpus_guard"] is None


def test_json_exposes_evidence_basis_and_original_import_record(db, job):
    make_finding(db, status="confirmed", tool="dependency-check", rule_id="CVE-2026-0001",
                 raw_outputs={"raw": {
                     "import_format": "dependency-check", "package": "demo",
                     "InstalledVersion": "1.0.0",
                     "dependency": {"fileName": "requirements.txt"},
                     "record": {"name": "CVE-2026-0001", "cvssv3": {"baseScore": 9.8}},
                 }},
                 triage={"evidence_basis": "report_only"})
    data = to_json(db, "job1")
    finding = data["findings"][0]
    assert finding["disposition"] == "retained_for_remediation"
    assert finding["evidence"]["basis"] == "report_only"
    assert finding["evidence"]["import"]["record"]["cvssv3"]["baseScore"] == 9.8
    assert "confirmed" not in data["dispositions"]["counts"]


def test_reports_expose_non_actionable_dispositions_with_evidence(db, job):
    make_finding(db, status="false_positive", tool="sonarqube", rule_id="S001",
                 raw_outputs={"raw": {
                     "import_format": "sonarqube",
                     "record": {"rule": "S001", "status": "OPEN"},
                 }})
    data = to_triage_json(db, "job1")
    assert data["dispositions"]["counts"] == {"false_positive": 1}
    record = data["dispositions"]["records"][0]
    assert record["disposition"] == "rejected_by_review"
    assert record["evidence"]["import"]["record"]["rule"] == "S001"
    sarif = to_sarif(db, "job1")
    assert sarif["runs"][0]["properties"]["dispositions"]["counts"] == {"false_positive": 1}


def test_json_triage_block_tolerates_null_triage(db, job):
    f = make_finding(db, status="confirmed")
    f.triage = None
    db.commit()
    finding = to_json(db, "job1")["findings"][0]
    assert finding["triage"]["impact"] is None
    assert finding["triage"]["in_chain"] is False


def test_scan_reports_include_triage_overview(db, job):
    make_finding(db, status="confirmed", priority="P0", title="urgent sqli")
    make_finding(db, status="false_positive", title="refuted noise")

    json_report = to_json(db, "job1")
    assert json_report["triage"]["summary"] == {
        "total_confirmed": 1,
        "accounted_records": 2,
        "reviewed_records": 2,
        "triage_candidates": 1,
        "triaged": 1,
        "priority_assigned": 1,
        "retained_for_remediation": 1,
        "false_positives": 1,
        "out_of_scope": 0,
        "duplicate_records": 0,
        "related_records": 0,
        "remediation_groups": 1,
        "remediation_occurrences": 1,
        "by_tier": {"P0": 1, "P1": 0, "P2": 0, "P3": 0, "P4": 0},
    }
    sarif = to_sarif(db, "job1")
    assert sarif["runs"][0]["properties"]["triage"]["summary"]["false_positives"] == 1


def test_triage_report_formats_include_playbook_and_details(db, job):
    make_finding(db, status="confirmed", priority="P0", title="urgent sqli", triage={
        "impact": "rce", "attack_vector": "remote_unauth", "exploitability": "trivial",
        "fix_effort": "trivial", "rationale": "Immediate action required.",
        "in_chain": True, "reachability": "reachable",
    })

    triage_json = to_triage_json(db, "job1")
    assert triage_json["report_type"] == "triage"
    assert triage_json["summary"]["by_tier"]["P0"] == 1
    assert triage_json["tiers"][0]["sla"] == "Immediate (out-of-band)"
    assert triage_json["tiers"][0]["findings"][0]["triage"]["fix_effort"] == "trivial"

    triage_sarif = to_triage_sarif(db, "job1")
    assert triage_sarif["runs"][0]["tool"]["driver"]["name"] == "Trident (triage)"
    assert triage_sarif["runs"][0]["properties"]["triage"]["summary"]["by_tier"]["P0"] == 1

    triage_table = to_triage_table(db, "job1")
    assert "Trident Triage" in triage_table
    assert "Immediate (out-of-band)" in triage_table
    assert "Immediate action required." in triage_table


def test_triage_sidecar_retains_correlation_summary(db, job):
    make_finding(db, status="confirmed", priority="P1")
    make_finding(db, status="related")
    make_finding(db, status="duplicate")
    make_finding(db, status="false_positive")

    data = to_triage_json(db, "job1")
    assert data["summary"] == {
        "total_confirmed": 1,
        "accounted_records": 4,
        "reviewed_records": 4,
        "triage_candidates": 1,
        "triaged": 1,
        "priority_assigned": 1,
        "retained_for_remediation": 1,
        "false_positives": 1,
        "out_of_scope": 0,
        "duplicate_records": 1,
        "related_records": 1,
        "remediation_groups": 1,
        "remediation_occurrences": 1,
        "by_tier": {"P0": 0, "P1": 1, "P2": 0, "P3": 0, "P4": 0},
    }


def test_triage_summary_accounts_dispositioned_only_scan(db, job):
    make_finding(db, status="out_of_scope")
    make_finding(db, status="related")

    summary = to_json(db, job.id)["triage"]["summary"]

    assert summary["accounted_records"] == 2
    assert summary["reviewed_records"] == 2
    assert summary["triage_candidates"] == 0
    assert summary["triaged"] == 0
    assert summary["retained_for_remediation"] == 0
    assert summary["false_positives"] == 0
    assert summary["out_of_scope"] == 1
    assert summary["related_records"] == 1


def test_sarif_triage_exposes_all_adjustment_fields(db, job):
    make_finding(db, status="confirmed", priority="P2", triage={
        "impact": "injection", "attack_vector": "remote_auth",
        "exploitability": "moderate", "fix_effort": "moderate",
        "model_impact": "other", "model_attack_vector": "remote_unauth",
        "guard": "class correction", "corpus_guard": "corpus correction",
        "reach_guard": "reach correction", "reachability": "unknown",
        "contested": True,
    })
    triage = to_triage_sarif(db, "job1")["runs"][0]["results"][0]["properties"]["triage"]
    assert triage["guard"] == "class correction"
    assert triage["class_guard"] == "class correction"
    assert triage["corpus_guard"] == "corpus correction"
    assert triage["reach_guard"] == "reach correction"
    assert triage["model_impact"] == "other"
    assert triage["contested"] is True


def test_reports_preserve_separate_severities_and_import_metadata(db, job):
    make_finding(
        db, status="confirmed", severity="critical", scanner_severity="critical",
        model_severity="info", tool="dependency-check", rule_id="CVE-1",
        raw_outputs={"raw": {
            "import_format": "dependency-check", "package": "library",
            "InstalledVersion": "1.2.3", "kev": {
                "listed": True, "source": "imported_record", "date_added": "2024-01-02",
            },
            "cpe_identity": {"status": "match"}, "record": {"name": "CVE-1"},
        }},
    )
    data = to_json(db, job.id)
    out = data["findings"][0]
    assert out["severity"] == "critical"
    assert out["scanner_severity"] == "critical"
    assert out["model_severity"] == "info"
    assert out["import_metadata"]["kev"]["listed"] is True
    assert out["import_metadata"]["identity"]["status"] == "match"
    assert out["remediation_action_id"] == data["remediation_actions"][0]["action_id"]
    action = data["remediation_actions"][0]
    assert action["evidence_basis"] == "report_only"
    assert action["kev_sources"] == ["imported_record"]
    assert action["kev_dates"] == ["2024-01-02"]
    assert action["evidence_references"][0]["record_preserved"] is True
    assert action["rationale_references"][0]["finding_id"] == out["id"]


def test_remediation_actions_group_package_and_preserve_occurrences(db, job):
    first = make_finding(
        db, id="package-one", status="confirmed", priority="P2", tool="dependency-check",
        raw_outputs={"raw": {
            "import_format": "dependency-check", "package": "angularjs",
            "InstalledVersion": "1.6.4", "record": {"name": "CVE-1"},
        }}, file="one/package.json",
    )
    make_finding(
        db, id="package-duplicate", status="duplicate", tool="dependency-check",
        raw_outputs={"raw": {
            "import_format": "dependency-check", "package": "angularjs",
            "InstalledVersion": "1.6.4", "record": {"name": "CVE-1"},
        }}, file="two/package.json", canonical_id=first.id,
    )
    db.commit()
    data = to_triage_json(db, job.id)
    assert data["summary"]["remediation_groups"] == 1
    action = data["remediation_actions"][0]
    assert action["package"] == "angularjs"
    assert action["version"] == "1.6.4"
    assert action["occurrence_count"] == 2
    assert {occ["file"] for occ in action["occurrences"]} == {
        "one/package.json", "two/package.json",
    }


def test_code_remediation_action_is_one_per_finding(db, job):
    first = make_finding(
        db, id="code-one", status="confirmed", priority="P3", tool="semgrep",
        rule_id="python.lang.security", file="app.py", line_start=12, line_end=12,
        hash="stable-finding-hash",
    )
    second = make_finding(
        db, id="code-two", status="confirmed", priority="P3", tool="semgrep",
        rule_id="python.lang.security", file="app.py", line_start=12, line_end=12,
        hash="stable-finding-hash",
    )
    data = to_triage_json(db, job.id)
    ids = [f["remediation_action_id"] for tier in data["tiers"] for f in tier["findings"]]
    assert len(ids) == 2
    assert ids[0] != ids[1]
    assert first.id != second.id
