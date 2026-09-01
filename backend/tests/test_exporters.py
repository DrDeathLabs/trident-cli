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
    assert finding["triage"]["class_guard"] == "hygiene-class: best-practice"
    assert finding["triage"]["corpus_guard"] is None


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
        "triaged": 1,
        "false_positives": 1,
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
