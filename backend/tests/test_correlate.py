"""WS2: cross-tool correlation & dedupe."""

from __future__ import annotations

from trident.correlate import correlate_findings
from trident.models import Finding
from tests.conftest import make_finding


def test_two_tools_same_line_collapse_to_one_canonical(db, job):
    # semgrep L56 and bandit L55 both flag the same SQLi (CWE-89, same file).
    make_finding(db, tool="semgrep", rule_id="sg.sqli", line_start=56, line_end=56, cwe="CWE-89")
    make_finding(db, tool="bandit", rule_id="B608", line_start=55, line_end=55, cwe="CWE-89")

    stats = correlate_findings(db, "job1")
    assert stats["duplicates"] == 0
    assert stats["related"] == 1

    canon = db.query(Finding).filter(Finding.job_id == "job1", Finding.status == "raw").all()
    related = db.query(Finding).filter(Finding.job_id == "job1", Finding.status == "related").all()
    assert len(canon) == 1 and len(related) == 1
    assert set(canon[0].corroborating_tools) == {"semgrep", "bandit"}
    assert related[0].canonical_id == canon[0].id
    assert canon[0].confidence > 0.7  # corroboration bump
    metadata = canon[0].raw_outputs["correlation"]
    assert metadata["group_size"] == 2
    assert metadata["duplicate_count"] == 0
    assert metadata["related_count"] == 1
    assert metadata["unique_record_count"] == 2
    assert metadata["aggregation_basis"].startswith("same normalized file")
    assert set(metadata["member_finding_ids"]) == {canon[0].id, related[0].id}


def test_distinct_vulns_not_merged(db, job):
    # Same file + CWE but far apart in the file -> two separate findings.
    make_finding(db, tool="semgrep", line_start=10, cwe="CWE-89")
    make_finding(db, tool="semgrep", line_start=200, cwe="CWE-89")
    stats = correlate_findings(db, "job1")
    assert stats["duplicates"] == 0
    assert stats["clusters"] == 2


def test_html_suffix_cwe_still_clusters(db, job):
    # A defensively-normalized CWE ('CWE-89' vs a stray variant) still buckets together.
    make_finding(db, tool="semgrep", line_start=20, cwe="CWE-89")
    make_finding(db, tool="bandit", line_start=21, cwe="CWE-89")
    stats = correlate_findings(db, "job1")
    assert stats["duplicates"] == 0
    assert stats["related"] == 1


def test_exact_repeated_record_is_duplicate(db, job):
    raw = {"raw": {"record": {"key": "same", "message": "same"}}}
    make_finding(db, tool="sonarqube", rule_id="S1", line_start=20, cwe="CWE-89", raw_outputs=raw)
    make_finding(db, tool="sonarqube", rule_id="S1", line_start=20, cwe="CWE-89", raw_outputs=raw)

    stats = correlate_findings(db, "job1")
    assert stats["duplicates"] == 1
    assert stats["related"] == 0
    assert db.query(Finding).filter_by(job_id="job1", status="duplicate").count() == 1


def test_distinct_same_rule_nearby_is_related_not_duplicate(db, job):
    make_finding(db, tool="sonarqube", rule_id="S6813", line_start=20, cwe="CWE-381")
    make_finding(db, tool="sonarqube", rule_id="S6813", line_start=23, cwe="CWE-381")

    stats = correlate_findings(db, "job1")
    assert stats["duplicates"] == 0
    assert stats["related"] == 1
    assert db.query(Finding).filter_by(job_id="job1", status="related").count() == 1


def test_imported_dependency_versions_are_not_collapsed(db, job):
    for finding_id, version, cve in (
        ("dep-v1", "1.0.0", "CVE-1"),
        ("dep-v2", "2.0.0", "CVE-2"),
    ):
        make_finding(
            db, id=finding_id, tool="dependency-check", rule_id=cve,
            file="pom.xml", raw_outputs={"raw": {
                "import_format": "dependency-check",
                "package": "example-lib", "InstalledVersion": version,
                "record": {"name": cve},
            }},
        )

    stats = correlate_findings(db, "job1")
    assert stats["dep_packages"] == 2
    assert stats["duplicates"] == 0
    assert db.query(Finding).filter_by(job_id="job1", status="raw").count() == 2
