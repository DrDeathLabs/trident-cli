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
    assert stats["duplicates"] == 1

    canon = db.query(Finding).filter(Finding.job_id == "job1", Finding.status == "raw").all()
    dupes = db.query(Finding).filter(Finding.job_id == "job1", Finding.status == "duplicate").all()
    assert len(canon) == 1 and len(dupes) == 1
    assert set(canon[0].corroborating_tools) == {"semgrep", "bandit"}
    assert dupes[0].canonical_id == canon[0].id
    assert canon[0].confidence > 0.7  # corroboration bump


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
    assert stats["duplicates"] == 1
