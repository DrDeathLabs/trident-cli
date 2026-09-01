"""WS0: eval ruler correctness — decoy handling, CWE normalization, multi-signal match."""

from __future__ import annotations

from trident.eval.matcher import Scorecard, ScorecardItem, match_findings


def _sc(*items):
    return Scorecard(target_id="t", version="1", vulns=list(items))


def _item(id, cwe, file, ls, desc, planted=True):
    return ScorecardItem(id=id, cwe=cwe, owasp="", severity="high", title=id,
                         file=file, line_start=ls, line_end=ls, description=desc,
                         expected_by=["semgrep"], planted=planted)


def _f(fid, cwe, file, ls, desc, tool="semgrep"):
    return {"id": fid, "tool": tool, "rule_id": "r", "severity": "high", "title": desc,
            "description": desc, "file": file, "line_start": ls, "line_end": ls,
            "cwe": cwe, "status": "confirmed", "iteration": 0}


def test_decoy_excluded_from_recall_denominator():
    sc = _sc(
        _item("V1", "CWE-89", "app/main.py", 10, "sql injection via concatenation"),
        _item("DECOY", "CWE-400", "app/main.py", 1, "unbounded body size", planted=False),
    )
    findings = [_f("f1", "CWE-89", "app/main.py", 10, "sql injection via concatenation")]
    r = match_findings(sc, findings)
    assert r["total_planted"] == 1  # decoy NOT counted
    assert r["recall"] == 1.0


def test_matching_decoy_is_reported_not_a_detection():
    sc = _sc(
        _item("V1", "CWE-89", "app/main.py", 10, "sql injection"),
        _item("DECOY", "CWE-400", "other.py", 5, "unbounded request body size", planted=False),
    )
    findings = [
        _f("f1", "CWE-89", "app/main.py", 10, "sql injection"),
        _f("f2", "CWE-400", "other.py", 5, "unbounded request body size"),
    ]
    r = match_findings(sc, findings)
    assert r["total_detected"] == 1          # only the planted one
    assert len(r["decoy_hits"]) == 1         # decoy match flagged as FP-resistance failure


def test_precision_is_confirmed_only_denominator():
    sc = _sc(_item("V1", "CWE-89", "app/main.py", 10, "sql injection"))
    findings = [
        _f("f1", "CWE-89", "app/main.py", 10, "sql injection"),
        _f("f2", "CWE-79", "app/x.py", 3, "some xss finding"),  # unmatched confirmed => FP
    ]
    r = match_findings(sc, findings)
    assert r["total_findings"] == 2
    assert r["precision"] == 0.5


def test_cwe_html_suffix_normalized_and_matches():
    sc = _sc(_item("V1", "CWE-502", "app/main.py", 95, "insecure deserialization via pickle"))
    # bandit-style CWE with a stray '.html' suffix must still match after normalization.
    findings = [_f("f1", "CWE-502.html", "app/main.py", 95, "pickle load of untrusted data", tool="bandit")]
    r = match_findings(sc, findings)
    assert r["total_detected"] == 1


def test_line_proximity_alone_does_not_match():
    # Same file + adjacent line but a totally unrelated CWE and description must NOT match.
    sc = _sc(_item("V1", "CWE-89", "app/main.py", 10, "sql injection via string concatenation"))
    findings = [_f("f1", "CWE-1021", "app/main.py", 11, "missing content security policy header")]
    r = match_findings(sc, findings)
    assert r["total_detected"] == 0
