"""Smoke tests for Trident core (no network — uses MockLLMBackend).

Run:  python tests/test_smoke.py   (from the backend/ directory)
"""

from __future__ import annotations

import os
import sys

# Force mock LLM BEFORE any trident import, and pin the backend singleton.
os.environ["TRIDENT_LLM_MOCK"] = "1"
_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from trident.llm.base import MockLLMBackend  # noqa: E402
import trident.llm.base as _base  # noqa: E402
_base._llm = MockLLMBackend()


def test_eval_matcher_exact_cwe():
    """The matcher should match a finding to a scorecard item by file+CWE+description."""
    from trident.eval.matcher import Scorecard, ScorecardItem, match_findings

    sc = Scorecard(target_id="t", version="1", vulns=[
        ScorecardItem(id="V1", cwe="CWE-89", owasp="", severity="high",
                      title="SQL injection in user search endpoint", file="app/main.py",
                      line_start=10, line_end=15,
                      description="The search endpoint builds a SQL query by string concatenation of user input into a SELECT statement, enabling SQL injection.",
                      expected_by=["semgrep"], planted=True),
    ])
    findings = [{
        "id": "f1", "tool": "semgrep", "rule_id": "python.sql-injection",
        "severity": "high", "title": "SQL injection",
        "description": "The search endpoint builds a SQL query by string concatenation of user input into a SELECT statement, enabling SQL injection.",
        "file": "app/main.py", "line_start": 10, "line_end": 15,
        "cwe": "CWE-89", "status": "confirmed", "iteration": 0,
    }]
    result = match_findings(sc, findings)
    assert result["total_planted"] == 1, f"planted={result['total_planted']}"
    assert result["total_detected"] == 1, f"detected={result['total_detected']} missed={result['missed']}"
    assert result["recall"] == 1.0
    assert len(result["matched"]) == 1
    assert len(result["missed"]) == 0
    assert len(result["false_positives"]) == 0


def test_eval_matcher_misses_wrong_cwe():
    """A finding in a different file with a non-matching CWE should miss."""
    from trident.eval.matcher import Scorecard, ScorecardItem, match_findings

    sc = Scorecard(target_id="t", version="1", vulns=[
        ScorecardItem(id="V1", cwe="CWE-89", owasp="", severity="high",
                      title="SQL injection in user search endpoint", file="app/main.py",
                      line_start=10, line_end=15,
                      description="SQL injection via string concatenation of user input into a SELECT statement.",
                      expected_by=["semgrep"], planted=True),
    ])
    findings = [{
        "id": "f1", "tool": "semgrep", "rule_id": "x",
        "severity": "low", "title": "Missing Content-Security-Policy header",
        "description": "The application does not set a Content-Security-Policy HTTP response header.",
        "file": "other.py", "line_start": 1, "line_end": 1,
        "cwe": "CWE-1021", "status": "confirmed", "iteration": 0,
    }]
    result = match_findings(sc, findings)
    assert result["total_detected"] == 0
    assert result["recall"] == 0.0
    assert len(result["missed"]) == 1
    assert len(result["false_positives"]) == 1


def test_eval_matcher_normalizes_windows_absolute_paths():
    """A Windows scan path still matches a relative scorecard path."""
    from trident.eval.matcher import Scorecard, ScorecardItem, match_findings

    sc = Scorecard(target_id="t", version="1", vulns=[
        ScorecardItem(id="V1", cwe="CWE-89", owasp="", severity="high",
                      title="SQL injection", file="app/main.py", line_start=10, line_end=15,
                      description="SQL injection via user input.", expected_by=["semgrep"],
                      planted=True),
    ])
    findings = [{
        "id": "f1", "tool": "semgrep", "rule_id": "python.sql-injection",
        "severity": "high", "title": "SQL injection",
        "description": "SQL injection via user input.",
        "file": r"C:\temp\pygoat\app\main.py", "line_start": 10, "line_end": 15,
        "cwe": "CWE-89", "status": "confirmed", "iteration": 0,
    }]
    result = match_findings(sc, findings)
    assert result["total_detected"] == 1
    assert result["recall"] == 1.0


def test_mock_llm_backend():
    """The MockLLMBackend returns schema-valid JSON without network."""
    import json
    from trident.llm.base import ChatMessage

    backend = MockLLMBackend()
    resp = backend.chat([ChatMessage("user", "hello")], model="glm-5.2:cloud")
    data = json.loads(resp.content)  # must be valid JSON now
    assert data["verdict"] == "confirmed"
    assert backend.health()["status"] == "ok"


def test_convergence_max_iterations():
    """Convergence should stop when iteration >= max_iterations."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from trident.models import Base, Job
    from trident.convergence import evaluate_convergence

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    db.add(Job(id="j1", target_name="t", source_type="demo", source_ref="", workspace_path="/tmp"))
    db.commit()

    # A raw finding remains (unresolved) so only the max-iterations rule can stop it.
    from trident.models import Finding
    db.add(Finding(id="fx", job_id="j1", hash="h", tool="semgrep", rule_id="r",
                   title="t", file="a.py", status="raw"))
    db.commit()
    res = evaluate_convergence(db, "j1", iteration=3, max_iterations=3,
                               min_new_findings=2, prev_disputed=0)
    assert res.converged is True
    assert "max_iterations" in res.reason
    db.close()


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  PASS {name}")
    print("\nAll smoke tests passed.")
