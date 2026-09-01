"""WS4: real deliberation — judge-skip, cross-examination, parse-error handling."""

from __future__ import annotations

import os

from trident.budget import LLMBudget
from trident.deliberation import (
    _rank_files, _scan_hotspots, _seed_block, collect_novel, run_reviews,
)
from trident.experts.auth import AuthExpert
from trident.experts.crypto import CryptoExpert
from trident.experts.injection import InjectionExpert
from trident.experts.judge import JudgeExpert
from trident.llm.base import set_mock_handler
from trident.models import FindingVerdict
from tests.conftest import make_finding


def test_unanimous_confident_skips_judge_below_floor(db, job, workspace):
    ws = workspace
    set_mock_handler(lambda m, model: {"verdict": "confirmed", "confidence": 0.9,
                                       "severity": "low", "narrative": "minor"})
    # low is below the default judge_severity_floor ("high"), so the judge is skipped.
    f = make_finding(db, cwe="CWE-89", severity="low", file="app/main.py", line_start=2, line_end=2)

    inj = InjectionExpert("job1", ws)
    judge = JudgeExpert("job1", ws)
    run_reviews(db, [inj], judge, [f], iteration=0, budget=LLMBudget(None))

    db.refresh(f)
    assert f.status == "confirmed"
    verdicts = db.query(FindingVerdict).filter(FindingVerdict.finding_id == f.id).all()
    experts = {v.expert for v in verdicts}
    assert "injection" in experts
    assert "judge" not in experts, "judge must be skipped on a unanimous confident sub-floor verdict"


def test_mandatory_judge_on_high_severity(db, job, workspace):
    """A would-be-confirmed high/critical finding always gets the adversarial judge,
    even when experts are unanimously confident (confidence is an unreliable trigger)."""
    ws = workspace
    def handler(messages, model):
        if "you are the judge" in messages[0].content.lower():
            return {"final_verdict": "confirmed", "final_confidence": 0.85, "reasoning": "verified"}
        return {"verdict": "confirmed", "confidence": 1.0, "narrative": "clearly SQLi"}
    set_mock_handler(handler)
    f = make_finding(db, cwe="CWE-89", severity="critical", file="app/main.py", line_start=2, line_end=2)

    inj = InjectionExpert("job1", ws)
    judge = JudgeExpert("job1", ws)
    run_reviews(db, [inj], judge, [f], iteration=0, budget=LLMBudget(None))

    db.refresh(f)
    verdicts = {v.expert for v in db.query(FindingVerdict).filter(FindingVerdict.finding_id == f.id).all()}
    assert "judge" in verdicts, "judge must run on a confirmed critical finding despite full confidence"
    assert f.status == "confirmed"


def test_disagreement_triggers_crossexam_and_judge(db, job, workspace):
    ws = workspace

    def handler(messages, model):
        sysmsg = messages[0].content.lower()
        if "you are the judge" in sysmsg:
            return {"final_verdict": "confirmed", "final_confidence": 0.8, "reasoning": "chief rules"}
        if "access control" in sysmsg:
            return {"verdict": "confirmed", "confidence": 0.8, "narrative": "auth: real"}
        if "cryptography" in sysmsg:
            return {"verdict": "refuted", "confidence": 0.7}
        return {"verdict": "disputed", "confidence": 0.5}

    set_mock_handler(handler)
    # CWE-347 is in BOTH the auth and crypto domains -> two relevant experts.
    f = make_finding(db, cwe="CWE-347", title="JWT verification disabled",
                     description="jwt none alg", file="app/main.py", line_start=2, line_end=2)

    auth, crypto, judge = AuthExpert("job1", ws), CryptoExpert("job1", ws), JudgeExpert("job1", ws)
    run_reviews(db, [auth, crypto], judge, [f], iteration=0, budget=LLMBudget(None))

    db.refresh(f)
    verdicts = db.query(FindingVerdict).filter(FindingVerdict.finding_id == f.id).all()
    assert "judge" in {v.expert for v in verdicts}, "judge must rule on a contested finding"
    from trident.models import DebateMessage
    roles = {m.role for m in db.query(DebateMessage).filter(DebateMessage.finding_id == f.id).all()}
    assert "challenge" in roles, "cross-examination round should have run"
    assert f.status == "confirmed"  # judge's ruling


def test_parse_error_is_not_a_verdict(db, job, workspace):
    ws = workspace

    def handler(messages, model):
        sysmsg = messages[0].content.lower()
        if "you are the judge" in sysmsg:
            return {"final_verdict": "refuted", "final_confidence": 0.9, "reasoning": "not real"}
        return "I cannot produce JSON."  # str -> unparseable for the expert

    set_mock_handler(handler)
    f = make_finding(db, cwe="CWE-89", file="app/main.py", line_start=2, line_end=2)

    inj = InjectionExpert("job1", ws)
    judge = JudgeExpert("job1", ws)
    run_reviews(db, [inj], judge, [f], iteration=0, budget=LLMBudget(None))

    db.refresh(f)
    inj_verdicts = db.query(FindingVerdict).filter(
        FindingVerdict.finding_id == f.id, FindingVerdict.expert == "injection").all()
    # The failure was recorded as parse_error and NEVER laundered into a real verdict.
    assert [v.verdict for v in inj_verdicts] == ["parse_error"]
    # Because the only expert failed to parse, the judge adjudicated the finding directly.
    assert f.status == "false_positive"


# --- hotspot-guided novel discovery ------------------------------------------

def _mkfile(root, rel, text):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(text)


def test_scan_hotspots_labels_sinks():
    text = "x = 1\nrequests.request('GET', url)\nout = '{{ q|safe }}'\nnormal()\n"
    hits = _scan_hotspots(text)
    assert (2, "ssrf") in hits and (3, "xss") in hits
    assert not any(lbl for ln, lbl in hits if ln == 4)  # inert line unflagged


def test_rank_files_prioritizes_sink_density(tmp_path):
    ws = str(tmp_path)
    # sink deep in the file (past a truncated head) — the exact PG-009 shape
    _mkfile(ws, "introduction/apis.py", "\n" * 80 + "    requests.request('GET', target_url)\n")
    _mkfile(ws, "templates/xss_lab.html", "<h3>{{ query|safe }}</h3>\n")
    _mkfile(ws, "util/inert.py", "def add(a, b):\n    return a + b\n")
    ranked = _rank_files(ws, seen=set(), limit=10)
    order = [rel for rel, _ in ranked]
    # both sink files outrank the inert one
    inert = order.index("util/inert.py")
    assert order.index("introduction/apis.py") < inert
    assert order.index("templates/xss_lab.html") < inert
    hotspots = dict(ranked)["introduction/apis.py"]
    assert any(lbl == "ssrf" and ln == 81 for ln, lbl in hotspots)


def test_seed_block_windows_around_deep_sink(tmp_path):
    ws = str(tmp_path)
    _mkfile(ws, "apis.py", "\n" * 80 + "    requests.request('GET', target_url)\n")
    block = _seed_block(ws, "apis.py", [(81, "ssrf")])
    assert "ssrf-candidate @L81" in block          # labeled hint
    assert "requests.request" in block             # the actual sink, not a truncated head
    assert "81:" in block                          # line-numbered for accurate reporting


def test_collect_novel_surfaces_seeded_sink(db, job, tmp_path):
    ws = str(tmp_path)
    _mkfile(ws, "apis.py", "\n" * 80 + "    requests.request('GET', request.GET['url'])\n")

    def handler(messages, model):
        return {"thinking": "found ssrf", "novel_findings": [{
            "title": "SSRF via user-supplied url", "file": "apis.py", "line_start": 81,
            "cwe": "CWE-918", "severity": "high", "confidence": 0.8,
            "description": "requests.request on attacker url"}]}

    set_mock_handler(handler)
    inj = InjectionExpert("job1", ws)  # non-agentic: sees only the seeded block
    novel = collect_novel(db, [inj], "job1", ws, iteration=0, budget=LLMBudget(None))
    assert any(n.cwe == "CWE-918" and n.file == "apis.py" for n in novel)
