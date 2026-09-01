"""Agent runtime tests: sandboxed tools + the explore-then-verdict loop (mock LLM)."""

from __future__ import annotations

import os

from trident.agent.loop import run_agent
from trident.agent.tools import WorkspaceTools
from trident.reliability.schemas import ReviewVerdict
from trident.llm.base import set_mock_handler
from tests.conftest import make_finding


# ---- sandboxed tools -------------------------------------------------------

def test_read_file_and_range(workspace):
    t = WorkspaceTools(workspace)
    out = t.read_file("app/main.py")
    assert "def f(q)" in out and "1:" in out
    ranged = t.read_file("app/main.py", 1, 2)
    assert "lines 1-2" in ranged


def test_sandbox_blocks_escape(workspace):
    t = WorkspaceTools(workspace)
    assert "access denied" in t.read_file("../../../etc/passwd")
    assert "access denied" in t.read_file("/etc/passwd")


def test_grep_and_find(workspace):
    t = WorkspaceTools(workspace)
    assert "app/main.py" in t.grep("SELECT")
    assert "no matches" in t.grep("zzz_nope_zzz")
    assert "app/main.py" in t.find_definition("f")
    assert "app/main.py" in t.find_references("sql")


def test_grep_bad_regex_is_handled(workspace):
    t = WorkspaceTools(workspace)
    assert "bad regex" in t.grep("(")


def test_list_dir(workspace):
    t = WorkspaceTools(workspace)
    assert "app/" in t.list_dir(".")


def test_scorecard_is_blinded(workspace):
    with open(os.path.join(workspace, "scorecard.toml"), "w") as fh:
        fh.write("secret answer key")
    t = WorkspaceTools(workspace)
    assert "no matches" in t.grep("answer key")  # scorecard skipped by the guard


# ---- the agent loop --------------------------------------------------------

def test_agent_returns_valid_verdict_without_tools(workspace):
    """Default mock emits no tool calls: the loop goes straight to extraction."""
    t = WorkspaceTools(workspace)
    res = run_agent("sys", "review this", t, ReviewVerdict,
                    model="mock", max_steps=4, final_instruction="give JSON")
    assert res.ok and res.obj.verdict in ("confirmed", "refuted", "disputed")
    assert res.trace == []
    assert res.llm_calls >= 2  # one exploration probe + one extraction


def test_agent_dispatches_tool_then_concludes(workspace):
    """A handler drives one grep call; the loop dispatches it and records the trace."""
    state = {"n": 0}

    def handler(messages, model):
        state["n"] += 1
        if state["n"] == 1:
            return {"_tool_calls": [
                {"id": "c1", "function": {"name": "grep", "arguments": '{"pattern": "SELECT"}'}}
            ]}
        return {"verdict": "confirmed", "confidence": 0.9}

    set_mock_handler(handler)
    t = WorkspaceTools(workspace)
    res = run_agent("sys", "review this", t, ReviewVerdict,
                    model="mock", max_steps=4, final_instruction="give JSON")
    assert res.ok
    assert len(res.trace) == 1 and res.trace[0]["tool"] == "grep"
    assert "app/main.py" in res.trace[0]["result_preview"]


def test_novel_discovery_samples_templates():
    """Novel-discovery file ranking must include HTML/templates — where server-rendered
    XSS (e.g. {{x|safe}}) lives — not just code files."""
    import os, shutil, tempfile
    from trident.deliberation import _rank_files
    d = tempfile.mkdtemp(prefix="tmpl_ws_")
    try:
        os.makedirs(os.path.join(d, "templates"))
        open(os.path.join(d, "views.py"), "w").close()
        open(os.path.join(d, "templates", "index.html"), "w").close()
        picked = _rank_files(d, seen=set(), limit=12)
        assert any(rel.endswith(".html") for rel, _ in picked), \
            "templates must be sampled for novel discovery"
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_agent_exploration_is_bounded_by_budget(workspace):
    """A budget cap stops the agent exploring — the fix for agentic runaway at scale."""
    from trident.budget import LLMBudget

    def handler(messages, model):
        # The final extraction turn carries the FINAL_MARKER; everything else is
        # exploration and keeps asking for tools (would run to max_steps=6).
        if any(m.content == "FINAL_MARKER" for m in messages):
            return {"verdict": "confirmed", "confidence": 0.9}
        return {"_tool_calls": [
            {"id": "c", "function": {"name": "grep", "arguments": '{"pattern": "x"}'}}
        ]}

    set_mock_handler(handler)
    t = WorkspaceTools(workspace)
    b = LLMBudget(limit=2)
    res = run_agent("sys", "task", t, ReviewVerdict, model="mock", max_steps=6,
                    final_instruction="FINAL_MARKER", budget=b)
    # Without the budget it would explore all 6 steps; the cap of 2 stops it at 2.
    assert len(res.trace) <= 2, "exploration must stop when the budget is spent"
    assert b.used >= 2
    assert res.ok  # still commits to a final verdict


def test_short_columns_are_clamped():
    """Verbose agentic output must never overflow owasp(64)/title(512) columns."""
    from trident.reliability.schemas import NovelFinding, ReviewVerdict
    v = ReviewVerdict.model_validate({
        "verdict": "confirmed",
        "owasp": "A02:2021-Cryptographic Failures / A07:2021-Identification and Authentication Failures",
    })
    assert v.owasp is not None and len(v.owasp) <= 64 and v.owasp.startswith("A02")
    nf = NovelFinding.model_validate({"title": "x" * 900})
    assert len(nf.title) <= 512


def test_agentic_expert_invoke_review(db, workspace):
    """An agentic expert produces a verdict + trace through invoke_review."""
    from trident.experts.injection import InjectionExpert

    def handler(messages, model):
        # First call explores, second concludes.
        if any("tool" in (m.role or "") for m in messages):
            return {"verdict": "confirmed", "confidence": 0.9}
        return {"_tool_calls": [
            {"id": "c1", "function": {"name": "read_file", "arguments": '{"path": "app/main.py"}'}}
        ]}

    set_mock_handler(handler)
    ex = InjectionExpert("job1", workspace, agentic=True)
    f = make_finding(db)
    res = ex.invoke_review(f)
    assert res.ok and res.obj.verdict == "confirmed"
    assert len(res.trace) == 1 and res.trace[0]["tool"] == "read_file"
    assert res.llm_calls >= 2
