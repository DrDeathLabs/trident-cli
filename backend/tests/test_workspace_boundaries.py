"""Regression tests for imported-source and agent workspace boundaries."""

from __future__ import annotations

import os

import pytest

from trident.agent.tools import WorkspaceTools
from trident.reachability.graph import CallGraph
from trident.reachability.reach import ReachContext
from trident.suppression import check_inline_suppression
from trident.triage import _read_context


def test_context_readers_reject_prefix_sibling(tmp_path):
    workspace = tmp_path / "repo"
    outside = tmp_path / "repo-private"
    workspace.mkdir()
    outside.mkdir()
    secret = outside / "secret.py"
    secret.write_text("def secret():\n    return 'private'\n", encoding="utf-8")

    assert _read_context(str(workspace), "../repo-private/secret.py", 1, 1) == ""
    ctx = ReachContext(str(workspace), CallGraph(), [])
    assert ctx._enclosing_func("../repo-private/secret.py", 1) is None


def test_report_only_suppression_does_not_read_external_file(tmp_path):
    workspace = tmp_path / "repo"
    workspace.mkdir()
    external = tmp_path / "outside.py"
    external.write_text("# trident-ignore\nvalue = 1\n", encoding="utf-8")
    # Construct the smallest Finding without requiring a database fixture.
    from trident.models import Finding as FindingModel

    candidate = FindingModel(
        id="boundary", job_id="job", hash="hash", tool="import",
        rule_id="R1", file=os.fspath(external), line_start=2, line_end=2,
        status="raw",
    )
    assert check_inline_suppression(os.fspath(workspace), candidate) is None


def test_agent_does_not_follow_external_symlink(tmp_path):
    workspace = tmp_path / "repo"
    workspace.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret marker\n", encoding="utf-8")
    link = workspace / "linked.txt"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    tools = WorkspaceTools(os.fspath(workspace))
    assert "access denied" in tools.read_file("linked.txt")
    assert "secret marker" not in tools.grep("secret marker")
