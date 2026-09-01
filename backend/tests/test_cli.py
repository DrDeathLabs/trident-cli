"""Tests for the trident CLI — _detect_source, _render_table, and scan exit codes.

Integration tests use Click's CliRunner with:
  - trident.db redirected to an in-memory SQLite
  - trident.cli._run_scan replaced by an async stub that seeds findings
so no LLM calls, no network, no on-disk state.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest
from click.testing import CliRunner
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from trident.cli import _detect_source, _render_table, cli
from trident import __version__
from trident.models import Base, Finding


@pytest.fixture
def tmpdir_path():
    """Temp directory that avoids pytest's tmp_path (Windows permission issue)."""
    d = tempfile.mkdtemp(prefix="trident_test_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_ns(**kw) -> SimpleNamespace:
    """Minimal Finding-like object for _render_table unit tests."""
    defaults = dict(priority="P2", title="SQL Injection", file="app/db.py", line_start=10)
    defaults.update(kw)
    return SimpleNamespace(**defaults)


def _mem_engine():
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(eng)
    return eng


def _seed_finding(Session, job_id: str, priority: str = "P1", status: str = "confirmed") -> None:
    s = Session()
    try:
        f = Finding(
            id=os.urandom(8).hex(),
            job_id=job_id,
            hash=os.urandom(6).hex(),
            tool="semgrep",
            rule_id="test.sqli",
            severity="high",
            confidence=0.9,
            title="SQL Injection",
            file="app/db.py",
            line_start=42,
            cwe="CWE-89",
            status=status,
            priority=priority,
            triage={
                "impact": "data_exposure", "attack_vector": "remote_auth",
                "exploitability": "moderate", "in_chain": False,
                "reachability": "unknown", "guard": None,
                "corpus_guard": None, "reach_guard": None,
            },
        )
        s.add(f)
        s.commit()
    finally:
        s.close()


def test_version_option_uses_package_version():
    result = CliRunner().invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


@pytest.fixture
def mem_db(monkeypatch):
    """Redirect trident.db to an in-memory SQLite for the duration of the test."""
    eng = _mem_engine()
    Session = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)

    @contextmanager
    def _session():
        s = Session()
        try:
            yield s
            s.commit()
        except Exception:
            s.rollback()
            raise
        finally:
            s.close()

    monkeypatch.setattr("trident.db.engine", eng)
    monkeypatch.setattr("trident.db.SessionLocal", Session)
    monkeypatch.setattr("trident.db.db_session", _session)
    return Session


def _mock_scan(Session, *, returns: bool = True, priority: str = "P1"):
    """Return an async stub for trident.cli._run_scan."""
    async def _stub(job_id, source_type, source_ref, target_name, profile, **_kw):
        if returns:
            _seed_finding(Session, job_id, priority=priority)
        return returns
    return _stub


# ---------------------------------------------------------------------------
# Unit: _detect_source
# ---------------------------------------------------------------------------

def test_detect_source_https_url():
    assert _detect_source("https://github.com/org/repo") == ("git", "https://github.com/org/repo")


def test_detect_source_ssh_url():
    assert _detect_source("git@github.com:org/repo.git") == ("git", "git@github.com:org/repo.git")


def test_detect_source_zip(tmpdir_path):
    z = str(Path(tmpdir_path) / "app.zip")
    src_type, ref = _detect_source(z)
    assert src_type == "upload"
    assert ref.endswith(".zip")


def test_detect_source_local_dir(tmpdir_path):
    src_type, ref = _detect_source(tmpdir_path)
    assert src_type == "mount"
    assert ref == str(Path(tmpdir_path).resolve())


# ---------------------------------------------------------------------------
# Unit: _render_table
# ---------------------------------------------------------------------------

def test_render_table_counts_each_tier():
    findings = [
        _make_ns(priority="P0", title="RCE"),
        _make_ns(priority="P1", title="SQLi"),
        _make_ns(priority="P1", title="SSRF"),
        _make_ns(priority="P3", title="Info leak"),
    ]
    table = _render_table(findings, "myapp")
    assert "P0" in table
    assert "P1" in table
    assert "P2" in table  # row present even with count 0
    assert "P3" in table


def test_render_table_shows_sample_title():
    findings = [_make_ns(priority="P1", title="Command injection", file="run.py", line_start=7)]
    table = _render_table(findings, "svc")
    assert "Command injection" in table
    assert "run.py" in table


def test_render_table_empty_findings():
    table = _render_table([], "empty-app")
    assert "Total confirmed: 0" in table
    assert "Triage plan:" in table


# ---------------------------------------------------------------------------
# Integration: scan command exit codes
# ---------------------------------------------------------------------------

def test_scan_exits_0_when_no_blockers(tmpdir_path, mem_db, monkeypatch):
    """No findings → exit 0."""
    async def _clean_stub(job_id, *_a, **_kw):
        return True

    monkeypatch.setattr("trident.cli._run_scan", _clean_stub)
    result = CliRunner().invoke(cli, ["scan", tmpdir_path, "--fail-on", "P1"])
    assert result.exit_code == 0, result.output


def test_scan_exits_1_when_p1_found(tmpdir_path, mem_db, monkeypatch):
    """P1 finding + --fail-on P1 → exit 1."""
    monkeypatch.setattr("trident.cli._run_scan", _mock_scan(mem_db, priority="P1"))
    result = CliRunner().invoke(cli, ["scan", tmpdir_path, "--fail-on", "P1"])
    assert result.exit_code == 1


def test_scan_exits_0_when_finding_below_threshold(tmpdir_path, mem_db, monkeypatch):
    """P3 finding + --fail-on P1 → exit 0 (P3 is below the gate)."""
    monkeypatch.setattr("trident.cli._run_scan", _mock_scan(mem_db, priority="P3"))
    result = CliRunner().invoke(cli, ["scan", tmpdir_path, "--fail-on", "P1"])
    assert result.exit_code == 0


def test_scan_fail_on_tier_boundary(tmpdir_path, mem_db, monkeypatch):
    """P2 finding: exits 0 with --fail-on P1, exits 1 with --fail-on P2."""
    monkeypatch.setattr("trident.cli._run_scan", _mock_scan(mem_db, priority="P2"))
    r1 = CliRunner().invoke(cli, ["scan", tmpdir_path, "--fail-on", "P1"])
    assert r1.exit_code == 0

    monkeypatch.setattr("trident.cli._run_scan", _mock_scan(mem_db, priority="P2"))
    r2 = CliRunner().invoke(cli, ["scan", tmpdir_path, "--fail-on", "P2"])
    assert r2.exit_code == 1


def test_scan_exits_2_on_scan_failure(tmpdir_path, mem_db, monkeypatch):
    """Ingest/scan failure (returns False) → exit 2."""
    monkeypatch.setattr("trident.cli._run_scan", _mock_scan(mem_db, returns=False))
    result = CliRunner().invoke(cli, ["scan", tmpdir_path])
    assert result.exit_code == 2


# ---------------------------------------------------------------------------
# Integration: output formats
# ---------------------------------------------------------------------------

def test_scan_sarif_output_to_file(tmpdir_path, mem_db, monkeypatch):
    """--output sarif --output-file writes valid SARIF 2.1.0."""
    monkeypatch.setattr("trident.cli._run_scan", _mock_scan(mem_db, priority="P0"))
    out_file = os.path.join(tmpdir_path, "results.sarif")
    result = CliRunner().invoke(cli, [
        "scan", tmpdir_path,
        "--output", "sarif",
        "--output-file", out_file,
        "--fail-on", "P1",
    ])
    assert result.exit_code == 1   # P0 is above P1 threshold
    sarif = json.loads(Path(out_file).read_text())
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["level"] == "error"   # P0 → error
    assert sarif["runs"][0]["results"][0]["properties"]["priority"] == "P0"


def test_scan_json_output_includes_priority(tmpdir_path, mem_db, monkeypatch):
    """--output json --quiet writes clean JSON to stdout."""
    monkeypatch.setattr("trident.cli._run_scan", _mock_scan(mem_db, priority="P2"))
    result = CliRunner().invoke(cli, [
        "scan", tmpdir_path,
        "--output", "json",
        "--quiet",
        "--fail-on", "P1",
    ])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["findings"][0]["priority"] == "P2"
    assert "triage" in data["findings"][0]


@pytest.mark.parametrize("output_format", ["table", "json", "sarif"])
def test_scan_writes_detailed_triage_sidecar(
    tmpdir_path, mem_db, monkeypatch, output_format,
):
    """The automatic triage pass can be saved as a matching report artifact."""
    monkeypatch.setattr("trident.cli._run_scan", _mock_scan(mem_db, priority="P1"))
    scan_file = Path(tmpdir_path) / f"scan.{output_format}"
    triage_file = Path(tmpdir_path) / f"triage.{output_format}"
    result = CliRunner().invoke(cli, [
        "scan", tmpdir_path,
        "--format", output_format,
        "--output-file", str(scan_file),
        "--triage-output-file", str(triage_file),
        "--fail-on", "P4",
        "--quiet",
    ])
    assert result.exit_code == 1
    assert scan_file.exists()
    assert triage_file.exists()
    if output_format == "json":
        assert json.loads(triage_file.read_text())["report_type"] == "triage"
    elif output_format == "sarif":
        triage = json.loads(triage_file.read_text())
        assert triage["version"] == "2.1.0"
        assert triage["runs"][0]["tool"]["driver"]["name"] == "Trident (triage)"
    else:
        assert "Trident Triage" in triage_file.read_text()


def test_scan_quiet_suppresses_progress_lines(tmpdir_path, mem_db, monkeypatch):
    """--quiet: no [trident] progress lines in combined output."""
    monkeypatch.setattr("trident.cli._run_scan", _mock_scan(mem_db, priority="P3"))
    result = CliRunner().invoke(cli, ["scan", tmpdir_path, "--quiet"])
    assert "[trident]" not in result.output


def test_install_tools_verify_warmup_runs_install_then_verify(monkeypatch):
    """The documented combined setup command must not skip installation."""
    calls = []

    monkeypatch.setattr(
        "trident.tools.installer.install_all",
        lambda tools_dir, echo: calls.append("install") or {"test": True},
    )
    monkeypatch.setattr(
        "trident.tools.installer.verify_tools",
        lambda tools_dir, echo: calls.append("verify") or {"test": True},
    )
    monkeypatch.setattr(
        "trident.tools.installer.warmup_dbs",
        lambda tools_dir, echo: calls.append("warmup"),
    )
    result = CliRunner().invoke(cli, ["install-tools", "--verify", "--warmup"])
    assert result.exit_code == 0, result.output
    assert calls == ["install", "verify", "warmup"]
