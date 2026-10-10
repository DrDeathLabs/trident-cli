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

import pytest
from click.testing import CliRunner
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from trident.cli import _detect_source, _render_table, cli
from trident import __version__
from trident.models import Base, Finding, Job


@pytest.fixture
def tmpdir_path():
    """Temp directory that avoids pytest's tmp_path (Windows permission issue)."""
    d = tempfile.mkdtemp(prefix="trident_test_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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


def _seed_reporting_rows(Session, job_id: str, rows: list[dict]) -> None:
    """Seed a fixed report population for summary/export reconciliation tests."""
    s = Session()
    try:
        for index, row in enumerate(rows):
            values = {
                "id": f"{job_id[:22]}-{index:02d}",
                "job_id": job_id,
                "hash": f"{job_id[:12]}-{index:02d}",
                "tool": "synthetic-scanner",
                "rule_id": f"synthetic.rule.{index}",
                "severity": "high",
                "confidence": 0.9,
                "title": row.get("title", f"Synthetic finding {index}"),
                "description": "Synthetic regression evidence.",
                "file": f"src/finding_{index}.py",
                "line_start": index + 1,
                "line_end": index + 1,
                "cwe": "CWE-89",
                "status": row.get("status", "confirmed"),
                "priority": row.get("priority"),
                "triage": {"rationale": "Synthetic regression assessment."},
            }
            s.add(Finding(**values))
        s.commit()
    finally:
        s.close()


def _reporting_stub(Session, rows: list[dict], *, unresolved_job: bool = False):
    async def _stub(job_id, *_args, **_kwargs):
        _seed_reporting_rows(Session, job_id, rows)
        if unresolved_job:
            from trident.models import Job
            s = Session()
            try:
                job = s.get(Job, job_id)
                job.status = "completed_with_unresolved"
                s.commit()
            finally:
                s.close()
        return True
    return _stub


def _parse_count_line(output: str, label: str) -> int:
    import re

    match = re.search(rf"(?m)^{re.escape(label)}:\s+(\d+)\s*$", output)
    assert match, f"missing numerical {label} count in output:\n{output}"
    return int(match.group(1))


def test_version_option_uses_package_version():
    result = CliRunner().invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_scan_help_describes_numeric_summary():
    result = CliRunner().invoke(cli, ["scan", "--help"])
    assert result.exit_code == 0
    assert "P0-P4 counts" in result.output
    assert "--openai-base-url" in result.output
    assert "Requires --backend openai" in result.output


def test_gateway_help_topic_documents_transport_and_setup():
    result = CliRunner().invoke(cli, ["help", "gateway"])
    assert result.exit_code == 0
    assert "OpenAI-compatible endpoints" in result.output
    assert "HTTP has no transport encryption" in result.output
    assert "trident config set llm.openai_api_key" in result.output
    assert "trident scan . --backend openai --model security-expert" in result.output


def test_openai_base_url_cli_override_is_applied_only_during_scan_and_restored(
    tmpdir_path, mem_db, monkeypatch,
):
    from trident.config import settings

    old_backend = settings.llm.backend
    old_url = settings.llm.openai_base_url
    observed = []

    async def _stub(*_args, **_kwargs):
        observed.append((settings.llm.backend, settings.llm.openai_base_url))
        return True

    monkeypatch.setattr("trident.cli._run_scan", _stub)
    monkeypatch.setattr(settings.llm, "backend", "ollama")
    monkeypatch.setattr(settings.llm, "openai_base_url", "https://persisted.example/v1")
    result = CliRunner().invoke(cli, [
        "scan", tmpdir_path, "--backend", "openai", "--openai-base-url",
        "http://192.0.2.10:8000/custom/v1", "--quiet",
    ])
    assert result.exit_code == 0, result.output
    assert observed == [("openai", "http://192.0.2.10:8000/custom/v1")]
    assert settings.llm.openai_base_url == "https://persisted.example/v1"
    assert settings.llm.backend == "ollama"
    assert old_backend
    assert old_url


@pytest.mark.parametrize(
    ("cli_args", "message"),
    [
        (("--backend", "ollama", "--openai-base-url", "http://gateway.example/v1"),
         "requires the openai backend"),
        (("--backend", "openai", "--openai-base-url", "file:///tmp/v1"),
         "valid HTTP(S) base URL"),
    ],
)
def test_invalid_openai_base_url_cli_override_does_not_mutate_settings(
    tmpdir_path, mem_db, monkeypatch, cli_args, message,
):
    from trident.config import settings

    monkeypatch.setattr(settings.llm, "backend", "ollama")
    monkeypatch.setattr(settings.llm, "openai_base_url", "https://persisted.example/v1")
    result = CliRunner().invoke(cli, ["scan", tmpdir_path, *cli_args])
    assert result.exit_code == 2
    assert message in result.output
    assert settings.llm.backend == "ollama"
    assert settings.llm.openai_base_url == "https://persisted.example/v1"


def test_scan_rejects_embedded_git_credentials_before_persisting_or_echoing_them(mem_db):
    secret = "synthetic-git-secret"
    result = CliRunner().invoke(
        cli, ["scan", f"https://user:{secret}@example.invalid/repo.git", "--quiet"],
    )
    assert result.exit_code == 2
    assert secret not in result.output
    session = mem_db()
    try:
        assert session.query(Job).count() == 0
    finally:
        session.close()


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

def test_render_table_is_a_compact_numeric_summary():
    report = {
        "triage": {
            "summary": {"by_tier": {"P0": 1, "P1": 2, "P2": 0, "P3": 1, "P4": 0}},
            "untriaged": 1,
        },
        "dispositions": {"counts": {"unresolved_model_error": 2}},
    }
    table = _render_table(report, "myapp")
    assert table.splitlines() == [
        "Trident Scan - myapp", "P0: 1", "P1: 2", "P2: 0", "P3: 1", "P4: 0",
        "Total: 4", "Untriaged: 1", "Unresolved: 2",
    ]
    assert "Sample" not in table
    assert "Triage plan" not in table


def test_render_table_empty_findings_shows_every_zero():
    report = {"triage": {"summary": {"by_tier": {}}, "untriaged": 0}, "dispositions": {}}
    table = _render_table(report, "empty-app")
    assert table.splitlines() == [
        "Trident Scan - empty-app", "P0: 0", "P1: 0", "P2: 0", "P3: 0", "P4: 0",
        "Total: 0", "Untriaged: 0", "Unresolved: 0",
    ]


def test_terminal_summary_reconciles_final_report_population(
    tmpdir_path, mem_db, monkeypatch,
):
    """Keep terminal counts aligned with the final report and status buckets."""
    rows = [
        {"priority": "P0", "title": "Critical item"},
        {"priority": "P1", "title": "High item one"},
        {"priority": "P1", "title": "High item two"},
        {"priority": "P2", "title": "Medium item"},
        {"priority": "P3", "title": "Low item"},
        {"priority": "P4", "title": "Informational item"},
        {"priority": None, "title": "Confirmed but untriaged"},
        {"priority": "P0", "status": "disputed", "title": "Disputed item"},
        {"priority": "P1", "status": "suppressed", "title": "Suppressed item"},
        {"priority": "P2", "status": "false_positive", "title": "False positive item"},
        {"priority": None, "status": "unresolved", "title": "Unresolved item"},
        {"priority": None, "status": "unresolved_model_error", "title": "Model-error item"},
        {"priority": None, "status": "unreviewed", "title": "Unreviewed item"},
    ]

    monkeypatch.setattr(
        "trident.cli._run_scan",
        _reporting_stub(mem_db, rows, unresolved_job=True),
    )
    table = CliRunner().invoke(cli, ["scan", tmpdir_path, "--quiet"])
    # The pipeline reports unresolved decisions as an integrity exit 2, while
    # still emitting the completed report for operator inspection.
    assert table.exit_code == 2, table.output

    # Reconcile every terminal count with the final report categories. The
    # pre-fix preview and ambiguous aggregate are captured in acceptance evidence.
    assert _parse_count_line(table.output, "P0") == 1
    assert _parse_count_line(table.output, "P1") == 2
    assert _parse_count_line(table.output, "P2") == 1
    assert _parse_count_line(table.output, "P3") == 1
    assert _parse_count_line(table.output, "P4") == 1
    assert _parse_count_line(table.output, "Total") == 6
    assert _parse_count_line(table.output, "Untriaged") == 1
    assert _parse_count_line(table.output, "Unresolved") == 3

    monkeypatch.setattr(
        "trident.cli._run_scan",
        _reporting_stub(mem_db, rows, unresolved_job=True),
    )
    machine = CliRunner().invoke(cli, ["scan", tmpdir_path, "--format", "json", "--quiet"])
    assert machine.exit_code == 2, machine.output
    report = json.loads(machine.output)
    assert [finding["title"] for finding in report["findings"]] == [
        "Critical item", "High item one", "High item two", "Medium item",
        "Low item", "Informational item", "Confirmed but untriaged",
    ]
    assert len({finding["id"] for finding in report["findings"]}) == 7
    assert report["triage"]["summary"]["by_tier"] == {
        "P0": 1, "P1": 2, "P2": 1, "P3": 1, "P4": 1,
    }
    assert report["triage"]["untriaged"] == 1
    assert report["dispositions"]["counts"]["unresolved"] == 1
    assert report["dispositions"]["counts"]["unresolved_model_error"] == 1
    assert report["dispositions"]["counts"]["unreviewed"] == 1
    assert report["dispositions"]["counts"]["disputed"] == 1
    assert report["dispositions"]["counts"]["suppressed"] == 1
    assert report["dispositions"]["counts"]["false_positive"] == 1


def test_terminal_summary_empty_population_has_explicit_zeros(
    tmpdir_path, mem_db, monkeypatch,
):
    async def _empty_scan(*_args, **_kwargs):
        return True

    monkeypatch.setattr("trident.cli._run_scan", _empty_scan)
    result = CliRunner().invoke(cli, ["scan", tmpdir_path, "--quiet"])
    assert result.exit_code == 0
    assert {tier: _parse_count_line(result.output, tier) for tier in (
        "P0", "P1", "P2", "P3", "P4",
    )} == {tier: 0 for tier in ("P0", "P1", "P2", "P3", "P4")}
    assert _parse_count_line(result.output, "Total") == 0
    assert _parse_count_line(result.output, "Untriaged") == 0
    assert _parse_count_line(result.output, "Unresolved") == 0


def test_cli_summary_and_gate_follow_finalized_json_population(
    tmpdir_path, mem_db, monkeypatch,
):
    """A report finding cannot disappear because a second DB query is stale."""
    report = {
        "findings": [{"id": "final-report-finding", "title": "Finalized P1", "priority": "P1"}],
        "triage": {
            "summary": {"by_tier": {"P0": 0, "P1": 1, "P2": 0, "P3": 0, "P4": 0}},
            "untriaged": 0,
        },
        "dispositions": {"counts": {}},
    }

    async def _scan_without_rows(*_args, **_kwargs):
        return True

    monkeypatch.setattr("trident.cli._run_scan", _scan_without_rows)
    monkeypatch.setattr("trident.reporters.exporters.to_json", lambda _db, _job_id: report)
    table = CliRunner().invoke(cli, [
        "scan", tmpdir_path, "--format", "table", "--quiet", "--fail-on", "P1",
    ])
    assert table.exit_code == 1
    assert _parse_count_line(table.output, "P1") == 1
    assert _parse_count_line(table.output, "Total") == 1

    machine = CliRunner().invoke(cli, [
        "scan", tmpdir_path, "--format", "json", "--quiet", "--fail-on", "P1",
    ])
    assert machine.exit_code == 1
    assert json.loads(machine.output)["findings"] == report["findings"]


@pytest.mark.parametrize("output_format", ["json", "sarif"])
def test_machine_output_is_uncontaminated_with_summary_population(
    tmpdir_path, mem_db, monkeypatch, output_format,
):
    rows = [
        {"priority": "P2", "title": "Machine-readable priority"},
        {"priority": None, "title": "Machine-readable untriaged"},
    ]
    monkeypatch.setattr("trident.cli._run_scan", _reporting_stub(mem_db, rows))
    result = CliRunner().invoke(cli, [
        "scan", tmpdir_path, "--format", output_format, "--quiet",
        "--severity-gate", "critical",
    ])
    assert result.exit_code == 2
    payload = json.loads(result.output)
    assert "[trident]" not in result.output
    if output_format == "json":
        assert [finding["title"] for finding in payload["findings"]] == [
            "Machine-readable priority", "Machine-readable untriaged",
        ]
    else:
        results = payload["runs"][0]["results"]
        assert [row["message"]["text"] for row in results] == [
            "Machine-readable priority", "Machine-readable untriaged",
        ]


@pytest.mark.parametrize("output_format", ["table", "json", "sarif"])
@pytest.mark.parametrize(("severity_gate", "expected_exit"), [("critical", 2), ("high", 2)])
def test_reporting_formats_share_population_and_preserve_severity_gate(
    tmpdir_path, mem_db, monkeypatch, output_format, severity_gate, expected_exit,
):
    rows = [
        {"priority": "P1", "title": "High finding"},
        {"priority": "P3", "title": "Low finding"},
        {"priority": None, "title": "Untriaged finding"},
        {"priority": "P0", "status": "disputed", "title": "Disputed candidate"},
    ]
    monkeypatch.setattr("trident.cli._run_scan", _reporting_stub(mem_db, rows))
    result = CliRunner().invoke(cli, [
        "scan", tmpdir_path, "--format", output_format, "--quiet",
        "--severity-gate", severity_gate,
    ])
    assert result.exit_code == expected_exit

    if output_format == "table":
        assert {tier: _parse_count_line(result.output, tier) for tier in (
            "P0", "P1", "P2", "P3", "P4",
        )} == {"P0": 0, "P1": 1, "P2": 0, "P3": 1, "P4": 0}
        assert _parse_count_line(result.output, "Total") == 2
        assert _parse_count_line(result.output, "Untriaged") == 1
        assert _parse_count_line(result.output, "Unresolved") == 0
        assert "High finding" not in result.output
    elif output_format == "json":
        report = json.loads(result.output)
        assert report["triage"]["summary"]["by_tier"] == {
            "P0": 0, "P1": 1, "P2": 0, "P3": 1, "P4": 0,
        }
        assert report["triage"]["untriaged"] == 1
        assert len(report["findings"]) == 3
        assert len({finding["id"] for finding in report["findings"]}) == 3
    else:
        report = json.loads(result.output)
        results = report["runs"][0]["results"]
        assert [item["message"]["text"] for item in results] == [
            "High finding", "Low finding", "Untriaged finding",
        ]
        assert len({item["partialFingerprints"]["primaryLocationLineHash"] for item in results}) == 3


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
