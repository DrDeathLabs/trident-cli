"""Tests for local credential and scan-data storage protections."""

from __future__ import annotations

import os
import json
import stat
from dataclasses import asdict

import pytest
from click.testing import CliRunner

from trident import config_manager
from trident.cli import cli
from trident.storage_security import atomic_write_private


def test_secret_config_is_private_and_never_echoed(tmp_path, monkeypatch):
    path = tmp_path / "private-config" / "config.toml"
    monkeypatch.setattr(config_manager, "_config_path", lambda: path)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("TRIDENT_OPENAI_API_KEY", raising=False)
    runner = CliRunner()
    secret = "synthetic-private-config-key"

    saved = runner.invoke(
        cli, ["config", "set", "llm.openai_api_key", "--stdin"],
        input=secret + "\n",
    )
    assert saved.exit_code == 0, saved.output
    assert secret not in saved.stdout + saved.stderr
    assert path.read_text(encoding="utf-8").find(secret) >= 0  # plaintext storage is documented

    if os.name == "nt":
        import subprocess

        from trident.storage_security import _system_tool

        for target in (path.parent, path):
            result = subprocess.run(
                [str(_system_tool("icacls")), str(target)], check=False,
                capture_output=True, text=True, encoding="utf-8", errors="replace",
            )
            assert result.returncode == 0, result.stderr
    else:
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    for args in (
        ["config", "get", "llm.openai_api_key"],
        ["config", "show"],
        ["config", "list"],
        ["config", "set", "--help"],
        ["config", "get", "--help"],
    ):
        result = runner.invoke(cli, args)
        assert result.exit_code == 0, result.output
        assert secret not in result.stdout + result.stderr


def test_config_read_permission_failure_is_safe(tmp_path, monkeypatch):
    path = tmp_path / "private-config" / "config.toml"
    path.parent.mkdir()
    path.write_text('[llm]\nopenai_api_key = "synthetic-hidden-key"\n', encoding="utf-8")
    monkeypatch.setattr(config_manager, "_config_path", lambda: path)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("TRIDENT_OPENAI_API_KEY", raising=False)

    def deny(_path, **_kwargs):
        raise OSError("synthetic-hidden-key permission details")

    monkeypatch.setattr("trident.config_manager.secure_file", deny)
    result = CliRunner().invoke(cli, ["config", "get", "llm.openai_api_key"])
    assert result.exit_code == 1
    assert result.stdout == ""
    assert "could not be read securely" in result.stderr
    assert "synthetic-hidden-key" not in result.stdout + result.stderr


def test_config_secret_write_failure_is_safe(tmp_path, monkeypatch):
    path = tmp_path / "private-config" / "config.toml"
    monkeypatch.setattr(config_manager, "_config_path", lambda: path)
    secret = "synthetic-write-secret"

    def fail(_key, value):
        raise OSError(f"write failed for {value}")

    monkeypatch.setattr(config_manager, "set_value", fail)
    result = CliRunner().invoke(
        cli, ["config", "set", "llm.openai_api_key"], input=f"{secret}\n{secret}\n",
    )
    assert result.exit_code == 1
    assert "Enter llm.openai_api_key" in result.stdout
    assert "could not be stored securely" in result.stderr
    assert secret not in result.stdout + result.stderr


def test_atomic_private_write_failure_keeps_existing_file(tmp_path, monkeypatch):
    target = tmp_path / "private-config" / "config.toml"
    atomic_write_private(target, b"previous")

    def deny(_path, **_kwargs):
        raise OSError("synthetic write failure")

    monkeypatch.setattr("trident.storage_security.secure_file", deny)
    with pytest.raises(OSError, match="synthetic write failure"):
        atomic_write_private(target, b"replacement")
    assert target.read_bytes() == b"previous"
    assert list(target.parent.glob(f".{target.name}.*.tmp")) == []


def test_atomic_private_write_does_not_retry_permission_denied(tmp_path, monkeypatch):
    target = tmp_path / "private-config" / "config.toml"
    target.parent.mkdir()
    target.write_bytes(b"previous")
    calls = []

    def deny_create(_path, _flags, _mode=0o777):
        calls.append(True)
        raise PermissionError("synthetic denied write")

    monkeypatch.setattr("trident.storage_security.secure_directory", lambda *_a, **_kw: None)
    monkeypatch.setattr("trident.storage_security.os.open", deny_create)

    with pytest.raises(PermissionError, match="synthetic denied write"):
        atomic_write_private(target, b"replacement")

    assert calls == [True]
    assert target.read_bytes() == b"previous"
    assert list(target.parent.glob(f".{target.name}.*.tmp")) == []


def test_atomic_private_write_replace_failure_keeps_existing_file(tmp_path, monkeypatch):
    target = tmp_path / "private-config" / "config.toml"
    atomic_write_private(target, b"previous")

    def fail_replace(_source, _destination):
        raise OSError("synthetic replace failure")

    monkeypatch.setattr("trident.storage_security.os.replace", fail_replace)
    with pytest.raises(OSError, match="synthetic replace failure"):
        atomic_write_private(target, b"replacement")

    assert target.read_bytes() == b"previous"
    assert list(target.parent.glob(f".{target.name}.*.tmp")) == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode-bit assertions are platform-specific")
def test_sensitive_path_permissions_are_revalidated_after_change(tmp_path):
    from trident.storage_security import secure_directory, secure_file

    directory = tmp_path / "private-data"
    target = directory / "records.sqlite"
    atomic_write_private(target, b"synthetic")

    directory.chmod(0o777)
    target.chmod(0o644)
    secure_directory(directory)
    secure_file(target)

    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_secure_file_rechecks_path_type_after_prior_secure_call(tmp_path, monkeypatch):
    from pathlib import Path

    from trident.storage_security import secure_file

    target = tmp_path / "record.sqlite"
    target.write_bytes(b"safe")
    secure_file(target)
    original_is_symlink = Path.is_symlink

    def swapped_path_is_symlink(path):
        if path == target:
            return True
        return original_is_symlink(path)

    monkeypatch.setattr(Path, "is_symlink", swapped_path_is_symlink)

    with pytest.raises(OSError, match="regular file"):
        secure_file(target)


@pytest.mark.skipif(os.name != "nt", reason="Windows reparse-point handling is platform-specific")
def test_secure_directory_rejects_windows_junction(tmp_path):
    """A junction is not reported by Path.is_symlink() on supported Windows Python."""
    import subprocess

    from trident.storage_security import secure_directory

    outside = tmp_path / "outside"
    link = tmp_path / "config-link"
    outside.mkdir()
    target = str(outside).replace("'", "''")
    junction = str(link).replace("'", "''")
    result = subprocess.run(
        [
            "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
            f"New-Item -ItemType Junction -Path '{junction}' -Target '{target}' | Out-Null",
        ],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert result.returncode == 0
    assert link.is_dir()
    assert not link.is_symlink()
    assert getattr(link.lstat(), "st_file_attributes", 0) & 0x400

    try:
        with pytest.raises(OSError, match="reparse point"):
            secure_directory(link)
        assert list(outside.iterdir()) == []
    finally:
        os.rmdir(link)


def test_detected_credential_material_is_redacted_from_database_reports(
    db, job, monkeypatch, tmp_path,
):
    from trident.models import Finding
    from trident.reporters.exporters import to_json
    from trident.tools.bandit import BanditTool
    from trident.tools.checkov import CheckovTool
    from trident.tools.gitleaks import GitleaksTool
    from trident.tools.gosec import GosecTool
    from trident.tools.semgrep import SemgrepTool
    from trident.tools.trivy import TrivyTool
    from trident.tools.trufflehog import TruffleHogTool

    secret = "SYNTHETIC_API_TOKEN_DO_NOT_PERSIST"
    serialize = lambda values: json.dumps([asdict(item) for item in values])
    workspace = str(tmp_path / "synthetic")
    (tmp_path / "synthetic").mkdir()

    gitleaks = GitleaksTool(workspace, job.id)

    def gitleaks_output(_db, command, **_kwargs):
        report_path = command[command.index("--report-path") + 1]
        with open(report_path, "w", encoding="utf-8") as stream:
            json.dump([{
                "RuleID": "synthetic-api-key", "File": "src/config.py",
                "StartLine": 4, "EndLine": 4, "Fingerprint": "synthetic-fingerprint",
                "Secret": secret, "Match": f"API_KEY={secret}",
            }], stream)
        return 1, ""

    monkeypatch.setattr(gitleaks, "_run_cmd", gitleaks_output)
    findings = gitleaks.run(db)
    assert secret not in json.dumps(findings[0].raw)
    assert secret not in findings[0].snippet

    secret_json = json.dumps({
        "Results": [{"Target": "src/config.py", "Secrets": [{
            "Category": "Secret", "Severity": "HIGH", "RuleID": "synthetic-api-key",
            "Title": "synthetic rule", "Match": secret, "StartLine": 4, "EndLine": 4,
        }]}],
    })
    trivy = TrivyTool(workspace, job.id)
    monkeypatch.setattr(trivy, "_run_cmd", lambda *_a, **_kw: (0, secret_json))
    trivy_findings = trivy.run(db)
    assert secret not in serialize(trivy_findings)

    trufflehog = TruffleHogTool(workspace, job.id)
    truffle = trufflehog._parse(json.dumps({
        "DetectorName": "Synthetic", "Verified": True, "Raw": secret,
        "RawV2": secret, "Redacted": secret,
        "SourceMetadata": {"Data": {"Filesystem": {"file": "src/config.py", "line": 4}}},
    }))
    assert secret not in serialize(truffle)

    fixtures = [
        (BanditTool, {"results": [{"test_id": "B105", "issue_text": f"hardcoded password {secret}",
            "issue_cwe": {"id": 259}, "filename": "src/config.py", "line_number": 4}]}),
        (GosecTool, {"Issues": [{"rule_id": "G101", "details": f"hardcoded credentials {secret}",
            "code": secret, "file": "src/config.go", "line": 4, "cwe": {"id": "798"}}]}),
        (SemgrepTool, {"results": [{"check_id": "generic.secrets.synthetic", "path": "src/config.py",
            "start": {"line": 4}, "end": {"line": 4}, "extra": {"lines": secret,
            "message": secret, "metadata": {"tags": ["secrets"]}}}]}),
    ]
    for tool_cls, payload in fixtures:
        tool = tool_cls(workspace, job.id)
        monkeypatch.setattr(tool, "_run_cmd", lambda *_a, _payload=payload, **_kw: (0, json.dumps(_payload)))
        output = tool.run(db)
        assert secret not in serialize(output), tool_cls.__name__

    checkov = CheckovTool(workspace, job.id)
    checkov_findings = checkov._parse(json.dumps({"check_type": "terraform", "results": {
        "failed_checks": [{"check_id": "CKV_SECRET_1", "check_name": f"credential {secret}",
            "file_path": "src/infra.tf", "file_line_range": [4, 4], "resource": secret,
            "guideline": secret}],
    }}))
    assert secret not in serialize(checkov_findings)

    report = json.dumps(to_json(db, job.id))
    assert secret not in report
    for finding in db.query(Finding).filter(Finding.job_id == job.id):
        assert secret not in json.dumps(finding.raw_outputs)


def test_scanner_output_events_do_not_persist_paths_or_secret_text(db, job, monkeypatch, tmp_path):
    from trident.events.publisher import EventType
    from trident.tools.base import ToolBase

    class SyntheticTool(ToolBase):
        name = "synthetic-scanner"

        def run(self, _db):
            return []

    recorded = []
    monkeypatch.setattr(
        "trident.tools.base.publish_event",
        lambda _db, _job, event_type, payload: recorded.append((event_type, payload)),
    )
    tool = SyntheticTool(str(tmp_path), job.id)
    tool._emit_started(db, [str(tmp_path / "private-customer" / "scanner.exe"), str(tmp_path)])
    tool._emit_stdout(db, "SYNTHETIC_API_TOKEN_DO_NOT_PERSIST")

    assert len(recorded) == 1
    event_type, payload = recorded[0]
    assert event_type == EventType.TOOL_STARTED
    serialized = json.dumps(payload)
    assert "private-customer" not in serialized
    assert "SYNTHETIC_API_TOKEN" not in serialized
    assert payload["command"] == "scanner.exe"
