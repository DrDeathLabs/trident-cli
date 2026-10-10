"""Parse tests for the Tier-1 net-widening adapters — pure `_parse`, no binaries."""

from __future__ import annotations

import json
import io
import stat
import tarfile
import zipfile
from hashlib import sha256
from types import SimpleNamespace

import pytest

import trident.tools.base as tool_base
import trident.tools.installer as installer
from trident.tools.checkov import CheckovTool
from trident.tools.govulncheck import GovulncheckTool
from trident.tools.osvscanner import OsvScannerTool
from trident.tools.trufflehog import TruffleHogTool


def test_python_environment_binary_precedes_inherited_path(tmp_path, monkeypatch):
    env_bin = tmp_path / "bin"
    env_bin.mkdir()
    executable = env_bin / "semgrep"
    executable.write_text("#!/bin/sh\n")
    monkeypatch.setattr(tool_base.sys, "executable", str(env_bin / "python"))
    assert tool_base.python_env_binary("semgrep") == str(executable)


def test_pip_tools_install_together_for_dependency_resolution(monkeypatch):
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr(installer.subprocess, "run", fake_run)
    result = installer.install_pip_tools(echo=lambda _message: None)

    assert result == {name: True for name in installer._PIP_TOOLS}
    assert len(calls) == 1
    assert calls[0][0:5] == [installer.sys.executable, "-m", "pip", "install", "--quiet"]
    assert calls[0][-4:] == installer._PIP_TOOLS


def test_archive_extractors_reject_path_traversal_and_links(tmp_path, monkeypatch):
    from trident import archive_safety
    from trident.archive_safety import safe_extract_tar, safe_extract_zip

    zip_data = io.BytesIO()
    with zipfile.ZipFile(zip_data, "w") as archive:
        archive.writestr("../outside.txt", "synthetic")
    zip_data.seek(0)
    zip_target = tmp_path / "zip-out"
    with zipfile.ZipFile(zip_data) as archive:
        with pytest.raises(RuntimeError, match="path traversal"):
            safe_extract_zip(archive, zip_target)
    assert not (tmp_path / "outside.txt").exists()

    link_data = io.BytesIO()
    with zipfile.ZipFile(link_data, "w") as archive:
        info = zipfile.ZipInfo("link")
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(info, "../../outside.txt")
    link_data.seek(0)
    with zipfile.ZipFile(link_data) as archive:
        with pytest.raises(RuntimeError, match="symbolic links"):
            safe_extract_zip(archive, tmp_path / "zip-links")

    tar_data = io.BytesIO()
    with tarfile.open(fileobj=tar_data, mode="w:gz") as archive:
        info = tarfile.TarInfo("../outside-tar.txt")
        payload = b"synthetic"
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    tar_data.seek(0)
    with tarfile.open(fileobj=tar_data, mode="r:gz") as archive:
        with pytest.raises(RuntimeError, match="path traversal"):
            safe_extract_tar(archive, tmp_path / "tar-out")
    assert not (tmp_path / "outside-tar.txt").exists()

    link_data = io.BytesIO()
    with tarfile.open(fileobj=link_data, mode="w:gz") as archive:
        info = tarfile.TarInfo("link")
        info.type = tarfile.SYMTYPE
        info.linkname = "../../outside-tar.txt"
        archive.addfile(info)
    link_data.seek(0)
    with tarfile.open(fileobj=link_data, mode="r:gz") as archive:
        with pytest.raises(RuntimeError, match="links and special"):
            safe_extract_tar(archive, tmp_path / "tar-links")

    budget_data = io.BytesIO()
    with zipfile.ZipFile(budget_data, "w") as archive:
        archive.writestr("first.txt", "123")
        archive.writestr("second.txt", "456")
    budget_data.seek(0)
    monkeypatch.setattr(archive_safety, "MAX_EXTRACTED_BYTES", 5)
    with zipfile.ZipFile(budget_data) as archive:
        with pytest.raises(RuntimeError, match="maximum supported extracted size"):
            safe_extract_zip(archive, tmp_path / "zip-budget")
    assert not (tmp_path / "zip-budget" / "first.txt").exists()

    budget_data.seek(0)
    monkeypatch.setattr(archive_safety, "MAX_EXTRACTED_BYTES", 100)
    monkeypatch.setattr(archive_safety, "MAX_ARCHIVE_MEMBERS", 1)
    with zipfile.ZipFile(budget_data) as archive:
        with pytest.raises(RuntimeError, match="maximum supported member count"):
            safe_extract_zip(archive, tmp_path / "zip-count")
    assert not (tmp_path / "zip-count" / "first.txt").exists()


def test_download_digest_check_detects_corruption():
    payload = b"synthetic trusted release archive"
    installer._verify_sha256(payload, sha256(payload).hexdigest(), "test archive")
    with pytest.raises(RuntimeError, match="SHA-256 digest"):
        installer._verify_sha256(payload, "0" * 64, "test archive")


def test_cwe_parser_rejects_dtd_and_entity_declarations():
    from defusedxml.common import EntitiesForbidden
    from trident.calibration.feeds.cwe import _parse_cwe_xml

    payload = b'<!DOCTYPE x [<!ENTITY expanded "synthetic">]><x>&expanded;</x>'
    with pytest.raises(EntitiesForbidden):
        _parse_cwe_xml(payload)


def test_model_manager_table_counts_are_allowlisted():
    from trident.model_manager import _count_table

    class Connection:
        def __init__(self):
            self.executed = []

        def execute(self, statement):
            self.executed.append(statement)
            return SimpleNamespace(fetchone=lambda: (7,))

    conn = Connection()
    assert _count_table(conn, "nvd") == 7
    assert conn.executed == ["SELECT COUNT(*) FROM nvd_cve"]
    assert _count_table(conn, "nvd_cve; DROP TABLE feed_status") == 0
    assert len(conn.executed) == 1


def test_osvscanner_parse():
    sample = json.dumps({"results": [{
        "source": {"path": "/ws/requirements.txt", "type": "lockfile"},
        "packages": [{
            "package": {"name": "django", "version": "2.2.0", "ecosystem": "PyPI"},
            "vulnerabilities": [{
                "id": "GHSA-abcd", "summary": "SQL injection in Django",
                "aliases": ["CVE-2020-9402"],
                "database_specific": {"severity": "HIGH"},
                "severity": [{"type": "CVSS_V3", "score": "7.5"}],
            }],
        }],
    }]})
    out = OsvScannerTool(workspace="/ws", job_id="j")._parse(sample)
    assert len(out) == 1
    f = out[0]
    assert f.tool == "osv-scanner" and f.rule_id == "GHSA-abcd"
    assert f.severity == "high" and f.file == "requirements.txt"
    assert "django" in f.title and "CVE-2020-9402" in f.description
    # package exposed in raw so correlate._dep_package groups it with trivy/grype
    from trident.correlate import _dep_package
    from trident.models import Finding
    assert _dep_package(Finding(raw_outputs={"raw": f.raw})) == "django"


def test_osvscanner_cvss_fallback_when_no_named_severity():
    sample = json.dumps({"results": [{"source": {"path": "/ws/go.mod"}, "packages": [{
        "package": {"name": "pkg", "version": "1.0"},
        "vulnerabilities": [{"id": "OSV-1", "severity": [{"type": "CVSS_V3", "score": "9.8"}]}],
    }]}]})
    out = OsvScannerTool(workspace="/ws", job_id="j")._parse(sample)
    assert out[0].severity == "critical"


def test_trufflehog_parse_skips_logs_and_flags_verified():
    lines = "\n".join([
        json.dumps({"level": "info", "msg": "scanning"}),  # log line, no DetectorName
        json.dumps({
            "SourceMetadata": {"Data": {"Filesystem": {"file": "/ws/config.py", "line": 10}}},
            "DetectorName": "AWS", "Verified": True, "Redacted": "AKIA...", "Raw": "AKIAxxx",
        }),
    ])
    out = TruffleHogTool(workspace="/ws", job_id="j")._parse(lines)
    assert len(out) == 1
    f = out[0]
    assert f.tool == "trufflehog" and f.rule_id == "AWS"
    assert f.severity == "critical" and f.cwe == "CWE-798"
    assert f.file == "config.py" and f.line_start == 10


def test_checkov_parse_handles_list_of_frameworks():
    sample = json.dumps([{
        "check_type": "dockerfile",
        "results": {"failed_checks": [{
            "check_id": "CKV_DOCKER_2", "check_name": "Ensure HEALTHCHECK exists",
            "file_path": "/Dockerfile", "file_line_range": [1, 5],
            "severity": "LOW", "guideline": "https://docs", "resource": "Dockerfile.",
        }]},
    }])
    out = CheckovTool(workspace="/ws", job_id="j")._parse(sample)
    assert len(out) == 1
    f = out[0]
    assert f.tool == "checkov" and f.rule_id == "CKV_DOCKER_2"
    assert f.severity == "low" and f.file == "Dockerfile"
    assert "dockerfile" in f.title


def test_govulncheck_parse_reachable_finding():
    stream = "".join([
        json.dumps({"osv": {"id": "GO-2021-0113", "summary": "OOB read",
                            "aliases": ["CVE-2021-38561"]}}),
        json.dumps({"finding": {"osv": "GO-2021-0113", "trace": [{
            "module": "golang.org/x/text", "package": "golang.org/x/text/language",
            "function": "Parse", "position": {"filename": "main.go", "line": 12}}]}}),
    ])
    out = GovulncheckTool(workspace="/ws", job_id="j")._parse(stream, module_dir="/ws")
    assert len(out) == 1
    f = out[0]
    assert f.tool == "govulncheck" and f.rule_id == "GO-2021-0113"
    assert f.severity == "high" and f.file == "main.go" and f.line_start == 12


def test_govulncheck_skips_when_no_go_mod(tmp_path):
    (tmp_path / "app.py").write_text("print(1)\n")
    t = GovulncheckTool(workspace=str(tmp_path), job_id="j")
    assert t._go_module_dirs() == []
    (tmp_path / "go.mod").write_text("module x\n")
    assert t._go_module_dirs() == [str(tmp_path)]


def test_adapters_tolerate_garbage_output():
    for cls in (OsvScannerTool, CheckovTool):
        assert cls(workspace="/ws", job_id="j")._parse("not json") == []
    assert TruffleHogTool(workspace="/ws", job_id="j")._parse("not json") == []
    assert GovulncheckTool(workspace="/ws", job_id="j")._parse("not json") == []
