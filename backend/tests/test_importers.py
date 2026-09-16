"""Tests for external report import mode."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from trident.ingest.importers import (
    ImportErrorValue,
    detect_format,
    dependency_check_match_evidence,
    is_imported_sonarqube_code_smell,
    map_source_path,
    parse_report,
    prepare_import,
    normalize_cpe_identity,
    normalize_kev,
)
from trident.evidence import build_evidence_payload, evidence_basis, prompt_evidence
from trident.cli import cli
from trident.models import Finding, Job


def _write(path: Path, payload: dict) -> str:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


def _sonar_issue(status: str = "OPEN") -> dict:
    return {
        "rule": "javasecurity:S5145",
        "severity": "MAJOR",
        "component": "demo:src/App.java",
        "line": 12,
        "status": status,
        "message": "Make sure this request cannot be forged.",
        "type": "VULNERABILITY",
        "tags": ["cwe-352"],
        "textRange": {"startLine": 12, "endLine": 14},
    }


def _sonar_report(*issues: dict) -> dict:
    return {"total": len(issues), "issues": list(issues), "paging": {"pageIndex": 1}}


def _dependency_report() -> dict:
    return {
        "reportSchema": "1.1",
        "dependencies": [{
            "fileName": "library.jar",
            "filePath": r"C:\build\lib\library.jar",
            "evidenceCollected": {
                "productEvidence": [{"value": "library"}],
                "versionEvidence": [{"value": "1.2.3"}],
            },
            "vulnerabilities": [{
                "source": "NVD",
                "name": "CVE-2024-0001",
                "severity": "HIGH",
                "description": "A dependency vulnerability.",
                "cwes": ["CWE-89"],
                "cvssv2": {"score": 7.5},
                "references": [{"url": "https://example.invalid/CVE-2024-0001"}],
                "vulnerableSoftware": [],
            }],
        }],
    }


def test_detects_supported_formats():
    assert detect_format(_sonar_report(_sonar_issue())) == "sonarqube"
    assert detect_format(_dependency_report()) == "dependency-check"


def test_rejects_cyclonedx_explicitly():
    with pytest.raises(ImportErrorValue, match="CycloneDX"):
        detect_format({"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []})


def test_invalid_json_is_rejected(tmp_path):
    path = tmp_path / "invalid.json"
    path.write_text("{not-json", encoding="utf-8")
    with pytest.raises(ImportErrorValue, match="could not read JSON"):
        parse_report(path)


def test_explicit_format_mismatch_is_rejected(tmp_path):
    path = _write(tmp_path / "sonar.json", _sonar_report(_sonar_issue()))
    with pytest.raises(ImportErrorValue, match="does not match"):
        parse_report(path, input_format="dependency-check")


def test_missing_required_sonar_field_is_rejected(tmp_path):
    issue = _sonar_issue()
    issue.pop("message")
    path = _write(tmp_path / "sonar.json", _sonar_report(issue))
    with pytest.raises(ImportErrorValue, match="missing 'message'"):
        parse_report(path)


def test_missing_sonar_status_is_rejected(tmp_path):
    issue = _sonar_issue()
    issue.pop("status")
    path = _write(tmp_path / "sonar.json", _sonar_report(issue))
    with pytest.raises(ImportErrorValue, match="missing 'status'"):
        parse_report(path)


def test_dependency_without_vulnerabilities_is_not_a_finding(tmp_path):
    payload = _dependency_report()
    payload["dependencies"].append({"fileName": "clean.jar", "vulnerabilities": []})
    path = _write(tmp_path / "dependency-check.json", payload)
    report = parse_report(path)
    assert report.records == 1
    assert len(report.findings) == 1


def test_sonarqube_import_filters_closed_and_maps_fields(tmp_path):
    path = _write(tmp_path / "sonar.json", _sonar_report(_sonar_issue(), _sonar_issue("CLOSED")))
    report = parse_report(path)
    assert report.format == "sonarqube"
    assert report.records == 2
    assert len(report.findings) == 1
    assert len(report.skipped) == 1
    assert report.skipped[0]["reason"] == "source_status_not_open"
    assert report.skipped[0]["record"]["status"] == "CLOSED"
    finding = report.findings[0]
    assert finding.tool == "sonarqube"
    assert finding.severity == "high"
    assert finding.file == "src/App.java"
    assert finding.line_start == 12
    assert finding.line_end == 14
    assert finding.cwe == "CWE-352"
    assert finding.raw["record"]["rule"] == "javasecurity:S5145"


def test_sonarqube_code_smell_is_retained_as_non_security_quality_finding(tmp_path, db, job):
    path = _write(tmp_path / "sonar.json", _sonar_report(_sonar_issue()))
    issue = json.loads(Path(path).read_text(encoding="utf-8"))["issues"][0]
    issue["type"] = "CODE_SMELL"
    Path(path).write_text(json.dumps(_sonar_report(issue)), encoding="utf-8")
    finding = parse_report(path).findings[0]
    stored = Finding(
        id="code-smell-finding", job_id=job.id, hash="code-smell-hash", tool=finding.tool,
        rule_id=finding.rule_id, severity=finding.severity, confidence=finding.confidence,
        title=finding.title, description=finding.description, file=finding.file,
        line_start=finding.line_start, line_end=finding.line_end, cwe=finding.cwe,
        raw_outputs={"raw": finding.raw}, status="raw",
    )
    db.add(stored)
    db.commit()
    assert is_imported_sonarqube_code_smell(stored)
    from trident.deliberation import _set_status
    _set_status(db, stored, "confirmed", 0.9, 0)
    assert stored.status == "out_of_scope"
    assert stored.triage["scope"] == "non_security_quality_issue"


def test_dependency_check_import_preserves_raw_record_and_cvss(tmp_path):
    path = _write(tmp_path / "dependency-check.json", _dependency_report())
    report = parse_report(path)
    assert report.records == 1
    finding = report.findings[0]
    assert finding.tool == "dependency-check"
    assert finding.rule_id == "CVE-2024-0001"
    assert finding.severity == "high"
    assert finding.cwe == "CWE-89"
    assert "CVSS v2: 7.5" in finding.description
    assert finding.raw["record"]["cvssv2"]["score"] == 7.5
    assert finding.raw["package"] == "library"
    assert finding.raw["InstalledVersion"] == "1.2.3"
    assert finding.raw["dependency"]["fileName"] == "library.jar"
    assert "vulnerabilities" not in finding.raw["dependency"]
    assert finding.raw["dependency_vulnerability_count"] == 1


def test_dependency_version_normalization_removes_quotes_and_preserves_raw(tmp_path):
    payload = _dependency_report()
    payload["dependencies"][0]["evidenceCollected"]["versionEvidence"] = [
        {"value": '"1.5"', "name": "version", "confidence": "HIGHEST"},
    ]
    path = _write(tmp_path / "dependency-check.json", payload)
    finding = parse_report(path).findings[0]
    assert finding.raw["installed_version_raw"] == '"1.5"'
    assert finding.raw["InstalledVersion"] == "1.5"
    assert "quotes_removed" in finding.raw["version_normalization"]


def test_import_evidence_contract_preserves_original_record_and_basis(tmp_path):
    path = _write(tmp_path / "dependency-check.json", _dependency_report())
    report = parse_report(path)
    finding = Finding(
        id="evidence-contract-finding", job_id="job1", hash="hash", tool=report.findings[0].tool,
        rule_id=report.findings[0].rule_id, severity=report.findings[0].severity,
        confidence=report.findings[0].confidence, title=report.findings[0].title,
        description=report.findings[0].description, file=report.findings[0].file,
        line_start=0, line_end=0, raw_outputs={"raw": report.findings[0].raw}, status="raw",
    )
    report_only = build_evidence_payload(finding)
    assert report_only["basis"] == "report_only"
    assert report_only["import"]["record"]["name"] == "CVE-2024-0001"
    assert report_only["import"]["dependency"]["fileName"] == "library.jar"
    assert evidence_basis(finding) == "report_only"
    prompt = prompt_evidence(finding)
    assert "CVE-2024-0001" in prompt
    assert "untrusted scanner/report data" in prompt


def test_import_evidence_contract_marks_matching_source_context(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    manifest = source / "requirements.txt"
    manifest.write_text("library==1.2.3\n", encoding="utf-8")
    path = _write(tmp_path / "dependency-check.json", _dependency_report())
    finding = parse_report(path, source_dir=str(source)).findings[0]
    stored = Finding(
        id="source-evidence-finding", job_id="job1", hash="hash", tool=finding.tool,
        rule_id=finding.rule_id, severity=finding.severity, confidence=finding.confidence,
        title=finding.title, description=finding.description, file="requirements.txt",
        line_start=0, line_end=0, raw_outputs={"raw": finding.raw}, status="raw",
    )
    assert evidence_basis(stored, str(source)) == "source_grounded"


def test_dependency_match_evidence_preserves_explicit_cpe_match(tmp_path):
    payload = _dependency_report()
    payload["dependencies"][0]["vulnerabilities"][0]["vulnerableSoftware"] = [{
        "software": {
            "id": "cpe:2.3:a:apache:library:*:*:*:*:*:*:*:*",
            "versionEndExcluding": "2.0.0",
            "vulnerabilityIdMatched": "true",
        },
    }]
    path = _write(tmp_path / "dependency-check.json", payload)
    finding = parse_report(path).findings[0]
    evidence = dependency_check_match_evidence(
        Finding(
            id="evidence-finding", job_id="job1", hash="hash", tool=finding.tool,
            rule_id=finding.rule_id, severity=finding.severity, confidence=finding.confidence,
            title=finding.title, description=finding.description, file=finding.file,
            line_start=finding.line_start, line_end=finding.line_end, cwe=finding.cwe,
            raw_outputs={"raw": finding.raw}, status="raw",
        )
    )
    assert evidence is not None
    assert evidence["package"] == "library"
    assert evidence["installed_version"] == "1.2.3"
    assert evidence["matched_software"][0]["versionEndExcluding"] == "2.0.0"


def test_product_only_dependency_match_is_not_strong_evidence(tmp_path):
    payload = _dependency_report()
    payload["dependencies"][0]["vulnerabilities"][0]["vulnerableSoftware"] = [{
        "software": {
            "id": "cpe:2.3:a:vendor:library:*:*:*:*:*:*:*:*",
            "vulnerabilityIdMatched": "true",
        },
    }]
    path = _write(tmp_path / "dependency-check.json", payload)
    finding = parse_report(path).findings[0]
    assert dependency_check_match_evidence(
        Finding(
            id="product-only-finding", job_id="job1", hash="hash", tool=finding.tool,
            rule_id=finding.rule_id, severity=finding.severity, confidence=finding.confidence,
            title=finding.title, description=finding.description, file=finding.file,
            line_start=finding.line_start, line_end=finding.line_end, cwe=finding.cwe,
            raw_outputs={"raw": finding.raw}, status="raw",
        )
    ) is None


def test_model_refutation_cannot_erase_explicit_dependency_match(db, job):
    from tests.conftest import make_finding
    from trident.deliberation import _set_status

    finding = make_finding(
        db,
        tool="dependency-check",
        rule_id="CVE-2026-42402",
        raw_outputs={"raw": {
            "import_format": "dependency-check",
            "package": "neethi",
            "InstalledVersion": "2.0.2",
            "record": {
                "name": "CVE-2026-42402",
                "vulnerableSoftware": [{"software": {
                    "id": "cpe:2.3:a:apache:neethi:*:*:*:*:*:*:*:*",
                    "versionEndExcluding": "3.2.2",
                    "vulnerabilityIdMatched": "true",
                }}],
            },
        }},
    )
    _set_status(db, finding, "false_positive", 0.9, 0, "model rejected it")
    assert finding.status == "disputed"
    assert finding.triage["contested"] is True
    assert finding.triage["import_evidence_conflict"]["rule_id"] == "CVE-2026-42402"
    assert db.query(Job).filter_by(id="job1").one().id == "job1"


def test_dependency_version_uses_strongest_evidence(tmp_path):
    payload = _dependency_report()
    payload["dependencies"][0]["evidenceCollected"]["versionEvidence"] = [
        {"name": "name", "confidence": "MEDIUM", "value": "library.jar"},
        {"name": "Implementation-Version", "confidence": "HIGH", "value": "1.2.3"},
    ]
    path = _write(tmp_path / "dependency-check.json", payload)
    finding = parse_report(path).findings[0]
    assert finding.raw["InstalledVersion"] == "1.2.3"


def test_dependency_version_prefers_explicit_version_over_package_name(tmp_path):
    payload = _dependency_report()
    payload["dependencies"][0]["evidenceCollected"]["versionEvidence"] = [
        {"name": "version", "confidence": "HIGH", "value": "3.5.3"},
        {"name": "package name", "confidence": "HIGHEST", "value": "ckeditor"},
    ]
    path = _write(tmp_path / "dependency-check.json", payload)
    finding = parse_report(path).findings[0]
    assert finding.raw["InstalledVersion"] == "3.5.3"


def test_dependency_version_path_suffix_is_normalized_and_preserved(tmp_path):
    payload = _dependency_report()
    payload["dependencies"][0]["evidenceCollected"]["versionEvidence"] = [
        {"name": "version", "confidence": "HIGH", "value": r"1.6.4\angular-animate"},
    ]
    path = _write(tmp_path / "dependency-check.json", payload)
    finding = parse_report(path).findings[0]
    assert finding.raw["InstalledVersion"] == "1.6.4"
    assert finding.raw["installed_version_raw"] == r"1.6.4\angular-animate"
    assert finding.raw["version_normalization"] == "path_suffix_removed"


def test_dependency_import_normalizes_kev_and_identity_conflict(tmp_path):
    payload = _dependency_report()
    vuln = payload["dependencies"][0]["vulnerabilities"][0]
    vuln["knownExploitedVulnerability"] = {
        "VendorProject": "Apache", "Product": "Different Product",
        "Name": "Example KEV", "DateAdded": "2024-01-01",
        "RequiredAction": "Patch", "DueDate": "2024-02-01",
    }
    vuln["vulnerableSoftware"] = [{"software": {
        "id": "cpe:2.3:a:unrelated:other-product:*:*:*:*:*:*:*:*",
        "vulnerabilityIdMatched": "true",
    }}]
    path = _write(tmp_path / "dependency-check.json", payload)
    finding = parse_report(path).findings[0]
    assert finding.raw["kev"] == {
        "listed": True, "source": "imported_record", "vendor_project": "Apache",
        "product": "Different Product", "name": "Example KEV", "date_added": "2024-01-01",
        "description": None, "required_action": "Patch", "due_date": "2024-02-01",
        "notes": None,
    }
    assert finding.raw["cpe_identity"]["status"] == "conflict"
    assert normalize_kev(vuln)["listed"] is True


def test_cpe_identity_reports_match_and_version_conflict():
    matching = {
        "vulnerableSoftware": [{"software": {
            "id": "cpe:2.3:a:vendor:library:*:*:*:*:*:*:*:*",
            "versionEndExcluding": "2.0.0", "vulnerabilityIdMatched": "true",
        }}],
    }
    assert normalize_cpe_identity("library", "1.2.3", matching)["status"] == "match"
    assert normalize_cpe_identity("library", "2.1.0", matching)["status"] == "conflict"


def test_prepare_import_rejects_duplicate_paths(tmp_path):
    path = _write(tmp_path / "sonar.json", _sonar_report(_sonar_issue()))
    with pytest.raises(ImportErrorValue, match="more than once"):
        prepare_import([path, path], "auto", None)


def test_cli_requires_source_for_novel_discovery(tmp_path):
    path = _write(tmp_path / "sonar.json", _sonar_report(_sonar_issue()))
    result = CliRunner().invoke(cli, ["scan", "--input-file", path, "--discover-novel"])
    assert result.exit_code == 2
    assert "requires --source-dir" in result.output


def test_source_path_mapping_only_uses_unique_match(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    file = source / "src" / "App.java"
    file.parent.mkdir()
    file.write_text("class App {}", encoding="utf-8")
    assert map_source_path(r"C:\build\src\App.java", str(source)) == "src/App.java"
    assert map_source_path(r"C:\build\missing.java", str(source)) == "C:/build/missing.java"


def test_source_path_mapping_does_not_guess_ambiguous_suffix(tmp_path):
    source = tmp_path / "source"
    for folder in ("one", "two"):
        target = source / folder / "App.java"
        target.parent.mkdir(parents=True)
        target.write_text("class App {}", encoding="utf-8")
    assert map_source_path(r"C:\build\App.java", str(source)) == "C:/build/App.java"


def test_source_context_maps_report_path_and_is_readable(tmp_path):
    source = tmp_path / "source"
    file = source / "src" / "App.java"
    file.parent.mkdir(parents=True)
    file.write_text("class App { int value = 1; }\n", encoding="utf-8")
    issue = _sonar_issue()
    issue["component"] = "demo:src/App.java"
    report_path = _write(tmp_path / "sonar.json", _sonar_report(issue))
    report = parse_report(report_path, source_dir=str(source))
    finding = report.findings[0]
    assert finding.file == "src/App.java"
    from trident.experts.base import ExpertBase
    assert "class App" in ExpertBase("job", str(source))._read_file(finding.file, 1, 1)


def test_import_hash_change_fails_before_persistence(tmp_path, db):
    path = Path(_write(tmp_path / "sonar.json", _sonar_report(_sonar_issue())))
    _reports, profile = prepare_import([str(path)], "auto", None)
    path.write_text(json.dumps(_sonar_report({**_sonar_issue(), "line": 99})), encoding="utf-8")
    job = Job(
        id="changed-import-job", target_name="imported", source_type="import", source_ref=str(path),
        workspace_path="", profile=profile,
    )
    db.add(job)
    db.commit()
    from trident.orchestrator import run_scan
    run_scan(job, db)
    db.refresh(job)
    assert job.status == "failed"
    assert "changed after validation" in job.error


def test_imported_findings_persist_through_normal_scan_and_triage(tmp_path, db, monkeypatch):
    path = _write(tmp_path / "sonar.json", _sonar_report(_sonar_issue()))
    _reports, profile = prepare_import([path], "auto", None)
    job = Job(
        id="import-job", target_name="imported", source_type="import", source_ref=path,
        workspace_path="", profile=profile,
    )
    db.add(job)
    db.commit()
    from trident.orchestrator import run_scan

    monkeypatch.setattr(
        "trident.orchestrator.get_tools",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("scanner executed in import mode")),
    )
    run_scan(job, db)
    db.refresh(job)
    assert job.status == "complete"
    from trident.triage import run_triage
    run_triage(db, job.id)
    finding = db.query(Finding).filter_by(job_id=job.id).one()
    assert finding.status == "confirmed"
    assert finding.priority in {"P0", "P1", "P2", "P3", "P4"}
    assert finding.triage["reachability"] == "unknown"


def test_report_only_prompts_disclose_missing_source_context():
    from types import SimpleNamespace

    from trident.prompts import (
        build_judge_prompt,
        build_redteam_prompt,
        build_review_prompt,
        build_triage_prompt,
    )

    finding = SimpleNamespace(
        tool="sonarqube", rule_id="S001", title="Imported issue", description="Report metadata",
        file="src/app.py", line_start=10, line_end=10, cwe=None, severity="high",
        narrative="Imported narrative", raw_outputs={"raw": {
            "import_format": "sonarqube",
            "record": {"rule": "S001", "status": "OPEN", "message": "Report evidence"},
        }},
    )
    unavailable = "[source context unavailable: imported report metadata only]"
    assert "did not inspect the source code" in build_review_prompt(
        "Injection", "injection", finding, unavailable
    )
    assert "No source code was" in build_judge_prompt(finding, "peer", unavailable)
    assert "hypothetical" in build_redteam_prompt("[id] finding", metadata_only=True)
    assert "No source code is available" in build_triage_prompt(finding, unavailable)
    assert "Report evidence" in build_judge_prompt(finding, "peer", unavailable)
    assert "Report evidence" in build_triage_prompt(finding, unavailable)
