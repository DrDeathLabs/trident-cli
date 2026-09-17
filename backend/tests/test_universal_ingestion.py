from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from trident.cli import cli
from trident.ingest.contracts import MAPPING_VERSION
from trident.ingest.importers import parse_report
from trident.ingest.mapping import MappingError, normalize_severity, select
from trident.ingest.inference import MappingProposal, propose_mapping_with_model
from trident.ingest.contracts import MappingValidation
from trident.llm.base import LLMResponse
from trident.reliability.structured import _default_ledger_path
from trident.config import settings


def _write(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def test_selector_is_data_only_and_supports_wildcards():
    payload = {"results": [{"title": "one"}, {"title": "two"}]}
    assert [item.value for item in select(payload, "$.results[*].title")] == ["one", "two"]
    with pytest.raises(MappingError):
        select(payload, "$.results[*][?(@.title)]")


def test_generic_top_level_array_has_complete_accounting_and_provenance(tmp_path):
    path = _write(tmp_path / "report.json", [
        {"id": "V-1", "title": "Injection", "severity": "HIGH", "file": "src/a.py", "line": 7},
        {"id": "V-2", "title": "Quality note"},
        "not-a-record",
    ])
    report = parse_report(path)
    assert report.format == "generic-json"
    assert report.records == 3
    assert report.accounting["total_records"] == 3
    assert sum(report.accounting[state] for state in (
        "mapped", "partially_mapped", "out_of_scope", "skipped", "malformed", "unsupported",
    )) == 3
    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.record_pointer == "/0"
    assert finding.raw["provenance"]["fields"]["severity"]["pointer"] == "/0/severity"
    assert finding.raw["provenance"]["fields"]["severity"]["original"] == "HIGH"


def test_explicit_mapping_is_replayable_and_strict(tmp_path):
    report_path = _write(tmp_path / "vendor.json", {"alerts": [{
        "threatCode": "TH-1", "headline": "Unsafe parser", "riskBand": 8,
        "where": {"path": "src/parser.py", "line": 11},
    }]})
    mapping = {
        "mapping_version": MAPPING_VERSION,
        "name": "vendor-holdout",
        "records": "$.alerts[*]",
        "tool": {"literal": "vendor-scanner"},
        "fields": {
            "rule_id": "$.threatCode", "title": "$.headline", "severity": "$.riskBand",
            "file": "$.where.path", "line_start": "$.where.line",
        },
    }
    mapping_path = _write(tmp_path / "map.json", mapping)
    first = parse_report(report_path, mapping=mapping)
    second = parse_report(report_path, mapping=mapping)
    assert first.mapping == second.mapping
    assert first.findings[0].rule_id == "TH-1"
    assert first.findings[0].severity == "info"
    assert first.findings[0].raw["provenance"]["fields"]["severity"]["original"] == 8
    assert first.findings[0].raw["severity_normalization"] == "numeric_without_cvss_semantics"
    assert first.findings[0].raw["mapping_sha256"] == second.findings[0].raw["mapping_sha256"]
    assert parse_report(report_path, mapping=json.loads(mapping_path.read_text())).accounting == first.accounting


def test_arbitrary_numeric_severity_is_not_assumed_to_be_cvss():
    normalized, basis = normalize_severity(8)
    assert normalized == "info"
    assert basis == "numeric_without_cvss_semantics"

    normalized, basis = normalize_severity("vendor-risk", cvss_score=8)
    assert normalized == "high"
    assert basis == "cvss_score_semantics"


def test_trivy_like_generic_mapping_preserves_identifier_and_cvss_semantics(tmp_path):
    payload = {"Results": [{"Vulnerabilities": [
        {"VulnerabilityID": "CVE-2023-30861", "VendorIDs": ["GHSA-m2qf-hxjv-5gpq"],
         "PkgName": "flask", "InstalledVersion": "1.0.2", "Severity": "HIGH",
         "CweIDs": ["CWE-539"], "CVSS": {"nvd": {"V3Score": 7.5,
         "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}}},
        {"VulnerabilityID": "CVE-2018-18074", "VendorIDs": ["GHSA-x84v-xcm2-53pg"],
         "PkgName": "requests", "InstalledVersion": "2.19.0", "Severity": "HIGH",
         "CweIDs": ["CWE-522"], "CVSS": {"nvd": {"V3Score": 7.5,
         "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}}},
    ]}]}
    report = parse_report(_write(tmp_path / "trivy.json", payload), no_schema_ai=True)
    assert report.accounting["mapped"] == 2
    assert [(f.cve, f.ghsa, f.cwe, f.package, f.installed_version, f.cvss_score)
            for f in report.findings] == [
        ("CVE-2023-30861", "GHSA-M2QF-HXJV-5GPQ", "CWE-539", "flask", "1.0.2", 7.5),
        ("CVE-2018-18074", "GHSA-X84V-XCM2-53PG", "CWE-522", "requests", "2.19.0", 7.5),
    ]
    assert all(f.mapping_identity for f in report.findings)
    assert all(f.raw["mapping_identity"] == f.mapping_identity for f in report.findings)


def test_grype_like_generic_mapping_separates_advisory_cve_package_and_cvss(tmp_path):
    payload = {"matches": [{
        "vulnerability": {"id": "GHSA-x84v-xcm2-53pg", "severity": "High",
        "description": "Requests issue", "cvss": [{"version": "3.1",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "metrics": {"baseScore": 7.5}}], "cwes": [{"cwe": "CWE-522"}]},
        "relatedVulnerabilities": [{"id": "CVE-2018-18074", "severity": "High"}],
        "artifact": {"id": "opaque-artifact-id", "name": "requests", "version": "2.19.0",
        "language": "python", "locations": [{"path": "requirements.txt"}]},
    }, {
        "vulnerability": {"id": "GHSA-j8r2-6x86-q33q", "severity": "Medium",
        "description": "Other issue", "cvss": [{"version": "3.1", "metrics": {"baseScore": 6.1}}]},
        "relatedVulnerabilities": [{"id": "CVE-2023-32681"}],
        "artifact": {"id": "another-opaque-id", "name": "requests", "version": "2.19.0"},
    }]}
    report = parse_report(_write(tmp_path / "grype.json", payload), no_schema_ai=True)
    assert report.accounting["mapped"] == 2
    assert [
        (f.source_record_id, f.ghsa, f.cve, f.package, f.installed_version, f.cvss_score)
        for f in report.findings
    ] == [
        ("GHSA-x84v-xcm2-53pg", "GHSA-X84V-XCM2-53PG", "CVE-2018-18074", "requests", "2.19.0", 7.5),
        ("GHSA-j8r2-6x86-q33q", "GHSA-J8R2-6X86-Q33Q", "CVE-2023-32681", "requests", "2.19.0", 6.1),
    ]


def test_semgrep_like_generic_mapping_does_not_fabricate_installed_version(tmp_path):
    payload = {"results": [{
        "check_id": "rule.one", "path": "app.py", "end": {"line": 2},
        "extra": {"severity": "ERROR", "message": "bad", "metadata": {
            "cwe": ["CWE-78"], "asvs": {"version": "4"}}},
    }, {
        "check_id": "rule.two", "path": "app.py", "end": {"line": 4},
        "extra": {"severity": "WARNING", "message": "worse", "metadata": {
            "cwe": ["CWE-327"], "asvs": {"version": "4"}}},
    }]}
    report = parse_report(_write(tmp_path / "semgrep.json", payload), no_schema_ai=True)
    assert report.accounting["mapped"] == 2
    assert all(f.installed_version is None for f in report.findings)


def test_source_record_id_does_not_use_descriptive_field(tmp_path):
    payload = {"findings": [{
        "record_key": "AR-1", "commentary": "This is descriptive evidence",
        "title": "Unsafe archive extraction", "severity": "high",
    }]}
    mapping = {
        "mapping_version": MAPPING_VERSION,
        "name": "identity-context",
        "records": "$.findings[*]",
        "tool": {"literal": "holdout"},
        "fields": {
            "source_record_id": "$.commentary",
            "rule_id": "$.record_key",
            "title": "$.title",
            "severity": "$.severity",
        },
    }
    with pytest.raises(Exception, match="semantic"):
        parse_report(_write(tmp_path / "identity-context.json", payload), mapping=mapping)


def test_unknown_vendor_schema_fails_closed_without_explicit_mapping(tmp_path):
    path = _write(tmp_path / "vendor.json", {"threats": [{
        "threatCode": "TH-1", "headline": "Unsafe parser", "riskBand": 8,
        "where": {"path": "src/parser.py", "line": 11},
    }]})
    with pytest.raises(Exception, match="provide --mapping"):
        parse_report(path, no_schema_ai=True)


def test_sarif_security_scope_and_location(tmp_path):
    payload = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "holdout", "rules": [{
                "id": "SEC-1", "shortDescription": {"text": "Injection"},
                "properties": {"tags": ["security", "CWE-89"]},
            }]}},
            "results": [
                {"ruleId": "SEC-1", "level": "error", "message": {"text": "bad query"},
                 "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"},
                 "region": {"startLine": 3, "endLine": 4}}}]},
                {"ruleId": "STYLE-1", "level": "warning", "message": {"text": "formatting"}},
            ],
        }],
    }
    report = parse_report(_write(tmp_path / "results.sarif", payload))
    assert report.accounting["mapped"] == 1
    assert report.accounting["out_of_scope"] == 1
    assert report.findings[0].file == "a.py"
    assert report.findings[0].raw["provenance"]["record_pointer"] == "/runs/0/results/0"


def test_cyclonedx_links_affected_component(tmp_path):
    payload = {
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "components": [{"bom-ref": "pkg", "name": "demo", "version": "1.0.0",
                         "purl": "pkg:pypi/demo@1.0.0"}],
        "vulnerabilities": [{"id": "CVE-2025-0001", "description": "bad", "affects": [{"ref": "pkg"}],
                              "ratings": [{"severity": "high", "score": 8.1}], "cwes": [89]}],
    }
    report = parse_report(_write(tmp_path / "bom.json", payload))
    assert report.format == "cyclonedx"
    assert report.findings[0].package == "demo"
    assert report.findings[0].installed_version == "1.0.0"
    assert report.findings[0].purl == "pkg:pypi/demo@1.0.0"
    assert report.accounting["total_records"] == 1


def test_generic_package_vulnerability_context_is_inherited_with_provenance(tmp_path):
    payload = {
        "packages": [{"name": "demo", "version": "1.0.0", "vulnerabilities": [
            {"id": "CVE-2025-0002", "description": "bad package", "severity": "high"},
        ]}],
    }
    path = _write(tmp_path / "packages.json", payload)
    report = parse_report(path)
    finding = report.findings[0]
    assert finding.package == "demo"
    assert finding.installed_version == "1.0.0"
    assert finding.raw["provenance"]["fields"]["package"]["pointer"] == "/packages/0/name"


def test_import_provenance_envelope_records_source_grounding(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("print('ok')\n", encoding="utf-8")
    payload = {"findings": [{
        "id": "F-1", "title": "Unsafe operation", "severity": "high",
        "file": "app.py", "line": 1,
    }]}
    report = parse_report(_write(tmp_path / "report.json", payload), source_dir=str(source))
    provenance = report.findings[0].raw["provenance"]
    assert provenance["source_context_available"] is True
    assert provenance["evidence_basis"] == "source_grounded"


def test_first_class_provenance_envelope_records_source_grounding(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("print('ok')\n", encoding="utf-8")
    sarif = {
        "version": "2.1.0", "runs": [{"tool": {"driver": {"name": "holdout",
        "rules": [{"id": "SEC-1", "properties": {"tags": ["security"]}}]}},
        "results": [{"ruleId": "SEC-1", "level": "error",
        "message": {"text": "bad"}, "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "app.py"}, "region": {"startLine": 1}
        }}]}]}]
    }
    report = parse_report(_write(tmp_path / "results.sarif", sarif), source_dir=str(source))
    provenance = report.findings[0].raw["provenance"]
    assert provenance["source_context_available"] is True
    assert provenance["evidence_basis"] == "source_grounded"

    bom = {
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "components": [{"bom-ref": "pkg", "name": "demo", "version": "1.0.0"}],
        "vulnerabilities": [{"id": "CVE-2026-0001", "description": "bad",
                              "affects": [{"ref": "pkg"}]}],
    }
    report = parse_report(_write(tmp_path / "bom.json", bom), source_dir=str(source))
    provenance = report.findings[0].raw["provenance"]
    assert provenance["source_context_available"] is False
    assert provenance["evidence_basis"] == "report_only"


@pytest.mark.parametrize("report_file", ["missing.py", r"C:\outside\missing.py"])
def test_generic_source_context_is_report_only_when_file_does_not_resolve(tmp_path, report_file):
    source = tmp_path / "source"
    source.mkdir()
    payload = {"findings": [{
        "id": "F-1", "title": "Unsafe operation", "severity": "high",
        "file": report_file, "line": 1,
    }]}
    finding = parse_report(
        _write(tmp_path / "report.json", payload), source_dir=str(source)
    ).findings[0]
    assert finding.source_context_available is False
    assert finding.evidence_basis == "report_only"
    assert finding.raw["provenance"]["source_context_available"] is False
    assert finding.raw["source_context_requested"] is True


def test_generic_source_context_does_not_guess_ambiguous_suffix(tmp_path):
    source = tmp_path / "source"
    (source / "one").mkdir(parents=True)
    (source / "two").mkdir()
    (source / "one" / "app.py").write_text("x\n", encoding="utf-8")
    (source / "two" / "app.py").write_text("y\n", encoding="utf-8")
    payload = {"findings": [{
        "id": "F-1", "title": "Unsafe operation", "severity": "high",
        "file": r"C:\build\app.py", "line": 1,
    }]}
    finding = parse_report(
        _write(tmp_path / "report.json", payload), source_dir=str(source)
    ).findings[0]
    assert finding.source_context_available is False
    assert finding.evidence_basis == "report_only"


def test_sarif_source_context_is_report_only_when_location_is_missing(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    payload = {
        "version": "2.1.0", "runs": [{"tool": {"driver": {"name": "holdout",
        "rules": [{"id": "SEC-1", "properties": {"tags": ["security"]}}]}},
        "results": [{"ruleId": "SEC-1", "level": "error", "message": {"text": "bad"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "missing.py"},
        "region": {"startLine": 1}}}]}]}],
    }
    finding = parse_report(
        _write(tmp_path / "missing.sarif", payload), source_dir=str(source)
    ).findings[0]
    assert finding.source_context_available is False
    assert finding.evidence_basis == "report_only"


def test_advisory_identifier_counts_as_deterministic_security_identity(tmp_path):
    path = _write(tmp_path / "osv.json", {"vulns": [{
        "osv_id": "OSV-2026-1", "details": "Dependency flaw",
        "database_specific": {"severity": "high"},
        "affected": [{"package": {"name": "demo"}}],
    }]})
    report = parse_report(path, no_schema_ai=True)
    assert report.accounting["mapped"] == 1
    assert report.findings[0].advisory_id == "OSV-2026-1"


def test_inspect_is_non_mutating_json_command(tmp_path):
    path = _write(tmp_path / "report.json", {"findings": [{
        "id": "F-1", "title": "Secret exposure", "severity": "high", "path": "secret.py",
    }]})
    result = CliRunner().invoke(cli, ["inspect", str(path), "--format", "json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["detected_format"] == "generic-json"
    assert payload["accounting"]["unexplained"] == 0
    assert "council" not in result.output.lower()


def test_model_may_propose_mapping_but_deterministic_validation_executes_it():
    payload = {"alerts": [{"threatCode": "TH-1", "headline": "Parser issue", "riskBand": 8}]}
    mapping = {
        "mapping_version": MAPPING_VERSION,
        "name": "model-proposal",
        "records": "$.alerts[*]",
        "tool": {"literal": "model-holdout"},
        "fields": {"rule_id": "$.threatCode", "title": "$.headline", "severity": "$.riskBand"},
    }

    class FakeBackend:
        def chat(self, messages, *, model, temperature=0.0, **kwargs):
            return LLMResponse(
                content=json.dumps(mapping),
                metadata={"backend": "approved-test-provider", "model_actual": "test-model-v2"},
            )

    proposal = propose_mapping_with_model(payload, backend=FakeBackend(), model="requested-model")
    assert proposal.source == "model_proposed"
    assert proposal.provider == "approved-test-provider"
    assert proposal.model_requested == "requested-model"
    assert proposal.model_actual == "test-model-v2"
    assert proposal.mapping["fields"]["rule_id"] == "$.threatCode"


def test_model_mapping_repairs_a_non_mapping_response():
    payload = {"alerts": [{"threatCode": "TH-1", "headline": "Parser issue", "riskBand": "high"}]}
    mapping = {
        "mapping_version": MAPPING_VERSION,
        "name": "repair-proposal",
        "records": "$.alerts[*]",
        "tool": {"literal": "repair-scanner"},
        "fields": {"rule_id": "$.threatCode", "title": "$.headline", "severity": "$.riskBand"},
    }

    class RepairBackend:
        def __init__(self):
            self.calls = 0

        def chat(self, messages, *, model, temperature=0.0, **kwargs):
            self.calls += 1
            content = json.dumps({"candidate_collections": ["$.alerts[*]"]}) if self.calls == 1 else json.dumps(mapping)
            return LLMResponse(
                content=content,
                metadata={"backend": "ollama", "model_actual": "nemotron-3-super"},
            )

    backend = RepairBackend()
    proposal = propose_mapping_with_model(payload, backend=backend, model="nemotron-3-super:cloud")
    assert backend.calls == 2
    assert len(proposal.response["attempts"]) == 2
    assert proposal.mapping["records"] == "$.alerts[*]"


def test_schema_ai_is_called_when_deterministic_inference_fails(monkeypatch, tmp_path):
    payload = {"threats": [{
        "threatCode": "TH-1", "headline": "Parser issue", "riskBand": "urgent",
    }]}
    path = _write(tmp_path / "unfamiliar.json", payload)
    mapping = {
        "mapping_version": MAPPING_VERSION,
        "name": "ai-holdout",
        "records": "$.threats[*]",
        "tool": {"literal": "ai-scanner"},
        "fields": {
            "rule_id": "$.threatCode", "title": "$.headline", "severity": "$.riskBand",
        },
    }
    proposal = MappingProposal(
        mapping=mapping, source="model_proposed",
        validation=MappingValidation(
            records_inspected=1, coverage={"rule_id": 1.0, "title": 1.0, "severity": 1.0},
            required_field_coverage=1.0, type_consistency=1.0, identifier_rate=1.0,
            confidence=1.0,
        ),
        provider="ollama", model_requested="nemotron-3-super:cloud",
        model_actual="nemotron-3-super",
        response={"content": json.dumps(mapping), "metadata": {"model_actual": "nemotron-3-super"}},
    )
    monkeypatch.setenv("TRIDENT_SCHEMA_AI", "1")
    monkeypatch.setattr("trident.ingest.importers.propose_mapping_with_model", lambda payload: proposal)
    report = parse_report(path)
    assert report.mapping_source == "model_proposed"
    assert report.findings[0].rule_id == "TH-1"
    assert report.findings[0].raw["provenance"]["fields"]["rule_id"]["pointer"] == "/threats/0/threatCode"


def test_sqlite_llm_ledger_defaults_to_a_sidecar(monkeypatch, tmp_path):
    monkeypatch.delenv("TRIDENT_LLM_LEDGER_PATH", raising=False)
    monkeypatch.setattr(settings.db, "backend", "sqlite")
    monkeypatch.setattr(settings.db, "sqlite_path", tmp_path / "scan.sqlite")
    assert _default_ledger_path() == str(tmp_path / "scan.sqlite.llm-ledger.sqlite")
