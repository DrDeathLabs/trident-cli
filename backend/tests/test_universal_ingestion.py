from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from trident.cli import cli
from trident.ingest.contracts import MAPPING_VERSION
from trident.ingest.importers import parse_report
from trident.ingest.mapping import MappingError, select
from trident.ingest.inference import propose_mapping_with_model
from trident.llm.base import LLMResponse


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
    assert first.findings[0].severity == "high"
    assert first.findings[0].raw["mapping_sha256"] == second.findings[0].raw["mapping_sha256"]
    assert parse_report(report_path, mapping=json.loads(mapping_path.read_text())).accounting == first.accounting


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
