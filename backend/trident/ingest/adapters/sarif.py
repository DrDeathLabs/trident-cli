"""Deterministic SARIF 2.1.0 security-result adapter."""

from __future__ import annotations

import re
from typing import Any

from trident.ingest.contracts import RecordAccounting, mapping_sha256
from trident.ingest.mapping import _resolve_source_file, normalize_severity
from trident.ingest.provenance import field_provenance, provenance_envelope
from trident.tools.base import RawFinding


def _text(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, dict):
        for key in ("text", "markdown", "value"):
            if isinstance(value.get(key), str) and value[key].strip():
                return value[key].strip()
    return str(value).strip() if value is not None and not isinstance(value, (list, dict)) else ""


def _cwe(value: Any) -> str | None:
    text = " ".join(_text(item) for item in value) if isinstance(value, list) else _text(value)
    match = re.search(r"CWE[-_: ]?(\d+)", text, re.I)
    return f"CWE-{match.group(1)}" if match else None


def _security_signal(result: dict[str, Any], rule: dict[str, Any], cwe: str | None) -> bool:
    props = result.get("properties") if isinstance(result.get("properties"), dict) else {}
    rule_props = rule.get("properties") if isinstance(rule.get("properties"), dict) else {}
    tags = props.get("tags") or rule_props.get("tags") or []
    tags_text = " ".join(_text(tag).lower() for tag in tags) if isinstance(tags, list) else _text(tags).lower()
    return bool(
        cwe or props.get("security-severity") or rule_props.get("security-severity")
        or any(token in tags_text for token in ("security", "vulnerability", "cwe", "owasp"))
        or re.search(r"\b(?:CVE|GHSA|CWE)-", _text(result.get("message")), re.I)
    )


def _advisory_ids(value: Any) -> tuple[str | None, str | None]:
    text = _text(value)
    cve = re.search(r"\bCVE-\d{4}-\d{4,}\b", text, re.I)
    ghsa = re.search(r"\bGHSA-[0-9A-Za-z-]+\b", text, re.I)
    return (cve.group(0).upper() if cve else None, ghsa.group(0).upper() if ghsa else None)


def parse_sarif(
    payload: dict[str, Any], *, report_sha256: str, source_dir: str | None = None,
) -> tuple[list[RawFinding], RecordAccounting, dict[str, Any]]:
    if payload.get("version") != "2.1.0" or not isinstance(payload.get("runs"), list):
        raise ValueError("SARIF input must declare version 2.1.0 and a runs array")
    findings: list[RawFinding] = []
    accounting = RecordAccounting()
    mapping_identity = f"sarif-2.1.0:{mapping_sha256({'adapter': 'sarif', 'version': '2.1.0'})}"
    for run_index, run in enumerate(payload["runs"]):
        if not isinstance(run, dict):
            accounting.add("malformed", f"/runs/{run_index}", reason="run is not an object")
            continue
        driver = run.get("tool", {}).get("driver", {}) if isinstance(run.get("tool"), dict) else {}
        tool_name = _text(driver.get("name")) or "sarif"
        rules = {str(rule.get("id")): rule for rule in (run.get("tool", {}).get("driver", {}).get("rules", []) or []) if isinstance(rule, dict) and rule.get("id")}
        results = run.get("results")
        if not isinstance(results, list):
            accounting.add("unsupported", f"/runs/{run_index}/results", reason="results is not an array")
            continue
        for result_index, result in enumerate(results):
            pointer = f"/runs/{run_index}/results/{result_index}"
            if not isinstance(result, dict):
                accounting.add("malformed", pointer, reason="result is not an object")
                continue
            rule_id = _text(result.get("ruleId"))
            rule = rules.get(rule_id, {})
            properties = result.get("properties") if isinstance(result.get("properties"), dict) else {}
            rule_props = rule.get("properties") if isinstance(rule.get("properties"), dict) else {}
            tags = properties.get("tags") or rule_props.get("tags") or []
            cwe = _cwe(properties.get("cwe") or rule_props.get("cwe") or tags)
            if not _security_signal(result, rule, cwe):
                accounting.add("out_of_scope", pointer, reason="SARIF result lacks security evidence")
                continue
            message = _text(result.get("message"))
            short = _text(rule.get("shortDescription")) or _text(rule.get("name")) or message or rule_id
            level = result.get("level") or properties.get("security-severity") or rule_props.get("security-severity")
            severity, severity_basis = normalize_severity(level, cvss_score=properties.get("security-severity"))
            location = {}
            locations = result.get("locations") if isinstance(result.get("locations"), list) else []
            source_locations: list[dict[str, Any]] = []
            for source_location in locations:
                if not isinstance(source_location, dict):
                    continue
                physical = source_location.get("physicalLocation")
                if not isinstance(physical, dict):
                    continue
                artifact_value = physical.get("artifactLocation") if isinstance(physical.get("artifactLocation"), dict) else {}
                region_value = physical.get("region") if isinstance(physical.get("region"), dict) else {}
                source_locations.append({
                    "file": _text(artifact_value.get("uri")),
                    "line_start": region_value.get("startLine"),
                    "line_end": region_value.get("endLine"),
                    "column": region_value.get("startColumn"),
                })
            if locations and isinstance(locations[0], dict):
                location = locations[0].get("physicalLocation") or {}
            artifact = location.get("artifactLocation") if isinstance(location.get("artifactLocation"), dict) else {}
            region = location.get("region") if isinstance(location.get("region"), dict) else {}
            original_file_name = _text(artifact.get("uri"))
            file_name, source_grounded = _resolve_source_file(original_file_name, source_dir)
            source_record_id = _text(result.get("id")) or rule_id or f"{run_index}:{result_index}"
            cve, ghsa = _advisory_ids(result.get("message"))
            source_status = _text(result.get("baselineState") or result.get("kind")) or None
            fields = {
                "rule_id": field_provenance(f"{pointer}/ruleId", result.get("ruleId")) if "ruleId" in result else None,
                "title": field_provenance(f"{pointer}/message", result.get("message")) if "message" in result else None,
                "severity": field_provenance(f"{pointer}/level", result.get("level")) if "level" in result else None,
                "file": field_provenance(f"{pointer}/locations/0/physicalLocation/artifactLocation/uri", original_file_name) if original_file_name else None,
                "line_start": field_provenance(f"{pointer}/locations/0/physicalLocation/region/startLine", region.get("startLine")) if region.get("startLine") is not None else None,
                "cwe": field_provenance(f"{pointer}/properties/cwe", properties.get("cwe")) if properties.get("cwe") is not None else None,
            }
            fields = {key: value for key, value in fields.items() if value is not None}
            raw = {
                "import_format": "sarif",
                "record": result,
                "run": {"tool": tool_name, "index": run_index},
                "rule": rule,
                "source_record_id": source_record_id,
                "locations": source_locations,
                "source_status": source_status,
                "severity_original": level,
                "severity_normalization": severity_basis,
                "source_context_requested": bool(source_dir),
                "provenance": provenance_envelope(
                    report_sha256=report_sha256, record_pointer=pointer,
                    mapping_identity=mapping_identity, fields=fields,
                    evidence_basis="source_grounded" if source_grounded else "report_only",
                    source_context_available=source_grounded,
                ),
            }
            finding = RawFinding(
                tool=tool_name, rule_id=rule_id or source_record_id, severity=severity,
                confidence=0.75, title=short, description=message or short,
                file=file_name, line_start=int(region.get("startLine") or 0),
                line_end=int(region.get("endLine") or region.get("startLine") or 0),
                cwe=cwe, raw=raw, source_format="sarif", source_record_id=source_record_id,
                cve=cve, ghsa=ghsa,
                locations=source_locations,
                report_sha256=report_sha256, record_pointer=pointer,
                mapping_identity=mapping_identity, field_provenance=fields,
                source_status=source_status,
                evidence_basis="source_grounded" if source_grounded else "report_only",
                source_context_available=source_grounded,
            )
            findings.append(finding)
            accounting.add("mapped" if rule_id and message else "partially_mapped", pointer)
    accounting.validate()
    return findings, accounting, {
        "adapter": "sarif-2.1.0", "mapping_source": "known_adapter",
        "mapping_identity": mapping_identity,
        "confidence": 1.0, "coverage": {"records": accounting.total_records},
    }
