"""Deterministic CycloneDX JSON vulnerability adapter."""

from __future__ import annotations

import re
from typing import Any

from trident.ingest.contracts import RecordAccounting, mapping_sha256
from trident.ingest.mapping import normalize_severity
from trident.ingest.provenance import field_provenance, provenance_envelope
from trident.tools.base import RawFinding


def _text(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float, bool)):
        return str(value)
    return ""


def _cwe(value: Any) -> str | None:
    if isinstance(value, list):
        for item in value:
            result = _cwe(item)
            if result:
                return result
        return None
    match = re.search(r"(?:CWE[-_: ]*)?(\d+)", _text(value), re.I)
    return f"CWE-{match.group(1)}" if match else None


def _components(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    stack = list(payload.get("components") or [])
    while stack:
        item = stack.pop()
        if not isinstance(item, dict):
            continue
        ref = _text(item.get("bom-ref"))
        if ref:
            result[ref] = item
        stack.extend(item.get("components") or [] if isinstance(item.get("components"), list) else [])
    return result


def parse_cyclonedx(
    payload: dict[str, Any], *, report_sha256: str, source_dir: str | None = None,
) -> tuple[list[RawFinding], RecordAccounting, dict[str, Any]]:
    if str(payload.get("bomFormat", "")).lower() != "cyclonedx":
        raise ValueError("CycloneDX input must declare bomFormat CycloneDX")
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise ValueError("CycloneDX report must contain a vulnerabilities array")
    components = _components(payload)
    findings: list[RawFinding] = []
    accounting = RecordAccounting()
    mapping_identity = f"cyclonedx-json:{mapping_sha256({'adapter': 'cyclonedx-json'})}"
    for index, vuln in enumerate(vulnerabilities):
        pointer = f"/vulnerabilities/{index}"
        if not isinstance(vuln, dict):
            accounting.add("malformed", pointer, reason="vulnerability is not an object")
            continue
        source_info = vuln.get("source") if isinstance(vuln.get("source"), dict) else {}
        vuln_id = _text(vuln.get("id")) or _text(source_info.get("name"))
        ratings = vuln.get("ratings") if isinstance(vuln.get("ratings"), list) else []
        rating = ratings[0] if ratings and isinstance(ratings[0], dict) else {}
        score = rating.get("score") if rating.get("score") is not None else rating.get("baseScore")
        severity_value = rating.get("severity") or score
        severity, severity_basis = normalize_severity(severity_value, cvss_score=score)
        affects = vuln.get("affects") if isinstance(vuln.get("affects"), list) else []
        refs = [_text(item.get("ref")) for item in affects if isinstance(item, dict) and item.get("ref")]
        component = components.get(refs[0], {}) if refs else {}
        advisories = vuln.get("advisories") if isinstance(vuln.get("advisories"), list) else []
        references = [item for item in advisories if isinstance(item, dict)]
        cwe = _cwe(vuln.get("cwes"))
        if not vuln_id and not cwe and not refs:
            accounting.add("unsupported", pointer, reason="CycloneDX vulnerability has no identifier or affected component")
            continue
        package = _text(component.get("name"))
        version = _text(component.get("version"))
        title = vuln_id or cwe or "CycloneDX vulnerability"
        description = _text(vuln.get("description")) or title
        fields = {
            "id": field_provenance(f"{pointer}/id", vuln.get("id")) if vuln.get("id") is not None else None,
            "severity": field_provenance(f"{pointer}/ratings/0/severity", rating.get("severity")) if rating.get("severity") is not None else None,
            "component": field_provenance(f"{pointer}/affects/0/ref", refs[0]) if refs else None,
            "package": field_provenance(f"/components/{refs[0]}/name", package) if package else None,
            "version": field_provenance(f"/components/{refs[0]}/version", version) if version else None,
            "cwe": field_provenance(f"{pointer}/cwes", vuln.get("cwes")) if vuln.get("cwes") is not None else None,
        }
        fields = {key: value for key, value in fields.items() if value is not None}
        raw = {
            "import_format": "cyclonedx",
            "record": vuln,
            "component": component,
            "component_ref": refs[0] if refs else None,
            "package": package or None,
            "InstalledVersion": version or None,
            "purl": _text(component.get("purl")) or None,
            "cpe": _text(component.get("cpe")) or None,
            "fixed_version": _text(vuln.get("fixedVersion")) or None,
            "references": references,
            "cvss_score": score,
            "cvss_vector": _text(rating.get("vector")) or None,
            "severity_original": severity_value,
            "severity_normalization": severity_basis,
            "source_context_requested": bool(source_dir),
            "provenance": provenance_envelope(
                report_sha256=report_sha256, record_pointer=pointer,
                mapping_identity=mapping_identity, fields=fields,
                evidence_basis="report_only",
                source_context_available=False,
            ),
        }
        findings.append(RawFinding(
            tool=_text(source_info.get("name")) or "cyclonedx",
            rule_id=vuln_id or cwe or "cyclonedx-vulnerability", severity=severity,
            confidence=0.8, title=title, description=description, cwe=cwe,
            recommendation=_text(vuln.get("recommendation")), raw=raw,
            source_format="cyclonedx", source_record_id=vuln_id or None,
            cve=vuln_id if vuln_id.upper().startswith("CVE-") else None,
            ghsa=vuln_id if vuln_id.upper().startswith("GHSA-") else None,
            cvss_score=float(score) if isinstance(score, (int, float)) else None,
            cvss_vector=raw["cvss_vector"], package=package or None,
            installed_version=version or None, purl=raw["purl"], cpe=raw["cpe"],
            fixed_version=raw["fixed_version"], references=references,
            report_sha256=report_sha256, record_pointer=pointer,
            mapping_identity=mapping_identity, field_provenance=fields,
            source_status=(
                _text((vuln.get("analysis") or {}).get("state"))
                if isinstance(vuln.get("analysis"), dict) else None
            ),
            evidence_basis="report_only",
            source_context_available=False,
        ))
        accounting.add("mapped" if vuln_id and (package or cwe or description) else "partially_mapped", pointer)
    accounting.validate()
    return findings, accounting, {
        "adapter": "cyclonedx-json", "mapping_source": "known_adapter",
        "mapping_identity": mapping_identity,
        "confidence": 1.0, "coverage": {"records": accounting.total_records},
    }
