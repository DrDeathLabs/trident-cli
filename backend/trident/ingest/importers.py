"""Import normalized findings from supported external scanner reports.

Import mode deliberately stops before scanner subprocess execution. The
resulting findings still enter Trident's normal correlation, review, chain, and
triage pipeline.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from trident.events.publisher import EventType, publish_event
from trident.ingest.adapters import parse_cyclonedx, parse_sarif
from trident.ingest.contracts import RecordAccounting, mapping_sha256
from trident.ingest.inference import infer_mapping, propose_mapping_with_model, schema_ai_requested
from trident.ingest.mapping import MappingError, apply_mapping, mapping_from_file
from trident.ingest.registry import detect_format as registry_detect_format
from trident.models import Finding, Severity, stable_finding_hash
from trident.tools.base import RawFinding
from trident.workspace import iter_workspace_files

SUPPORTED_FORMATS = ("sonarqube", "dependency-check", "sarif", "cyclonedx", "generic-json")

_VERSION_PREFIX = re.compile(
    r"^[vV]?(?P<version>\d+(?:\.\d+){0,3}(?:[-+][0-9A-Za-z.-]+)?)"
    r"(?P<suffix>[\\/].*)?$"
)


class ImportErrorValue(ValueError):
    """Raised when an external report cannot be safely imported."""


@dataclass(frozen=True)
class ImportedReport:
    path: str
    format: str
    sha256: str
    records: int
    findings: tuple[RawFinding, ...]
    skipped: tuple[dict[str, Any], ...] = ()
    accounting: dict[str, Any] | None = None
    mapping: dict[str, Any] | None = None
    mapping_source: str = "known_adapter"
    mapping_stats: dict[str, Any] | None = None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _as_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ImportErrorValue(f"{label} must be a JSON object")
    return value


def detect_format(payload: Any) -> str:
    """Return a deterministic first-class format or fail closed."""
    try:
        detected = registry_detect_format(payload)
    except ValueError as exc:
        raise ImportErrorValue(str(exc)) from exc
    if detected:
        return detected
    raise ImportErrorValue(
        "unsupported known report envelope; use generic JSON inference or provide "
        "a trident-json-mapping-v1 mapping"
    )


def _bounded_json(payload: Any, *, depth: int = 0, nodes: list[int] | None = None) -> None:
    nodes = nodes if nodes is not None else [0]
    if depth > 64:
        raise ImportErrorValue("JSON nesting exceeds the safety limit of 64 levels")
    nodes[0] += 1
    if nodes[0] > 1_000_000:
        raise ImportErrorValue("JSON input exceeds the safety node limit")
    if isinstance(payload, dict):
        for value in payload.values():
            _bounded_json(value, depth=depth + 1, nodes=nodes)
    elif isinstance(payload, list):
        for value in payload:
            _bounded_json(value, depth=depth + 1, nodes=nodes)


def _object_pointer(payload: Any, target: Any, pointer: str = "", depth: int = 0) -> str | None:
    """Find a source pointer for an adapter-retained object by identity."""
    if depth > 64:
        return None
    if payload is target:
        return pointer
    if isinstance(payload, dict):
        for key, value in payload.items():
            found = _object_pointer(value, target, f"{pointer}/{str(key).replace('~', '~0').replace('/', '~1')}", depth + 1)
            if found is not None:
                return found
    elif isinstance(payload, list):
        for index, value in enumerate(payload):
            found = _object_pointer(value, target, f"{pointer}/{index}", depth + 1)
            if found is not None:
                return found
    return None


def _attach_legacy_provenance(
    payload: Any, findings: list[RawFinding], *, report_sha256: str,
    source_format: str, source_context_available: bool,
) -> None:
    identity = f"{source_format}:deterministic-adapter-v1"
    for finding in findings:
        raw = finding.raw if isinstance(finding.raw, dict) else {}
        record = raw.get("record")
        pointer = _object_pointer(payload, record) if record is not None else None
        pointer = pointer or raw.get("record_pointer") or ""
        raw.setdefault("report_sha256", report_sha256)
        raw.setdefault("record_pointer", pointer)
        raw.setdefault("mapping_identity", identity)
        raw.setdefault("source_context_available", source_context_available)
        finding.raw = raw
        finding.source_format = source_format
        finding.report_sha256 = report_sha256
        finding.record_pointer = pointer
        finding.mapping_identity = identity
        finding.evidence_basis = "source_grounded" if source_context_available else "report_only"
        finding.source_context_available = source_context_available


def _severity(value: Any) -> str:
    value = str(value or "info").strip().lower()
    return value if value in {s.value for s in Severity} else "info"


def normalize_kev(record: dict[str, Any]) -> dict[str, Any]:
    """Normalize the direct KEV assertion carried by an imported record."""
    value = record.get("knownExploitedVulnerability")
    if not isinstance(value, dict):
        return {"listed": False, "source": "imported_record"}
    return {
        "listed": True,
        "source": "imported_record",
        "vendor_project": value.get("VendorProject"),
        "product": value.get("Product"),
        "name": value.get("Name"),
        "date_added": value.get("DateAdded"),
        "description": value.get("Description"),
        "required_action": value.get("RequiredAction"),
        "due_date": value.get("DueDate"),
        "notes": value.get("Notes"),
    }


def _identity_token(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())


def _cpe_product(cpe: str) -> str:
    parts = cpe.split(":")
    if cpe.startswith("cpe:2.3:") and len(parts) > 4:
        return parts[4]
    if cpe.startswith("cpe:/"):
        legacy_parts = cpe[5:].split(":")
        return legacy_parts[2] if len(legacy_parts) > 2 else ""
    return ""


def _version_key(value: Any) -> tuple[int, ...] | None:
    match = re.match(r"^(\d+(?:\.\d+)*)", str(value or "").strip())
    if not match:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def _version_in_cpe_range(version: str, software: dict[str, Any]) -> bool | None:
    installed = _version_key(version)
    bounds = {
        key: _version_key(software.get(key))
        for key in (
            "versionStartIncluding", "versionStartExcluding",
            "versionEndIncluding", "versionEndExcluding",
        )
        if software.get(key) is not None
    }
    if not bounds or installed is None or any(value is None for value in bounds.values()):
        return None
    if "versionStartIncluding" in bounds and installed < bounds["versionStartIncluding"]:
        return False
    if "versionStartExcluding" in bounds and installed <= bounds["versionStartExcluding"]:
        return False
    if "versionEndIncluding" in bounds and installed > bounds["versionEndIncluding"]:
        return False
    if "versionEndExcluding" in bounds and installed >= bounds["versionEndExcluding"]:
        return False
    return True


def normalize_cpe_identity(
    package: str, version: str, vulnerability: dict[str, Any],
) -> dict[str, Any]:
    """Compare package identity with the CPEs Dependency-Check matched.

    This is deliberately a review signal, not an automatic rejection.  A CPE
    may use a vendor naming convention that does not exactly match an artifact,
    so the result is retained with the candidates for Council review.
    """
    software_rows = []
    for item in vulnerability.get("vulnerableSoftware") or []:
        if not isinstance(item, dict) or not isinstance(item.get("software"), dict):
            continue
        software = item["software"]
        if str(software.get("vulnerabilityIdMatched", "")).lower() in {"true", "1", "yes"}:
            software_rows.append(software)
    if not software_rows:
        software_rows = [
            item["software"] for item in vulnerability.get("vulnerableSoftware") or []
            if isinstance(item, dict) and isinstance(item.get("software"), dict)
        ]
    cpes = [str(row.get("id")) for row in software_rows if row.get("id")]
    if not cpes:
        return {"status": "unknown", "basis": "no_cpe_evidence", "cpes": []}

    package_token = _identity_token(package)
    products = [_cpe_product(cpe) for cpe in cpes]
    product_matches = [
        product for product in products
        if product and (package_token == _identity_token(product)
                        or _identity_token(product) in package_token
                        or package_token in _identity_token(product))
    ]
    matched = bool(product_matches)
    status = "match" if matched else "conflict"

    version_checks = [
        _version_in_cpe_range(version, row)
        for row in software_rows
        if row.get("id") in cpes
    ]
    usable_version_checks = [value for value in version_checks if value is not None]
    version_match: bool | None = None
    if usable_version_checks:
        version_match = any(usable_version_checks)
        if matched and not version_match:
            status = "conflict"

    # A KEV record can name a major product line explicitly.  Keep a major
    # version mismatch visible as an applicability conflict even when the CPE
    # product token itself is broad (for example, Struts versus Struts 2).
    kev = normalize_kev(vulnerability)
    advisory_product = str(kev.get("product") or "")
    version_number = re.match(r"^(\d+)", str(version or ""))
    advisory_major = re.search(r"\b(\d+)\b", advisory_product)
    if matched and version_number and advisory_major:
        advisory_version_match = version_number.group(1) == advisory_major.group(1)
        if not advisory_version_match:
            status = "conflict"
        if version_match is None:
            version_match = advisory_version_match

    return {
        "status": status,
        "basis": "matched_cpe_product_identity",
        "package": package,
        "installed_version": version,
        "cpes": cpes,
        "cpe_products": products,
        "package_token": package_token,
        "version_match": version_match,
        "kev_product": advisory_product or None,
    }


def _cwe(value: Any) -> str | None:
    if isinstance(value, list):
        for item in value:
            result = _cwe(item)
            if result:
                return result
        return None
    match = re.search(r"(?:cwe[-_: ]*)?(\d+)", str(value or ""), re.IGNORECASE)
    return f"CWE-{match.group(1)}" if match else None


def _sonar_path(component: str) -> str:
    # Sonar components commonly use project-key:path. Do not split Windows
    # drive letters or paths that are already plain file names.
    if not re.match(r"^[A-Za-z]:[\\/]", component) and re.match(r"^[^:/\\]+:.+", component):
        return component.split(":", 1)[1]
    return component


def _under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


@lru_cache(maxsize=4096)
def map_source_path(original: str, source_dir: str | None) -> str:
    """Map a report path to source context only when the match is reliable."""
    if not source_dir or not original:
        return original
    root = Path(source_dir).resolve()
    candidate = Path(original)
    windows_absolute = bool(re.match(r"^[A-Za-z]:[\\/]", original)) or original.startswith(("\\\\", "//"))
    if not candidate.is_absolute() and not windows_absolute:
        direct = (root / candidate).resolve()
        if direct.is_file() and _under(direct, root):
            return direct.relative_to(root).as_posix()
        return original.replace("\\", "/")
    try:
        absolute = candidate.resolve()
    except OSError:
        absolute = candidate
    if _under(absolute, root):
        return absolute.relative_to(root).as_posix()

    normalized = original.replace("\\", "/").rstrip("/").lower()
    matches: list[Path] = []
    root_prefix = root.as_posix().rstrip("/").lower() + "/"
    for full_name in iter_workspace_files(root):
        full = Path(full_name).resolve()
        relative = full.as_posix().lower().removeprefix(root_prefix)
        if normalized.endswith("/" + relative):
            matches.append(full)
    if len(matches) == 1:
        return matches[0].relative_to(root).as_posix()
    return original.replace("\\", "/")


def _parse_sonarqube(
    payload: dict[str, Any], source_dir: str | None,
) -> tuple[list[RawFinding], int, list[dict[str, Any]]]:
    issues = payload.get("issues")
    if not isinstance(issues, list):
        raise ImportErrorValue("SonarQube report field 'issues' must be an array")
    out: list[RawFinding] = []
    skipped: list[dict[str, Any]] = []
    for index, issue_value in enumerate(issues):
        issue = _as_dict(issue_value, f"SonarQube issue {index}")
        status = str(issue.get("status", "OPEN")).upper()
        if status != "OPEN":
            skipped.append({
                "index": index,
                "reason": "source_status_not_open",
                "status": status,
                "type": issue.get("type"),
                "key": issue.get("key"),
                "rule": issue.get("rule"),
                "severity": issue.get("severity"),
                "component": issue.get("component"),
                "message": issue.get("message"),
                "record": issue,
            })
            continue
        for required in ("rule", "component", "message", "status"):
            if not issue.get(required):
                raise ImportErrorValue(f"SonarQube issue {index} is missing '{required}'")
        text_range = issue.get("textRange")
        if text_range is not None and not isinstance(text_range, dict):
            raise ImportErrorValue(f"SonarQube issue {index} field 'textRange' must be an object")
        text_range = text_range or {}
        try:
            start = int(text_range.get("startLine") or issue.get("line") or 0)
            end = int(text_range.get("endLine") or start)
        except (TypeError, ValueError) as exc:
            raise ImportErrorValue(f"SonarQube issue {index} has an invalid line number") from exc
        tags = issue.get("tags") or []
        cwe = _cwe(issue.get("cwe")) or _cwe(tags)
        path = map_source_path(_sonar_path(str(issue["component"])), source_dir)
        sonar_severity = str(issue.get("severity", "INFO")).lower()
        out.append(RawFinding(
            tool="sonarqube",
            rule_id=str(issue["rule"]),
            severity={
                "blocker": "critical", "critical": "critical", "major": "high",
                "minor": "medium", "info": "info",
            }.get(sonar_severity, "info"),
            confidence=0.7,
            title=str(issue["message"]),
            description=str(issue["message"]),
            file=path,
            line_start=start,
            line_end=end,
            cwe=cwe,
            recommendation=(
                "SonarQube reports a quick fix for this issue."
                if issue.get("quickFixAvailable") else ""
            ),
            raw={"import_format": "sonarqube", "record": issue, "severity_original": issue.get("severity")},
            source_format="sonarqube", source_record_id=str(issue.get("key") or issue["rule"]),
            source_status=status,
        ))
    return out, len(issues), skipped


def _normalize_dependency_version(value: str) -> tuple[str, str | None]:
    raw = str(value or "").strip()
    notes: list[str] = []
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in {"'", '"'}:
        raw = raw[1:-1].strip()
        notes.append("quotes_removed")
    match = _VERSION_PREFIX.match(raw)
    if not match:
        return raw or "unknown-version", "+".join(notes) or None
    normalized = match.group("version")
    if match.group("suffix"):
        notes.append("path_suffix_removed")
    else:
        notes.append("leading_numeric_version")
    return normalized, "+".join(notes)


def _dependency_parts(dep: dict[str, Any]) -> tuple[str, str]:
    evidence = dep.get("evidenceCollected") or {}
    products = evidence.get("productEvidence") or []
    versions = evidence.get("versionEvidence") or []
    product = next(
        (str(x.get("value")) for x in products if x.get("value")), "unknown-package"
    )
    # Dependency-Check may list the filename itself before the manifest or
    # archive metadata. Prefer the strongest version evidence, otherwise a
    # path such as ``wss4j`` is reported as the installed version instead of
    # the actual value (for example ``1.5.3``).
    confidence_rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "HIGHEST": 3}

    def version_rank(item: dict[str, Any]) -> tuple[int, int]:
        label = str(item.get("name") or "").lower()
        semantic = int("version" in label or "implementation-version" in label)
        # A field explicitly labelled as a version is more reliable than a
        # package-name token, even when the package-name evidence has a higher
        # scanner confidence.  Dependency-Check commonly reports values such
        # as ``ckeditor`` or ``ibm`` under ``package name`` in versionEvidence.
        return semantic, confidence_rank.get(str(item.get("confidence") or "").upper(), -1)

    version_item = max(
        (x for x in versions if x.get("value")),
        key=version_rank,
        default=None,
    )
    version = str(version_item["value"]) if version_item else "unknown-version"
    return product, _normalize_dependency_version(version)[0]


def _parse_dependency_check(
    payload: dict[str, Any], source_dir: str | None,
) -> tuple[list[RawFinding], int]:
    dependencies = payload.get("dependencies")
    if not isinstance(dependencies, list):
        raise ImportErrorValue("Dependency-Check report field 'dependencies' must be an array")
    out: list[RawFinding] = []
    vulnerability_count = 0
    for dep_index, dep_value in enumerate(dependencies):
        dep = _as_dict(dep_value, f"Dependency-Check dependency {dep_index}")
        vulnerabilities = dep.get("vulnerabilities") or []
        if not isinstance(vulnerabilities, list):
            raise ImportErrorValue(
                f"Dependency-Check dependency {dep_index} field 'vulnerabilities' must be an array"
            )
        path = str(dep.get("filePath") or dep.get("fileName") or "")
        mapped_path = map_source_path(path, source_dir)
        package_name, package_version = _dependency_parts(dep)
        version_items = (dep.get("evidenceCollected") or {}).get("versionEvidence") or []
        version_item = max(
            (x for x in version_items if x.get("value")),
            key=lambda item: (
                int("version" in str(item.get("name") or "").lower()
                    or "implementation-version" in str(item.get("name") or "").lower()),
                {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "HIGHEST": 3}.get(
                    str(item.get("confidence") or "").upper(), -1
                ),
            ),
            default=None,
        )
        raw_version = str(version_item.get("value")) if version_item else package_version
        normalized_version, version_note = _normalize_dependency_version(raw_version)
        package_version = normalized_version
        package = f"{package_name} {package_version}"
        # The parent dependency record contains the complete vulnerability
        # list. Keep the dependency context, but do not repeat that list once
        # for every CVE in the database. The exact vulnerability record is
        # preserved below and the report path plus SHA-256 are stored in the
        # job profile.
        dependency_context = {
            key: value for key, value in dep.items() if key != "vulnerabilities"
        }
        for vuln_index, vuln_value in enumerate(vulnerabilities):
            vuln = _as_dict(vuln_value, f"Dependency-Check vulnerability {dep_index}:{vuln_index}")
            if not vuln.get("name") or "description" not in vuln:
                raise ImportErrorValue(
                    f"Dependency-Check vulnerability {dep_index}:{vuln_index} is missing "
                    "'name' or 'description'"
                )
            vulnerability_count += 1
            cvss = vuln.get("cvssv3") or vuln.get("cvssv2") or {}
            cvss_score = cvss.get("baseScore") if cvss.get("baseScore") is not None else cvss.get("score")
            cvss_vector = cvss.get("vectorString") or cvss.get("vector")
            cvss_label = "CVSS v3" if vuln.get("cvssv3") else "CVSS v2"
            cvss_text = f"{cvss_label}: {cvss_score}" if cvss_score is not None else ""
            description = str(vuln["description"] or f"{vuln['name']} reported by {vuln.get('source', 'Dependency-Check')}")
            if cvss_text:
                description = f"{description} ({cvss_text})"
                kev = normalize_kev(vuln)
                identity = normalize_cpe_identity(package_name, package_version, vuln)
                source_status = (
                    vuln.get("analysis", {}).get("state")
                    if isinstance(vuln.get("analysis"), dict) else vuln.get("status")
                )
                out.append(RawFinding(
                tool="dependency-check",
                rule_id=str(vuln["name"]),
                severity=_severity(vuln.get("severity")),
                confidence=0.8,
                title=f"{vuln['name']} in {package}",
                description=description,
                file=mapped_path,
                cwe=_cwe(vuln.get("cwes")),
                raw={
                    "import_format": "dependency-check",
                    # These top-level keys are also understood by the existing
                    # dependency correlation logic.
                    "package": package_name,
                    "InstalledVersion": package_version,
                    "installed_version_raw": raw_version,
                    "version_normalization": version_note,
                    "kev": kev,
                    "cpe_identity": identity,
                    "dependency": dependency_context,
                    "dependency_vulnerability_count": len(vulnerabilities),
                    "cvss_score": cvss_score,
                    "cvss_vector": cvss_vector,
                    "references": vuln.get("references") or [],
                    "severity_original": vuln.get("severity"),
                    "source_status": source_status,
                    "record": vuln,
                },
                source_format="dependency-check", source_record_id=str(vuln["name"]),
                cve=str(vuln["name"]) if str(vuln["name"]).upper().startswith("CVE-") else None,
                cvss_score=float(cvss_score) if isinstance(cvss_score, (int, float)) else None,
                cvss_vector=str(cvss_vector) if cvss_vector else None,
                package=package_name, installed_version=package_version,
                references=vuln.get("references") or [],
                    source_status=source_status,
            ))
    return out, vulnerability_count


def parse_report(
    path: str | Path, input_format: str = "auto", source_dir: str | None = None,
    mapping: dict[str, Any] | None = None, no_schema_ai: bool = False,
) -> ImportedReport:
    report_path = Path(path).expanduser().resolve()
    if not report_path.is_file():
        raise ImportErrorValue(f"input report not found: {path}")
    try:
        if report_path.stat().st_size > 100 * 1024 * 1024:
            raise ImportErrorValue("input report exceeds the 100 MiB safety limit")
    except OSError as exc:
        raise ImportErrorValue(f"could not stat JSON input report {path}: {exc}") from exc
    try:
        payload = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ImportErrorValue(f"could not read JSON input report {path}: {exc}") from exc
    _bounded_json(payload)
    report_sha256 = _sha256(report_path)
    detected_known: str | None = None
    try:
        detected_known = registry_detect_format(payload)
    except ValueError as exc:
        raise ImportErrorValue(str(exc)) from exc
    requested = input_format
    if requested == "auto":
        detected = detected_known or "generic-json"
    else:
        detected = requested
        if detected not in SUPPORTED_FORMATS:
            raise ImportErrorValue(f"unsupported input format: {detected}")
        if detected_known and detected != detected_known:
            raise ImportErrorValue(
                f"input format {detected} does not match detected format {detected_known} for {path}"
            )
        if not detected_known and detected != "generic-json":
            raise ImportErrorValue(
                f"input format {detected} does not match detected format unknown-json for {path}"
            )
    skipped: list[dict[str, Any]] = []
    mapping_spec: dict[str, Any] | None = None
    mapping_source = "known_adapter"
    mapping_stats: dict[str, Any] | None = None
    if detected == "sonarqube":
        payload = _as_dict(payload, f"input report {path}")
        findings, records, skipped = _parse_sonarqube(payload, source_dir)
        accounting = RecordAccounting()
        for index, issue in enumerate(payload.get("issues") or []):
            state = "skipped" if isinstance(issue, dict) and str(issue.get("status", "OPEN")).upper() != "OPEN" else "mapped"
            accounting.add(state, f"/issues/{index}", reason="source_status_not_open" if state == "skipped" else None)
        accounting.validate()
        mapping_stats = {"adapter": "sonarqube-issue-json", "confidence": 1.0}
    elif detected == "dependency-check":
        payload = _as_dict(payload, f"input report {path}")
        findings, records = _parse_dependency_check(payload, source_dir)
        accounting = RecordAccounting()
        for finding in findings:
            pointer = (finding.raw.get("record_pointer") if finding.raw else None) or ""
            accounting.add("mapped", pointer or "/dependencies")
        accounting.validate()
        mapping_stats = {"adapter": "dependency-check-reportSchema-1.1", "confidence": 1.0}
    elif detected == "sarif":
        try:
            findings, accounting, mapping_stats = parse_sarif(payload, report_sha256=report_sha256, source_dir=source_dir)
        except (TypeError, ValueError) as exc:
            raise ImportErrorValue(str(exc)) from exc
    elif detected == "cyclonedx":
        try:
            findings, accounting, mapping_stats = parse_cyclonedx(payload, report_sha256=report_sha256, source_dir=source_dir)
        except (TypeError, ValueError) as exc:
            raise ImportErrorValue(str(exc)) from exc
    else:
        try:
            mapping_spec = mapping or infer_mapping(payload).mapping
            mapping_source = "user_supplied" if mapping is not None else "deterministic"
            proposal = None
            if mapping is None and not no_schema_ai and schema_ai_requested():
                deterministic = infer_mapping(payload)
                if deterministic.validation.confidence < 0.55:
                    proposal = propose_mapping_with_model(payload)
                    mapping_spec = proposal.mapping
                    mapping_source = proposal.source
            findings, accounting, mapping_stats = apply_mapping(
                payload, mapping_spec, report_sha256=report_sha256,
                source_format="generic-json", source_context_available=bool(source_dir),
                source_dir=source_dir,
            )
            if proposal:
                mapping_stats.update({
                    "provider": proposal.provider,
                    "model_requested": proposal.model_requested,
                    "model_actual": proposal.model_actual,
                    "response": proposal.response,
                })
        except MappingError as exc:
            if no_schema_ai or not schema_ai_requested():
                reason = "schema AI disabled" if no_schema_ai else "schema AI not configured"
                raise ImportErrorValue(
                    f"generic JSON mapping failed ({reason}): {exc}; provide --mapping FILE"
                ) from exc
            raise ImportErrorValue(
                f"generic JSON could not be safely mapped: {exc}; provide --mapping FILE"
            ) from exc
    accounting.validate()
    if detected in {"sonarqube", "dependency-check"}:
        _attach_legacy_provenance(
            payload, findings, report_sha256=report_sha256,
            source_format=detected, source_context_available=bool(source_dir),
        )
    # Attach report-level provenance to legacy first-class adapter records and
    # make the exact nested pointer available to downstream exporters.
    for finding in findings:
        raw = finding.raw if isinstance(finding.raw, dict) else {}
        raw.setdefault("report_sha256", report_sha256)
        raw.setdefault("record_pointer", finding.record_pointer)
        raw.setdefault("mapping_identity", mapping_stats.get("mapping_identity") if mapping_stats else detected)
        raw.setdefault("source_context_available", bool(source_dir))
        finding.raw = raw
    return ImportedReport(
        str(report_path), detected, report_sha256, accounting.total_records, tuple(findings),
        tuple(skipped), accounting=accounting.as_dict(include_records=True), mapping=mapping_spec,
        mapping_source=mapping_source, mapping_stats=mapping_stats,
    )


def prepare_import(
    paths: list[str], input_format: str, source_dir: str | None,
    mapping_path: str | None = None, no_schema_ai: bool = False,
) -> tuple[list[ImportedReport], dict[str, Any]]:
    if not paths:
        raise ImportErrorValue("at least one --input-file is required for import mode")
    resolved = [str(Path(p).expanduser().resolve()) for p in paths]
    if len(set(resolved)) != len(resolved):
        raise ImportErrorValue("the same input report was supplied more than once")
    if source_dir and not Path(source_dir).is_dir():
        raise ImportErrorValue(f"source directory not found: {source_dir}")
    mapping = mapping_from_file(mapping_path) if mapping_path else None
    reports = [
        parse_report(
            p, input_format=input_format, source_dir=source_dir,
            mapping=mapping, no_schema_ai=no_schema_ai,
        )
        for p in resolved
    ]
    metadata = {
        "import_mode": True,
        "import_format": input_format,
        "schema_ai": not no_schema_ai,
        "mapping_path": str(Path(mapping_path).expanduser().resolve()) if mapping_path else None,
        "mapping_sha256": mapping_sha256(mapping) if mapping else None,
        "import_inputs": [
            {
                "path": r.path, "format": r.format, "sha256": r.sha256,
                "records": r.records, "findings": len(r.findings),
                "skipped_records": len(r.skipped), "skipped": list(r.skipped),
                "accounting": {
                    key: value for key, value in (r.accounting or {}).items() if key != "records"
                },
                "mapping_source": r.mapping_source,
                "mapping": r.mapping,
                "mapping_stats": r.mapping_stats,
            }
            for r in reports
        ],
        "source_context": str(Path(source_dir).resolve()) if source_dir else None,
        "discover_novel": False,
    }
    return reports, metadata


def persist_imported_findings(
    db: Session, job_id: str, reports: list[ImportedReport],
) -> int:
    count = 0
    for report in reports:
        for rf in report.findings:
            raw = dict(rf.raw or {})
            raw.setdefault("import_format", rf.source_format or report.format)
            raw.setdefault("report_sha256", rf.report_sha256 or report.sha256)
            raw.setdefault("record_pointer", rf.record_pointer)
            raw.setdefault("mapping_identity", rf.mapping_identity or report.mapping_source)
            raw.setdefault("canonical", {
                "source_tool": rf.tool,
                "source_format": rf.source_format or report.format,
                "source_record_id": rf.source_record_id,
                "rule_id": rf.rule_id,
                "cve": rf.cve,
                "ghsa": rf.ghsa,
                "advisory_id": rf.advisory_id,
                "cwe": rf.cwe,
                "original_severity": raw.get("severity_original") or (
                    ((raw.get("provenance") or {}).get("fields") or {}).get("severity", {}).get("original")
                    if isinstance((raw.get("provenance") or {}).get("fields"), dict) else None
                ) or rf.severity,
                "normalized_severity": rf.severity,
                "cvss_score": rf.cvss_score,
                "cvss_vector": rf.cvss_vector,
                "title": rf.title,
                "description": rf.description,
                "file": rf.file,
                "line_start": rf.line_start,
                "line_end": rf.line_end,
                "locations": rf.locations,
                "package": rf.package or raw.get("package"),
                "installed_version": rf.installed_version or raw.get("InstalledVersion"),
                "ecosystem": rf.ecosystem or raw.get("ecosystem"),
                "purl": rf.purl or raw.get("purl"),
                "cpe": rf.cpe or raw.get("cpe"),
                "dependency_path": rf.dependency_path,
                "fixed_version": rf.fixed_version or raw.get("fixed_version"),
                "references": rf.references,
                "source_status": rf.source_status,
            })
            raw.setdefault("provenance", {
                "report_sha256": rf.report_sha256 or report.sha256,
                "record_pointer": rf.record_pointer,
                "mapping_identity": rf.mapping_identity or report.mapping_source,
                "fields": rf.field_provenance,
                "evidence_basis": rf.evidence_basis,
                "source_context_available": rf.source_context_available,
            })
            finding = Finding(
                job_id=job_id,
                hash=stable_finding_hash(rf.file, rf.line_start, rf.rule_id, rf.snippet),
                tool=rf.tool,
                rule_id=rf.rule_id,
                severity=rf.severity,
                scanner_severity=rf.severity,
                confidence=rf.confidence,
                title=rf.title,
                description=rf.description,
                file=rf.file,
                line_start=rf.line_start,
                line_end=rf.line_end,
                snippet=rf.snippet,
                cwe=rf.cwe,
                owasp=rf.owasp,
                recommendation=rf.recommendation,
                raw_outputs={"raw": raw},
                status="raw",
                iteration=0,
            )
            db.add(finding)
            db.flush()
            publish_event(db, job_id, EventType.FINDING_RAW, {
                "finding_id": finding.id, "tool": finding.tool, "rule_id": finding.rule_id,
                "file": finding.file, "line_start": finding.line_start,
                "severity": finding.severity, "title": finding.title, "cwe": finding.cwe,
                "imported": True,
            })
            identity = (rf.raw or {}).get("cpe_identity") or {}
            if identity.get("status") == "conflict":
                publish_event(db, job_id, EventType.FINDING_IMPORT_CONFLICT, {
                    "finding_id": finding.id,
                    "rule_id": finding.rule_id,
                    "reason": "deterministic package/CPE identity conflict",
                    "identity": identity,
                })
            count += 1
    return count


def dependency_check_match_evidence(finding: Finding) -> dict[str, Any] | None:
    """Return strong Dependency-Check match evidence for an imported finding.

    Dependency-Check records the CPE match that caused a vulnerability to be
    emitted.  A model may still reject that record, but a ``true`` match is a
    material piece of report evidence.  The deliberation layer uses this
    helper to keep a model-only refutation visible as disputed instead of
    silently treating the imported record as a false positive.
    """
    raw = (finding.raw_outputs or {}).get("raw") or {}
    if raw.get("import_format") != "dependency-check":
        return None
    record = raw.get("record") or {}
    matches: list[dict[str, Any]] = []
    for item in record.get("vulnerableSoftware") or []:
        if not isinstance(item, dict):
            continue
        software = item.get("software")
        if not isinstance(software, dict):
            continue
        matched = software.get("vulnerabilityIdMatched")
        if str(matched).strip().lower() not in {"true", "1", "yes"}:
            continue
        # A product-level CPE match is not enough to defeat a model refutation.
        # Require an explicit affected-version boundary so legacy or generic
        # CPE matches remain reviewable as possible false positives.
        if not any(
            software.get(key) is not None
            for key in (
                "versionStartIncluding", "versionStartExcluding",
                "versionEndIncluding", "versionEndExcluding",
            )
        ):
            continue
        matches.append({
            key: software[key]
            for key in (
                "id", "versionStartIncluding", "versionStartExcluding",
                "versionEndIncluding", "versionEndExcluding",
                "vulnerabilityIdMatched",
            )
            if key in software
        })
    if not matches:
        return None
    return {
        "rule_id": finding.rule_id,
        "package": raw.get("package"),
        "installed_version": raw.get("InstalledVersion"),
        "matched_software": matches,
    }


def is_imported_sonarqube_code_smell(finding: Finding) -> bool:
    """Identify an imported SonarQube maintainability issue.

    SonarQube's issue type is authoritative for this narrow classification.
    A code smell is not a false positive: it can be a valid maintainability or
    reliability finding.  The security queue keeps it out of remediation
    triage, while the report preserves it as an out-of-scope quality record.
    """
    raw = (finding.raw_outputs or {}).get("raw") or {}
    if raw.get("import_format") != "sonarqube":
        return False
    record = raw.get("record") or {}
    return str(record.get("type") or "").strip().upper() == "CODE_SMELL"
