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
from trident.models import Finding, Severity, stable_finding_hash
from trident.tools.base import RawFinding
from trident.workspace import iter_workspace_files

SUPPORTED_FORMATS = ("sonarqube", "dependency-check")

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


def detect_format(payload: dict[str, Any]) -> str:
    """Detect only the two intentionally supported report contracts."""
    if isinstance(payload.get("issues"), list) and (
        "paging" in payload or "total" in payload or "components" in payload
    ):
        return "sonarqube"
    if str(payload.get("reportSchema", "")) == "1.1" and isinstance(
        payload.get("dependencies"), list
    ):
        return "dependency-check"
    if "bomFormat" in payload or "specVersion" in payload:
        raise ImportErrorValue(
            "CycloneDX JSON is not supported by this importer; use a SonarQube "
            "or OWASP Dependency-Check JSON report"
        )
    raise ImportErrorValue(
        "unsupported JSON report; expected SonarQube issue JSON or "
        "OWASP Dependency-Check reportSchema 1.1"
    )


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
            raw={"import_format": "sonarqube", "record": issue},
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
            cvss = vuln.get("cvssv2") or {}
            cvss_text = f"CVSS v2: {cvss.get('score')}" if cvss.get("score") is not None else ""
            description = str(vuln["description"] or f"{vuln['name']} reported by {vuln.get('source', 'Dependency-Check')}")
            if cvss_text:
                description = f"{description} ({cvss_text})"
            kev = normalize_kev(vuln)
            identity = normalize_cpe_identity(package_name, package_version, vuln)
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
                    "record": vuln,
                },
            ))
    return out, vulnerability_count


def parse_report(
    path: str | Path, input_format: str = "auto", source_dir: str | None = None,
) -> ImportedReport:
    report_path = Path(path).expanduser().resolve()
    if not report_path.is_file():
        raise ImportErrorValue(f"input report not found: {path}")
    try:
        payload = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ImportErrorValue(f"could not read JSON input report {path}: {exc}") from exc
    payload = _as_dict(payload, f"input report {path}")
    actual = detect_format(payload)
    detected = actual if input_format == "auto" else input_format
    if detected not in SUPPORTED_FORMATS:
        raise ImportErrorValue(f"unsupported input format: {detected}")
    if actual != detected:
        raise ImportErrorValue(
            f"input format {detected} does not match detected format {actual} for {path}"
        )
    if detected == "sonarqube":
        findings, records, skipped = _parse_sonarqube(payload, source_dir)
    else:
        findings, records = _parse_dependency_check(payload, source_dir)
        skipped = []
    return ImportedReport(
        str(report_path), detected, _sha256(report_path), records, tuple(findings),
        tuple(skipped),
    )


def prepare_import(
    paths: list[str], input_format: str, source_dir: str | None,
) -> tuple[list[ImportedReport], dict[str, Any]]:
    if not paths:
        raise ImportErrorValue("at least one --input-file is required for import mode")
    resolved = [str(Path(p).expanduser().resolve()) for p in paths]
    if len(set(resolved)) != len(resolved):
        raise ImportErrorValue("the same input report was supplied more than once")
    if source_dir and not Path(source_dir).is_dir():
        raise ImportErrorValue(f"source directory not found: {source_dir}")
    reports = [parse_report(p, input_format=input_format, source_dir=source_dir) for p in resolved]
    metadata = {
        "import_mode": True,
        "import_format": input_format,
        "import_inputs": [
            {
                "path": r.path, "format": r.format, "sha256": r.sha256,
                "records": r.records, "findings": len(r.findings),
                "skipped_records": len(r.skipped), "skipped": list(r.skipped),
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
                raw_outputs={"raw": rf.raw},
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
