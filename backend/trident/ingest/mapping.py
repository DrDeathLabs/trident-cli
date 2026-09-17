"""Safe, versioned JSON mapping and deterministic generic normalization.

Selectors are parsed token-by-token.  They are never evaluated as Python,
shell, templates, or arbitrary expressions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from trident.ingest.contracts import (
    MAPPING_VERSION,
    MappingValidation,
    RecordAccounting,
    mapping_sha256,
)
from trident.ingest.provenance import field_provenance, join_pointer, pointer_get, provenance_envelope
from trident.tools.base import RawFinding

_MAX_SELECTOR_LENGTH = 512
_MAX_SELECTOR_TOKENS = 64
_KNOWN_FIELDS = {
    "source_record_id", "rule_id", "cve", "ghsa", "advisory_id", "cwe", "owasp",
    "severity", "cvss_score", "cvss_vector", "title", "description", "recommendation",
    "file", "line_start", "line_end", "column", "snippet", "package",
    "installed_version", "ecosystem", "purl", "cpe", "dependency_path", "fixed_version",
    "references", "source_status", "confidence", "tool",
}
_IMPORTANT_FIELDS = ("rule_id", "title", "description", "severity", "cwe", "cve", "package", "file")
_IDENTIFIER_RE = re.compile(r"\b(?:CVE-\d{4}-\d{4,}|GHSA-[0-9A-Za-z-]+|OSV-[0-9A-Za-z-]+|CWE[-_: ]?\d+)\b", re.I)
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
_GHSA_RE = re.compile(r"^GHSA-[0-9A-Za-z]{4}(?:-[0-9A-Za-z]{4}){2}$", re.I)
_CWE_RE = re.compile(r"^CWE-\d+$", re.I)
_PROVIDER_VALUES = {"ghsa", "nvd", "osv", "redhat", "ubuntu", "amazon", "oracle-oval"}
_SEVERITY_ALIASES = {
    "critical": "critical", "blocker": "critical", "fatal": "critical",
    "high": "high", "error": "high", "major": "high", "severe": "high",
    "medium": "medium", "moderate": "medium", "warning": "medium", "important": "medium",
    "low": "low", "minor": "low",
    "info": "info", "informational": "info", "none": "info",
}


class MappingError(ValueError):
    """A mapping is invalid, unsafe, or cannot be applied reliably."""


@dataclass(frozen=True)
class Selection:
    value: Any
    pointer: str


def _parse_selector(selector: str) -> list[str | int]:
    if not isinstance(selector, str) or not selector or len(selector) > _MAX_SELECTOR_LENGTH:
        raise MappingError("selector must be a non-empty bounded string")
    if not selector.startswith("$"):
        raise MappingError(f"selector must start with '$': {selector!r}")
    tokens: list[str | int] = []
    index = 1
    while index < len(selector):
        if selector[index] == ".":
            end = index + 1
            while end < len(selector) and selector[end] not in ".[]":
                end += 1
            key = selector[index + 1:end]
            if not key or key in {"*", ".."}:
                raise MappingError(f"invalid object selector: {selector!r}")
            tokens.append(key)
            index = end
            continue
        if selector[index] != "[":
            raise MappingError(f"invalid selector syntax: {selector!r}")
        end = selector.find("]", index + 1)
        if end < 0:
            raise MappingError(f"unterminated selector token: {selector!r}")
        token = selector[index + 1:end]
        if token == "*":
            tokens.append("*")
        elif token.isdigit():
            tokens.append(int(token))
        elif len(token) >= 2 and token[0] == token[-1] == '"':
            key = token[1:-1]
            if not key or any(char in key for char in "\r\n"):
                raise MappingError("invalid quoted selector key")
            tokens.append(key)
        else:
            raise MappingError(f"only numeric, wildcard, or quoted indexes are allowed: {selector!r}")
        index = end + 1
    if len(tokens) > _MAX_SELECTOR_TOKENS:
        raise MappingError("selector is too deeply nested")
    return tokens


def select(payload: Any, selector: str, *, base_pointer: str = "") -> list[Selection]:
    """Return bounded selector results with exact source pointers."""
    nodes = [Selection(payload, base_pointer)]
    for token in _parse_selector(selector):
        next_nodes: list[Selection] = []
        for node in nodes:
            value = node.value
            if token == "*":
                if isinstance(value, list):
                    for idx, item in enumerate(value):
                        next_nodes.append(Selection(item, join_pointer(node.pointer, idx)))
                continue
            if isinstance(token, int):
                if isinstance(value, list) and token < len(value):
                    next_nodes.append(Selection(value[token], join_pointer(node.pointer, token)))
                continue
            if isinstance(value, dict) and token in value:
                next_nodes.append(Selection(value[token], join_pointer(node.pointer, token)))
        nodes = next_nodes
        if not nodes:
            break
    return nodes


def _validate_literal(value: Any, label: str) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        raise MappingError(f"{label} literal must be a bounded non-empty string")


def validate_mapping(mapping: Any) -> dict[str, Any]:
    if not isinstance(mapping, dict):
        raise MappingError("mapping must be a JSON object")
    allowed = {"mapping_version", "name", "records", "tool", "fields"}
    unknown = set(mapping) - allowed
    if unknown:
        raise MappingError(f"unknown mapping keys: {sorted(unknown)}")
    if mapping.get("mapping_version") != MAPPING_VERSION:
        raise MappingError(f"mapping_version must be {MAPPING_VERSION!r}")
    _validate_literal(mapping.get("name"), "mapping name")
    if not isinstance(mapping.get("records"), str):
        raise MappingError("mapping records must be a selector string")
    _parse_selector(mapping["records"])
    tool = mapping.get("tool")
    if tool is not None:
        if not isinstance(tool, dict) or set(tool) not in ({"literal"}, {"selector"}):
            raise MappingError("tool must contain exactly literal or selector")
        if "literal" in tool:
            _validate_literal(tool["literal"], "tool")
        else:
            _parse_selector(tool["selector"])
    fields = mapping.get("fields")
    if not isinstance(fields, dict) or not fields:
        raise MappingError("mapping fields must be a non-empty object")
    unknown_fields = set(fields) - _KNOWN_FIELDS
    if unknown_fields:
        raise MappingError(f"unsupported mapping fields: {sorted(unknown_fields)}")
    for field_name, selector in fields.items():
        if not isinstance(selector, str):
            raise MappingError(f"mapping field {field_name!r} must be a selector string")
        _parse_selector(selector)
    return mapping


def mapping_from_file(path: str) -> dict[str, Any]:
    import json
    from pathlib import Path

    candidate = Path(path).expanduser().resolve()
    if not candidate.is_file():
        raise MappingError(f"mapping file not found: {path}")
    try:
        value = json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MappingError(f"could not read mapping file {path}: {exc}") from exc
    return validate_mapping(value)


def _scalar(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return value


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, list):
        return "; ".join(_text(item) for item in value if _text(item))
    if isinstance(value, dict):
        for key in ("text", "value", "name", "id", "message"):
            if key in value and _text(value[key]):
                return _text(value[key])
    return ""


def _path_tokens(selector: str) -> list[str]:
    """Return lowercase selector tokens for semantic context checks."""
    try:
        return [str(token).lower() for token in _parse_selector(selector) if token != "*"]
    except MappingError:
        return []


def _identifier_value(value: Any, kind: str) -> str | None:
    text = _text(value)
    if not text:
        return None
    pattern = {"cve": _CVE_RE, "ghsa": _GHSA_RE, "cwe": _CWE_RE}.get(kind)
    if pattern is None:
        return text
    # Lists and descriptive strings may contain several identifiers.  A
    # canonical field is accepted only when the requested identifier class is
    # present; another class must never be silently relabeled.
    if isinstance(value, list) or " " in text or ";" in text:
        candidates = re.findall(r"(?:CVE-\d{4}-\d{4,}|GHSA-[0-9A-Za-z-]+|CWE[-_: ]?\d+)", text, re.I)
        for candidate in candidates:
            normalized = candidate.upper().replace("_", "-").replace(":", "-")
            if kind == "cwe" and normalized.startswith("CWE "):
                normalized = normalized.replace("CWE ", "CWE-")
            if pattern.fullmatch(normalized):
                return normalized
        return None
    normalized = text.upper().replace("_", "-").replace(":", "-")
    if kind == "cwe" and normalized.startswith("CWE "):
        normalized = normalized.replace("CWE ", "CWE-")
    return normalized if pattern.fullmatch(normalized) else None


def _semantic_field_valid(field: str, value: Any, selector: str = "") -> bool:
    """Validate canonical meaning, not only JSON shape or field coverage."""
    if value in (None, "", [], {}):
        return True
    tokens = _path_tokens(selector)
    token_set = set(tokens)
    if field in {"cve", "ghsa", "cwe"}:
        return _identifier_value(value, field) is not None
    if field in {"rule_id", "source_record_id"}:
        text = _text(value).lower()
        if text in _PROVIDER_VALUES:
            return False
        if field == "source_record_id" and {
            "description", "message", "commentary", "narrative", "detail",
            "explanation", "title", "caption", "epithet", "severity",
            "risk", "priority", "gravity",
        } & token_set:
            return False
        if field == "source_record_id" and {"datasource", "provider", "namespace"} & token_set:
            return False
        if field == "rule_id" and {"datasource", "provider"} & token_set:
            return False
    if field == "cvss_score":
        if "version" in token_set and not ({"score", "basescore", "base_score"} & token_set):
            return False
        try:
            number = float(value)
        except (TypeError, ValueError):
            return False
        return 0.0 <= number <= 10.0
    if field == "cvss_vector":
        return _text(value).upper().startswith("CVSS:")
    if field == "installed_version":
        forbidden_context = {"asvs", "schema", "specversion", "api", "rule", "control", "cvss"}
        if forbidden_context & token_set:
            return False
        if tokens and tokens[-1] == "version":
            allowed_parents = {"artifact", "component", "package", "dependency", "installed", "detected"}
            if len(tokens) < 2 or tokens[-2] not in allowed_parents:
                return False
    if field == "package" and tokens:
        if tokens[-1] in {"id", "uuid", "hash"} and "artifact" in token_set:
            return False
    return True


def _candidate_rank(field: str, path: str, value: Any) -> tuple[int, int] | None:
    """Rank a candidate path after semantic filtering.

    The second value is a deterministic tie-breaker.  Lower ranks are better.
    """
    if not _semantic_field_valid(field, value, path):
        return None
    tokens = _path_tokens(path)
    key = tokens[-1] if tokens else ""
    parent = tokens[-2] if len(tokens) > 1 else ""
    rank = path.count(".")
    preferred = {
        "source_record_id": {"vulnerabilityid", "vulnerability_id", "findingid", "finding_id", "uuid", "id"},
        "rule_id": {"ruleid", "rule_id", "checkid", "check_id", "detector"},
        "cve": {"cve", "cveid", "cve_id", "vulnerabilityid", "vulnerability_id", "id"},
        "ghsa": {"ghsa", "ghsaid", "ghsa_id", "vendorids", "vendor_ids", "id"},
        "cvss_score": {"basescore", "base_score", "cvssscore", "cvss_score", "score"},
        "package": {"name", "packagename", "package_name", "pkgname", "pkg_name"},
        "installed_version": {"installedversion", "installed_version", "version", "packageversion", "package_version"},
    }.get(field, set())
    if key not in preferred and not (field == "installed_version" and key == "version"):
        rank += 3
    if field == "package" and key in {"id", "uuid", "hash"}:
        rank += 20
    if field == "source_record_id" and parent in {"datasource", "provider", "artifact"}:
        rank += 20
    if field == "cve" and "relatedvulnerabilities" in tokens:
        rank -= 5
    if field == "ghsa" and key in {"vendorids", "vendor_ids", "ghsa", "ghsaid", "ghsa_id"}:
        rank -= 5
    if field == "cvss_score" and key in {"basescore", "base_score"}:
        rank -= 6
    if field == "package" and key == "name":
        rank -= 5
    if field == "installed_version" and parent in {"artifact", "component", "package", "dependency"}:
        rank -= 4
    return rank, len(path)


def normalize_severity(value: Any, *, cvss_score: Any = None) -> tuple[str, str]:
    """Return normalized severity and an auditable deterministic basis."""
    text = _text(value).lower()
    if text in _SEVERITY_ALIASES:
        return _SEVERITY_ALIASES[text], f"text_alias:{text}"
    if cvss_score is not None and isinstance(cvss_score, (int, float)):
        number = float(cvss_score)
        if 0 <= number <= 10:
            return (
                "critical" if number >= 9 else "high" if number >= 7 else
                "medium" if number >= 4 else "low" if number > 0 else "info",
                "cvss_score_semantics",
            )
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return "info", "numeric_without_cvss_semantics"
    return "info", "unrecognized_or_missing_default_info"


def _identifier(value: Any, prefix: str | None = None) -> str | None:
    text = _text(value)
    if not text:
        return None
    if prefix:
        match = re.search(rf"\b{re.escape(prefix)}[-_: ]?(\d+)\b", text, re.I)
        return f"{prefix.upper()}-{match.group(1)}" if match else text
    match = _IDENTIFIER_RE.search(text)
    return match.group(0).upper() if match else text


def _line(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _record_locations(record: dict[str, Any]) -> list[dict[str, Any]]:
    value = record.get("locations")
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    value = record.get("location")
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def _map_source_file(value: str, source_dir: str | None) -> str:
    return _resolve_source_file(value, source_dir)[0]


def _resolve_source_file(value: str, source_dir: str | None) -> tuple[str, bool]:
    """Normalize a report path and report whether a permitted file resolved."""
    normalized = (value or "").replace("\\", "/")
    if not source_dir or not value:
        return normalized, False
    root = Path(source_dir).expanduser().resolve()
    candidate = Path(value)
    try:
        resolved = (candidate if candidate.is_absolute() else root / candidate).resolve()
        resolved.relative_to(root)
    except (OSError, ValueError):
        resolved = None
    if resolved is not None and resolved.is_file():
        return resolved.relative_to(root).as_posix(), True
    # Reports often contain a build-machine absolute path.  A suffix match is
    # grounding only when exactly one permitted file matches; ambiguity and
    # missing files remain report-only.
    suffix = normalized.rstrip("/").lower()
    matches: list[Path] = []
    try:
        for item in root.rglob("*"):
            if item.is_file() and item.as_posix().lower().endswith(suffix):
                matches.append(item.resolve())
                if len(matches) > 1:
                    break
    except OSError:
        return normalized, False
    if len(matches) == 1:
        return matches[0].relative_to(root).as_posix(), True
    return normalized, False


def _first(selection: list[Selection]) -> Selection | None:
    return selection[0] if selection else None


def _inherit_component_context(payload: Any, pointer: str) -> dict[str, Selection]:
    """Recover package context for nested ``package -> vulnerabilities`` data.

    This is structural context, not a vendor adapter: the selected
    vulnerability record remains the accounting unit and every inherited value
    retains its own exact pointer.
    """
    parts = [part for part in pointer.split("/") if part]
    for length in range(len(parts) - 1, 0, -1):
        parent_pointer = "/" + "/".join(parts[:length])
        try:
            parent = pointer_get(payload, parent_pointer)
        except (KeyError, IndexError, TypeError, ValueError):
            continue
        if not isinstance(parent, dict):
            continue
        name_key = next((key for key in ("name", "package", "component", "artifact", "library") if parent.get(key)), None)
        version_key = next((key for key in ("version", "installedVersion", "installed_version") if parent.get(key)), None)
        if name_key or version_key:
            inherited: dict[str, Selection] = {}
            if name_key:
                inherited["package"] = Selection(parent[name_key], join_pointer(parent_pointer, name_key))
            if version_key:
                inherited["installed_version"] = Selection(parent[version_key], join_pointer(parent_pointer, version_key))
            for field, keys in (("ecosystem", ("ecosystem", "type", "packageType")), ("purl", ("purl",)), ("cpe", ("cpe",))):
                key = next((candidate for candidate in keys if parent.get(candidate)), None)
                if key:
                    inherited[field] = Selection(parent[key], join_pointer(parent_pointer, key))
            return inherited
    return {}


def _inherit_rule_context(payload: Any, extracted: dict[str, Any]) -> dict[str, Selection]:
    """Resolve a common top-level rules table referenced by a result rule ID."""
    if not isinstance(payload, dict) or not extracted.get("rule_id"):
        return {}
    rules = payload.get("rules")
    rule_id = _text(extracted.get("rule_id"))
    rule: dict[str, Any] | None = None
    pointer = "/rules"
    if isinstance(rules, dict) and isinstance(rules.get(rule_id), dict):
        rule = rules[rule_id]
        pointer = join_pointer(pointer, rule_id)
    elif isinstance(rules, list):
        for index, item in enumerate(rules):
            if isinstance(item, dict) and _text(item.get("id")) == rule_id:
                rule = item
                pointer = join_pointer(pointer, index)
                break
    if rule is None:
        return {}
    inherited: dict[str, Selection] = {}
    for field, keys in (
        ("title", ("title", "name", "shortDescription")),
        ("description", ("description", "message", "details", "help")),
        ("cwe", ("cwe", "weakness")),
    ):
        key = next((candidate for candidate in keys if rule.get(candidate) not in (None, "")), None)
        if key:
            inherited[field] = Selection(rule[key], join_pointer(pointer, key))
    return inherited


def validate_mapping_against_payload(payload: Any, mapping: dict[str, Any]) -> MappingValidation:
    mapping = validate_mapping(mapping)
    record_nodes = select(payload, mapping["records"])
    if len(record_nodes) > 10_000:
        record_nodes = record_nodes[:10_000]
    coverage: dict[str, float] = {}
    type_scores: list[float] = []
    semantic_observed = 0
    semantic_valid = 0
    errors: list[str] = []
    for field_name, selector in mapping["fields"].items():
        present = 0
        typed = 0
        for record in record_nodes:
            found = _first(select(record.value, selector, base_pointer=record.pointer))
            if found and found.value not in (None, "", [], {}):
                if field_name in {
                    "cve", "ghsa", "cwe", "cvss_score", "cvss_vector", "package",
                    "installed_version", "rule_id", "source_record_id",
                }:
                    semantic_observed += 1
                    if _semantic_field_valid(field_name, found.value, selector):
                        semantic_valid += 1
                    else:
                        errors.append(
                            f"{field_name}: selector {selector!r} produced a semantically invalid value"
                        )
                        continue
                present += 1
                if field_name in {"line_start", "line_end", "column", "cvss_score", "confidence"}:
                    typed += isinstance(found.value, (int, float)) and not isinstance(found.value, bool)
                else:
                    typed += isinstance(found.value, (str, int, float, bool, list, dict))
        coverage[field_name] = present / len(record_nodes) if record_nodes else 0.0
        if present:
            type_scores.append(typed / present)
    required = [coverage.get(field, 0.0) for field in ("title", "description", "rule_id", "cve", "severity", "package", "file")]
    required_coverage = max(required) if required else 0.0
    identifier_rate = max(
        coverage.get(field, 0.0)
        for field in ("rule_id", "cve", "ghsa", "advisory_id", "cwe")
    ) if record_nodes else 0.0
    semantic_validity = semantic_valid / semantic_observed if semantic_observed else 1.0
    base_confidence = (
        0.45 * required_coverage
        + 0.25 * (sum(type_scores) / len(type_scores) if type_scores else 0)
        + 0.3 * identifier_rate
    )
    confidence = min(1.0, base_confidence * semantic_validity)
    return MappingValidation(
        records_inspected=len(record_nodes), coverage=coverage,
        required_field_coverage=required_coverage,
        type_consistency=sum(type_scores) / len(type_scores) if type_scores else 0.0,
        identifier_rate=identifier_rate, confidence=confidence,
        errors=tuple(sorted(set(errors))), semantic_validity=semantic_validity,
    )


def _security_signal(values: dict[str, Any]) -> bool:
    identifiers = any(values.get(key) for key in ("rule_id", "cve", "ghsa", "advisory_id", "cwe"))
    narrative = any(_text(values.get(key)) for key in ("title", "description"))
    context = any(values.get(key) for key in ("severity", "package", "file", "source_status"))
    return (identifiers or narrative) and context


def apply_mapping(
    payload: Any, mapping: dict[str, Any], *, report_sha256: str,
    source_format: str = "generic-json", source_context_available: bool = False,
    source_dir: str | None = None,
) -> tuple[list[RawFinding], RecordAccounting, dict[str, Any]]:
    """Apply a validated mapping and account for every selected record."""
    mapping = validate_mapping(mapping)
    mapping_id = f"{mapping['name']}:{mapping_sha256(mapping)}"
    records = select(payload, mapping["records"])
    accounting = RecordAccounting()
    findings: list[RawFinding] = []
    tool_selector = mapping.get("tool")
    for record_node in records:
        pointer = record_node.pointer or ""
        if not isinstance(record_node.value, dict):
            accounting.add("malformed", pointer, reason="record is not an object")
            continue
        extracted: dict[str, Any] = {}
        provenance: dict[str, dict[str, Any]] = {}
        for field_name, selector in mapping["fields"].items():
            selected = _first(select(record_node.value, selector, base_pointer=pointer))
            if selected is None:
                continue
            value = _scalar(selected.value)
            extracted[field_name] = value
            provenance[field_name] = field_provenance(selected.pointer, selected.value)
        inherited = _inherit_component_context(payload, pointer)
        inherited.update(_inherit_rule_context(payload, extracted))
        for field_name, selected in inherited.items():
            if field_name not in extracted or extracted[field_name] in (None, "", [], {}):
                extracted[field_name] = selected.value
                provenance[field_name] = field_provenance(selected.pointer, selected.value)
        semantic_rejections: dict[str, str] = {}
        for field_name, selector in mapping["fields"].items():
            if field_name in extracted and not _semantic_field_valid(field_name, extracted[field_name], selector):
                semantic_rejections[field_name] = (
                    f"selector {selector!r} produced a semantically invalid canonical value"
                )
                extracted.pop(field_name, None)
                provenance.pop(field_name, None)
        if tool_selector:
            if "literal" in tool_selector:
                tool_value = tool_selector["literal"]
            else:
                selected = _first(select(record_node.value, tool_selector["selector"], base_pointer=pointer))
                tool_value = _text(selected.value) if selected else "generic-json"
        else:
            tool_value = "generic-json"
        reported_severity = extracted.get("severity")
        severity, severity_basis = normalize_severity(reported_severity, cvss_score=extracted.get("cvss_score"))
        if "severity" in provenance:
            provenance["severity_normalization"] = {
                "basis": severity_basis,
                "original": provenance["severity"].get("original"),
            }
        has_signal = _security_signal(extracted)
        extracted["severity"] = severity
        if not has_signal:
            accounting.add("out_of_scope", pointer, reason="minimum vulnerability evidence gate")
            continue
        title = _text(extracted.get("title")) or _text(extracted.get("rule_id")) or "Imported security finding"
        description = _text(extracted.get("description")) or title
        cve = _identifier_value(extracted.get("cve"), "cve")
        ghsa = _identifier_value(extracted.get("ghsa"), "ghsa")
        source_record_id = _text(extracted.get("source_record_id")) or None
        if source_record_id and source_record_id.lower() in _PROVIDER_VALUES:
            source_record_id = None
        rule_id = _text(extracted.get("rule_id")) or cve or ghsa or source_record_id or "generic-json"
        cwe = _identifier_value(extracted.get("cwe"), "cwe")
        cvss_score = extracted.get("cvss_score")
        if isinstance(cvss_score, str):
            try:
                cvss_score = float(cvss_score)
            except ValueError:
                cvss_score = None
        if cvss_score is not None and not _semantic_field_valid("cvss_score", cvss_score, mapping["fields"].get("cvss_score", "")):
            semantic_rejections.setdefault("cvss_score", "value is outside the CVSS score range or lacks CVSS semantics")
            cvss_score = None
        normalized_file, source_grounded = _resolve_source_file(_text(extracted.get("file")), source_dir)
        raw = {
            "import_format": source_format,
            "record": record_node.value,
            "source_record_id": source_record_id,
            "identifiers": {
                key: value for key, value in (
                    ("cve", cve), ("ghsa", ghsa), ("advisory_id", _text(extracted.get("advisory_id")) or None),
                ) if value
            },
            "package": _text(extracted.get("package")) or None,
            "InstalledVersion": _text(extracted.get("installed_version")) or None,
            "ecosystem": _text(extracted.get("ecosystem")) or None,
            "purl": _text(extracted.get("purl")) or None,
            "cpe": _text(extracted.get("cpe")) or None,
            "fixed_version": _text(extracted.get("fixed_version")) or None,
            "references": extracted.get("references") or [],
            "source_status": _text(extracted.get("source_status")) or None,
            "cvss_score": cvss_score,
            "cvss_vector": _text(extracted.get("cvss_vector")) or None,
            "severity_original": reported_severity,
            "mapping_identity": mapping_id,
            "mapping_sha256": mapping_sha256(mapping),
            "provenance": provenance_envelope(
                report_sha256=report_sha256, record_pointer=pointer,
                mapping_identity=mapping_id, fields=provenance,
                evidence_basis="source_grounded" if source_grounded else "report_only",
                source_context_available=source_grounded,
            ),
            "severity_normalization": severity_basis,
            "source_context_requested": bool(source_context_available or source_dir),
        }
        if semantic_rejections:
            raw["semantic_rejections"] = semantic_rejections
        raw["source_context_available"] = source_grounded
        raw["locations"] = _record_locations(record_node.value)
        finding = RawFinding(
            tool=_text(tool_value) or "generic-json", rule_id=rule_id, severity=severity,
            confidence=0.65, title=title, description=description,
            file=normalized_file, line_start=_line(extracted.get("line_start")),
            line_end=_line(extracted.get("line_end")) or _line(extracted.get("line_start")),
            locations=raw["locations"],
            snippet=_text(extracted.get("snippet")), cwe=cwe,
            owasp=_text(extracted.get("owasp")) or None,
            recommendation=_text(extracted.get("recommendation")), raw=raw,
            source_format=source_format, source_record_id=raw["source_record_id"],
            cve=cve,
            ghsa=ghsa,
            advisory_id=_text(extracted.get("advisory_id")) or None,
            cvss_score=cvss_score, cvss_vector=raw["cvss_vector"],
            package=raw["package"], installed_version=raw["InstalledVersion"],
            ecosystem=raw["ecosystem"], purl=raw["purl"], cpe=raw["cpe"],
            dependency_path=extracted.get("dependency_path"),
            fixed_version=raw["fixed_version"], references=raw["references"],
            source_status=raw["source_status"], record_pointer=pointer,
            report_sha256=report_sha256, mapping_identity=mapping_id,
            field_provenance=provenance, evidence_basis="source_grounded" if source_grounded else "report_only",
            source_context_available=source_grounded,
        )
        has_primary = any(extracted.get(key) for key in (
            "rule_id", "cve", "ghsa", "advisory_id", "cwe", "title", "description",
        ))
        has_context = reported_severity not in (None, "") or any(
            extracted.get(key) for key in ("cvss_score", "package", "file")
        )
        accounting.add("mapped" if has_primary and has_context else "partially_mapped", pointer)
        findings.append(finding)
    accounting.validate()
    stats = validate_mapping_against_payload(payload, mapping).as_dict()
    stats["mapping_sha256"] = mapping_sha256(mapping)
    stats["mapping_identity"] = mapping_id
    return findings, accounting, stats
