"""Deterministic expert routing from bounded, structured finding evidence."""

from __future__ import annotations

import os
import re
from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class RoutingDecision:
    expert: str
    relevant: bool
    score: int
    reasons: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["reasons"] = list(self.reasons)
        return data


def legacy_expert_match(finding: Any, expert: Any) -> bool:
    """Preserve the pre-structured router as a compatibility eligibility floor.

    This intentionally keeps the original exact tool match, normalized CWE
    match, and whole-word keyword behavior.  Structured signals may add expert
    coverage, but may never remove a review accepted by this function.
    """
    if expert.source_tools and str(finding.tool) in expert.source_tools:
        return True
    cwe = (finding.cwe or "").strip()
    if cwe and expert.domains:
        match = re.search(r"\d+", cwe)
        normalized = f"CWE-{match.group(0)}" if match else cwe
        if normalized in expert.domains:
            return True
    text = f"{finding.title} {finding.description} {finding.rule_id}".lower()
    return any(
        re.search(rf"\b{re.escape(word)}\b", text)
        for word in expert.keywords
    )


_OWASP_EXPERTS = {
    "A01": {"auth"},
    "A02": {"crypto"},
    "A03": {"injection"},
    "A05": {"secrets_config"},
    "A06": {"dependency"},
    "A07": {"auth"},
    "A08": {"dependency", "injection"},
    "A10": {"injection"},
}
_SPECIAL_SCANNER_EXPERTS = {
    "gitleaks": "secrets_config",
    "trufflehog": "secrets_config",
    "checkov": "secrets_config",
}
_SEMANTIC_PATTERNS = {
    "injection": re.compile(
        r"\b(?:sql injection|sqli|command injection|os command injection|xss|"
        r"cross.site scripting|ssrf|server.side request forgery|path traversal|"
        r"unsafe deserialization|insecure deserialization|code injection|template injection)\b",
        re.I,
    ),
    "auth": re.compile(
        r"\b(?:authentication bypass|authentication flaw|authentication failure|"
        r"authorization bypass|authorization flaw|broken access control|idor|"
        r"insecure direct object reference|jwt|session fixation|privilege escalation|"
        r"unauthenticated access|missing authorization check)\b",
        re.I,
    ),
    "crypto": re.compile(
        r"\b(?:weak cryptograph(?:y|ic)|weak hash(?:ing)?|weak cipher|weak algorithm|"
        r"weak randomness|predictable random|tls certificate verification|"
        r"disabled certificate verification|signature validation weakness|"
        r"md5|sha.?1|des|ecb mode)\b",
        re.I,
    ),
    "dependency": re.compile(
        r"\b(?:vulnerable dependency|outdated dependency|transitive dependency|"
        r"known vulnerable package|dependency advisory|affected package version|"
        r"software component vulnerability)\b",
        re.I,
    ),
    "secrets_config": re.compile(
        r"\b(?:exposed secret|secret detected|credential leaked|exposed credential|"
        r"hard.?coded (?:credential|password|secret|api key)|hard.?coded credential|"
        r"private key exposed|debug mode enabled|permissive cors|insecure configuration|"
        r"infrastructure misconfiguration|overly broad permissions|security header missing)\b",
        re.I,
    ),
}
_DEPENDENCY_MANIFESTS = {
    "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
    "pnpm-lock.yaml", "requirements.txt", "pyproject.toml", "poetry.lock",
    "pipfile.lock", "go.mod", "go.sum", "cargo.toml", "cargo.lock",
    "pom.xml", "gradle.lockfile", "composer.lock", "gemfile.lock",
}
_IAC_EXTENSIONS = {".tf", ".tfvars", ".hcl", ".yaml", ".yml"}
_CVE = re.compile(r"\b(?:CVE-\d{4}-\d{4,}|GHSA-[0-9A-Z-]{8,}|OSV-\d{4}-\d{4,})\b", re.I)
_CWE = re.compile(r"\bCWE[-_: ]?(\d+)\b", re.I)
_OWASP = re.compile(r"\b(A\d{2})(?:\s*:\s*\d{4})?\b", re.I)


def _bounded_text(value: Any, limit: int = 512) -> str:
    if isinstance(value, str):
        return value[:limit].strip()
    if isinstance(value, (int, float)):
        return str(value)
    return ""


def _raw_evidence(finding: Any) -> dict[str, Any]:
    outputs = getattr(finding, "raw_outputs", None)
    if not isinstance(outputs, dict):
        return {}
    raw = outputs.get("raw")
    return raw if isinstance(raw, dict) else {}


def _scanner_names(finding: Any) -> tuple[set[str], set[str]]:
    primary = {_bounded_text(getattr(finding, "tool", ""), 64).lower()}
    corroborating = getattr(finding, "corroborating_tools", None)
    if isinstance(corroborating, (list, tuple, set)):
        secondary = {_bounded_text(name, 64).lower() for name in list(corroborating)[:20]}
    else:
        secondary = set()
    raw = _raw_evidence(finding)
    for key in ("tool", "scanner", "source_tool"):
        value = _bounded_text(raw.get(key), 64).lower()
        if value:
            primary.add(value)
    return ({name for name in primary if name}, {name for name in secondary if name})


def _has_dependency_metadata(finding: Any) -> bool:
    raw = _raw_evidence(finding)
    # Only normalized package fields are routing signals. Arbitrary report text
    # and unbounded raw scanner metadata are deliberately ignored.
    return any(
        _bounded_text(raw.get(key), 256)
        for key in ("package", "ecosystem", "purl", "dependency", "InstalledVersion", "fixed_version")
    )


def _cwe(finding: Any) -> str:
    match = _CWE.search(_bounded_text(getattr(finding, "cwe", None), 64))
    return f"CWE-{match.group(1)}" if match else ""


def _owasp(finding: Any) -> str:
    match = _OWASP.search(_bounded_text(getattr(finding, "owasp", None), 64))
    return match.group(1).upper() if match else ""


def _path_context(finding: Any) -> tuple[bool, bool]:
    path = _bounded_text(getattr(finding, "file", ""), 512).replace("\\", "/").lower()
    base = os.path.basename(path)
    extension = os.path.splitext(base)[1]
    dependency = base in _DEPENDENCY_MANIFESTS
    iac = extension in _IAC_EXTENSIONS and any(
        part in {"infra", "infrastructure", "terraform", "k8s", "kubernetes", "deploy", "deployment"}
        for part in path.split("/")
    )
    return dependency, iac


def route_expert(finding: Any, expert: Any) -> RoutingDecision:
    """Return a deterministic relevance score with bounded evidence reasons."""
    name = _bounded_text(getattr(expert, "name", ""), 64)
    score = 0
    reasons: list[str] = []

    legacy_match = legacy_expert_match(finding, expert)

    def add(points: int, reason: str) -> None:
        nonlocal score
        score = min(100, score + points)
        if reason not in reasons:
            reasons.append(reason)

    cwe = _cwe(finding)
    domains = getattr(expert, "domains", set()) or set()
    if cwe and cwe in domains:
        add(100, "CWE match")

    owasp = _owasp(finding)
    if name in _OWASP_EXPERTS.get(owasp, set()):
        add(85, "OWASP match")

    primary_scanners, corroborating_scanners = _scanner_names(finding)
    source_tools = {str(tool).lower() for tool in (getattr(expert, "source_tools", ()) or ())}
    if primary_scanners & source_tools or any(
        _SPECIAL_SCANNER_EXPERTS.get(scanner) == name for scanner in primary_scanners
    ):
        add(80, "scanner match")
    if corroborating_scanners & source_tools or any(
        _SPECIAL_SCANNER_EXPERTS.get(scanner) == name for scanner in corroborating_scanners
    ):
        add(60, "corroborating-tool match")

    dependency_manifest, iac_context = _path_context(finding)
    if name == "dependency":
        rule_id = _bounded_text(getattr(finding, "rule_id", ""), 128)
        if _has_dependency_metadata(finding) or _CVE.search(rule_id):
            add(65, "dependency evidence")
        if dependency_manifest:
            add(25, "file-type match")

    if name == "secrets_config" and iac_context:
        add(25, "configuration context")

    title = _bounded_text(getattr(finding, "title", ""), 512)
    description = _bounded_text(getattr(finding, "description", ""), 1_024)
    rule_id = _bounded_text(getattr(finding, "rule_id", ""), 128)
    semantic_text = f"{title} {description} {rule_id}"
    pattern = _SEMANTIC_PATTERNS.get(name)
    if pattern and pattern.search(semantic_text):
        # A specific CWE or OWASP classification takes precedence over a
        # misleading generic title. Other domains can still route on their own
        # independent structured evidence or precise description evidence.
        structured_conflict = bool(cwe and domains and cwe not in domains)
        title_only = not pattern.search(f"{description} {rule_id}")
        if not (structured_conflict and title_only):
            add(45, "semantic rule match")

    # A CVE identifier is strong only when paired with package evidence or a
    # dependency-specific scanner. It cannot turn unrelated source findings into
    # dependency reviews on its own.
    if name == "dependency" and _CVE.search(rule_id) and _has_dependency_metadata(finding):
        add(25, "known-vulnerability identifier")

    if legacy_match:
        add(35, "legacy compatibility match")

    # Structured evidence broadens and explains routing.  It is not permitted
    # to suppress any selection made by the preserved legacy router.
    relevant = legacy_match or score >= 35
    return RoutingDecision(name, relevant, score, tuple(reasons))


def route_finding(finding: Any, experts: list[Any]) -> list[RoutingDecision]:
    """Return all expert decisions in a stable order for display and audit."""
    return [route_expert(finding, expert) for expert in sorted(experts, key=lambda item: item.name)]
