"""Dependency/SBOM expert — transitive deps, license, known CVEs."""

from __future__ import annotations

from trident.prompts import SYSTEM_BASE
from trident.experts.base import ExpertBase, register_expert


@register_expert
class DependencyExpert(ExpertBase):
    name = "dependency"
    persona = "Dependency & SBOM Expert"
    domain = "Third-party dependencies, transitive packages, known CVEs, license risk"
    domains = {"CWE-1035", "CWE-1104", "CWE-937"}
    keywords = ("cve", "dependency", "package", "vulnerable", "outdated", "transitive", "sbom", "license")
    source_tools = ("trivy", "grype", "pip-audit", "npm-audit", "osv-scanner", "govulncheck")
    system_prompt = SYSTEM_BASE + "\n" + (
        "You specialize in dependency risk: known vulnerabilities in third-party packages, "
        "transitive dependency chains, outdated/unfixed versions, license compliance."
    )
