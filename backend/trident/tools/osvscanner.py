"""OSV-Scanner adapter — all-ecosystem dependency vulnerabilities via OSV.dev.

Complements grype/trivy/pip-audit/npm-audit: one scanner across Python, Go, JS,
Java, Rust, Ruby, PHP, .NET, etc. Overlap is expected and desirable — the
correlation layer collapses duplicates into corroboration.
"""

from __future__ import annotations

import json
import os
import time

from sqlalchemy.orm import Session

from trident.models import Severity
from trident.tools.base import RawFinding, ToolBase, register_tool

# OSV severity strings (database_specific.severity) → our enum.
_SEV_MAP = {
    "CRITICAL": Severity.critical.value, "HIGH": Severity.high.value,
    "MODERATE": Severity.medium.value, "MEDIUM": Severity.medium.value,
    "LOW": Severity.low.value,
}


def _sev_from_cvss(score: float) -> str:
    if score >= 9.0:
        return Severity.critical.value
    if score >= 7.0:
        return Severity.high.value
    if score >= 4.0:
        return Severity.medium.value
    return Severity.low.value


@register_tool
class OsvScannerTool(ToolBase):
    name = "osv-scanner"

    def run(self, db: Session) -> list[RawFinding]:
        t0 = time.time()
        # Exit code is nonzero when vulns are found; we parse stdout regardless.
        cmd = ["osv-scanner", "scan", "source", "-r", "--format", "json", self.workspace]
        _rc, output = self._run_cmd(db, cmd, timeout=900)
        findings = self._parse(output)
        self.persist_findings(db, findings)
        self._emit_complete(db, len(findings), time.time() - t0)
        return findings

    def _sev(self, vuln: dict) -> str:
        ds = (vuln.get("database_specific") or {}).get("severity")
        if isinstance(ds, str) and ds.upper() in _SEV_MAP:
            return _SEV_MAP[ds.upper()]
        for s in vuln.get("severity") or []:
            try:
                return _sev_from_cvss(float(s.get("score", 0)))
            except (TypeError, ValueError):
                continue
        return Severity.medium.value

    def _rel(self, path: str) -> str:
        try:
            if path and os.path.isabs(path):
                return os.path.relpath(path, self.workspace)
        except ValueError:
            pass
        return path or ""

    def _parse(self, output: str) -> list[RawFinding]:
        try:
            data = json.loads(output)
        except (json.JSONDecodeError, TypeError):
            return []
        findings: list[RawFinding] = []
        for result in data.get("results", []):
            src = (result.get("source") or {}).get("path", "")
            for pkg in result.get("packages", []):
                p = pkg.get("package", {})
                name, version = p.get("name", "?"), p.get("version", "")
                for vuln in pkg.get("vulnerabilities", []):
                    vid = vuln.get("id", "OSV")
                    aliases = ", ".join(vuln.get("aliases", [])[:3])
                    findings.append(RawFinding(
                        tool=self.name,
                        rule_id=vid,
                        severity=self._sev(vuln),
                        confidence=0.85,
                        title=f"{vid} in {name} {version}".strip(),
                        description=(vuln.get("summary") or vuln.get("details", ""))[:1000]
                        + (f" (aliases: {aliases})" if aliases else ""),
                        file=self._rel(src),
                        line_start=0,
                        line_end=0,
                        snippet=f"{name}@{version}",
                        cwe=None,  # OSV dep advisories rarely carry a CWE; correlate on package/CVE
                        recommendation="Upgrade to a fixed version (see the advisory).",
                        # Expose package/version at the top level so correlate._dep_package
                        # groups these with trivy/grype's CVEs for the same pin (one
                        # corroborated canonical per package, not N double-counted CVEs).
                        raw={**vuln, "package": name, "version": version},
                    ))
        return findings
