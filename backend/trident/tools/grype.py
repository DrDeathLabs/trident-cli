"""Grype adapter — SBOM/dependency vulnerability scanner."""

from __future__ import annotations

import json
import time

from sqlalchemy.orm import Session

from trident.models import Severity
from trident.tools.base import RawFinding, ToolBase, register_tool

SEV_MAP = {
    "Critical": Severity.critical.value,
    "High": Severity.high.value,
    "Medium": Severity.medium.value,
    "Low": Severity.low.value,
    "Negligible": Severity.info.value,
    "Unknown": Severity.info.value,
}


@register_tool
class GrypeTool(ToolBase):
    name = "grype"

    def run(self, db: Session) -> list[RawFinding]:
        t0 = time.time()
        cmd = ["grype", f"dir:{self.workspace}", "-o", "json", "--quiet"]
        rc, output = self._run_cmd(db, cmd, timeout=900)
        findings: list[RawFinding] = []
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            data = {"matches": []}
        for m in data.get("matches", []):
            vuln = m.get("vulnerability", {})
            artifact = m.get("artifact", {})
            sev = SEV_MAP.get(vuln.get("severity", "Unknown"), Severity.medium.value)
            findings.append(RawFinding(
                tool=self.name,
                rule_id=vuln.get("id", "grype"),
                severity=sev,
                confidence=0.85,
                title=f"{vuln.get('id', '?')} in {artifact.get('name', '?')} {artifact.get('version', '')}",
                description=vuln.get("description", ""),
                file=artifact.get("name", ""),
                line_start=0,
                line_end=0,
                snippet="",
                recommendation="Upgrade to fixed version: " + (
                    str(vuln.get("fix", {}).get("versions", ["n/a"])[0])
                    if vuln.get("fix") else "No fix available"),
                raw=m,
            ))
        self.persist_findings(db, findings)
        self._emit_complete(db, len(findings), time.time() - t0)
        return findings