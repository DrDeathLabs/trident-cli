"""npm-audit adapter — JS/TS dependency vulnerability scanner."""

from __future__ import annotations

import json
import subprocess
import time

from sqlalchemy.orm import Session

from trident.models import Severity
from trident.tools.base import RawFinding, ToolBase, register_tool

SEV_MAP = {"critical": Severity.critical.value, "high": Severity.high.value,
           "moderate": Severity.medium.value, "low": Severity.low.value,
           "info": Severity.info.value}


@register_tool
class NpmAuditTool(ToolBase):
    name = "npm-audit"

    def run(self, db: Session) -> list[RawFinding]:
        t0 = time.time()
        # Run npm audit --json directly (no install needed)
        self._emit_started(db, f"npm audit --json (cwd={self.workspace})")
        findings: list[RawFinding] = []
        try:
            proc = subprocess.run(
                ["npm", "audit", "--json"], cwd=self.workspace,
                capture_output=True, text=True, timeout=600,
            )
            try:
                data = json.loads(proc.stdout)
            except json.JSONDecodeError:
                data = {}
        except FileNotFoundError:
            self._emit(db, "tool.error", {"tool": self.name, "error": "npm not found"})
            self._emit_complete(db, 0, 0)
            return []
        for vuln_id, vuln in (data.get("vulnerabilities") or {}).items():
            sev = SEV_MAP.get((vuln.get("severity") or "moderate").lower(), Severity.medium.value)
            via = vuln.get("via", [])
            cwe = None
            if isinstance(via, list) and via and isinstance(via[0], dict):
                cwes = via[0].get("cwe", [])
                if cwes:
                    cwe = cwes[0]
            findings.append(RawFinding(
                tool=self.name,
                rule_id=vuln_id,
                severity=sev,
                confidence=0.8,
                title=f"{vuln_id} in npm dependency ({vuln.get('severity', '')})",
                description=f"Vulnerable package: {vuln.get('name', vuln_id)} "
                            f"{vuln.get('range', '')}. {vuln.get('via', '')}"[:300],
                file="package-lock.json",
                line_start=0,
                line_end=0,
                snippet="",
                cwe=cwe,
                recommendation=f"Upgrade {vuln.get('name', vuln_id)} to a fixed version.",
                raw=vuln,
            ))
        self.persist_findings(db, findings)
        self._emit_complete(db, len(findings), time.time() - t0)
        return findings