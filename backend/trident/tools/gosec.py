"""gosec adapter — Go SAST."""

from __future__ import annotations

import json
import time

from sqlalchemy.orm import Session

from trident.models import Severity
from trident.tools.base import RawFinding, ToolBase, register_tool

SEV_MAP = {"HIGH": Severity.high.value, "MEDIUM": Severity.medium.value, "LOW": Severity.low.value}


@register_tool
class GosecTool(ToolBase):
    name = "gosec"

    def run(self, db: Session) -> list[RawFinding]:
        t0 = time.time()
        cmd = ["gosec", "-fmt", "json", "-quiet", self.workspace]
        rc, output = self._run_cmd(db, cmd, timeout=600)
        findings: list[RawFinding] = []
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            data = {"Issues": []}
        for issue in data.get("Issues", []):
            sev = SEV_MAP.get(issue.get("severity", "MEDIUM"), Severity.medium.value)
            loc = int(issue.get("line", 0))
            cwe = issue.get("cwe", {}).get("id")
            if cwe and str(cwe).isdigit():
                cwe = f"CWE-{cwe}"
            findings.append(RawFinding(
                tool=self.name,
                rule_id=issue.get("details", "gosec"),
                severity=sev,
                confidence=0.7,
                title=issue.get("details", ""),
                description=issue.get("details", ""),
                file=issue.get("file", ""),
                line_start=loc,
                line_end=loc,
                snippet=issue.get("code", ""),
                cwe=cwe,
                recommendation=issue.get("details", ""),
                raw=issue,
            ))
        self.persist_findings(db, findings)
        self._emit_complete(db, len(findings), time.time() - t0)
        return findings