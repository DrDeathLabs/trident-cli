"""gosec adapter — Go SAST."""

from __future__ import annotations

import json
import time

from sqlalchemy.orm import Session

from trident.models import Severity
from trident.tools.base import RawFinding, ToolBase, register_tool
from trident.tools.redaction import is_credential_rule, redacted_credential_raw

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
            rule_id = issue.get("rule_id", "gosec")
            credential = is_credential_rule(
                rule_id, issue.get("details"), cwe=cwe,
            )
            findings.append(RawFinding(
                tool=self.name,
                rule_id=rule_id,
                severity=sev,
                confidence=0.7,
                title="Potential credential embedded in source" if credential else issue.get("details", ""),
                description=(
                    "A potential credential is present; its value is omitted from Trident output."
                    if credential else issue.get("details", "")
                ),
                file=issue.get("file", ""),
                line_start=loc,
                line_end=loc,
                snippet="[REDACTED]" if credential else issue.get("code", ""),
                cwe=cwe,
                recommendation=(
                    "Remove the credential from source, rotate it, and use a secrets manager."
                    if credential else issue.get("details", "")
                ),
                raw=(
                    redacted_credential_raw(self.name, rule_id, issue.get("file", ""), loc, loc, cwe=cwe)
                    if credential else issue
                ),
            ))
        self.persist_findings(db, findings)
        self._emit_complete(db, len(findings), time.time() - t0)
        return findings
