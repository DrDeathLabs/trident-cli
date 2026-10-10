"""Bandit adapter — Python SAST."""

from __future__ import annotations

import json
import time

from sqlalchemy.orm import Session

from trident.models import Severity
from trident.tools.base import RawFinding, ToolBase, register_tool
from trident.tools.redaction import is_credential_rule, redacted_credential_raw

SEV_MAP = {"HIGH": Severity.high.value, "MEDIUM": Severity.medium.value, "LOW": Severity.low.value}


@register_tool
class BanditTool(ToolBase):
    name = "bandit"

    def run(self, db: Session) -> list[RawFinding]:
        t0 = time.time()
        cmd = ["bandit", "-r", self.workspace, "-f", "json", "-q"]
        rc, output = self._run_cmd(db, cmd, timeout=600)
        findings: list[RawFinding] = []
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            data = {"results": []}
        for r in data.get("results", []):
            sev = SEV_MAP.get(r.get("issue_severity", "MEDIUM"), Severity.medium.value)
            # bandit's issue_cwe.id is the numeric CWE (e.g. 502); the link is a
            # ".../502.html" URL, so never derive the id from the link's last segment.
            cwe_obj = r.get("issue_cwe") or {}
            cwe = f"CWE-{cwe_obj['id']}" if cwe_obj.get("id") else None
            loc = r.get("line_number", 0)
            rule_id = r.get("test_id", "bandit")
            credential = is_credential_rule(rule_id, r.get("issue_text"), cwe=cwe)
            # bandit JSON does not include source code; use issue_text as snippet context.
            snippet_text = r.get("issue_text", "")[:200]
            findings.append(RawFinding(
                tool=self.name,
                rule_id=rule_id,
                severity=sev,
                confidence=0.75,
                title="Potential credential embedded in source" if credential else r.get("issue_text", ""),
                description=(
                    "A potential credential is present; its value is omitted from Trident output."
                    if credential else r.get("issue_text", "")
                ),
                file=r.get("filename", ""),
                line_start=loc,
                line_end=loc,
                snippet="[REDACTED]" if credential else snippet_text,
                cwe=cwe,
                recommendation=r.get("more_info", ""),
                raw=(
                    redacted_credential_raw(self.name, rule_id, r.get("filename", ""), loc, loc, cwe=cwe)
                    if credential else r
                ),
            ))
        self.persist_findings(db, findings)
        self._emit_complete(db, len(findings), time.time() - t0)
        return findings
