"""gitleaks adapter — secrets detection."""

from __future__ import annotations

import json
import os
import tempfile
import time

from sqlalchemy.orm import Session

from trident.models import Severity
from trident.tools.base import RawFinding, ToolBase, register_tool


@register_tool
class GitleaksTool(ToolBase):
    name = "gitleaks"

    def run(self, db: Session) -> list[RawFinding]:
        t0 = time.time()
        fd, report_path = tempfile.mkstemp(suffix=".json", prefix="gitleaks_")
        os.close(fd)
        # --no-git: the workspace is a plain file copy, not a git repo, so scan
        # files directly instead of walking (nonexistent) git history.
        cmd = ["gitleaks", "detect", "--source", self.workspace, "--no-git",
               "--report-format", "json", "--report-path", report_path, "--no-banner", "--verbose"]
        self._run_cmd(db, cmd, timeout=600)
        findings: list[RawFinding] = []
        try:
            with open(report_path) as f:
                data = json.load(f)
        except Exception:
            data = []
        finally:
            try:
                os.unlink(report_path)
            except OSError:
                pass
        for r in data:
            loc = r.get("StartLine", 0)
            findings.append(RawFinding(
                tool=self.name,
                rule_id=r.get("RuleID", "gitleaks"),
                severity=Severity.high.value,
                confidence=0.85,
                title=f"Hardcoded secret: {r.get('RuleID', '')}",
                description=r.get("Description", "Potential secret leaked in source"),
                file=r.get("File", ""),
                line_start=loc,
                line_end=loc,
                snippet=r.get("Secret", "")[:60] + "..." if r.get("Secret") else "",
                cwe="CWE-798",
                recommendation="Remove the secret from source, rotate it, and use a secrets manager.",
                raw=r,
            ))
        self.persist_findings(db, findings)
        self._emit_complete(db, len(findings), time.time() - t0)
        return findings