"""TruffleHog adapter — secrets detection with live verification.

Complements gitleaks: a much larger detector set, and `Verified` tells us a
credential was confirmed live (high-signal, low-FP). Output is JSONL (one JSON
object per line).
"""

from __future__ import annotations

import json
import os
import time

from sqlalchemy.orm import Session

from trident.models import Severity
from trident.tools.base import RawFinding, ToolBase, register_tool


@register_tool
class TruffleHogTool(ToolBase):
    name = "trufflehog"

    def run(self, db: Session) -> list[RawFinding]:
        t0 = time.time()
        # --no-update: don't phone home for a self-update mid-scan.
        cmd = ["trufflehog", "filesystem", self.workspace, "--json", "--no-update"]
        _rc, output = self._run_cmd(db, cmd, timeout=600)
        findings = self._parse(output)
        self.persist_findings(db, findings)
        self._emit_complete(db, len(findings), time.time() - t0)
        return findings

    def _rel(self, path: str) -> str:
        try:
            if path and os.path.isabs(path):
                return os.path.relpath(path, self.workspace)
        except ValueError:
            pass
        return path or ""

    def _parse(self, output: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        for line in (output or "").splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            detector = r.get("DetectorName")
            if not detector:  # skip log/non-finding lines
                continue
            fs = ((r.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem") or {}
            verified = bool(r.get("Verified"))
            findings.append(RawFinding(
                tool=self.name,
                rule_id=str(detector),
                # A verified (live) credential is worse than a mere pattern match.
                severity=Severity.critical.value if verified else Severity.high.value,
                confidence=0.95 if verified else 0.7,
                title=f"{'Verified' if verified else 'Potential'} secret: {detector}",
                description=(f"TruffleHog detected a {detector} secret"
                            + (" and VERIFIED it is live." if verified
                               else " (unverified).")),
                file=self._rel(fs.get("file", "")),
                line_start=int(fs.get("line", 0) or 0),
                line_end=int(fs.get("line", 0) or 0),
                snippet=(r.get("Redacted") or "")[:60],
                cwe="CWE-798",
                recommendation="Rotate the credential immediately and move it to a secrets manager.",
                raw=r,
            ))
        return findings
