"""pip-audit adapter — Python dependency vulnerability scanner."""

from __future__ import annotations

import json
import os
import time

from sqlalchemy.orm import Session

from trident.models import Severity
from trident.tools.base import RawFinding, ToolBase, register_tool

# Directories not worth auditing for requirements manifests.
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "vendor"}

SEV_MAP = {"HIGH": Severity.high.value, "CRITICAL": Severity.critical.value,
           "MEDIUM": Severity.medium.value, "LOW": Severity.low.value,
           "MODERATE": Severity.medium.value}


@register_tool
class PipAuditTool(ToolBase):
    name = "pip-audit"

    def _find_requirements(self) -> list[str]:
        """All requirements*.txt files anywhere in the tree (not just the root)."""
        out: list[str] = []
        for root, dirs, files in os.walk(self.workspace):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
            for fn in files:
                if fn.startswith("requirements") and fn.endswith(".txt"):
                    out.append(os.path.join(root, fn))
        return out

    def run(self, db: Session) -> list[RawFinding]:
        t0 = time.time()
        findings: list[RawFinding] = []
        for req in self._find_requirements():
            rel = os.path.relpath(req, self.workspace)
            # --desc off is the valid flag (not --no-desc); --no-deps audits the
            # pinned versions without resolving the whole tree.
            cmd = ["pip-audit", "-r", req, "-f", "json", "--desc", "off", "--no-deps"]
            rc, output = self._run_cmd(db, cmd, timeout=600)
            try:
                data = json.loads(output)
            except json.JSONDecodeError:
                continue  # pip-audit failed on this manifest (e.g. uninstallable pin)
            for dep in data.get("dependencies", []):
                for vuln in dep.get("vulns", []) or []:
                    sev = SEV_MAP.get((vuln.get("severity") or "").upper(), Severity.medium.value)
                    findings.append(RawFinding(
                        tool=self.name,
                        rule_id=vuln.get("id", "pip-audit"),
                        severity=sev,
                        confidence=0.85,
                        title=f"{vuln.get('id', '?')} in {dep.get('name', '?')} {dep.get('version', '')}",
                        description=vuln.get("description", "")[:300],
                        file=rel,
                        line_start=0,
                        line_end=0,
                        snippet="",
                        recommendation="Upgrade to a fixed version.",
                        raw=vuln,
                    ))
        self.persist_findings(db, findings)
        self._emit_complete(db, len(findings), time.time() - t0)
        return findings