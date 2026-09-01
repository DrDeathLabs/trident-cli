"""Checkov adapter — infrastructure-as-code / container misconfiguration.

A vuln class the other tools don't cover: Terraform, CloudFormation, Kubernetes,
Dockerfile, Helm, ARM, secrets-in-IaC. Deterministic policy checks.
"""

from __future__ import annotations

import json
import time

from sqlalchemy.orm import Session

from trident.models import Severity
from trident.tools.base import RawFinding, ToolBase, register_tool

_SEV_MAP = {
    "CRITICAL": Severity.critical.value, "HIGH": Severity.high.value,
    "MEDIUM": Severity.medium.value, "MODERATE": Severity.medium.value,
    "LOW": Severity.low.value, "INFO": Severity.info.value,
}


@register_tool
class CheckovTool(ToolBase):
    name = "checkov"

    def run(self, db: Session) -> list[RawFinding]:
        t0 = time.time()
        # --compact drops per-check code blocks; --quiet suppresses the banner.
        cmd = ["checkov", "-d", self.workspace, "-o", "json", "--compact", "--quiet"]
        _rc, output = self._run_cmd(db, cmd, timeout=600)
        findings = self._parse(output)
        self.persist_findings(db, findings)
        self._emit_complete(db, len(findings), time.time() - t0)
        return findings

    def _rel(self, path: str) -> str:
        path = (path or "").lstrip("/")  # checkov paths are workspace-relative but leading-slashed
        # If it accidentally embeds the absolute workspace, strip it.
        ws = self.workspace.lstrip("/")
        if ws and path.startswith(ws):
            path = path[len(ws):].lstrip("/")
        return path

    def _parse(self, output: str) -> list[RawFinding]:
        try:
            data = json.loads(output)
        except (json.JSONDecodeError, TypeError):
            return []
        # checkov emits a single object, or a LIST of objects (one per framework).
        blocks = data if isinstance(data, list) else [data]
        findings: list[RawFinding] = []
        for block in blocks:
            if not isinstance(block, dict):
                continue
            check_type = block.get("check_type", "iac")
            failed = (block.get("results") or {}).get("failed_checks", [])
            for c in failed:
                rng = c.get("file_line_range") or [0, 0]
                sev = _SEV_MAP.get(str(c.get("severity") or "").upper(), Severity.medium.value)
                findings.append(RawFinding(
                    tool=self.name,
                    rule_id=c.get("check_id", "checkov"),
                    severity=sev,
                    confidence=0.8,
                    title=f"[{check_type}] {c.get('check_name', c.get('check_id', ''))}",
                    description=c.get("check_name", ""),
                    file=self._rel(c.get("file_path", "")),
                    line_start=int(rng[0] or 0),
                    line_end=int(rng[-1] or 0),
                    snippet=c.get("resource", ""),
                    cwe=None,
                    recommendation=c.get("guideline", "") or "",
                    raw=c,
                ))
        return findings
