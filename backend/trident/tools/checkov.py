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
from trident.tools.redaction import is_credential_rule, redacted_credential_raw

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
                rule_id = c.get("check_id", "checkov")
                file = self._rel(c.get("file_path", ""))
                line_start = int(rng[0] or 0)
                line_end = int(rng[-1] or 0)
                credential = is_credential_rule(
                    rule_id, c.get("check_name"), c.get("guideline"),
                )
                findings.append(RawFinding(
                    tool=self.name,
                    rule_id=rule_id,
                    severity=sev,
                    confidence=0.8,
                    title=("Potential credential exposed" if credential else
                           f"[{check_type}] {c.get('check_name', c.get('check_id', ''))}"),
                    description=(
                        "A potential credential is present; its value is omitted from Trident output."
                        if credential else c.get("check_name", "")
                    ),
                    file=file,
                    line_start=line_start,
                    line_end=line_end,
                    snippet="[REDACTED]" if credential else c.get("resource", ""),
                    cwe=None,
                    recommendation=(
                        "Remove the credential from source, rotate it, and use a secrets manager."
                        if credential else c.get("guideline", "") or ""
                    ),
                    raw=(
                        redacted_credential_raw(
                            self.name, rule_id, file, line_start, line_end,
                        ) if credential else c
                    ),
                ))
        return findings
