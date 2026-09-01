"""Trivy adapter — dependency + config/IaC scanning."""

from __future__ import annotations

import json
import time

from sqlalchemy.orm import Session

from trident.models import Severity
from trident.tools.base import RawFinding, ToolBase, register_tool

SEV_MAP = {
    "CRITICAL": Severity.critical.value,
    "HIGH": Severity.high.value,
    "MEDIUM": Severity.medium.value,
    "LOW": Severity.low.value,
    "UNKNOWN": Severity.info.value,
}


@register_tool
class TrivyTool(ToolBase):
    name = "trivy"

    def run(self, db: Session) -> list[RawFinding]:
        t0 = time.time()
        findings: list[RawFinding] = []
        # fs scan for config + secrets + vulns
        # DB is cached in the trident_trivy_cache volume; trivy refreshes it as
        # needed. (Previously --skip-db-update on an empty cache => zero findings.)
        cmd = [
            "trivy", "fs", "--format", "json", "--quiet",
            "--scanners", "vuln,secret,config,misconfig",
            self.workspace,
        ]
        rc, output = self._run_cmd(db, cmd, timeout=900)
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            data = {"Results": []}

        for result in data.get("Results", []):
            target = result.get("Target", "")
            # Vulnerabilities
            for vuln in result.get("Vulnerabilities", []) or []:
                sev = SEV_MAP.get((vuln.get("Severity") or "").upper(), Severity.medium.value)
                findings.append(RawFinding(
                    tool=self.name,
                    rule_id=vuln.get("VulnerabilityID", "trivy-vuln"),
                    severity=sev,
                    confidence=0.85,
                    title=f"{vuln.get('VulnerabilityID', '?')} in {vuln.get('PkgName', '?')} {vuln.get('InstalledVersion', '')}",
                    description=vuln.get("Description", ""),
                    file=target,
                    line_start=0,
                    line_end=0,
                    snippet="",
                    cwe=None,
                    recommendation="Upgrade to fixed version: " + str(vuln.get("FixedVersion", "n/a")),
                    raw=vuln,
                ))
            # Misconfigurations
            for mc in result.get("Misconfigurations", []) or []:
                sev = SEV_MAP.get((mc.get("Severity") or "").upper(), Severity.medium.value)
                findings.append(RawFinding(
                    tool=self.name,
                    rule_id=mc.get("ID", "trivy-misconfig"),
                    severity=sev,
                    confidence=0.7,
                    title=mc.get("Title", mc.get("ID", "")),
                    description=mc.get("Message", ""),
                    file=target,
                    line_start=mc.get("StartLine", 0),
                    line_end=mc.get("EndLine", 0),
                    snippet="",
                    recommendation=mc.get("Resolution", ""),
                    raw=mc,
                ))
            # Secrets
            for sec in result.get("Secrets", []) or []:
                sev = SEV_MAP.get((sec.get("Severity") or "").upper(), Severity.high.value)
                findings.append(RawFinding(
                    tool=self.name,
                    rule_id=sec.get("RuleID", "trivy-secret"),
                    severity=sev,
                    confidence=0.8,
                    title=f"Secret detected: {sec.get('Title', '')}",
                    description=sec.get("Match", "")[:200],
                    file=target,
                    line_start=sec.get("StartLine", 0),
                    line_end=sec.get("EndLine", 0),
                    snippet="",
                    recommendation="Remove the secret and rotate it; use a secrets manager.",
                    raw=sec,
                ))
        self.persist_findings(db, findings)
        self._emit_complete(db, len(findings), time.time() - t0)
        return findings