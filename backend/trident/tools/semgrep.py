"""Semgrep adapter — multi-language SAST."""

from __future__ import annotations

import json
import os
import time

from sqlalchemy.orm import Session

from trident.models import Severity
from trident.tools.base import RawFinding, ToolBase, register_tool

SEV_MAP = {"ERROR": Severity.high.value, "WARNING": Severity.medium.value, "INFO": Severity.low.value}

# Rulesets to run. `auto` picks language-appropriate rules; the explicit packs add
# breadth (security audit + OWASP Top-10 + secrets). Override via SEMGREP_CONFIGS
# (space-separated) to tune the recall/noise trade-off without a code change.
_DEFAULT_CONFIGS = "auto p/security-audit p/owasp-top-ten p/secrets"


def _configs() -> list[str]:
    raw = os.environ.get("SEMGREP_CONFIGS", _DEFAULT_CONFIGS).split()
    args: list[str] = []
    for c in raw:
        args += ["--config", c]
    return args


@register_tool
class SemgrepTool(ToolBase):
    name = "semgrep"

    def run(self, db: Session) -> list[RawFinding]:
        t0 = time.time()
        cmd = [
            "semgrep", "scan", *_configs(), "--json", "--no-rewrite-rule-ids",
            "--quiet", self.workspace,
        ]
        rc, output = self._run_cmd(db, cmd, timeout=900)
        findings: list[RawFinding] = []
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            data = {"results": []}
        for r in data.get("results", []):
            sev = SEV_MAP.get(r.get("extra", {}).get("severity", "WARNING"), Severity.medium.value)
            check_id = r.get("check_id", "semgrep")
            path = r.get("path", "")
            start = r.get("start", {})
            end = r.get("end", {})
            snippet = r.get("extra", {}).get("lines", "")
            metadata = r.get("extra", {}).get("metadata", {})
            cwe = None
            for c in metadata.get("cwe", []):
                if isinstance(c, str):
                    cwe = c.split(":")[0].replace("CWE-", "CWE-")
                    break
            findings.append(RawFinding(
                tool=self.name,
                rule_id=check_id,
                severity=sev,
                confidence=0.8,
                title=metadata.get("message", check_id),
                description=r.get("extra", {}).get("message", ""),
                file=path,
                line_start=start.get("line", 0),
                line_end=end.get("line", start.get("line", 0)),
                snippet=snippet,
                cwe=cwe,
                recommendation=metadata.get("fix", ""),
                raw=r,
            ))
        self.persist_findings(db, findings)
        self._emit_complete(db, len(findings), time.time() - t0)
        return findings