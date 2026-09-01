"""govulncheck adapter — official Go vulnerability database check.

Call-graph aware: it reports vulns in code paths actually reachable from the
module, so it complements gosec (SAST) and grype/osv (package-level) with low-FP,
reachability-aware Go findings. Runs per go.mod; a no-op on non-Go repos.
"""

from __future__ import annotations

import json
import os
import time

from sqlalchemy.orm import Session

from trident.models import Severity
from trident.tools.base import RawFinding, ToolBase, register_tool

_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "vendor", "dist", "build"}


def _iter_json(output: str):
    """Yield each top-level JSON object from govulncheck's concatenated stream."""
    dec = json.JSONDecoder()
    s = (output or "").strip()
    i, n = 0, len(s)
    while i < n:
        while i < n and s[i] in " \r\n\t":
            i += 1
        if i >= n:
            break
        try:
            obj, end = dec.raw_decode(s, i)
        except json.JSONDecodeError:
            break
        yield obj
        i = end


@register_tool
class GovulncheckTool(ToolBase):
    name = "govulncheck"

    def _go_module_dirs(self) -> list[str]:
        dirs: list[str] = []
        for root, subs, files in os.walk(self.workspace):
            subs[:] = [d for d in subs if d not in _SKIP_DIRS]
            if "go.mod" in files:
                dirs.append(root)
        return dirs

    def run(self, db: Session) -> list[RawFinding]:
        t0 = time.time()
        mod_dirs = self._go_module_dirs()
        if not mod_dirs:  # not a Go repo — skip cleanly
            self._emit_complete(db, 0, time.time() - t0)
            return []
        findings: list[RawFinding] = []
        for d in mod_dirs:
            cmd = ["govulncheck", "-json", "./..."]
            _rc, output = self._run_cmd(db, cmd, cwd=d, timeout=600)
            findings.extend(self._parse(output, module_dir=d))
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

    def _parse(self, output: str, module_dir: str = "") -> list[RawFinding]:
        osv_defs: dict[str, dict] = {}
        # A vuln can surface as several findings (import- vs call-level); keep the
        # most specific (a trace frame with a source position = reachable call).
        best: dict[str, dict] = {}
        for obj in _iter_json(output):
            if "osv" in obj and isinstance(obj["osv"], dict):
                o = obj["osv"]
                osv_defs[o.get("id", "")] = o
            elif "finding" in obj:
                f = obj["finding"]
                oid = f.get("osv", "")
                frame = None
                for fr in f.get("trace", []) or []:
                    if fr.get("position"):
                        frame = fr  # last framed position = the reachable call site
                if oid and (oid not in best or (frame and not best[oid].get("frame"))):
                    best[oid] = {"finding": f, "frame": frame}
        findings: list[RawFinding] = []
        for oid, info in best.items():
            o = osv_defs.get(oid, {})
            frame = info.get("frame") or {}
            pos = frame.get("position") or {}
            reachable = bool(frame)
            fpath = pos.get("filename", "")
            if fpath and module_dir and not os.path.isabs(fpath):
                fpath = os.path.join(module_dir, fpath)
            aliases = ", ".join(o.get("aliases", [])[:3])
            findings.append(RawFinding(
                tool=self.name,
                rule_id=oid,
                # A reachable (called) vuln is higher priority than a mere import.
                severity=Severity.high.value if reachable else Severity.medium.value,
                confidence=0.9 if reachable else 0.6,
                title=f"{oid} in {frame.get('package', o.get('summary', 'Go dependency'))}"[:200],
                description=(o.get("summary") or o.get("details", ""))[:1000]
                + (f" (aliases: {aliases})" if aliases else ""),
                file=self._rel(fpath),
                line_start=int(pos.get("line", 0) or 0),
                line_end=int(pos.get("line", 0) or 0),
                snippet=frame.get("function", ""),
                cwe=None,
                recommendation="Upgrade the affected Go module to a fixed version.",
                raw=info["finding"],
            ))
        return findings
