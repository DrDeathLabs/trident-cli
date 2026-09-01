"""Tool harness base class + registry.

Deterministic scanners produce raw findings; each adapter normalizes to the
common Finding schema and streams live events as it runs.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from loguru import logger
from sqlalchemy.orm import Session

from trident.events.publisher import EventType, publish_event
from trident.models import Finding, Severity, stable_finding_hash


def python_env_binary(name: str) -> str | None:
    """Return a console-script path from the Python environment running Trident.

    WSL commonly inherits the Windows PATH.  That PATH can contain a console
    script for a different Python installation, so checking ``shutil.which``
    first may execute the wrong interpreter (or report a tool as broken).  The
    active environment's Scripts/bin directory is authoritative for tools
    installed by ``trident install-tools``.
    """
    # Do not resolve the interpreter symlink: on POSIX virtual environments
    # ``bin/python`` commonly points at ``/usr/bin/python3`` while the console
    # scripts live beside the venv's symlink.
    env_bin = Path(sys.executable).parent
    names = [name]
    underscored = name.replace("-", "_")
    if underscored != name:
        names.append(underscored)
    if sys.platform == "win32":
        # Windows environments can contain extensionless console-script shims
        # that are not executable by CreateProcess. Prefer real launchers.
        names = [
            f"{candidate}{suffix}"
            for suffix in (".exe", ".cmd", ".bat")
            for candidate in tuple(names)
        ] + names
    for candidate_name in names:
        candidate = env_bin / candidate_name
        if candidate.is_file():
            return str(candidate)
    return None


def resolve_binary(name: str) -> str:
    """Return the absolute path to `name`, preferring Trident's own tools_dir
    over the system PATH so `trident install-tools` works without PATH edits."""
    from trident.config import settings
    suffix = ".exe" if sys.platform == "win32" else ""
    managed = settings.tools_dir / (name + suffix)
    if managed.exists():
        return str(managed)
    active_env = python_env_binary(name)
    if active_env:
        return active_env
    found = shutil.which(name)
    return found if found else name  # let Popen raise FileNotFoundError if truly absent


@dataclass
class RawFinding:
    """A normalized finding from a tool, before expert review."""
    tool: str
    rule_id: str
    severity: str = Severity.medium.value
    confidence: float = 0.7
    title: str = ""
    description: str = ""
    file: str = ""
    line_start: int = 0
    line_end: int = 0
    snippet: str = ""
    cwe: str | None = None
    owasp: str | None = None
    recommendation: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


class ToolBase(ABC):
    """Base class for deterministic scanning tools."""

    name: str = "base"

    def __init__(self, workspace: str, job_id: str):
        self.workspace = workspace
        self.job_id = job_id

    @abstractmethod
    def run(self, db: Session) -> list[RawFinding]:
        """Run the tool and return normalized raw findings."""
        ...

    def _emit(self, db: Session, event_type: str, payload: dict | None = None):
        publish_event(db, self.job_id, event_type, payload or {})

    def _emit_started(self, db: Session, command: str):
        self._emit(db, EventType.TOOL_STARTED, {"tool": self.name, "command": command})

    def _emit_complete(self, db: Session, findings_count: int, duration_s: float):
        self._emit(
            db, EventType.TOOL_COMPLETE,
            {"tool": self.name, "findings": findings_count, "duration_s": round(duration_s, 2)},
        )

    def _emit_stdout(self, db: Session, line: str):
        self._emit(db, EventType.TOOL_STDOUT, {"tool": self.name, "line": line[:2000]})

    def _emit_finding(self, db: Session, rf: RawFinding):
        self._emit(db, EventType.TOOL_FINDING, {
            "tool": rf.tool, "rule_id": rf.rule_id, "file": rf.file,
            "line_start": rf.line_start, "severity": rf.severity, "title": rf.title,
        })

    def _run_cmd(
        self, db: Session, cmd: list[str], cwd: str | None = None, timeout: int = 600,
    ) -> tuple[int, str]:
        """Run a subprocess, streaming stdout lines as events. Returns (rc, output).

        stdout and stderr are kept on SEPARATE pipes so a tool's diagnostics can
        never corrupt the JSON we parse from stdout. stderr is drained on a
        background thread (no DB access — the session is not thread-safe). On
        timeout the process is killed and rc=124 is returned so callers can tell
        the output is incomplete.
        """
        cmd = [resolve_binary(cmd[0])] + list(cmd[1:])
        self._emit_started(db, " ".join(cmd))
        try:
            proc = subprocess.Popen(
                cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1, encoding="utf-8", errors="replace",
            )
        except FileNotFoundError as e:
            self._emit(db, EventType.TOOL_ERROR, {"tool": self.name, "error": f"binary not found: {e}"})
            return 127, ""

        err_lines: list[str] = []

        def _drain_err():
            try:
                for line in proc.stderr:  # type: ignore[union-attr]
                    err_lines.append(line.rstrip())
            except Exception:
                pass

        err_thread = threading.Thread(target=_drain_err, daemon=True)
        err_thread.start()

        lines: list[str] = []
        assert proc.stdout is not None
        for line in proc.stdout:
            line = line.rstrip()
            lines.append(line)
            self._emit_stdout(db, line)

        timed_out = False
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            if sys.platform == "win32":
                # proc.kill() only sends TerminateProcess to the top-level process;
                # grandchildren survive. taskkill /T kills the whole tree.
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                    capture_output=True,
                )
            else:
                proc.kill()
            proc.wait()
            timed_out = True
            self._emit(db, EventType.TOOL_ERROR, {"tool": self.name, "error": f"timed out after {timeout}s"})
        err_thread.join(timeout=2)
        if err_lines:
            self._emit(db, EventType.TOOL_STDOUT, {"tool": self.name, "line": ("[stderr] " + err_lines[-1])[:2000]})
        rc = 124 if timed_out else proc.returncode
        return rc, "\n".join(lines)

    def persist_findings(
        self, db: Session, raw_findings: list[RawFinding], iteration: int = 0,
    ) -> list[Finding]:
        """Persist raw findings to DB as status='raw' and emit finding events."""
        out: list[Finding] = []
        for rf in raw_findings:
            f = Finding(
                job_id=self.job_id,
                hash=stable_finding_hash(rf.file, rf.line_start, rf.rule_id, rf.snippet),
                tool=rf.tool,
                rule_id=rf.rule_id,
                severity=rf.severity,
                confidence=rf.confidence,
                title=rf.title,
                description=rf.description,
                file=rf.file,
                line_start=rf.line_start,
                line_end=rf.line_end,
                snippet=rf.snippet,
                cwe=rf.cwe,
                owasp=rf.owasp,
                recommendation=rf.recommendation,
                raw_outputs={"raw": rf.raw},
                status="raw",
                iteration=iteration,
            )
            db.add(f)
            db.flush()
            out.append(f)
            self._emit_finding(db, rf)
            # Also emit a normalized finding.raw event for the UI
            self._emit(db, EventType.FINDING_RAW, {
                "finding_id": f.id, "tool": rf.tool, "rule_id": rf.rule_id,
                "file": rf.file, "line_start": rf.line_start, "severity": rf.severity,
                "title": rf.title, "cwe": rf.cwe,
            })
        return out


# Registry of available tools
TOOL_REGISTRY: dict[str, type[ToolBase]] = {}


def register_tool(cls: type[ToolBase]) -> type[ToolBase]:
    TOOL_REGISTRY[cls.name] = cls
    return cls


def get_tools(names: list[str], workspace: str, job_id: str) -> list[ToolBase]:
    tools: list[ToolBase] = []
    for n in names:
        cls = TOOL_REGISTRY.get(n)
        if cls:
            tools.append(cls(workspace=workspace, job_id=job_id))
        else:
            logger.warning(f"Unknown tool requested: {n}")
    return tools
