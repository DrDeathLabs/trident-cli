"""Suppression: .tridentignore file parser + inline comment checker.

.tridentignore format (one entry per line; # lines are comments):
  <correlation_key>       — 24-char hex; suppress by stable cross-tool identity
  <rule_id_glob>          — fnmatch glob; suppress all matching rule IDs
  <file>:<line>           — suppress at an exact file+line location
"""

from __future__ import annotations

import fnmatch
from pathlib import Path

from loguru import logger
from sqlalchemy.orm import Session

from trident.models import Finding

_IGNORE_FILE = ".tridentignore"
_INLINE_MARKERS = ("# trident-ignore", "// trident-ignore", "-- trident-ignore")


class SuppressionSet:
    def __init__(
        self,
        correlation_keys: set[str],
        rule_globs: list[str],
        file_lines: set[tuple[str, int]],
    ):
        self.correlation_keys = correlation_keys
        self.rule_globs = rule_globs
        self.file_lines = file_lines

    def matches(self, finding: Finding) -> str | None:
        """Return a reason string if the finding is suppressed, else None."""
        if finding.correlation_key and finding.correlation_key in self.correlation_keys:
            return f".tridentignore: correlation_key {finding.correlation_key}"
        for glob in self.rule_globs:
            if fnmatch.fnmatch(finding.rule_id or "", glob):
                return f".tridentignore: rule_id matches {glob}"
        key = (finding.file or "", finding.line_start or 0)
        if key in self.file_lines:
            return f".tridentignore: {finding.file}:{finding.line_start}"
        return None


def load_suppression_set(workspace: str) -> SuppressionSet:
    """Parse .tridentignore from the workspace root."""
    ignore_path = Path(workspace) / _IGNORE_FILE
    correlation_keys: set[str] = set()
    rule_globs: list[str] = []
    file_lines: set[tuple[str, int]] = set()

    if not ignore_path.exists():
        return SuppressionSet(correlation_keys, rule_globs, file_lines)

    for raw in ignore_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # 24-char lowercase hex → correlation_key
        if len(line) == 24 and all(c in "0123456789abcdef" for c in line):
            correlation_keys.add(line)
        elif ":" in line and not line.startswith("*"):
            # Might be file:line — try parsing the suffix as an int
            parts = line.rsplit(":", 1)
            try:
                file_lines.add((parts[0], int(parts[1])))
            except ValueError:
                rule_globs.append(line)
        else:
            rule_globs.append(line)

    logger.debug(
        f"Suppression set: {len(correlation_keys)} keys, "
        f"{len(rule_globs)} globs, {len(file_lines)} file:line entries"
    )
    return SuppressionSet(correlation_keys, rule_globs, file_lines)


def check_inline_suppression(workspace: str, finding: Finding) -> str | None:
    """Check whether the finding's source line carries a trident-ignore comment.

    Checks the flagged line AND the line immediately above it (1-indexed).
    Returns the reason string if suppressed, else None.
    """
    if not finding.file or not finding.line_start:
        return None

    # Resolve relative to workspace; fall back to treating as absolute.
    candidate = Path(workspace) / finding.file
    if not candidate.exists():
        candidate = Path(finding.file)
    if not candidate.exists():
        return None

    try:
        source_lines = candidate.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None

    for idx in (finding.line_start - 1, finding.line_start - 2):
        if 0 <= idx < len(source_lines):
            text = source_lines[idx]
            for marker in _INLINE_MARKERS:
                if marker in text:
                    after = text[text.index(marker) + len(marker):].strip()
                    return f"inline: {after}" if after else "inline suppress"
    return None


def apply_suppressions(db: Session, job_id: str, workspace: str) -> int:
    """Apply .tridentignore and inline suppressions to all raw findings for a job.

    Returns the count of findings suppressed.
    Called in the orchestrator after the tool phase, before correlation.
    """
    suppression_set = load_suppression_set(workspace)
    findings = db.query(Finding).filter(
        Finding.job_id == job_id,
        Finding.status == "raw",
    ).all()

    count = 0
    for f in findings:
        reason = suppression_set.matches(f) or check_inline_suppression(workspace, f)
        if reason:
            f.status = "suppressed"
            f.suppression_reason = reason
            count += 1

    if count:
        logger.info(f"Suppressed {count} findings for job {job_id}")
    return count


def write_to_ignore_file(workspace: str, key: str) -> None:
    """Append a correlation_key to .tridentignore, creating the file if absent."""
    ignore_path = Path(workspace) / _IGNORE_FILE
    if ignore_path.exists():
        existing = {
            l.strip()
            for l in ignore_path.read_text(encoding="utf-8", errors="replace").splitlines()
        }
        if key in existing:
            return
    with ignore_path.open("a", encoding="utf-8") as fh:
        fh.write(f"{key}\n")


def remove_from_ignore_file(workspace: str, key: str) -> None:
    """Remove a correlation_key from .tridentignore."""
    ignore_path = Path(workspace) / _IGNORE_FILE
    if not ignore_path.exists():
        return
    lines = ignore_path.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
    ignore_path.write_text(
        "".join(l for l in lines if l.strip() != key),
        encoding="utf-8",
    )
