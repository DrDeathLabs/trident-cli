"""Helpers for keeping detected credential values out of persisted evidence."""

from __future__ import annotations

import re
from typing import Any

_CREDENTIAL_CWES = {"CWE-256", "CWE-259", "CWE-798"}
_CREDENTIAL_TERMS = re.compile(
    r"(?i)(?:secret|credential|password|api[\s_-]?key|token|hard.?coded.{0,20}(?:key|pass|cred))"
)


def is_credential_rule(*values: Any, cwe: str | None = None) -> bool:
    """Return whether scanner metadata identifies a credential finding."""
    if str(cwe or "").upper() in _CREDENTIAL_CWES:
        return True
    return any(_CREDENTIAL_TERMS.search(str(value or "")) for value in values)


def redacted_credential_raw(
    tool: str, rule_id: str, file: str, line_start: int, line_end: int,
    *, cwe: str | None = None,
) -> dict[str, Any]:
    """Return only location/classification metadata, never scanner match text."""
    return {
        "redacted": True,
        "tool": tool,
        "rule_id": rule_id,
        "file": file,
        "line_start": line_start,
        "line_end": line_end,
        "cwe": cwe,
    }
