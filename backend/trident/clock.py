"""UTC clock helpers kept compatible with the existing naive DB timestamps."""

from __future__ import annotations

from datetime import datetime, timezone


def utcnow() -> datetime:
    """Return current UTC without the deprecated datetime.utcnow()."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def utcfromtimestamp(timestamp: float) -> datetime:
    """Convert a POSIX timestamp to naive UTC for DB comparisons."""
    return datetime.fromtimestamp(timestamp, timezone.utc).replace(tzinfo=None)
