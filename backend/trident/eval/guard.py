"""Eval blinding guard — the single source of truth for scorecard detection.

The worker refuses to ingest any tree containing a scorecard file so the
council can never read the answer key. Imported by the ingest pipeline.
"""

from __future__ import annotations

import os

SCORECARD_SUFFIXES = (".toml", ".json", ".yaml", ".yml")


def is_scorecard_filename(name: str) -> bool:
    """True if a filename looks like a scorecard (e.g. scorecard.toml, scorecard.v2.json)."""
    n = name.lower()
    return n.startswith("scorecard") and n.endswith(SCORECARD_SUFFIXES)


def workspace_has_scorecard(workspace: str) -> bool:
    """Blinding guard: True if the tree contains any scorecard file."""
    for _root, _dirs, files in os.walk(workspace):
        for fn in files:
            if is_scorecard_filename(fn):
                return True
    return False
