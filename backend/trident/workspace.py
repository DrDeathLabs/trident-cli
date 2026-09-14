"""Shared rules for walking user workspaces without scanning generated trees."""

from __future__ import annotations

import os
from collections.abc import MutableSequence
from pathlib import Path


_SKIP_DIRS = frozenset({
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    "virtualenv", "vendor", "dist", "build", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", ".tox", "site-packages", "migrations", "alembic",
})
_SKIP_PREFIXES = (
    ".venv", ".pytest", ".ruff", ".mypy", ".tox", ".release-", ".wsl-",
)


def should_skip_dir(name: str) -> bool:
    """Return whether a directory is generated, vendored, or test-only."""
    lowered = name.lower()
    return lowered in _SKIP_DIRS or lowered.startswith(_SKIP_PREFIXES)


def prune_dirs(dirs: MutableSequence[str], *, skip_tests: bool = False) -> None:
    """Prune a mutable ``os.walk`` directory list in place."""
    dirs[:] = [
        name for name in dirs
        if not should_skip_dir(name) and not (skip_tests and name.lower() in {"tests", "test"})
    ]


def is_within(root: str | os.PathLike[str], candidate: str | os.PathLike[str]) -> bool:
    """Return whether a resolved candidate stays inside the resolved root."""
    root_real = os.path.realpath(os.fspath(root))
    candidate_real = os.path.realpath(os.fspath(candidate))
    try:
        return os.path.commonpath((root_real, candidate_real)) == root_real
    except ValueError:
        return False


def iter_workspace_files(root: str | os.PathLike[str], *, skip_tests: bool = False):
    """Yield regular files without following symlinked files or directories.

    A repository can contain a symlink to credentials or another checkout. All
    source walkers use this helper so agentic review and reachability analysis
    remain inside the declared workspace boundary.
    """
    root_path = Path(root).resolve()
    for current_root, dirs, files in os.walk(root_path, followlinks=False):
        prune_dirs(dirs, skip_tests=skip_tests)
        dirs[:] = [
            name for name in dirs
            if not (Path(current_root) / name).is_symlink()
        ]
        for name in files:
            path = Path(current_root) / name
            if path.is_symlink() or not path.is_file():
                continue
            if not is_within(root_path, path):
                continue
            yield path
