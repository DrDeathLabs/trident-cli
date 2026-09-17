"""Validate the deterministic pre-publication release invariants.

This script performs no publication and does not create or move tags. It is
used by the manual release workflow after checkout and can be exercised locally
against an annotated or lightweight tag.
"""

from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path


def _git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip()
        raise SystemExit(f"git {' '.join(args)} failed: {detail}")
    return result.stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--confirm", required=True)
    parser.add_argument("--package-version", required=True)
    parser.add_argument("--notes-root", required=True, type=Path)
    args = parser.parse_args()

    if args.confirm != "PUBLISH":
        raise SystemExit("release confirmation must be exactly PUBLISH")
    if not re.fullmatch(r"v\d+\.\d+\.\d+", args.tag):
        raise SystemExit("release tag must match vMAJOR.MINOR.PATCH")
    if not re.fullmatch(r"[0-9a-fA-F]{40}", args.source_sha):
        raise SystemExit("source SHA must be a full 40-character commit SHA")

    tag_commit = _git("rev-list", "-n", "1", args.tag)
    head = _git("rev-parse", "HEAD")
    expected_version = args.tag.removeprefix("v")
    notes_file = args.notes_root / f"{expected_version}.md"

    if tag_commit.lower() != args.source_sha.lower():
        raise SystemExit("tag does not resolve to the approved source SHA")
    if head.lower() != args.source_sha.lower():
        raise SystemExit("checked-out HEAD does not equal the approved source SHA")
    if args.package_version != expected_version:
        raise SystemExit("package version does not equal the release tag")
    if not notes_file.is_file():
        raise SystemExit(f"release notes file does not exist: {notes_file}")

    print(f"tag_commit={tag_commit}")
    print(f"head={head}")
    print(f"package_version={args.package_version}")
    print(f"release_notes={notes_file}")
    print("release_candidate_validation=ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
