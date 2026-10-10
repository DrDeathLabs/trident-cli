from __future__ import annotations

import tomllib
from pathlib import Path


def test_package_license_copy_matches_repository_license() -> None:
    backend = Path(__file__).resolve().parents[1]
    repository_license = backend.parent / "LICENSE"
    package_license = backend / "LICENSE"
    project = tomllib.loads((backend / "pyproject.toml").read_text(encoding="utf-8"))

    assert project["project"]["license"] == "BUSL-1.1"
    assert project["project"]["license-files"] == ["LICENSE"]
    assert package_license.read_bytes() == repository_license.read_bytes()
