"""Base class for all corpus data fetchers."""

from __future__ import annotations

import os
import time
from pathlib import Path


def get_data_dir() -> Path:
    return Path(os.environ.get("CALIBRATION_DATA_DIR", "/data/calibration"))


class BaseFetcher:
    name: str

    @property
    def cache_dir(self) -> Path:
        return get_data_dir() / "feeds" / self.name

    def fetch(self, force: bool = False) -> int:
        """Download + store raw data. Returns record count."""
        raise NotImplementedError

    def _cache_path(self, filename: str) -> Path:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        return self.cache_dir / filename

    def _stale(self, path: Path, max_age_hours: int = 24) -> bool:
        if not path.exists():
            return True
        age = time.time() - path.stat().st_mtime
        return age > max_age_hours * 3600
