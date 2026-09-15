"""Shared paths for calibration feeds, corpus data, and the trained model."""

from __future__ import annotations

import os
from pathlib import Path

import platformdirs


def data_dir() -> Path:
    """Return the one calibration directory used by every calibration stage.

    Configuration wins over the environment, followed by the platform-specific
    user data directory.  The configuration import is lazy to avoid importing
    the full settings stack while calibration modules are being initialized.
    """
    try:
        from trident import config_manager
        value, _ = config_manager.get("model.data_dir")
    except Exception:
        value = None
    if value:
        return Path(value).expanduser()
    value = os.environ.get("CALIBRATION_DATA_DIR")
    if value:
        return Path(value).expanduser()
    return Path(platformdirs.user_data_dir("Trident")) / "calibration"


def corpus_db_path() -> Path:
    return data_dir() / "corpus.db"


def model_path() -> Path:
    return data_dir() / "model.joblib"
