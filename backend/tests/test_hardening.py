"""Regression tests for imported-report evidence hardening."""

from __future__ import annotations

from trident.calibration import paths


def test_all_calibration_consumers_use_configured_data_directory(tmp_path, monkeypatch):
    configured = tmp_path / "calibration"
    monkeypatch.setattr("trident.config_manager.get", lambda key: (str(configured), "config"))
    monkeypatch.delenv("CALIBRATION_DATA_DIR", raising=False)

    from trident.calibration.corpus import db as corpus_db
    from trident.calibration.feeds import base as feeds_base
    from trident import model_manager

    assert paths.data_dir() == configured
    assert corpus_db._data_dir() == configured
    assert feeds_base.get_data_dir() == configured
    assert model_manager._data_dir() == configured
    conn = corpus_db.get_db()
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 0
    conn.close()


def test_environment_directory_is_shared_when_no_explicit_config(tmp_path, monkeypatch):
    monkeypatch.setattr("trident.config_manager.get", lambda key: ("", "default"))
    monkeypatch.setenv("CALIBRATION_DATA_DIR", str(tmp_path))

    from trident.calibration.corpus import db as corpus_db
    from trident.calibration.feeds import base as feeds_base
    from trident import model_manager

    assert paths.data_dir() == tmp_path
    assert corpus_db._data_dir() == tmp_path
    assert feeds_base.get_data_dir() == tmp_path
    assert model_manager.corpus_db_path() == tmp_path / "corpus.db"
    assert model_manager.model_path() == tmp_path / "model.joblib"
