"""Desktop-mode config branching — SQLite/in-process coexists with the
default Postgres/Celery path; neither should affect the other's defaults."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import pytest
from trident.config import DBConfig, Settings


@pytest.fixture
def tmp():
    d = tempfile.mkdtemp(prefix="trident_cfg_")
    yield Path(d)
    shutil.rmtree(d, ignore_errors=True)


def test_sqlite_is_the_default_backend():
    """SQLite is the standalone default — Docker opts in via explicit env var."""
    db = DBConfig()
    assert db.backend == "sqlite"
    assert db.url.startswith("sqlite:///")


def test_postgres_when_explicitly_set(monkeypatch):
    monkeypatch.setenv("TRIDENT_DB_BACKEND", "postgres")
    db = DBConfig()
    assert db.backend == "postgres"
    assert db.url.startswith("postgresql+psycopg2://")


def test_sqlite_backend_produces_sqlite_url(tmp, monkeypatch):
    monkeypatch.setenv("TRIDENT_DB_BACKEND", "sqlite")
    monkeypatch.setenv("TRIDENT_SQLITE_PATH", str(tmp / "trident.db"))
    db = DBConfig()
    assert db.backend == "sqlite"
    assert db.url == f"sqlite:///{tmp / 'trident.db'}"


def test_sqlite_path_env_var_not_silently_ignored_when_set(tmp, monkeypatch):
    """Regression: Path("") is truthy, so `Path(env) or default` never falls
    through to the default even when the env var IS set to something real —
    the opposite bug (falling through when it shouldn't) is what this guards."""
    custom = tmp / "custom" / "path.db"
    monkeypatch.setenv("TRIDENT_SQLITE_PATH", str(custom))
    db = DBConfig()
    assert db.sqlite_path == custom


def test_sqlite_path_defaults_under_app_data_dir_when_unset(monkeypatch):
    monkeypatch.delenv("TRIDENT_SQLITE_PATH", raising=False)
    db = DBConfig()
    assert db.sqlite_path.name == "trident.db"
    assert db.sqlite_path != Path("")  # the bug this guards against


def test_task_backend_default_is_inprocess():
    """inprocess is the standalone default — Docker opts in via explicit env var."""
    assert Settings().task_backend == "inprocess"


def test_task_backend_celery_when_explicitly_set(monkeypatch):
    monkeypatch.setenv("TRIDENT_TASK_BACKEND", "celery")
    assert Settings().task_backend == "celery"


def test_task_backend_inprocess_via_env(monkeypatch):
    monkeypatch.setenv("TRIDENT_TASK_BACKEND", "inprocess")
    assert Settings().task_backend == "inprocess"


def test_workspaces_dir_respects_explicit_env_unaffected(monkeypatch):
    """docker-compose.yml always sets this explicitly — must be unaffected."""
    monkeypatch.setenv("TRIDENT_WORKSPACES", "/workspaces")
    assert str(Settings().workspaces_dir) == "/workspaces" or str(
        Settings().workspaces_dir
    ).replace("\\", "/") == "/workspaces"


def test_workspaces_dir_falls_back_to_app_data_dir_when_unset(monkeypatch):
    monkeypatch.delenv("TRIDENT_WORKSPACES", raising=False)
    ws = Settings().workspaces_dir
    assert ws.name == "workspaces"
    assert str(ws) != "/workspaces"


def test_tools_dir_respects_explicit_env(monkeypatch, tmp):
    custom = tmp / "tools"
    monkeypatch.setenv("TRIDENT_TOOLS_DIR", str(custom))
    assert Settings().tools_dir == custom
