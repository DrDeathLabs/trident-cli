"""Shared test fixtures. Forces the mock LLM and an in-memory SQLite DB — no network."""

from __future__ import annotations

import os
import sys

os.environ["TRIDENT_LLM_MOCK"] = "1"
os.environ["TRIDENT_DISABLE_EVENTS"] = "1"  # no external Redis in tests
_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

import shutil  # noqa: E402
import tempfile  # noqa: E402

import pytest  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

import trident.llm.base as _base  # noqa: E402
from trident.llm.base import MockLLMBackend, set_mock_handler  # noqa: E402
from trident.models import Base, Finding, Job  # noqa: E402

_base._llm = MockLLMBackend()


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


@pytest.fixture
def job(db):
    j = Job(id="job1", target_name="t", source_type="demo", source_ref="", workspace_path="/tmp/ws")
    db.add(j)
    db.commit()
    return j


@pytest.fixture(autouse=True)
def _reset_mock():
    set_mock_handler(None)
    yield
    set_mock_handler(None)


@pytest.fixture
def workspace():
    """A temp workspace with a small source file (avoids pytest's tmp_path base dir)."""
    d = tempfile.mkdtemp(prefix="trident_ws_", dir=_BACKEND)
    app = os.path.join(d, "app")
    os.makedirs(app)
    with open(os.path.join(app, "main.py"), "w") as fh:
        fh.write("def f(q):\n    sql = 'SELECT ' + q\n    return sql\n" * 5)
    yield d
    shutil.rmtree(d, ignore_errors=True)


def make_finding(db, job_id="job1", **kw):
    defaults = dict(
        id=kw.pop("id", None) or os.urandom(8).hex(),
        job_id=job_id, hash=os.urandom(6).hex(), tool="semgrep", rule_id="r1",
        severity="high", confidence=0.7, title="SQL injection", description="sqli",
        file="app/main.py", line_start=10, line_end=10, cwe="CWE-89", status="raw",
    )
    defaults.update(kw)
    f = Finding(**defaults)
    db.add(f)
    db.commit()
    return f
