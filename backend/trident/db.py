"""Database session management."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from trident.config import settings

if settings.db.backend == "sqlite":
    # check_same_thread=False: desktop-mode tasks run via asyncio.to_thread
    # (see tasks/runner.py), so the engine is used from worker threads other
    # than the one that created it — SQLite's default same-thread check would
    # otherwise reject that. WAL mode gives reasonable read/write concurrency
    # for a single-user desktop process (irrelevant for Postgres, so scoped to
    # this branch only).
    engine = create_engine(
        settings.db.url, pool_pre_ping=True, connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_conn, _record):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()
else:
    engine = create_engine(settings.db.url, pool_pre_ping=True, pool_recycle=1800)

SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


@contextmanager
def db_session() -> Generator[Session, None, None]:
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db() -> Generator[Session, None, None]:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def apply_migrations() -> None:
    """Add any columns present in the ORM models but missing from the live DB.

    Runs as a lightweight ALTER TABLE pass after create_all so that existing
    SQLite databases (created before a column was added) are brought up to date
    without requiring Alembic in the CLI/desktop flow.
    """
    if settings.db.backend != "sqlite":
        return  # Postgres deployments use Alembic migrations instead

    from sqlalchemy import inspect, text

    inspector = inspect(engine)

    # Map of table → {column_name: DDL_type_string} to add when missing
    _migrations: dict[str, dict[str, str]] = {
        "findings": {
            "suppression_reason": "TEXT",
        },
    }

    with engine.connect() as conn:
        for table, columns in _migrations.items():
            if table not in inspector.get_table_names():
                continue
            existing = {col["name"] for col in inspector.get_columns(table)}
            for col_name, col_type in columns.items():
                if col_name not in existing:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_type}"))
            conn.commit()