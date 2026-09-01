"""SQLite corpus DB connection and schema helper."""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


def _data_dir() -> Path:
    return Path(os.environ.get("CALIBRATION_DATA_DIR", "/data/calibration"))


def get_db() -> sqlite3.Connection:
    """Return a WAL-mode sqlite3 connection, creating the file if needed."""
    data_dir = _data_dir()
    data_dir.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(data_dir / "corpus.db")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.row_factory = sqlite3.Row
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS feed_status (
            feed TEXT PRIMARY KEY,
            status TEXT,
            last_updated TEXT,
            record_count INTEGER,
            error_msg TEXT
        );

        CREATE TABLE IF NOT EXISTS nvd_cve (
            cve_id TEXT PRIMARY KEY,
            cwe TEXT,
            attack_vector TEXT,
            privileges_required TEXT,
            user_interaction TEXT,
            scope TEXT,
            confidentiality TEXT,
            integrity TEXT,
            availability TEXT,
            base_score REAL,
            base_severity TEXT,
            published TEXT,
            last_modified TEXT
        );

        CREATE TABLE IF NOT EXISTS epss (
            cve_id TEXT PRIMARY KEY,
            epss_score REAL,
            percentile REAL,
            score_date TEXT
        );

        CREATE TABLE IF NOT EXISTS kev (
            cve_id TEXT PRIMARY KEY,
            vuln_name TEXT,
            date_added TEXT
        );

        CREATE TABLE IF NOT EXISTS exploitdb (
            exploit_id TEXT PRIMARY KEY,
            cve_id TEXT,
            description TEXT
        );

        CREATE TABLE IF NOT EXISTS cwe_tree (
            cwe_id TEXT PRIMARY KEY,
            name TEXT,
            parent_cwe TEXT
        );

        CREATE TABLE IF NOT EXISTS cwe_profiles (
            cwe TEXT PRIMARY KEY,
            cve_count INTEGER,
            median_cvss REAL,
            p25_cvss REAL,
            p75_cvss REAL,
            mean_epss REAL,
            p90_epss REAL,
            kev_rate REAL,
            exploit_rate REAL,
            modal_attack_vector TEXT,
            modal_impact TEXT,
            expected_tier TEXT,
            built_at TEXT
        );

        CREATE TABLE IF NOT EXISTS vulnrichment (
            cve_id TEXT PRIMARY KEY,
            exploitation TEXT,
            automatable TEXT,
            technical_impact TEXT
        );

        CREATE TABLE IF NOT EXISTS osv_cve (
            cve_id TEXT PRIMARY KEY,
            ecosystem_count INTEGER,
            package_count INTEGER
        );

        CREATE TABLE IF NOT EXISTS corpus_meta (
            key TEXT PRIMARY KEY,
            value TEXT,
            updated_at TEXT
        );
    """)
    conn.commit()

    # Migration: add new columns to cwe_profiles if they don't exist yet
    for col_sql in [
        "ALTER TABLE cwe_profiles ADD COLUMN active_exploit_rate REAL",
        "ALTER TABLE cwe_profiles ADD COLUMN osv_ecosystem_breadth REAL",
    ]:
        try:
            conn.execute(col_sql)
            conn.commit()
        except Exception:
            pass  # column already exists


def set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO corpus_meta(key, value, updated_at) VALUES(?,?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
        (key, value, now),
    )
    conn.commit()


def get_meta(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute("SELECT value FROM corpus_meta WHERE key=?", (key,)).fetchone()
    return row["value"] if row else None


def set_feed_status(
    conn: sqlite3.Connection,
    feed: str,
    status: str,
    record_count: int | None = None,
    error_msg: str | None = None,
) -> None:
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO feed_status(feed, status, last_updated, record_count, error_msg) "
        "VALUES(?,?,?,?,?) ON CONFLICT(feed) DO UPDATE SET "
        "status=excluded.status, last_updated=excluded.last_updated, "
        "record_count=excluded.record_count, error_msg=excluded.error_msg",
        (feed, status, now, record_count, error_msg),
    )
    conn.commit()
