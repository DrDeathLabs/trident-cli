"""Trident model manager — wraps calibration corpus + model lifecycle for the CLI.

Provides progress-aware wrappers around the calibration pipeline so the CLI
can display live rich progress without duplicating the core logic.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

import platformdirs


def _data_dir() -> Path:
    from trident import config_manager
    val, _ = config_manager.get("model.data_dir")
    if val:
        return Path(val)
    import os
    env = os.environ.get("CALIBRATION_DATA_DIR")
    if env:
        return Path(env)
    return Path(platformdirs.user_data_dir("Trident")) / "calibration"


def model_path() -> Path:
    return _data_dir() / "model.joblib"


def corpus_db_path() -> Path:
    return _data_dir() / "corpus.db"


def _get_conn():
    """Get a corpus DB connection pointed at the user data dir."""
    import sqlite3
    data_dir = _data_dir()
    data_dir.mkdir(parents=True, exist_ok=True)
    db_path = corpus_db_path()
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.row_factory = sqlite3.Row
    from trident.calibration.corpus.db import init_schema
    init_schema(conn)
    return conn


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

def get_status() -> dict[str, Any]:
    """Return a status dict: feed freshness, corpus row counts, model info."""
    status: dict[str, Any] = {
        "corpus_db_exists": corpus_db_path().exists(),
        "model_exists": model_path().exists(),
        "feeds": {},
        "corpus_profiles": 0,
        "model": None,
    }

    if not corpus_db_path().exists():
        return status

    try:
        conn = _get_conn()
        # Feed freshness — data is in feed_status table
        feed_rows = {
            row["feed"]: row
            for row in conn.execute("SELECT feed, status, last_updated, record_count FROM feed_status").fetchall()
        }
        for feed in ("nvd", "epss", "kev", "exploitdb", "cwe", "vulnrichment", "osv"):
            fr = feed_rows.get(feed)
            count_rows = _count_table(conn, feed)
            status["feeds"][feed] = {
                "last_run": fr["last_updated"] if fr else None,
                "rows": count_rows,
                "feed_status": fr["status"] if fr else "unknown",
            }

        # CWE profiles
        cur = conn.execute("SELECT COUNT(*) FROM cwe_profiles")
        status["corpus_profiles"] = (cur.fetchone() or (0,))[0]
    except Exception as e:
        status["db_error"] = str(e)

    if model_path().exists():
        try:
            import joblib
            m = joblib.load(model_path())
            status["model"] = {
                "trained_at": getattr(m, "_trained_at", None),
                "n_samples": getattr(m, "_n_samples", None),
                "accuracy": getattr(m, "_accuracy", None),
            }
        except Exception:
            pass

    return status


def _count_table(conn, table: str) -> int:
    _table_map = {
        "nvd": "nvd_cve", "epss": "epss", "kev": "kev",
        "exploitdb": "exploitdb", "cwe": "cwe_tree",
        "vulnrichment": "vulnrichment", "osv": "osv_cve",
    }
    real = _table_map.get(table, table)
    try:
        cur = conn.execute(f"SELECT COUNT(*) FROM {real}")
        return (cur.fetchone() or (0,))[0]
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# Refresh (download + build + train)
# ---------------------------------------------------------------------------

def refresh(
    sources: list[str] | None = None,
    force: bool = False,
    progress_cb: Callable[..., None] | None = None,
    page_cb: Callable[[str, int, int], None] | None = None,
) -> dict[str, Any]:
    """Download feeds, build corpus, train model.

    progress_cb(feed_name, status, rows_or_stats) is called at key transitions:
      - (feed, "start", 0)          — feed download beginning
      - (feed, "done", row_count)   — feed download complete
      - (feed, "error", 0)          — feed download failed
      - ("__corpus__", "start", 0)  — corpus build beginning
      - ("__corpus__", "done", n)   — corpus build complete (n = profile count)
      - ("__model__", "start", 0)   — model training beginning
      - ("__model__", "done", stats) — model training complete (stats = dict)

    page_cb(feed_name, fetched, total) is called after each NVD page for
    granular download progress.

    Returns dict with feed_results, profile_count, and model stats.
    """
    import os
    from trident.calibration.feeds import _get_fetchers, ALL_FEEDS

    _data_dir().mkdir(parents=True, exist_ok=True)
    old_env = os.environ.get("CALIBRATION_DATA_DIR")
    os.environ["CALIBRATION_DATA_DIR"] = str(_data_dir())

    feed_results: dict[str, dict] = {}
    targets = sources if sources else ALL_FEEDS
    fetchers = _get_fetchers()

    try:
        for feed in targets:
            cls = fetchers.get(feed)
            if cls is None:
                feed_results[feed] = {"status": "error", "count": 0, "error": f"Unknown: {feed}"}
                if progress_cb:
                    progress_cb(feed, "error", 0)
                continue
            if progress_cb:
                progress_cb(feed, "start", 0)
            try:
                fetcher = cls()
                if page_cb and hasattr(fetcher, "_page_cb"):
                    fetcher._page_cb = lambda f, t, _n=feed: page_cb(_n, f, t)
                count = fetcher.fetch(force=force)
                feed_results[feed] = {"status": "done", "count": count, "error": None}
                if progress_cb:
                    progress_cb(feed, "done", count)
            except Exception as e:
                feed_results[feed] = {"status": "error", "count": 0, "error": str(e)}
                if progress_cb:
                    progress_cb(feed, "error", 0)
    finally:
        if old_env is None:
            os.environ.pop("CALIBRATION_DATA_DIR", None)
        else:
            os.environ["CALIBRATION_DATA_DIR"] = old_env

    conn = _get_conn()

    if progress_cb:
        progress_cb("__corpus__", "start", 0)
    profile_count = build_corpus_only(conn)
    if progress_cb:
        progress_cb("__corpus__", "done", profile_count)

    if progress_cb:
        progress_cb("__model__", "start", 0)
    model_stats = train_only(conn)
    if progress_cb:
        progress_cb("__model__", "done", model_stats)

    return {
        "feed_results": feed_results,
        "profile_count": profile_count,
        "model": model_stats,
    }


def _with_data_dir(fn, *args, **kwargs):
    """Run fn with CALIBRATION_DATA_DIR set to our user data dir."""
    import os
    old = os.environ.get("CALIBRATION_DATA_DIR")
    os.environ["CALIBRATION_DATA_DIR"] = str(_data_dir())
    try:
        return fn(*args, **kwargs)
    finally:
        if old is None:
            os.environ.pop("CALIBRATION_DATA_DIR", None)
        else:
            os.environ["CALIBRATION_DATA_DIR"] = old


def build_corpus_only(conn=None) -> int:
    """Rebuild CWE profiles from existing raw data. Returns profile count."""
    from trident.calibration.corpus.build import build_corpus
    if conn is None:
        conn = _get_conn()
    return _with_data_dir(build_corpus, conn)


def train_only(conn=None) -> dict:
    """Retrain the sklearn model from existing CWE profiles. Returns model stats."""
    from trident.calibration.model import train
    if conn is None:
        conn = _get_conn()
    return _with_data_dir(train, conn)


def reset_all() -> None:
    """Delete the corpus DB and model file."""
    db = corpus_db_path()
    mp = model_path()
    if db.exists():
        db.unlink()
    if mp.exists():
        mp.unlink()


def get_model_info() -> dict[str, Any] | None:
    """Return model metadata (accuracy, n_samples, trained_at, top features)."""
    if not model_path().exists():
        return None
    try:
        import joblib
        m = joblib.load(model_path())
        info: dict[str, Any] = {
            "trained_at": getattr(m, "_trained_at", "unknown"),
            "n_samples": getattr(m, "_n_samples", "unknown"),
            "accuracy": getattr(m, "_accuracy", "unknown"),
            "model_type": type(m).__name__,
        }
        if hasattr(m, "feature_importances_") and hasattr(m, "_feature_names"):
            pairs = sorted(
                zip(m._feature_names, m.feature_importances_),
                key=lambda x: -x[1],
            )
            info["top_features"] = [{"name": n, "importance": round(v, 4)} for n, v in pairs[:10]]
        return info
    except Exception as e:
        return {"error": str(e)}
