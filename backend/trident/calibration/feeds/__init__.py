"""Feed management — refresh all data sources and report status."""

from __future__ import annotations

from loguru import logger

from trident.calibration.corpus.db import get_db, init_schema

ALL_FEEDS = ["nvd", "epss", "kev", "exploitdb", "cwe", "vulnrichment", "osv"]

_FETCHER_CLASSES = None


def _get_fetchers() -> dict:
    global _FETCHER_CLASSES
    if _FETCHER_CLASSES is None:
        from trident.calibration.feeds.nvd import NVDFetcher
        from trident.calibration.feeds.epss import EPSSFetcher
        from trident.calibration.feeds.kev import KEVFetcher
        from trident.calibration.feeds.exploitdb import ExploitDBFetcher
        from trident.calibration.feeds.cwe import CWEFetcher
        from trident.calibration.feeds.vulnrichment import VulnrichmentFetcher
        from trident.calibration.feeds.osv import OSVFetcher
        _FETCHER_CLASSES = {
            "nvd": NVDFetcher,
            "epss": EPSSFetcher,
            "kev": KEVFetcher,
            "exploitdb": ExploitDBFetcher,
            "cwe": CWEFetcher,
            "vulnrichment": VulnrichmentFetcher,
            "osv": OSVFetcher,
        }
    return _FETCHER_CLASSES


def refresh_all(sources: list[str] | None = None, force: bool = False) -> dict:
    """Run each fetcher in sequence. Returns {feed: {status, count, error}}."""
    targets = sources if sources else ALL_FEEDS
    fetchers = _get_fetchers()
    results: dict[str, dict] = {}

    for feed in targets:
        cls = fetchers.get(feed)
        if cls is None:
            results[feed] = {"status": "error", "count": 0, "error": f"Unknown feed: {feed}"}
            continue
        try:
            count = cls().fetch(force=force)
            results[feed] = {"status": "done", "count": count, "error": None}
        except Exception as e:
            logger.exception(f"Feed {feed} failed")
            results[feed] = {"status": "error", "count": 0, "error": str(e)}

    return results


_STALE_RUNNING_MINUTES = 5


def get_status() -> dict:
    """Return current feed_status rows + corpus_meta as a status dict."""
    from datetime import datetime, timezone, timedelta
    conn = get_db()
    init_schema(conn)
    try:
        stale_cutoff = (datetime.now(timezone.utc) - timedelta(minutes=_STALE_RUNNING_MINUTES)).isoformat()
        feeds = {}
        for row in conn.execute("SELECT * FROM feed_status").fetchall():
            status = row["status"]
            last_updated = row["last_updated"] or ""
            # A "running" feed with no heartbeat for >5 min means the worker died
            if status == "running" and last_updated < stale_cutoff:
                status = "error"
                conn.execute(
                    "UPDATE feed_status SET status='error', error_msg='Worker stopped — click Refresh to restart' "
                    "WHERE feed=?", (row["feed"],)
                )
                conn.commit()
            feeds[row["feed"]] = {
                "status": status,
                "last_updated": last_updated,
                "record_count": row["record_count"],
                "error_msg": row["error_msg"] if status == "error" else None,
            }
        meta = {
            row["key"]: row["value"]
            for row in conn.execute("SELECT key, value FROM corpus_meta").fetchall()
        }
        return {"feeds": feeds, "meta": meta}
    finally:
        conn.close()
