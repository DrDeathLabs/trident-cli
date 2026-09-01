"""NVD 2.0 REST API fetcher — resumable full pull with per-page checkpointing."""

from __future__ import annotations

import os
import time
from datetime import datetime, timedelta, timezone

import httpx
from loguru import logger

from trident.calibration.corpus.db import get_db, init_schema, set_feed_status, set_meta, get_meta
from trident.calibration.feeds.base import BaseFetcher

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_PAGE_SIZE = 2000
_CHECKPOINT_KEY = "nvd_full_checkpoint"   # stores next startIndex to fetch
_PROGRESS_KEY = "nvd_fetch_progress"      # "fetched/total" string for UI


def _rate_delay() -> float:
    # NVD: 50 req/30s with key (0.6s gap), 5 req/30s without (6s gap)
    return 0.6 if os.environ.get("NVD_API_KEY") else 6.0


def _headers() -> dict:
    key = os.environ.get("NVD_API_KEY")
    return {"apiKey": key} if key else {}


def _extract_cvss(metrics: dict) -> dict | None:
    for version_key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(version_key)
        if entries:
            data = entries[0].get("cvssData", {})
            return {
                "attack_vector": data.get("attackVector"),
                "privileges_required": data.get("privilegesRequired"),
                "user_interaction": data.get("userInteraction"),
                "scope": data.get("scope"),
                "confidentiality": data.get("confidentialityImpact"),
                "integrity": data.get("integrityImpact"),
                "availability": data.get("availabilityImpact"),
                "base_score": data.get("baseScore"),
                "base_severity": data.get("baseSeverity"),
            }
    return None


def _extract_cwe(weaknesses: list) -> str | None:
    for w in weaknesses:
        for desc in w.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-"):
                return val
    return None


def _upsert_cves(conn, rows: list[dict]) -> None:
    conn.executemany(
        "INSERT INTO nvd_cve(cve_id, cwe, attack_vector, privileges_required, "
        "user_interaction, scope, confidentiality, integrity, availability, "
        "base_score, base_severity, published, last_modified) "
        "VALUES(:cve_id,:cwe,:attack_vector,:privileges_required,:user_interaction,"
        ":scope,:confidentiality,:integrity,:availability,:base_score,:base_severity,"
        ":published,:last_modified) "
        "ON CONFLICT(cve_id) DO UPDATE SET "
        "cwe=excluded.cwe, attack_vector=excluded.attack_vector, "
        "privileges_required=excluded.privileges_required, "
        "user_interaction=excluded.user_interaction, scope=excluded.scope, "
        "confidentiality=excluded.confidentiality, integrity=excluded.integrity, "
        "availability=excluded.availability, base_score=excluded.base_score, "
        "base_severity=excluded.base_severity, published=excluded.published, "
        "last_modified=excluded.last_modified",
        rows,
    )
    conn.commit()


def _fetch_page(client: httpx.Client, params: dict) -> dict:
    for attempt in range(6):
        resp = client.get(_NVD_URL, params=params, headers=_headers(), timeout=60)
        if resp.status_code == 429:
            wait = max(int(resp.headers.get("Retry-After", 30)), 30) * (attempt + 1)
            logger.warning(f"NVD 429 — backing off {wait}s (attempt {attempt + 1}/6)")
            time.sleep(wait)
            continue
        resp.raise_for_status()
        return resp.json()
    raise RuntimeError("NVD API returned 429 after 6 retries")


def _parse_page(data: dict) -> list[dict]:
    rows = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        cvss = _extract_cvss(cve.get("metrics", {}))
        if cvss is None:
            continue
        rows.append({
            "cve_id": cve_id,
            "cwe": _extract_cwe(cve.get("weaknesses", [])),
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            **cvss,
        })
    return rows


class NVDFetcher(BaseFetcher):
    name = "nvd"
    _page_cb = None  # injected by model_manager for live progress: (fetched, total) → None

    def fetch(self, force: bool = False) -> int:
        conn = get_db()
        init_schema(conn)
        delay = _rate_delay()
        total = 0

        try:
            if force:
                # Wipe checkpoint so we start clean
                conn.execute(f"DELETE FROM corpus_meta WHERE key='{_CHECKPOINT_KEY}'")
                conn.execute(f"DELETE FROM corpus_meta WHERE key='{_PROGRESS_KEY}'")
                conn.commit()
                last_modified = None
            else:
                last_modified = get_meta(conn, "nvd_last_modified")

            set_feed_status(conn, self.name, "running")

            with httpx.Client() as client:
                if last_modified:
                    total = self._incremental(client, conn, last_modified, delay)
                else:
                    total = self._full(client, conn, delay)

            now = datetime.now(timezone.utc).isoformat()
            set_meta(conn, "nvd_last_modified", now)
            # Clean up working keys on success
            conn.execute(f"DELETE FROM corpus_meta WHERE key='{_CHECKPOINT_KEY}'")
            conn.execute(f"DELETE FROM corpus_meta WHERE key='{_PROGRESS_KEY}'")
            conn.commit()
            set_feed_status(conn, self.name, "done", record_count=total)
            logger.info(f"NVD fetch complete — {total:,} CVEs with CVSS scores")

        except Exception as e:
            logger.exception("NVD fetch failed")
            set_feed_status(conn, self.name, "error", error_msg=str(e))
        finally:
            conn.close()

        return total

    def _full(self, client: httpx.Client, conn, delay: float) -> int:
        """Resumable full pull — checkpoints startIndex after every page."""
        checkpoint = get_meta(conn, _CHECKPOINT_KEY)
        start = int(checkpoint) if checkpoint else 0

        # Seed fetched count from what's already in the DB when resuming
        fetched = conn.execute("SELECT COUNT(*) FROM nvd_cve").fetchone()[0] if start > 0 else 0
        total_results = 0

        logger.info(f"NVD full pull — {'resuming from' if start else 'starting at'} startIndex={start}")

        while True:
            data = _fetch_page(client, {"startIndex": start, "resultsPerPage": _PAGE_SIZE})
            rows = _parse_page(data)
            total_results = data.get("totalResults", 0)

            if rows:
                _upsert_cves(conn, rows)
                fetched += len(rows)

            next_start = start + _PAGE_SIZE

            # Checkpoint every page — if the worker dies we resume here, not at 0
            set_meta(conn, _CHECKPOINT_KEY, str(next_start))
            set_meta(conn, _PROGRESS_KEY, f"{fetched}/{total_results}")
            set_feed_status(conn, self.name, "running", record_count=fetched)

            if self._page_cb:
                self._page_cb(fetched, total_results)

            logger.debug(f"NVD page startIndex={start} — {fetched:,}/{total_results:,}")

            if next_start >= total_results:
                break

            start = next_start
            time.sleep(delay)

        return fetched

    def _incremental(self, client: httpx.Client, conn, last_modified: str, delay: float) -> int:
        """Fetch only CVEs modified since last run, in ≤90-day chunks (NVD 120-day limit)."""
        try:
            start_dt = datetime.fromisoformat(last_modified.replace("Z", "+00:00"))
            if start_dt.tzinfo is None:
                start_dt = start_dt.replace(tzinfo=timezone.utc)
        except Exception:
            start_dt = datetime(2015, 1, 1, tzinfo=timezone.utc)

        end_dt = datetime.now(timezone.utc)
        chunk = timedelta(days=90)
        total = 0
        cursor = start_dt

        while cursor < end_dt:
            window_end = min(cursor + chunk, end_dt)
            params = {
                "lastModStartDate": cursor.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "lastModEndDate": window_end.strftime("%Y-%m-%dT%H:%M:%S.999"),
            }
            total += self._fetch_window_simple(client, conn, params, delay)
            cursor = window_end
            time.sleep(delay)

        return total

    def _fetch_window_simple(self, client, conn, params, delay) -> int:
        """Non-resumable paginated fetch for incremental windows (short windows, fast)."""
        count = 0
        start = 0
        while True:
            data = _fetch_page(client, {**params, "startIndex": start, "resultsPerPage": _PAGE_SIZE})
            rows = _parse_page(data)
            if rows:
                _upsert_cves(conn, rows)
                count += len(rows)
            total_results = data.get("totalResults", 0)
            next_start = start + _PAGE_SIZE
            if next_start >= total_results:
                break
            start = next_start
            time.sleep(delay)
        return count
