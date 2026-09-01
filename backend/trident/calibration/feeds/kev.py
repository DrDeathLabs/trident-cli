"""CISA KEV JSON fetcher."""

from __future__ import annotations

import httpx
from loguru import logger

from trident.calibration.corpus.db import get_db, init_schema, set_feed_status
from trident.calibration.feeds.base import BaseFetcher

_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class KEVFetcher(BaseFetcher):
    name = "kev"

    def fetch(self, force: bool = False) -> int:
        conn = get_db()
        init_schema(conn)
        set_feed_status(conn, self.name, "running")
        count = 0

        try:
            resp = httpx.get(_KEV_URL, timeout=60, follow_redirects=True)
            resp.raise_for_status()
            data = resp.json()

            rows = [
                (v["cveID"], v.get("vulnerabilityName"), v.get("dateAdded"))
                for v in data.get("vulnerabilities", [])
            ]

            conn.execute("DELETE FROM kev")
            conn.executemany(
                "INSERT INTO kev(cve_id, vuln_name, date_added) VALUES(?,?,?)",
                rows,
            )
            conn.commit()
            count = len(rows)
            set_feed_status(conn, self.name, "done", record_count=count)
        except Exception as e:
            logger.exception("KEV fetch failed")
            set_feed_status(conn, self.name, "error", error_msg=str(e))
        finally:
            conn.close()

        return count
