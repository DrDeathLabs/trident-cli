"""EPSS daily CSV fetcher."""

from __future__ import annotations

import csv
import gzip
from datetime import date

import httpx
from loguru import logger

from trident.calibration.corpus.db import get_db, init_schema, set_feed_status
from trident.calibration.feeds.base import BaseFetcher

_EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"


class EPSSFetcher(BaseFetcher):
    name = "epss"

    def fetch(self, force: bool = False) -> int:
        conn = get_db()
        init_schema(conn)
        set_feed_status(conn, self.name, "running")
        count = 0

        try:
            resp = httpx.get(_EPSS_URL, timeout=120, follow_redirects=True)
            resp.raise_for_status()

            raw = gzip.decompress(resp.content)
            text = raw.decode("utf-8")

            lines = text.splitlines()
            # First line: #model_version:... (metadata comment)
            # Second line: header
            data_lines = [l for l in lines if not l.startswith("#")]
            reader = csv.DictReader(data_lines)

            score_date = date.today().isoformat()
            rows = []
            for row in reader:
                rows.append((row["cve"], float(row["epss"]), float(row["percentile"]), score_date))

            conn.execute("DELETE FROM epss")
            conn.executemany(
                "INSERT INTO epss(cve_id, epss_score, percentile, score_date) VALUES(?,?,?,?)",
                rows,
            )
            conn.commit()
            count = len(rows)
            set_feed_status(conn, self.name, "done", record_count=count)
        except Exception as e:
            logger.exception("EPSS fetch failed")
            set_feed_status(conn, self.name, "error", error_msg=str(e))
        finally:
            conn.close()

        return count
