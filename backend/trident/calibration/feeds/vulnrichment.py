"""CISA Vulnrichment fetcher — SSVC exploitation/impact enrichment from GitHub repo."""

from __future__ import annotations

import io
import json
import zipfile

import httpx
from loguru import logger

from trident.calibration.corpus.db import get_db, init_schema, set_feed_status
from trident.calibration.feeds.base import BaseFetcher

_ZIP_URL = "https://github.com/cisagov/vulnrichment/archive/refs/heads/develop.zip"


def _parse_ssvc(adp_container: dict) -> dict:
    """Extract exploitation, automatable, technical_impact from ADP SSVC metrics."""
    result = {"exploitation": None, "automatable": None, "technical_impact": None}
    for metric in adp_container.get("metrics", []):
        other = metric.get("other", {})
        if (other.get("type") or "").lower() == "ssvc":
            for opt in other.get("content", {}).get("options", []):
                for key, val in opt.items():
                    kl = key.lower().replace(" ", "_")
                    if kl == "exploitation":
                        result["exploitation"] = val.lower()
                    elif kl == "automatable":
                        result["automatable"] = val.lower()
                    elif kl == "technical_impact":
                        result["technical_impact"] = val.lower()
    return result


def _extract_records(zip_bytes: bytes) -> list[tuple]:
    """Walk ZIP, parse every .json file that looks like a CVE record."""
    rows = []
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for name in zf.namelist():
            if not name.endswith(".json"):
                continue
            basename = name.rsplit("/", 1)[-1]
            if not basename.upper().startswith("CVE-"):
                continue
            try:
                data = json.loads(zf.read(name))
            except Exception:
                continue

            cve_id = (
                data.get("cveMetadata", {}).get("cveId")
                or basename.replace(".json", "")
            )
            if not cve_id.upper().startswith("CVE-"):
                continue

            adp_list = data.get("containers", {}).get("adp", [])
            for adp in adp_list:
                ssvc = _parse_ssvc(adp)
                if any(v is not None for v in ssvc.values()):
                    rows.append((
                        cve_id.upper(),
                        ssvc["exploitation"],
                        ssvc["automatable"],
                        ssvc["technical_impact"],
                    ))
                    break  # first ADP with SSVC data wins

    return rows


class VulnrichmentFetcher(BaseFetcher):
    name = "vulnrichment"

    def fetch(self, force: bool = False) -> int:
        conn = get_db()
        init_schema(conn)
        set_feed_status(conn, self.name, "running")
        count = 0

        try:
            logger.info("Downloading CISA Vulnrichment ZIP from GitHub…")
            resp = httpx.get(_ZIP_URL, timeout=300, follow_redirects=True)
            resp.raise_for_status()
            logger.info(f"Vulnrichment ZIP downloaded — {len(resp.content) / 1e6:.1f} MB")

            rows = _extract_records(resp.content)
            logger.info(f"Vulnrichment: {len(rows)} CVEs with SSVC data")

            conn.execute("DELETE FROM vulnrichment")
            conn.executemany(
                "INSERT OR REPLACE INTO vulnrichment(cve_id, exploitation, automatable, technical_impact) "
                "VALUES(?,?,?,?)",
                rows,
            )
            conn.commit()
            count = len(rows)
            set_feed_status(conn, self.name, "done", record_count=count)

        except Exception as e:
            logger.exception("Vulnrichment fetch failed")
            set_feed_status(conn, self.name, "error", error_msg=str(e))
        finally:
            conn.close()

        return count
