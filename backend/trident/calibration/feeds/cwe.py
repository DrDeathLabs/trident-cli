"""CWE taxonomy XML fetcher."""

from __future__ import annotations

import io
import zipfile

from defusedxml import ElementTree as ET
import httpx
from loguru import logger

from trident.calibration.corpus.db import get_db, init_schema, set_feed_status
from trident.calibration.feeds.base import BaseFetcher

_CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
_NS = "{http://cwe.mitre.org/cwe-7}"


def _parse_cwe_xml(xml_bytes: bytes) -> list[tuple[str, str, str | None]]:
    """Parse CWE taxonomy XML while rejecting DTD and entity declarations."""
    root = ET.fromstring(xml_bytes)
    rows = []
    for weakness in root.findall(f".//{_NS}Weakness"):
        cwe_id = f"CWE-{weakness.get('ID')}"
        name = weakness.get("Name", "")
        parent = None
        related = weakness.find(f"{_NS}Related_Weaknesses")
        if related is not None:
            for relation in related.findall(f"{_NS}Related_Weakness"):
                if relation.get("Nature") == "ChildOf":
                    parent = f"CWE-{relation.get('CWE_ID')}"
                    break
        rows.append((cwe_id, name, parent))
    return rows


class CWEFetcher(BaseFetcher):
    name = "cwe"

    def fetch(self, force: bool = False) -> int:
        conn = get_db()
        init_schema(conn)
        set_feed_status(conn, self.name, "running")
        count = 0

        try:
            resp = httpx.get(_CWE_URL, timeout=120, follow_redirects=True)
            resp.raise_for_status()

            with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
                xml_name = next(n for n in zf.namelist() if n.endswith(".xml"))
                xml_bytes = zf.read(xml_name)

            rows = _parse_cwe_xml(xml_bytes)

            conn.execute("DELETE FROM cwe_tree")
            conn.executemany(
                "INSERT INTO cwe_tree(cwe_id, name, parent_cwe) VALUES(?,?,?)",
                rows,
            )
            conn.commit()
            count = len(rows)
            set_feed_status(conn, self.name, "done", record_count=count)
        except Exception as e:
            logger.exception("CWE fetch failed")
            set_feed_status(conn, self.name, "error", error_msg=str(e))
        finally:
            conn.close()

        return count
