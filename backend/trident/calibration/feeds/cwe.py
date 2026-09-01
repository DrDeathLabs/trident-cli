"""CWE taxonomy XML fetcher."""

from __future__ import annotations

import io
import xml.etree.ElementTree as ET
import zipfile

import httpx
from loguru import logger

from trident.calibration.corpus.db import get_db, init_schema, set_feed_status
from trident.calibration.feeds.base import BaseFetcher

_CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
_NS = "{http://cwe.mitre.org/cwe-7}"


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

            root = ET.fromstring(xml_bytes)
            weaknesses = root.findall(f".//{_NS}Weakness")

            rows = []
            for w in weaknesses:
                cwe_id = f"CWE-{w.get('ID')}"
                name = w.get("Name", "")
                parent = None
                related = w.find(f"{_NS}Related_Weaknesses")
                if related is not None:
                    for rel in related.findall(f"{_NS}Related_Weakness"):
                        if rel.get("Nature") == "ChildOf":
                            parent = f"CWE-{rel.get('CWE_ID')}"
                            break
                rows.append((cwe_id, name, parent))

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
