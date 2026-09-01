"""OSV fetcher — ecosystem breadth per CVE via GCS per-ecosystem bulk ZIPs."""

from __future__ import annotations

import io
import json
import re
import zipfile
from collections import defaultdict

import httpx
from loguru import logger

from trident.calibration.corpus.db import get_db, init_schema, set_feed_status, set_meta
from trident.calibration.feeds.base import BaseFetcher

# Major ecosystems available at osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip
_ECOSYSTEMS = ["PyPI", "npm", "Maven", "Go", "crates.io", "NuGet", "RubyGems", "Packagist"]
_GCS_BASE = "https://osv-vulnerabilities.storage.googleapis.com"
_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


def _download_ecosystem(client: httpx.Client, ecosystem: str) -> dict[str, set[str]]:
    """Download and parse one ecosystem ZIP. Returns {cve_id: {package_names}}."""
    url = f"{_GCS_BASE}/{ecosystem}/all.zip"
    resp = client.get(url, timeout=120, follow_redirects=True)
    if resp.status_code == 404:
        logger.warning(f"OSV: no zip for ecosystem {ecosystem} — skipping")
        return {}
    resp.raise_for_status()

    cve_to_packages: dict[str, set[str]] = defaultdict(set)
    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        for name in zf.namelist():
            if not name.endswith(".json"):
                continue
            try:
                data = json.loads(zf.read(name))
            except Exception:
                continue

            # Extract CVE aliases
            cves = [
                a for a in data.get("aliases", [])
                if _CVE_RE.match(a)
            ]
            if not cves:
                continue

            # Extract affected package names
            packages = set()
            for aff in data.get("affected", []):
                pkg = aff.get("package", {}).get("name", "")
                if pkg:
                    packages.add(pkg)

            for cve in cves:
                cve_to_packages[cve.upper()].update(packages)

    logger.info(f"OSV {ecosystem}: {len(resp.content) / 1e6:.1f} MB → {len(cve_to_packages)} CVEs")
    return dict(cve_to_packages)


class OSVFetcher(BaseFetcher):
    name = "osv"

    def fetch(self, force: bool = False) -> int:
        conn = get_db()
        init_schema(conn)
        set_feed_status(conn, self.name, "running")
        count = 0

        try:
            # Aggregate ecosystem coverage per CVE across all ecosystems
            cve_ecosystems: dict[str, set[str]] = defaultdict(set)
            cve_packages: dict[str, set[str]] = defaultdict(set)

            with httpx.Client() as client:
                for i, eco in enumerate(_ECOSYSTEMS):
                    try:
                        set_meta(conn, "osv_fetch_progress",
                                 f"{i + 1}/{len(_ECOSYSTEMS)} ecosystems")
                        set_feed_status(conn, self.name, "running", record_count=len(cve_ecosystems))
                        eco_data = _download_ecosystem(client, eco)
                        for cve_id, pkgs in eco_data.items():
                            cve_ecosystems[cve_id].add(eco)
                            cve_packages[cve_id].update(pkgs)
                    except Exception as e:
                        logger.warning(f"OSV {eco} failed: {e}")

            rows = [
                (cve_id, len(ecos), len(cve_packages[cve_id]))
                for cve_id, ecos in cve_ecosystems.items()
            ]

            conn.execute("DELETE FROM osv_cve")
            conn.executemany(
                "INSERT OR REPLACE INTO osv_cve(cve_id, ecosystem_count, package_count) VALUES(?,?,?)",
                rows,
            )
            conn.commit()
            count = len(rows)
            set_feed_status(conn, self.name, "done", record_count=count)
            logger.info(f"OSV complete — {count:,} CVEs with ecosystem coverage")

        except Exception as e:
            logger.exception("OSV fetch failed")
            set_feed_status(conn, self.name, "error", error_msg=str(e))
        finally:
            conn.close()

        return count
