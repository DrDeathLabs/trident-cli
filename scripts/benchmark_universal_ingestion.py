"""Measure bounded generic JSON ingestion on a large synthetic report."""

from __future__ import annotations

import argparse
import json
import tempfile
import time
import tracemalloc
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--records", type=int, default=10_000)
    args = parser.parse_args()
    from trident.ingest.importers import parse_report

    payload = {
        "results": [
            {
                "id": f"V-{index}", "title": "Synthetic vulnerability",
                "description": "bounded performance fixture", "severity": "medium",
                "file": f"src/file_{index % 40}.py", "line": (index % 100) + 1,
            }
            for index in range(args.records)
        ]
    }
    with tempfile.TemporaryDirectory(prefix="trident-ingestion-benchmark-") as directory:
        path = Path(directory) / "large.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        file_bytes = path.stat().st_size
        tracemalloc.start()
        started = time.perf_counter()
        report = parse_report(path)
        elapsed = time.perf_counter() - started
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
    print(json.dumps({
        "file_bytes": file_bytes,
        "records": report.records,
        "findings": len(report.findings),
        "accounting": {key: value for key, value in report.accounting.items() if key != "records"},
        "parse_normalize_seconds": round(elapsed, 4),
        "peak_tracemalloc_bytes": peak,
    }, indent=2))


if __name__ == "__main__":
    main()
