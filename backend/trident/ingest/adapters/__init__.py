"""First-class deterministic external report adapters."""

from trident.ingest.adapters.cyclonedx import parse_cyclonedx
from trident.ingest.adapters.sarif import parse_sarif

__all__ = ["parse_cyclonedx", "parse_sarif"]
