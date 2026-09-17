"""Contracts shared by external evidence adapters and the import pipeline.

The ingestion boundary is deliberately data-only.  These small contracts keep
adapter output, mapping provenance, and record accounting independent from the
database and from the downstream review pipeline.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

MAPPING_VERSION = "trident-json-mapping-v1"
TERMINAL_RECORD_STATES = (
    "mapped",
    "partially_mapped",
    "out_of_scope",
    "skipped",
    "malformed",
    "unsupported",
)


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def mapping_sha256(mapping: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(mapping).encode("utf-8")).hexdigest()


@dataclass
class RecordAccounting:
    """One terminal disposition for every record in a selected collection."""

    total_records: int = 0
    counts: dict[str, int] = field(
        default_factory=lambda: {state: 0 for state in TERMINAL_RECORD_STATES}
    )
    records: list[dict[str, Any]] = field(default_factory=list)

    def add(self, state: str, pointer: str, *, reason: str | None = None) -> None:
        if state not in TERMINAL_RECORD_STATES:
            raise ValueError(f"invalid terminal record state: {state}")
        self.total_records += 1
        self.counts[state] += 1
        detail: dict[str, Any] = {"pointer": pointer, "state": state}
        if reason:
            detail["reason"] = reason
        self.records.append(detail)

    def validate(self) -> None:
        accounted = sum(self.counts.values())
        if self.total_records != accounted:
            raise ValueError(
                "import record accounting invariant failed: "
                f"total_records={self.total_records}, accounted={accounted}"
            )
        if len(self.records) != self.total_records:
            raise ValueError(
                "import record detail count does not match total_records: "
                f"{len(self.records)} != {self.total_records}"
            )

    def as_dict(self, *, include_records: bool = False) -> dict[str, Any]:
        self.validate()
        payload: dict[str, Any] = {
            "total_records": self.total_records,
            **self.counts,
            "unexplained": self.total_records - sum(self.counts.values()),
        }
        if include_records:
            payload["records"] = list(self.records)
        return payload


@dataclass(frozen=True)
class MappingValidation:
    """Deterministic validation statistics for a mapping over a report."""

    records_inspected: int
    coverage: dict[str, float]
    required_field_coverage: float
    type_consistency: float
    identifier_rate: float
    confidence: float
    errors: tuple[str, ...] = ()
    semantic_validity: float = 1.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "records_inspected": self.records_inspected,
            "coverage": self.coverage,
            "required_field_coverage": self.required_field_coverage,
            "type_consistency": self.type_consistency,
            "identifier_rate": self.identifier_rate,
            "confidence": self.confidence,
            "semantic_validity": self.semantic_validity,
            "errors": list(self.errors),
        }


@dataclass(frozen=True)
class MappingProposal:
    mapping: dict[str, Any]
    source: str
    validation: MappingValidation
    provider: str | None = None
    model_requested: str | None = None
    model_actual: str | None = None
    response: dict[str, Any] | None = None
