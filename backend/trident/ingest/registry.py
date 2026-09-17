"""Deterministic input-format adapter registry."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class AdapterMatch:
    name: str
    confidence: float
    reason: str


@dataclass(frozen=True)
class Adapter:
    name: str
    detector: Callable[[Any], AdapterMatch | None]


def _sonarqube(payload: Any) -> AdapterMatch | None:
    if isinstance(payload, dict) and isinstance(payload.get("issues"), list) and (
        "paging" in payload or "total" in payload or "components" in payload
    ):
        return AdapterMatch("sonarqube", 1.0, "issues array with SonarQube envelope")
    return None


def _dependency_check(payload: Any) -> AdapterMatch | None:
    if isinstance(payload, dict) and str(payload.get("reportSchema", "")) == "1.1" and isinstance(
        payload.get("dependencies"), list
    ):
        return AdapterMatch("dependency-check", 1.0, "reportSchema 1.1 dependencies array")
    return None


def _sarif(payload: Any) -> AdapterMatch | None:
    if isinstance(payload, dict) and payload.get("version") == "2.1.0" and isinstance(
        payload.get("runs"), list
    ):
        return AdapterMatch("sarif", 1.0, "SARIF 2.1.0 runs array")
    return None


def _cyclonedx(payload: Any) -> AdapterMatch | None:
    if isinstance(payload, dict) and str(payload.get("bomFormat", "")).lower() == "cyclonedx":
        if isinstance(payload.get("vulnerabilities"), list):
            return AdapterMatch("cyclonedx", 1.0, "CycloneDX vulnerability collection")
        return AdapterMatch("cyclonedx", 0.95, "CycloneDX BOM envelope")
    return None


ADAPTERS: tuple[Adapter, ...] = (
    Adapter("sonarqube", _sonarqube),
    Adapter("dependency-check", _dependency_check),
    Adapter("sarif", _sarif),
    Adapter("cyclonedx", _cyclonedx),
)


def detect_adapters(payload: Any) -> list[AdapterMatch]:
    return sorted(
        (match for adapter in ADAPTERS if (match := adapter.detector(payload))),
        key=lambda item: item.confidence,
        reverse=True,
    )


def detect_format(payload: Any) -> str | None:
    matches = detect_adapters(payload)
    if not matches:
        return None
    if len(matches) > 1 and matches[0].confidence == matches[1].confidence:
        raise ValueError(
            "ambiguous input format: " + ", ".join(item.name for item in matches[:2])
        )
    return matches[0].name
