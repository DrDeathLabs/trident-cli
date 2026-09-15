"""JSON pointer and immutable import provenance helpers."""

from __future__ import annotations

from typing import Any


def pointer_escape(value: str | int) -> str:
    return str(value).replace("~", "~0").replace("/", "~1")


def join_pointer(base: str, token: str | int) -> str:
    return f"{base}/{pointer_escape(token)}" if base else f"/{pointer_escape(token)}"


def pointer_get(payload: Any, pointer: str) -> Any:
    """Resolve an RFC 6901 JSON pointer without evaluating expressions."""
    if pointer in {"", "/"}:
        return payload if pointer == "" else None
    if not pointer.startswith("/"):
        raise ValueError(f"invalid JSON pointer: {pointer!r}")
    value = payload
    for raw_token in pointer[1:].split("/"):
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(value, list):
            value = value[int(token)]
        elif isinstance(value, dict):
            value = value[token]
        else:
            raise KeyError(pointer)
    return value


def field_provenance(pointer: str, original: Any) -> dict[str, Any]:
    return {"pointer": pointer, "original": original}


def provenance_envelope(
    *, report_sha256: str, record_pointer: str, mapping_identity: str,
    fields: dict[str, dict[str, Any]], evidence_basis: str = "report_only",
    source_context_available: bool = False,
) -> dict[str, Any]:
    return {
        "report_sha256": report_sha256,
        "record_pointer": record_pointer,
        "mapping_identity": mapping_identity,
        "fields": fields,
        "evidence_basis": evidence_basis,
        "source_context_available": source_context_available,
    }
