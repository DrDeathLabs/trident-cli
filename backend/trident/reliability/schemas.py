"""Pydantic schemas for every structured LLM response in the council.

These are the contract between the LLM and the pipeline. A response that does
not validate is a *parse failure* — explicitly distinct from a genuine expert
disagreement — so malformed model output can never masquerade as a verdict.

Validators are deliberately lenient about *shape* (coerce "0.8" -> 0.8,
"HIGH" -> "high", strip a "CWE" prefix) but strict about *domain* (verdict and
severity must resolve to a known enum), so we accept sloppy-but-correct output
and reject nonsense.
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Verdict = Literal["confirmed", "refuted", "disputed"]
Severity = Literal["critical", "high", "medium", "low", "info"]

_SEVERITY_ALIASES = {
    "crit": "critical", "critical": "critical",
    "high": "high", "hi": "high",
    "medium": "medium", "med": "medium", "moderate": "medium",
    "low": "low",
    "info": "info", "informational": "info", "none": "info", "negligible": "info",
}
_VERDICT_ALIASES = {
    "confirmed": "confirmed", "confirm": "confirmed", "true_positive": "confirmed",
    "true positive": "confirmed", "tp": "confirmed", "valid": "confirmed",
    "refuted": "refuted", "refute": "refuted", "false_positive": "refuted",
    "false positive": "refuted", "fp": "refuted", "invalid": "refuted", "rejected": "refuted",
    "disputed": "disputed", "dispute": "disputed", "uncertain": "disputed",
    "needs_info": "disputed", "unclear": "disputed", "unknown": "disputed",
}


def _coerce_confidence(v) -> float:
    if v is None:
        return 0.5
    try:
        f = float(v)
    except (TypeError, ValueError):
        return 0.5
    if f > 1.0:  # tolerate 0-100 scale
        f = f / 100.0
    return max(0.0, min(1.0, f))


def _coerce_severity(v) -> str | None:
    if v is None:
        return None
    s = str(v).strip().lower()
    return _SEVERITY_ALIASES.get(s, s if s in _SEVERITY_ALIASES.values() else "medium")


def _coerce_verdict(v) -> str:
    s = str(v or "").strip().lower()
    return _VERDICT_ALIASES.get(s, "disputed")


def _coerce_cwe(v) -> str | None:
    if v is None:
        return None
    m = re.search(r"(\d+)", str(v))
    return f"CWE-{m.group(1)}" if m else None


def _coerce_owasp(v) -> str | None:
    """Keep a single OWASP category and fit the owasp column (String(64)).

    Agentic experts sometimes emit compound values ("A02:... / A07:..."); take the
    first and truncate so a verbose model can never overflow the column.
    """
    if v is None:
        return None
    s = str(v).strip()
    for sep in (" / ", ";", ",", " and "):
        if sep in s:
            s = s.split(sep)[0].strip()
            break
    return s[:64] or None


class ReviewVerdict(BaseModel):
    """An expert's review of a single finding."""
    model_config = ConfigDict(extra="ignore")

    thinking: str | None = None
    verdict: Verdict = "disputed"
    confidence: float = 0.5
    severity: Severity | None = None
    cwe: str | None = None
    owasp: str | None = None
    narrative: str | None = None
    remediation: str | None = None
    exploit_scenario: str | None = None

    @field_validator("verdict", mode="before")
    @classmethod
    def _v(cls, v):
        return _coerce_verdict(v)

    @field_validator("confidence", mode="before")
    @classmethod
    def _c(cls, v):
        return _coerce_confidence(v)

    @field_validator("severity", mode="before")
    @classmethod
    def _s(cls, v):
        return _coerce_severity(v)

    @field_validator("cwe", mode="before")
    @classmethod
    def _cwe(cls, v):
        return _coerce_cwe(v)

    @field_validator("owasp", mode="before")
    @classmethod
    def _owasp(cls, v):
        return _coerce_owasp(v)


class JudgeVerdict(BaseModel):
    """The judge's final ruling on a finding."""
    model_config = ConfigDict(extra="ignore")

    thinking: str | None = None
    final_verdict: Verdict = "disputed"
    final_confidence: float = 0.5
    final_severity: Severity | None = None
    reasoning: str | None = None
    false_positive_reason: str | None = None

    @field_validator("final_verdict", mode="before")
    @classmethod
    def _v(cls, v):
        return _coerce_verdict(v)

    @field_validator("final_confidence", mode="before")
    @classmethod
    def _c(cls, v):
        return _coerce_confidence(v)

    @field_validator("final_severity", mode="before")
    @classmethod
    def _s(cls, v):
        return _coerce_severity(v)


class NovelFinding(BaseModel):
    model_config = ConfigDict(extra="ignore")

    title: str = "Novel finding"
    file: str = ""
    line_start: int = 0
    line_end: int = 0
    cwe: str | None = None
    severity: Severity = "medium"
    confidence: float = 0.5
    description: str = ""
    recommendation: str = ""
    snippet: str = ""

    @field_validator("confidence", mode="before")
    @classmethod
    def _c(cls, v):
        return _coerce_confidence(v)

    @field_validator("severity", mode="before")
    @classmethod
    def _s(cls, v):
        return _coerce_severity(v) or "medium"

    @field_validator("cwe", mode="before")
    @classmethod
    def _cwe(cls, v):
        return _coerce_cwe(v)

    @field_validator("line_start", "line_end", mode="before")
    @classmethod
    def _int(cls, v):
        try:
            return int(v or 0)
        except (TypeError, ValueError):
            return 0

    @field_validator("title", mode="before")
    @classmethod
    def _title(cls, v):
        return (str(v)[:500] if v else "Novel finding")


class NovelFindingList(BaseModel):
    model_config = ConfigDict(extra="ignore")
    thinking: str | None = None
    novel_findings: list[NovelFinding] = Field(default_factory=list)


class AttackPath(BaseModel):
    model_config = ConfigDict(extra="ignore")
    goal: str = ""
    steps: list[str] = Field(default_factory=list)
    findings_used: list[str] = Field(default_factory=list)
    likelihood: Literal["high", "medium", "low"] = "medium"

    @field_validator("likelihood", mode="before")
    @classmethod
    def _l(cls, v):
        s = str(v or "medium").strip().lower()
        return s if s in ("high", "medium", "low") else "medium"


class AttackPathList(BaseModel):
    model_config = ConfigDict(extra="ignore")
    thinking: str | None = None
    attack_paths: list[AttackPath] = Field(default_factory=list)


class Citation(BaseModel):
    model_config = ConfigDict(extra="ignore")
    type: str = "finding"
    ref: str = ""
    label: str = ""


class ChatAnswer(BaseModel):
    model_config = ConfigDict(extra="ignore")
    thinking: str | None = None
    answer: str = ""
    citations: list[Citation] = Field(default_factory=list)


# ---- Triage: prioritize a confirmed finding from the code (no arch context) ----

ImpactType = Literal[
    "rce", "auth_bypass", "data_exposure", "data_tampering", "ssrf",
    "injection", "dos", "info_disclosure", "other",
]
AttackVector = Literal["remote_unauth", "remote_auth", "adjacent", "local", "physical"]
Exploitability = Literal["trivial", "moderate", "difficult"]
FixEffort = Literal["trivial", "moderate", "involved"]

_IMPACT_ALIASES = {
    "rce": "rce", "remote code execution": "rce", "code execution": "rce", "command execution": "rce",
    "auth_bypass": "auth_bypass", "authentication bypass": "auth_bypass",
    "authorization bypass": "auth_bypass", "privilege escalation": "auth_bypass", "idor": "auth_bypass",
    "data_exposure": "data_exposure", "data breach": "data_exposure", "data leak": "data_exposure",
    "information disclosure": "info_disclosure", "info_disclosure": "info_disclosure", "info leak": "info_disclosure",
    "data_tampering": "data_tampering", "tampering": "data_tampering", "data integrity": "data_tampering",
    "ssrf": "ssrf", "injection": "injection", "sqli": "injection", "xss": "injection",
    "dos": "dos", "denial of service": "dos", "other": "other",
}
_VECTOR_ALIASES = {
    "remote_unauth": "remote_unauth", "network": "remote_unauth", "remote": "remote_unauth",
    "unauthenticated": "remote_unauth", "internet": "remote_unauth",
    "remote_auth": "remote_auth", "authenticated": "remote_auth",
    "adjacent": "adjacent", "adjacent network": "adjacent",
    "local": "local", "cli": "local", "physical": "physical",
}
_EXPLOIT_ALIASES = {
    "trivial": "trivial", "easy": "trivial", "low": "trivial",
    "moderate": "moderate", "medium": "moderate",
    "difficult": "difficult", "hard": "difficult", "high": "difficult",
}
_EFFORT_ALIASES = {
    "trivial": "trivial", "low": "trivial", "quick": "trivial", "config": "trivial",
    "moderate": "moderate", "medium": "moderate",
    "involved": "involved", "high": "involved", "large": "involved", "refactor": "involved",
}


def _alias(v, table, default):
    return table.get(str(v or "").strip().lower(), default)


class TriageAssessment(BaseModel):
    """LLM's code-grounded triage factors for a confirmed finding. The priority
    tier is computed from these by a transparent rubric (trident/triage.py)."""
    model_config = ConfigDict(extra="ignore")

    thinking: str | None = None
    impact: ImpactType = "other"
    attack_vector: AttackVector = "local"       # conservative default when unclear
    exploitability: Exploitability = "moderate"
    fix_effort: FixEffort = "moderate"
    rationale: str = ""

    @field_validator("impact", mode="before")
    @classmethod
    def _i(cls, v):
        return _alias(v, _IMPACT_ALIASES, "other")

    @field_validator("attack_vector", mode="before")
    @classmethod
    def _v(cls, v):
        return _alias(v, _VECTOR_ALIASES, "local")

    @field_validator("exploitability", mode="before")
    @classmethod
    def _e(cls, v):
        return _alias(v, _EXPLOIT_ALIASES, "moderate")

    @field_validator("fix_effort", mode="before")
    @classmethod
    def _f(cls, v):
        return _alias(v, _EFFORT_ALIASES, "moderate")
