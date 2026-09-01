"""Trident core data models (SQLAlchemy ORM + Pydantic schemas)."""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime
from enum import Enum as PyEnum

from sqlalchemy import (
    JSON, BigInteger, Boolean, Column, DateTime, Float, ForeignKey, Integer,
    Sequence, String, Table, Text, Index,
)
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from trident.clock import utcnow


class Base(DeclarativeBase):
    pass


def _new_id() -> str:
    return uuid.uuid4().hex


def stable_finding_hash(file: str, line_start: int, rule_id: str, snippet: str) -> str:
    """Per-tool identity hash — stable across iterations of the same finding.

    Includes rule_id, so it is tool-specific. For cross-tool dedupe use
    `correlation_key`, which deliberately omits rule_id.
    """
    # Coerce defensively: some tools pass line_start as snippet or vice-versa.
    file = str(file) if file is not None else ""
    line_start = str(line_start) if line_start is not None else ""
    rule_id = str(rule_id) if rule_id is not None else ""
    snippet = str(snippet) if snippet is not None else ""
    raw = f"{file}|{line_start}|{rule_id}|{snippet.strip()[:200]}"
    return hashlib.sha256(raw.encode()).hexdigest()[:24]


def _norm_cwe(cwe: str | None) -> str:
    if not cwe:
        return ""
    import re
    m = re.search(r"(\d+)", str(cwe))
    return f"CWE-{m.group(1)}" if m else str(cwe).strip().upper()


def _norm_path(path: str) -> str:
    """Normalize a file path for correlation: forward slashes, basename-tail agnostic."""
    return (path or "").replace("\\", "/").strip().lstrip("./")


def correlation_key(file: str, line_start: int, cwe: str | None, title: str = "") -> str:
    """Cross-tool identity for a finding — deliberately excludes rule_id.

    Two tools flagging the same file+line+CWE collapse to one canonical finding.
    When CWE is absent, falls back to a coarse title token so tool findings
    without a CWE still cluster sensibly.
    """
    f = _norm_path(file)
    c = _norm_cwe(cwe) or (title or "").strip().lower()[:40]
    raw = f"{f}|{line_start}|{c}"
    return hashlib.sha256(raw.encode()).hexdigest()[:24]


class JobStatus(str, PyEnum):
    queued = "queued"
    ingesting = "ingesting"
    scanning = "scanning"
    complete = "complete"
    failed = "failed"
    cancelled = "cancelled"


class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_new_id)
    target_name: Mapped[str] = mapped_column(String(256))
    source_type: Mapped[str] = mapped_column(String(32))  # git|upload|mount|demo
    source_ref: Mapped[str] = mapped_column(Text)         # url / path / filename
    workspace_path: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), default=JobStatus.queued.value, index=True)
    profile: Mapped[dict] = mapped_column(JSON, default=dict)
    languages: Mapped[list] = mapped_column(JSON, default=list)
    commit_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    is_scored: Mapped[bool] = mapped_column(Boolean, default=False)
    target_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    current_iteration: Mapped[int] = mapped_column(Integer, default=0)
    max_iterations: Mapped[int] = mapped_column(Integer, default=3)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    findings: Mapped[list["Finding"]] = relationship(
        back_populates="job", cascade="all, delete-orphan"
    )
    events: Mapped[list["JobEvent"]] = relationship(
        back_populates="job", cascade="all, delete-orphan"
    )
    chat_messages: Mapped[list["ChatMessage"]] = relationship(
        back_populates="job", cascade="all, delete-orphan"
    )

    __table_args__ = (Index("ix_jobs_status_created", "status", "created_at"),)


class Severity(str, PyEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


SEVERITY_RANK = {s.value: i for i, s in enumerate(Severity)}


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_new_id)
    job_id: Mapped[str] = mapped_column(String(32), ForeignKey("jobs.id"), index=True)
    hash: Mapped[str] = mapped_column(String(24), index=True)
    # Cross-tool identity (excludes rule_id): duplicates share this key.
    correlation_key: Mapped[str | None] = mapped_column(String(24), nullable=True, index=True)
    # For a duplicate, points at the canonical finding that represents the cluster.
    canonical_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True
    )
    # Tools that independently reported this cluster (corroboration raises confidence).
    corroborating_tools: Mapped[list] = mapped_column(JSON, default=list)
    # Set when an expert's LLM output could not be validated (a parse failure,
    # explicitly NOT a verdict — see council/structured.py).
    review_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    tool: Mapped[str] = mapped_column(String(64))   # semgrep|bandit|expert:injection|...
    rule_id: Mapped[str] = mapped_column(String(128))
    severity: Mapped[str] = mapped_column(String(16), default=Severity.medium.value, index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str] = mapped_column(Text, default="")
    file: Mapped[str] = mapped_column(Text, default="")
    line_start: Mapped[int] = mapped_column(Integer, default=0)
    line_end: Mapped[int] = mapped_column(Integer, default=0)
    snippet: Mapped[str] = mapped_column(Text, default="")
    cwe: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    owasp: Mapped[str | None] = mapped_column(String(64), nullable=True)
    recommendation: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    narrative: Mapped[str | None] = mapped_column(Text, nullable=True)
    exploit_scenario: Mapped[str | None] = mapped_column(Text, nullable=True)
    attack_paths: Mapped[list] = mapped_column(JSON, default=list)
    raw_outputs: Mapped[dict] = mapped_column(JSON, default=dict)
    # Triage: priority tier (P0..P4) + the code-grounded factors it was computed from.
    priority: Mapped[str | None] = mapped_column(String(4), nullable=True, index=True)
    triage: Mapped[dict] = mapped_column(JSON, default=dict)
    # raw|confirmed|disputed|false_positive|duplicate|parse_error|unreviewed|suppressed
    status: Mapped[str] = mapped_column(String(32), default="raw")
    suppression_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    iteration: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    job: Mapped["Job"] = relationship(back_populates="findings")
    debate: Mapped[list["DebateMessage"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )
    verdicts: Mapped[list["FindingVerdict"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_findings_job_severity", "job_id", "severity"),
        Index("ix_findings_job_status", "job_id", "status"),
    )


class DebateMessage(Base):
    __tablename__ = "debate_messages"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_new_id)
    finding_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("findings.id", ondelete="CASCADE"), nullable=True, index=True
    )
    job_id: Mapped[str] = mapped_column(String(32), ForeignKey("jobs.id"), index=True)
    speaker: Mapped[str] = mapped_column(String(64))  # expert persona or tool/judge/redteam
    role: Mapped[str] = mapped_column(String(32))    # review|challenge|verdict|redteam|debate
    content: Mapped[str] = mapped_column(Text, default="")
    thinking: Mapped[str | None] = mapped_column(Text, nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    finding: Mapped["Finding | None"] = relationship(back_populates="debate")


class FindingVerdict(Base):
    """One expert's (or the judge's) verdict on a finding, with rationale.

    Persisted per review so inter-expert disagreement is measurable (entropy)
    and exposed per finding via the API.
    """
    __tablename__ = "finding_verdicts"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_new_id)
    job_id: Mapped[str] = mapped_column(String(32), ForeignKey("jobs.id"), index=True)
    finding_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("findings.id", ondelete="CASCADE"), index=True
    )
    expert: Mapped[str] = mapped_column(String(64))   # expert name (injection|auth|judge|...)
    persona: Mapped[str] = mapped_column(String(64), default="")
    verdict: Mapped[str] = mapped_column(String(32))  # confirmed|refuted|disputed|abstain|parse_error
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    model: Mapped[str] = mapped_column(String(64), default="")
    iteration: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    finding: Mapped["Finding"] = relationship(back_populates="verdicts")

    __table_args__ = (Index("ix_verdicts_finding_expert", "finding_id", "expert"),)


class TriageOverride(Base):
    """Human correction of a triage priority tier.

    Never mutates the original Finding.triage dict — the LLM's assessment is
    preserved for audit and for the calibration pipeline (Direction 2).  The
    override is a separate record that the UI reads alongside the triage result.
    one-to-one with Finding (unique constraint on finding_id).
    """
    __tablename__ = "triage_overrides"

    id:                Mapped[str]      = mapped_column(String(32), primary_key=True, default=_new_id)
    finding_id:        Mapped[str]      = mapped_column(String(32), ForeignKey("findings.id", ondelete="CASCADE"), unique=True, index=True)
    job_id:            Mapped[str]      = mapped_column(String(32), ForeignKey("jobs.id",      ondelete="CASCADE"), index=True)
    original_priority: Mapped[str|None] = mapped_column(String(4), nullable=True)
    override_priority: Mapped[str]      = mapped_column(String(4))
    rationale:         Mapped[str|None] = mapped_column(Text, nullable=True)
    created_at:        Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    finding: Mapped["Finding"] = relationship()


class TriageOverrideOut(BaseModel):
    model_config = {"from_attributes": True}
    id: str
    finding_id: str
    original_priority: str | None
    override_priority: str
    rationale: str | None
    created_at: datetime


class GuardCandidateProposal(Base):
    """LLM-drafted guard rule awaiting human review.

    Never auto-applies: the system proposes, a human approves, and the approved
    guard becomes a code/config change via a PR.  `status` transitions:
    pending → approved | rejected.
    """
    __tablename__ = "guard_candidate_proposals"

    id:                     Mapped[str]       = mapped_column(String(32), primary_key=True, default=_new_id)
    group_key:              Mapped[str]       = mapped_column(String(128), index=True)
    group_type:             Mapped[str]       = mapped_column(String(32))
    group_value:            Mapped[str]       = mapped_column(String(128))
    evidence_total:         Mapped[int]       = mapped_column(Integer)
    evidence_barbell_pct:   Mapped[float]     = mapped_column(Float)
    evidence_target_count:  Mapped[int]       = mapped_column(Integer)
    proposed_matcher:       Mapped[str]       = mapped_column(Text)
    proposed_vector_ceiling: Mapped[str|None] = mapped_column(String(32), nullable=True)
    proposed_impact_ceiling: Mapped[str|None] = mapped_column(String(32), nullable=True)
    rationale:              Mapped[str]       = mapped_column(Text)
    narrowness_note:        Mapped[str|None]  = mapped_column(Text, nullable=True)
    status:                 Mapped[str]       = mapped_column(String(16), default="pending")
    review_rationale:       Mapped[str|None]  = mapped_column(Text, nullable=True)
    created_at:             Mapped[datetime]  = mapped_column(DateTime, default=utcnow)
    reviewed_at:            Mapped[datetime|None] = mapped_column(DateTime, nullable=True)


class GuardCandidateProposalOut(BaseModel):
    model_config = {"from_attributes": True}
    id: str
    group_key: str
    group_type: str
    group_value: str
    evidence_total: int
    evidence_barbell_pct: float
    evidence_target_count: int
    proposed_matcher: str
    proposed_vector_ceiling: str | None
    proposed_impact_ceiling: str | None
    rationale: str
    narrowness_note: str | None
    status: str
    review_rationale: str | None
    created_at: datetime
    reviewed_at: datetime | None


attack_chain_findings = Table(
    "attack_chain_findings",
    Base.metadata,
    Column("chain_id", String(32), ForeignKey("attack_chains.id", ondelete="CASCADE"), primary_key=True),
    Column("finding_id", String(32), ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True),
)


class AttackChain(Base):
    """A red-team attack path linking the specific findings it chains together."""
    __tablename__ = "attack_chains"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_new_id)
    job_id: Mapped[str] = mapped_column(String(32), ForeignKey("jobs.id"), index=True)
    goal: Mapped[str] = mapped_column(String(256), default="")
    steps: Mapped[list] = mapped_column(JSON, default=list)
    likelihood: Mapped[str] = mapped_column(String(16), default="medium")
    iteration: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    findings: Mapped[list["Finding"]] = relationship(secondary=attack_chain_findings)


class JobEvent(Base):
    __tablename__ = "job_events"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_new_id)
    # Monotonic per-DB sequence for meaningful pagination/replay (uuid ids are not
    # ordered). Postgres assigns via the sequence; SQLite leaves it NULL.
    seq: Mapped[int | None] = mapped_column(
        BigInteger, Sequence("job_event_seq"), nullable=True, index=True
    )
    job_id: Mapped[str] = mapped_column(String(32), ForeignKey("jobs.id"), index=True)
    type: Mapped[str] = mapped_column(String(64), index=True)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    job: Mapped["Job"] = relationship(back_populates="events")

    __table_args__ = (Index("ix_events_job_created", "job_id", "created_at"),)


class ChatMessage(Base):
    __tablename__ = "chat_messages"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_new_id)
    job_id: Mapped[str] = mapped_column(String(32), ForeignKey("jobs.id"), index=True)
    finding_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("findings.id", ondelete="CASCADE"), nullable=True, index=True
    )
    role: Mapped[str] = mapped_column(String(16))  # user|assistant
    content: Mapped[str] = mapped_column(Text, default="")
    context_refs: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    job: Mapped["Job"] = relationship(back_populates="chat_messages")


class EvalReport(Base):
    __tablename__ = "eval_reports"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_new_id)
    job_id: Mapped[str] = mapped_column(String(32), ForeignKey("jobs.id"), index=True)
    target_id: Mapped[str] = mapped_column(String(64))
    recall: Mapped[float] = mapped_column(Float, default=0.0)
    precision: Mapped[float] = mapped_column(Float, default=0.0)
    total_planted: Mapped[int] = mapped_column(Integer, default=0)
    total_detected: Mapped[int] = mapped_column(Integer, default=0)
    total_findings: Mapped[int] = mapped_column(Integer, default=0)
    matched: Mapped[list] = mapped_column(JSON, default=list)
    missed: Mapped[list] = mapped_column(JSON, default=list)
    false_positives: Mapped[list] = mapped_column(JSON, default=list)
    decoy_hits: Mapped[list] = mapped_column(JSON, default=list)
    attribution: Mapped[dict] = mapped_column(JSON, default=dict)
    per_cwe: Mapped[dict] = mapped_column(JSON, default=dict)
    per_expert: Mapped[dict] = mapped_column(JSON, default=dict)
    per_tool: Mapped[dict] = mapped_column(JSON, default=dict)
    per_iteration: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


# ---- Pydantic schemas (API layer) ----


class FindingOut(BaseModel):
    id: str
    job_id: str
    tool: str
    rule_id: str
    severity: str
    confidence: float
    title: str
    description: str
    file: str
    line_start: int
    line_end: int
    snippet: str
    cwe: str | None = None
    owasp: str | None = None
    recommendation: str = ""
    remediation: str | None = None
    narrative: str | None = None
    exploit_scenario: str | None = None
    attack_paths: list = Field(default_factory=list)
    correlation_key: str | None = None
    canonical_id: str | None = None
    corroborating_tools: list = Field(default_factory=list)
    review_error: str | None = None
    priority: str | None = None
    triage: dict = Field(default_factory=dict)
    status: str = "raw"
    suppression_reason: str | None = None
    iteration: int = 0
    created_at: datetime | None = None

    model_config = {"from_attributes": True}

    # Older rows predate these columns and read back as NULL — coerce so the API
    # never 500s on a legacy finding.
    @field_validator("triage", mode="before")
    @classmethod
    def _triage_none(cls, v):
        return v or {}

    @field_validator("corroborating_tools", "attack_paths", mode="before")
    @classmethod
    def _list_none(cls, v):
        return v or []


class JobOut(BaseModel):
    id: str
    target_name: str
    source_type: str
    source_ref: str
    status: str
    profile: dict = Field(default_factory=dict)
    current_iteration: int = 0
    max_iterations: int = 3
    languages: list = Field(default_factory=list)
    is_scored: bool = False
    target_id: str | None = None
    commit_hash: str | None = None
    error: str | None = None
    created_at: datetime | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None

    model_config = {"from_attributes": True}


class FindingVerdictOut(BaseModel):
    id: str
    finding_id: str
    expert: str
    persona: str = ""
    verdict: str
    confidence: float
    rationale: str | None = None
    model: str = ""
    iteration: int = 0
    created_at: datetime | None = None

    model_config = {"from_attributes": True}


class AttackChainOut(BaseModel):
    id: str
    goal: str
    steps: list = Field(default_factory=list)
    likelihood: str = "medium"
    iteration: int = 0
    finding_ids: list = Field(default_factory=list)
    created_at: datetime | None = None

    model_config = {"from_attributes": True}


class NewScanRequest(BaseModel):
    source_type: str = "demo"  # git|upload|mount|demo
    source_ref: str = ""       # git url / host path; empty for demo
    target_name: str = ""
    is_scored: bool = False
    target_id: str | None = None
    profile: dict = Field(default_factory=dict)


class ChatRequest(BaseModel):
    message: str
    finding_id: str | None = None


class ChatMessageOut(BaseModel):
    id: str
    role: str
    content: str
    context_refs: dict = Field(default_factory=dict)
    created_at: datetime | None = None

    model_config = {"from_attributes": True}


class EvalReportOut(BaseModel):
    job_id: str
    target_id: str
    recall: float
    precision: float
    total_planted: int
    total_detected: int
    total_findings: int
    matched: list
    missed: list
    false_positives: list
    decoy_hits: list = Field(default_factory=list)
    attribution: dict = Field(default_factory=dict)
    per_cwe: dict
    per_expert: dict
    per_tool: dict
    per_iteration: list

    model_config = {"from_attributes": True}
