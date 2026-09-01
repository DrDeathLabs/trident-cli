"""LLM-based guard proposal drafter — Phase 2.

Given a GuardCandidate (a finding class with a barbell P0+P4 distribution),
calls the LLM once to draft a guard rule: a regex matcher, optional factor
ceilings, a rationale, and a narrowness note listing what the guard should NOT
match.

The proposal is persisted as a GuardCandidateProposal (status=pending) for
human review. It is NEVER auto-applied — an approved proposal requires a
human PR/config change to take effect.
"""

from __future__ import annotations

from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from trident.calibration.discover import GuardCandidate
from trident.clock import utcnow
from trident.config import settings
from trident.llm.base import ChatMessage
from trident.models import GuardCandidateProposal
from trident.reliability.structured import chat_structured

_SYSTEM = """\
You are a security-tool calibration assistant. Your job is to draft a narrowly-scoped
guard rule for an automated SAST triage system that systematically over-escalates
a specific class of findings.

The system assigns priority P0–P4 to security findings. A finding class shows a
"barbell" distribution — nearly all findings land at P0 (critical) or P4 (noise),
with almost nothing in the middle — which is the signature of LLM over-escalation.
Your goal is to propose a deterministic cap rule that corrects the P0 over-escalation
for this class, without ever suppressing genuine critical findings.

Rules:
- The matcher regex MUST be narrow — it must NOT match common high-severity classes
  like SQL injection, RCE, or auth bypass.
- Proposed ceilings should be conservative: propose the minimum cap that fixes the
  over-escalation; do not over-cap.
- Explain exactly what the guard would and would NOT match.
- If you are not confident a cap is appropriate, say so in the rationale.
"""

_TIERS = ["P0", "P1", "P2", "P3", "P4"]
_VECTORS = ["remote_unauth", "remote_auth", "adjacent", "local", "physical"]
_IMPACTS = ["rce", "auth_bypass", "data_exposure", "data_tampering", "ssrf",
            "injection", "dos", "info_disclosure", "other"]


class _GuardDraft(BaseModel):
    proposed_matcher: str = Field(
        description="Python regex pattern matching finding titles/descriptions for this class. "
                    "Must be narrow — should NOT match SQL injection, RCE, auth bypass, etc."
    )
    proposed_vector_ceiling: str | None = Field(
        default=None,
        description=f"Cap attack_vector to this value for matched findings, or null if no cap needed. "
                    f"Must be one of: {_VECTORS}"
    )
    proposed_impact_ceiling: str | None = Field(
        default=None,
        description=f"Cap impact to this value for matched findings, or null if no cap needed. "
                    f"Must be one of: {_IMPACTS}"
    )
    rationale: str = Field(
        description="Human-readable explanation of why this class is over-escalated and why the "
                    "proposed cap is appropriate. 2–4 sentences."
    )
    narrowness_note: str = Field(
        description="Explicit list of finding types this guard would NOT match, confirming it "
                    "won't suppress genuine critical findings. 1–3 sentences."
    )


def draft_proposal(candidate: GuardCandidate, db: Session) -> GuardCandidateProposal:
    """Call the LLM to draft a guard proposal for `candidate`, persist and return it."""
    dist_lines = "  ".join(
        f"{t}: {candidate.priority_dist.get(t, 0)}"
        for t in _TIERS
    )
    override_note = ""
    if candidate.override_count > 0 and candidate.downgrade_pct is not None:
        override_note = (
            f"\n- Human overrides recorded: {candidate.override_count} "
            f"({candidate.downgrade_pct*100:.0f}% were downgrade corrections)"
        )

    prompt = f"""\
Finding class evidence:
- Class: {candidate.group_type} = {candidate.group_value}
- Total confirmed findings: {candidate.total}
- Distinct scan targets: {candidate.target_count}
- Priority distribution: {dist_lines}
- Barbell share (P0+P4): {candidate.barbell_pct*100:.0f}%
  (P0: {candidate.p0_pct*100:.0f}%  P4: {candidate.p4_pct*100:.0f}%){override_note}

Based on this evidence, draft a guard rule that would cap the over-escalation for this
finding class. Remember: propose only what is necessary; when in doubt, do not cap.
"""

    result = chat_structured(
        [ChatMessage("system", _SYSTEM), ChatMessage("user", prompt)],
        _GuardDraft,
        model=settings.llm.triage_model or settings.llm.default_model,
        temperature=0.2,
    )

    if not result.ok:
        raise RuntimeError(f"LLM failed to draft proposal: {result.error}")

    draft = result.obj
    proposal = GuardCandidateProposal(
        group_key=candidate.group_key,
        group_type=candidate.group_type,
        group_value=candidate.group_value,
        evidence_total=candidate.total,
        evidence_barbell_pct=candidate.barbell_pct,
        evidence_target_count=candidate.target_count,
        proposed_matcher=draft.proposed_matcher,
        proposed_vector_ceiling=draft.proposed_vector_ceiling,
        proposed_impact_ceiling=draft.proposed_impact_ceiling,
        rationale=draft.rationale,
        narrowness_note=draft.narrowness_note,
        status="pending",
        created_at=utcnow(),
    )
    db.add(proposal)
    db.commit()
    db.refresh(proposal)
    return proposal
