"""Judge / Adversary expert — challenges findings, kills false positives, assigns final confidence."""

from __future__ import annotations

from trident.config import settings
from trident.experts.base import ExpertBase
from trident.llm.base import ChatMessage
from trident.models import Finding
from trident.prompts import SYSTEM_BASE, build_judge_prompt
from trident.reliability.schemas import JudgeVerdict
from trident.reliability.structured import StructuredResult, chat_structured


class JudgeExpert(ExpertBase):
    """The judge/adjudicator role — not a domain reviewer, constructed explicitly."""
    name = "judge"
    persona = "Judge / Adversary"
    domain = "Skeptical adversary: verifies or refutes findings, assigns final confidence"
    system_prompt = SYSTEM_BASE + "\n" + (
        "You are the JUDGE. You are the skeptical adversary on the council. "
        "Your role is to kill false positives and assign a final confidence. "
        "You do NOT rubber-stamp. If a claim is not substantiated by the code, REFUTE it. "
        "You must cite specific code when confirming or refuting. Weigh the experts' "
        "rationales below, but decide independently from the evidence."
    )

    def _model_for_role(self) -> str:
        return settings.llm.model_for("judge")

    def invoke_judge(
        self, finding: Finding, prior_verdicts: list[dict] | None = None,
    ) -> StructuredResult[JudgeVerdict]:
        """Adjudicate a finding given the experts' full rationales. No DB access."""
        prior_verdicts = prior_verdicts or []
        if prior_verdicts:
            verdicts_block = "\n".join(
                f"- {v.get('persona', '?')}: {v.get('verdict', '?')} "
                f"(confidence {v.get('confidence', '?')}) — {(v.get('rationale') or '')[:500]}"
                for v in prior_verdicts
            )
        else:
            verdicts_block = "(no prior expert verdicts — adjudicate the tool finding directly)"
        snippet = self._read_file(finding.file, finding.line_start, finding.line_end) if finding.file else ""
        ext = self._ext_for(finding.file)
        prompt = build_judge_prompt(finding, verdicts_block, snippet, ext)
        return chat_structured(
            [ChatMessage("system", self.system_prompt), ChatMessage("user", prompt)],
            JudgeVerdict, model=self.model, temperature=0.1,
        )
