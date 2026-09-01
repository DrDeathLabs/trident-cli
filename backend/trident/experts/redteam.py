"""Red Team expert — chains confirmed findings into attack paths."""

from __future__ import annotations

from trident.config import settings
from trident.experts.base import ExpertBase
from trident.llm.base import ChatMessage
from trident.models import Finding
from trident.prompts import SYSTEM_BASE, build_redteam_prompt
from trident.reliability.schemas import AttackPathList
from trident.reliability.structured import StructuredResult, chat_structured


class RedTeamExpert(ExpertBase):
    """The red-team role — not a domain reviewer, constructed explicitly."""
    name = "redteam"
    persona = "Red Team (Attacker)"
    domain = "Attacker perspective: chains confirmed findings into exploit scenarios"
    system_prompt = SYSTEM_BASE + "\n" + (
        "You are the RED TEAM expert. You think like a motivated attacker. "
        "You chain confirmed vulnerabilities into realistic attack paths to show "
        "business impact (RCE, data exfiltration, account takeover). Reference the "
        "exact finding ids you use in each path's `findings_used`."
    )

    def _model_for_role(self) -> str:
        return settings.llm.model_for("redteam")

    def invoke_chains(self, confirmed_findings: list[Finding]) -> StructuredResult[AttackPathList]:
        """Build attack paths from confirmed findings. No DB access."""
        block = "\n".join(
            f"- [{f.id}] {f.title} ({f.severity}, {f.cwe or '-'}) @ {f.file}:{f.line_start}\n"
            f"  {f.description[:200]}"
            for f in confirmed_findings[:40]
        )
        prompt = build_redteam_prompt(block)
        return chat_structured(
            [ChatMessage("system", self.system_prompt), ChatMessage("user", prompt)],
            AttackPathList, model=self.model, temperature=0.3,
        )
