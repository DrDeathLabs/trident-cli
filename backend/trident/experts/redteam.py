"""Red Team expert — chains confirmed findings into attack paths."""

from __future__ import annotations

import hashlib
import json

from trident.config import settings
from trident.evidence import evidence_basis, prompt_evidence
from trident.experts.base import ExpertBase
from trident.llm.base import ChatMessage
from trident.models import Finding, SEVERITY_RANK
from trident.prompts import SYSTEM_BASE, build_redteam_prompt
from trident.reliability.schemas import AttackPathList
from trident.reliability.structured import StructuredResult, _contract, chat_structured

_MAX_REDFINDINGS = 40


def select_redteam_findings(findings: list[Finding]) -> list[Finding]:
    """Choose the bounded Red-Team set in stable severity/path/id order."""
    ordered = sorted(
        findings,
        key=lambda finding: (
            SEVERITY_RANK.get(str(finding.severity), 99),
            (finding.file or "").replace("\\", "/").casefold(),
            int(finding.line_start or 0),
            str(finding.id),
        ),
    )
    return ordered[:_MAX_REDFINDINGS]


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

    def build_model_input(self, confirmed_findings: list[Finding]) -> dict:
        """Build the exact messages and canonical digest used for a Red-Team call."""
        selected = select_redteam_findings(confirmed_findings)
        records = "\n".join(
            f"- [{f.id}] {f.title} ({f.severity}, {f.cwe or '-'}) @ {f.file}:{f.line_start}\n"
            f"  {f.description[:200]}\n"
            f"  Evidence basis: {evidence_basis(f, self.workspace)}\n"
            f"  {prompt_evidence(f, self.workspace)}"
            for f in selected
        )
        selected_ids = ", ".join(str(f.id) for f in selected) or "none"
        block = f"SELECTED FINDING IDS: {selected_ids}\n{records}"
        user_prompt = build_redteam_prompt(block, metadata_only=not bool(self.workspace))
        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": user_prompt},
        ]
        # chat_structured appends this exact schema contract before invoking the
        # backend. Include those final model-visible messages in the fingerprint
        # so the cache key cannot omit or drift from the actual request.
        prepared_messages = _contract(
            [ChatMessage(message["role"], message["content"]) for message in messages],
            AttackPathList,
        )
        canonical = {
            "model": self.model,
            "messages": [
                {"role": message.role, "content": message.content}
                for message in prepared_messages
            ],
            "temperature": 0.3,
            "response_schema": AttackPathList.model_json_schema(),
        }
        encoded = json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return {
            **canonical,
            "fingerprint": hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
            "selected_finding_ids": [str(f.id) for f in selected],
            "chat_messages": [ChatMessage(message["role"], message["content"]) for message in messages],
        }

    def invoke_chains(
        self,
        confirmed_findings: list[Finding],
        iteration: int = 0,
        model_input: dict | None = None,
    ) -> StructuredResult[AttackPathList]:
        """Build attack paths from confirmed findings. No DB access."""
        model_input = model_input or self.build_model_input(confirmed_findings)
        return chat_structured(
            model_input["chat_messages"],
            AttackPathList, model=self.model, temperature=0.3,
            context={"run_id": self.job_id, "task_type": "redteam",
                     "council_role": self.name, "iteration": iteration},
        )
