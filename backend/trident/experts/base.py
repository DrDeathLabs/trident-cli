"""Council of Experts base class + registry.

Each expert reviews findings in its domain. The LLM call itself is DB-free and
thread-safe (`invoke_review`) so a batch of reviews can run concurrently; all
persistence happens on the orchestrating thread afterwards.
"""

from __future__ import annotations

import os
import re
from abc import ABC

from loguru import logger
from sqlalchemy.orm import Session

from trident.agent.loop import run_agent
from trident.agent.tools import WorkspaceTools
from trident.config import settings
from trident.prompts import (
    AGENT_PROPOSE_FINAL, AGENT_REVIEW_FINAL, AGENT_SYSTEM_SUFFIX,
    build_agent_propose_task, build_agent_review_task,
    build_propose_prompt, build_review_prompt,
)
from trident.reliability.schemas import NovelFindingList, ReviewVerdict
from trident.reliability.structured import StructuredResult, chat_structured
from trident.events.publisher import EventType, publish_event
from trident.llm.base import ChatMessage
from trident.models import DebateMessage, Finding

EXT_MAP = {
    ".py": "python", ".go": "go", ".js": "javascript", ".ts": "typescript",
    ".jsx": "javascript", ".tsx": "typescript", ".java": "java", ".rb": "ruby",
    ".php": "php", ".cs": "csharp", ".rs": "rust", ".tf": "hcl", ".yaml": "yaml",
    ".yml": "yaml",
}

EXPERT_REGISTRY: dict[str, type["ExpertBase"]] = {}


class ExpertBase(ABC):
    """Base class for council experts."""

    name: str = "base"
    persona: str = "Expert"
    domain: str = "general"
    system_prompt: str = "You are a security expert."
    # Relevance routing: CWE set (authoritative) + keyword fallback (word-boundary)
    # + originating-tool match (for tool-shaped domains like dependencies).
    domains: set[str] = set()
    keywords: tuple[str, ...] = ()
    source_tools: tuple[str, ...] = ()

    def __init__(self, job_id: str, workspace: str, agentic: bool = False,
                 model: str | None = None):
        self.job_id = job_id
        self.workspace = workspace
        self.model = model or self._model_for_role()
        self.agentic = agentic
        self._tools = WorkspaceTools(workspace) if agentic else None

    def _model_for_role(self) -> str:
        return settings.llm.model_for("expert")

    # ---- relevance --------------------------------------------------------
    def is_relevant(self, finding: Finding) -> bool:
        if self.source_tools and str(finding.tool) in self.source_tools:
            return True
        cwe = (finding.cwe or "").strip()
        if cwe and self.domains:
            m = re.search(r"\d+", cwe)
            norm = f"CWE-{m.group(0)}" if m else cwe
            if norm in self.domains:
                return True
        if not self.keywords:
            return False
        text = f"{finding.title} {finding.description} {finding.rule_id}".lower()
        return any(re.search(rf"\b{re.escape(k)}\b", text) for k in self.keywords)

    # ---- DB-free LLM call (safe to run in a thread pool) -----------------
    def _ext_for(self, path: str) -> str:
        return EXT_MAP.get(os.path.splitext(path or "")[1].lower(), "text")

    def invoke_review(
        self, finding: Finding, peers: list[dict] | None = None,
        budget=None, agentic: bool | None = None,
    ) -> StructuredResult[ReviewVerdict]:
        """Review a finding. No DB access — returns a validated verdict or a parse failure.

        `agentic` overrides per call (selective agentic): the caller keeps cheap
        single-shot review for most findings and reserves tool exploration for the
        ones worth it. None = use the expert's job-level flag.
        """
        use_agentic = self.agentic if agentic is None else (agentic and self._tools is not None)
        ext = self._ext_for(finding.file)
        snippet = self._read_file(finding.file, finding.line_start, finding.line_end)
        if use_agentic and self._tools is not None:
            task = build_agent_review_task(self.persona, self.domain, finding, snippet, ext, peers=peers)
            return run_agent(
                self.system_prompt + AGENT_SYSTEM_SUFFIX, task, self._tools, ReviewVerdict,
                model=self.model, max_steps=settings.agent.max_steps,
                final_instruction=AGENT_REVIEW_FINAL, budget=budget,
            )
        if budget is not None:
            budget.take(1)
        prompt = build_review_prompt(self.persona, self.domain, finding, snippet, ext, peers=peers)
        return chat_structured(
            [ChatMessage("system", self.system_prompt), ChatMessage("user", prompt)],
            ReviewVerdict, model=self.model,
        )

    def invoke_propose(self, files_block: str, budget=None) -> StructuredResult[NovelFindingList]:
        """Propose novel findings the tools may have missed, in this expert's domain."""
        if self.agentic and self._tools is not None:
            task = build_agent_propose_task(self.persona, self.domain, files_block)
            return run_agent(
                self.system_prompt + AGENT_SYSTEM_SUFFIX, task, self._tools, NovelFindingList,
                model=self.model, max_steps=settings.agent.max_steps,
                final_instruction=AGENT_PROPOSE_FINAL, temperature=0.3, budget=budget,
            )
        if budget is not None:
            budget.take(1)
        prompt = build_propose_prompt(self.persona, self.domain, files_block)
        return chat_structured(
            [ChatMessage("system", self.system_prompt), ChatMessage("user", prompt)],
            NovelFindingList, model=self.model, temperature=0.3,
        )

    def _read_file(self, path: str, line_start: int = 0, line_end: int = 0, context: int = 5) -> str:
        """Read a snippet of a file from the workspace, scoped (blinded to scorecard)."""
        full = os.path.join(self.workspace, path)
        real = os.path.realpath(full)
        ws_real = os.path.realpath(self.workspace)
        if os.path.commonpath([real, ws_real]) != ws_real:
            return "[access denied: outside workspace]"
        try:
            with open(real, encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except Exception:
            return f"[could not read {path}]"
        if line_start and line_end:
            s = max(1, line_start - context)
            e = min(len(lines), line_end + context)
            return "".join(f"{i+1}: {lines[i]}" for i in range(s - 1, e))
        return "".join(lines[:400])

    # ---- persistence helpers (main thread) --------------------------------
    def _emit(self, db: Session, event_type: str, payload: dict | None = None):
        publish_event(db, self.job_id, event_type, payload or {})

    def _save_debate(
        self, db: Session, finding_id: str | None, role: str, content: str,
        thinking: str | None = None, confidence: float | None = None,
    ) -> DebateMessage:
        msg = DebateMessage(
            finding_id=finding_id, job_id=self.job_id, speaker=self.persona,
            role=role, content=content, thinking=thinking, confidence=confidence,
        )
        db.add(msg)
        db.flush()
        self._emit(db, EventType.DEBATE_MESSAGE, {
            "speaker": self.persona, "role": role, "finding_id": finding_id,
            "expert": self.name, "confidence": confidence,
            "content_preview": content[:500], "thinking": (thinking or "")[:300],
        })
        return msg


def register_expert(cls: type[ExpertBase]) -> type[ExpertBase]:
    EXPERT_REGISTRY[cls.name] = cls
    return cls


def get_experts(names: list[str], job_id: str, workspace: str,
                agentic: bool = False, model: str | None = None) -> list[ExpertBase]:
    out: list[ExpertBase] = []
    for n in names:
        cls = EXPERT_REGISTRY.get(n)
        if cls:
            out.append(cls(job_id=job_id, workspace=workspace, agentic=agentic, model=model))
        else:
            logger.warning(f"Unknown expert: {n}")
    return out
