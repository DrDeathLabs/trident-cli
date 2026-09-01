"""Orchestrator — the iterative refinement loop controller.

iteration 0: tools scan repo -> raw findings -> cross-tool correlation/dedupe
each iteration:
  1. relevant experts review findings (parallel), cross-examine when contested
  2. judge rules on contested findings (unanimous-confident skips the judge)
  3. experts propose novel findings the tools missed (every iteration)
  4. red team chains confirmed findings into attack paths (persisted as AttackChains)
  5. convergence check -> stop when no unresolved work, cap hit, or budget spent
"""

from __future__ import annotations

import importlib
import pkgutil

from loguru import logger
from sqlalchemy.orm import Session

from trident.budget import LLMBudget
from trident.clock import utcnow
from trident.config import settings
from trident.convergence import evaluate_convergence
from trident.correlate import correlate_findings
from trident.suppression import apply_suppressions
from trident.deliberation import build_attack_chains, collect_novel, run_reviews
from trident.events.publisher import EventType, publish_event
from trident.experts.base import get_experts
from trident.experts.judge import JudgeExpert
from trident.experts.redteam import RedTeamExpert
from trident.llm.base import LLMUnavailable
from trident.models import Finding, Job, JobStatus
from trident.tools.base import get_tools


def _import_plugins() -> None:
    """Auto-discover every tool and expert module so their registries populate."""
    import trident.experts as experts_pkg
    import trident.tools as tools_pkg

    for pkg in (tools_pkg, experts_pkg):
        for mod in pkgutil.iter_modules(pkg.__path__):
            if mod.name in ("base", "__init__"):
                continue
            importlib.import_module(f"{pkg.__name__}.{mod.name}")


def run_scan(job: Job, db: Session) -> None:
    """Run the full iterative scan loop for a job."""
    job_id = job.id
    workspace = job.workspace_path
    profile = job.profile or {}
    tool_names = profile.get("tools", settings.enabled_tools)
    expert_names = profile.get("experts", settings.enabled_experts)
    max_iter = profile.get("max_iterations", settings.loop.max_iterations)
    min_new = profile.get("min_new_findings", settings.loop.min_new_findings)
    call_cap = profile.get("max_llm_calls", settings.loop.max_llm_calls) or None
    budget = LLMBudget(limit=call_cap)
    agentic = bool(profile.get("agentic", settings.agent.enabled))
    model_override = profile.get("model") or None

    job.status = JobStatus.scanning.value
    job.started_at = job.started_at or utcnow()
    db.commit()
    publish_event(db, job_id, EventType.JOB_STARTED, {"target": job.target_name})

    _import_plugins()

    try:
        # ---- iteration 0: deterministic tools ----
        # Tools run sequentially: they share a single (non-thread-safe) session and
        # each spawns subprocesses for the real work.
        publish_event(db, job_id, EventType.SCAN_TOOLS_START, {"tools": tool_names})
        for t in get_tools(tool_names, workspace, job_id):
            try:
                t.run(db)
            except Exception as e:
                logger.exception(f"Tool error: {e}")
        db.commit()

        # ---- suppression (.tridentignore + inline comments) ----
        apply_suppressions(db, job_id, workspace)
        db.commit()

        # ---- cross-tool correlation / dedupe ----
        publish_event(db, job_id, EventType.SCAN_CORRELATE_START, {})
        correlate_findings(db, job_id)
        db.commit()

        # Domain reviewers come from the registry; the judge and red-team are
        # distinct roles, constructed explicitly (not part of the review pool).
        review_experts = get_experts(expert_names, job_id, workspace,
                                     agentic=agentic, model=model_override)
        judge = JudgeExpert(job_id, workspace, model=model_override)
        redteam = RedTeamExpert(job_id, workspace, model=model_override)
        if agentic:
            publish_event(db, job_id, EventType.AGENT_ENABLED, {"max_steps": settings.agent.max_steps})
        if model_override:
            publish_event(db, job_id, EventType.JOB_STARTED, {"model": model_override})

        seen_files: set[str] = set()
        prev_disputed = 0
        iteration = 0
        while True:
            job.current_iteration = iteration
            db.commit()
            publish_event(db, job_id, EventType.JOB_ITERATION_START, {"iteration": iteration})

            # Targets: unreviewed raw findings, plus disputed ones to re-litigate.
            statuses = ["raw"] if iteration == 0 else ["raw", "disputed", "unreviewed"]
            targets = db.query(Finding).filter(
                Finding.job_id == job_id, Finding.status.in_(statuses)
            ).all()
            publish_event(db, job_id, EventType.SCAN_EXPERTS_START, {
                "iteration": iteration, "findings_to_review": len(targets),
            })
            run_reviews(db, review_experts, judge, targets, iteration, budget)
            db.commit()

            # ---- novel discovery (every iteration, incl. 0) ----
            if not budget.exhausted:
                publish_event(db, job_id, EventType.SCAN_DEBATE_START, {"iteration": iteration})
                novel = collect_novel(db, review_experts, job_id, workspace, iteration,
                                      budget, seen=seen_files)
                db.commit()
                if novel:
                    run_reviews(db, review_experts, judge, novel, iteration, budget)
                    db.commit()

            # ---- red team ----
            publish_event(db, job_id, EventType.SCAN_REDTEAM_START, {"iteration": iteration})
            confirmed = db.query(Finding).filter(
                Finding.job_id == job_id, Finding.status == "confirmed"
            ).all()
            if redteam:
                build_attack_chains(db, job_id, redteam, confirmed, iteration, budget)
                db.commit()

            # ---- convergence ----
            conv = evaluate_convergence(
                db, job_id, iteration, max_iter, min_new, prev_disputed,
                budget_exhausted=budget.exhausted,
            )
            prev_disputed = conv.disputed
            publish_event(db, job_id, EventType.JOB_ITERATION_COMPLETE, {
                "iteration": iteration, "converged": conv.converged, "reason": conv.reason,
                "entropy": conv.entropy, "unresolved": conv.unresolved,
            })
            db.commit()
            if budget.exhausted:
                publish_event(db, job_id, EventType.BUDGET_EXHAUSTED, {"used": budget.used})
            if conv.converged:
                break
            iteration += 1

        # Fail-open: any finding still disputed after all iterations converged is
        # promoted to confirmed so it enters the triage queue rather than
        # disappearing into limbo. The expert vote record documents the
        # uncertainty; triage + human override make the final priority call.
        remaining_disputed = db.query(Finding).filter(
            Finding.job_id == job_id, Finding.status == "disputed"
        ).all()
        for f in remaining_disputed:
            f.status = "confirmed"
            # Preserve the disagreement signal so the UI can flag these for review.
            f.triage = {**f.triage, "contested": True}
        if remaining_disputed:
            logger.info(
                f"fail-open: promoted {len(remaining_disputed)} disputed findings "
                f"to confirmed for job {job_id}"
            )
            db.commit()

        confirmed_count = db.query(Finding).filter(
            Finding.job_id == job_id, Finding.status == "confirmed"
        ).count()
        job.status = JobStatus.complete.value
        job.completed_at = utcnow()
        db.commit()
        publish_event(db, job_id, EventType.JOB_COMPLETE, {
            "total_findings": db.query(Finding).filter(Finding.job_id == job_id).count(),
            "confirmed": confirmed_count, "llm_calls": budget.used,
        })
        db.commit()

    except LLMUnavailable as e:
        logger.error(f"LLM unavailable for job {job_id}: {e}")
        _fail_job(db, job, f"LLM endpoint unavailable: {e}")
    except Exception as e:
        logger.exception(f"Scan failed for job {job_id}")
        _fail_job(db, job, f"{type(e).__name__}: {e}")


def _fail_job(db: Session, job: Job, error: str) -> None:
    """Record a job failure, recovering from a possibly-poisoned transaction."""
    db.rollback()  # the failure may have aborted the current transaction
    try:
        job.status = JobStatus.failed.value
        job.error = error[:2000]
        db.commit()
        publish_event(db, job.id, EventType.JOB_FAILED, {"error": error[:500]})
        db.commit()
    except Exception:
        logger.exception("failed to record job failure")
        db.rollback()
