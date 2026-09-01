"""Deliberation — multi-expert review with cross-examination and a judge ruling.

Per finding:
  Phase A (parallel): every domain-relevant expert reviews it independently.
  Phase B (conditional): if experts disagree — or a lone verdict is uncertain —
    each relevant expert reviews again, this time seeing peers' rationales
    (cross-examination).
  Ruling: a unanimous, high-confidence verdict is applied directly (the judge is
    skipped to save cost); anything contested goes to the judge, who sees the
    experts' full rationales — not a vote tally.

Every expert/judge verdict is persisted as a FindingVerdict (with rationale) so
inter-expert disagreement is measurable. A response that fails schema validation
is recorded as a parse_error verdict and sets `finding.review_error` — it is
never counted as a verdict.

Also home to novel-finding discovery (collect_novel) and attack-chain building
(build_attack_chains) — the "run the LLM, persist rows, publish events" steps.

LLM calls run through a bounded thread pool; all DB writes happen on the calling
thread (the session is not thread-safe). A per-job budget caps total calls.
"""

from __future__ import annotations

import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from loguru import logger
from sqlalchemy.orm import Session

from trident.budget import LLMBudget
from trident.config import settings
from trident.events.publisher import EventType, publish_event
from trident.experts.judge import JudgeExpert
from trident.models import (
    SEVERITY_RANK, AttackChain, Finding, FindingVerdict, correlation_key, stable_finding_hash,
)
from trident.reliability.schemas import ReviewVerdict

UNCERTAIN_LOW, UNCERTAIN_HIGH = 0.35, 0.75
CONFIDENT = 0.75


@dataclass
class _V:
    """A collected verdict from one reviewer."""
    expert: str
    persona: str
    verdict: str
    confidence: float
    rationale: str
    obj: ReviewVerdict | None = None


def _parallel(fn, items, budget: LLMBudget, on_result=None):
    """Run fn over items in a bounded pool. Returns [(item, result)].

    The budget is metered inside fn (each LLM call / agent step takes 1 in real
    time), so this just stops submitting new work once the budget is spent. result
    is an Exception on failure, or None if skipped for budget. If `on_result` is
    given it is called (on this thread) as each result arrives, so callers can
    persist + stream incrementally instead of after the whole batch.
    """
    workers = max(1, settings.llm.concurrency)
    out: list[tuple] = []
    submitted = {}
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for it in items:
            if budget.exhausted:
                out.append((it, None))
                continue
            submitted[ex.submit(fn, it)] = it
        for fut in as_completed(submitted):
            it = submitted[fut]
            try:
                res = fut.result()
            except Exception as e:  # pragma: no cover - defensive
                logger.exception("deliberation task failed")
                res = e
            out.append((it, res))
            if on_result is not None:
                on_result(it, res)
    return out


def _persist_review(db, finding, expert, res, iteration, role) -> _V | None:
    """Persist one expert review (verdict + debate message). None on parse failure."""
    if isinstance(res, Exception) or res is None or not getattr(res, "ok", False):
        err = str(getattr(res, "error", res) or "parse failure")
        db.add(FindingVerdict(
            job_id=finding.job_id, finding_id=finding.id, expert=expert.name,
            persona=expert.persona, verdict="parse_error", confidence=0.0,
            rationale=err[:1000], model=expert.model, iteration=iteration,
        ))
        finding.review_error = err[:1000]
        expert._save_debate(db, finding.id, role, f"[unparseable response] {err[:300]}")
        publish_event(db, finding.job_id, EventType.FINDING_PARSE_ERROR, {
            "finding_id": finding.id, "expert": expert.name, "error": err[:300],
        })
        return None

    _persist_trace(db, finding, expert, res)
    v: ReviewVerdict = res.obj
    rationale = v.narrative or v.thinking or ""
    db.add(FindingVerdict(
        job_id=finding.job_id, finding_id=finding.id, expert=expert.name,
        persona=expert.persona, verdict=v.verdict, confidence=v.confidence,
        rationale=rationale[:2000], model=expert.model, iteration=iteration,
    ))
    expert._save_debate(db, finding.id, role, rationale[:1000],
                        thinking=v.thinking, confidence=v.confidence)
    return _V(expert.name, expert.persona, v.verdict, v.confidence, rationale, v)


def _persist_trace(db, finding, expert, res) -> None:
    """Persist an agent's tool-call trace as debate messages + agent.step events."""
    trace = getattr(res, "trace", None)
    if not trace:
        return
    for step in trace:
        args = step.get("args", {})
        arg_s = ", ".join(f"{k}={v}" for k, v in args.items())[:120]
        summary = f"{step.get('tool')}({arg_s})"
        expert._save_debate(db, finding.id, "tool_call", summary,
                            thinking=step.get("result_preview", "")[:300])
        publish_event(db, finding.job_id, EventType.AGENT_STEP, {
            "finding_id": finding.id, "expert": expert.name,
            "tool": step.get("tool"), "args": args,
            "result_preview": step.get("result_preview", "")[:200],
        })


def _peers_excluding(verdicts: list[_V], persona: str) -> list[dict]:
    return [
        {"persona": v.persona, "verdict": v.verdict, "confidence": v.confidence, "rationale": v.rationale}
        for v in verdicts if v.persona != persona
    ]


def _contested(valid: list[_V]) -> bool:
    labels = {v.verdict for v in valid}
    if len(labels) > 1:
        return True
    return any(UNCERTAIN_LOW <= v.confidence <= UNCERTAIN_HIGH for v in valid)


def _unanimous_confident(valid: list[_V]) -> bool:
    if not valid:
        return False
    labels = {v.verdict for v in valid}
    return (
        len(labels) == 1
        and next(iter(labels)) in ("confirmed", "refuted")
        and all(v.confidence >= CONFIDENT for v in valid)
    )


def _needs_mandatory_judge(finding: Finding, valid: list[_V]) -> bool:
    """Force the adversarial judge on a would-be-confirmed finding at/above the
    severity floor — independent of (unreliable) self-reported confidence, so the
    findings that matter always get an independent second opinion."""
    floor = settings.loop.judge_severity_floor
    if not floor or not valid or valid[0].verdict != "confirmed":
        return False
    sevs = [finding.severity] + [v.obj.severity for v in valid if v.obj and v.obj.severity]
    best_rank = min((SEVERITY_RANK.get(s, 99) for s in sevs), default=99)
    return best_rank <= SEVERITY_RANK.get(floor, 1)


def _apply_enrichment(finding: Finding, valid: list[_V]) -> None:
    """Take narrative/remediation/etc. from the most confident confirming expert."""
    confirming = sorted(
        [v for v in valid if v.verdict == "confirmed" and v.obj], key=lambda v: -v.confidence
    )
    if not confirming:
        return
    obj = confirming[0].obj
    finding.narrative = obj.narrative or finding.narrative
    finding.remediation = obj.remediation or finding.remediation
    finding.exploit_scenario = obj.exploit_scenario or finding.exploit_scenario
    if obj.cwe and not finding.cwe:
        finding.cwe = obj.cwe
    if obj.owasp and not finding.owasp:
        finding.owasp = obj.owasp
    if obj.severity:
        finding.severity = obj.severity


def _set_status(db, finding, status, confidence, iteration, reason=""):
    finding.status = status
    finding.confidence = confidence
    if status == "confirmed":
        finding.review_error = None
        publish_event(db, finding.job_id, EventType.FINDING_CONFIRMED, {
            "finding_id": finding.id, "confidence": confidence, "severity": finding.severity,
            "iteration": iteration,
        })
    elif status == "false_positive":
        finding.review_error = None
        publish_event(db, finding.job_id, EventType.FINDING_REFUTED, {
            "finding_id": finding.id, "reason": reason[:300],
        })


def _mean_conf(valid: list[_V]) -> float:
    return sum(v.confidence for v in valid) / len(valid) if valid else 0.5


def _apply_consensus(db, finding, valid, iteration):
    label = valid[0].verdict
    conf = _mean_conf(valid)
    if label == "confirmed":
        _apply_enrichment(finding, valid)
        _set_status(db, finding, "confirmed", conf, iteration)
    elif label == "refuted":
        _set_status(db, finding, "false_positive", conf, iteration)
    else:
        finding.status = "disputed"
        finding.confidence = conf


def _apply_judge(db, judge: JudgeExpert, finding, valid, iteration, budget):
    if not budget.take(1):
        # Out of budget: fall back to expert consensus if any, else leave for retry.
        if valid:
            _apply_consensus(db, finding, valid, iteration)
        else:
            finding.status = "unreviewed"
        return
    res = judge.invoke_judge(finding, [v.__dict__ for v in valid])
    if isinstance(res, Exception) or not res.ok:
        err = str(getattr(res, "error", res) or "judge parse failure")
        db.add(FindingVerdict(
            job_id=finding.job_id, finding_id=finding.id, expert="judge",
            persona=judge.persona, verdict="parse_error", confidence=0.0,
            rationale=err[:1000], model=judge.model, iteration=iteration,
        ))
        # Fall back to the experts' consensus rather than inventing a dispute.
        if valid:
            _apply_consensus(db, finding, valid, iteration)
        else:
            finding.status = "unreviewed"
            finding.review_error = err[:1000]
        return

    jv = res.obj
    db.add(FindingVerdict(
        job_id=finding.job_id, finding_id=finding.id, expert="judge",
        persona=judge.persona, verdict=jv.final_verdict, confidence=jv.final_confidence,
        rationale=(jv.reasoning or "")[:2000], model=judge.model, iteration=iteration,
    ))
    judge._save_debate(db, finding.id, "verdict", (jv.reasoning or "")[:1000],
                       thinking=jv.thinking, confidence=jv.final_confidence)
    publish_event(db, finding.job_id, EventType.JUDGE_VERDICT, {
        "finding_id": finding.id, "verdict": jv.final_verdict, "confidence": jv.final_confidence,
        "severity": jv.final_severity or finding.severity,
        "reasoning": (jv.reasoning or "")[:500],
        "false_positive_reason": jv.false_positive_reason,
    })
    if jv.final_severity:
        finding.severity = jv.final_severity
    if jv.final_verdict == "confirmed":
        _apply_enrichment(finding, valid)
        _set_status(db, finding, "confirmed", jv.final_confidence, iteration)
    elif jv.final_verdict == "refuted":
        _set_status(db, finding, "false_positive", jv.final_confidence, iteration,
                    reason=jv.false_positive_reason or "")
    else:
        finding.status = "disputed"
        finding.confidence = jv.final_confidence


def run_reviews(db: Session, review_experts, judge: JudgeExpert, findings, iteration, budget):
    """Deliberate over a batch of findings. Persists verdicts and final statuses."""
    if not findings:
        return

    relevant_map = {f.id: [e for e in review_experts if e.is_relevant(f)] for f in findings}

    # ---- Phase A: independent parallel reviews (always single-shot) ----
    # Selective agentic: Phase A stays cheap single-shot on every finding; tool
    # exploration is reserved for cross-examination (contested findings) and novel
    # discovery, where it actually pays off — this is what keeps agentic scans
    # bounded on real repos.
    tasks = [(f, e) for f in findings for e in relevant_map[f.id]]
    verdicts: dict[str, list[_V]] = {f.id: [] for f in findings}

    def _persist_incremental(t, res):
        f, e = t
        v = _persist_review(db, f, e, res, iteration, "review")
        if v is not None:
            verdicts[f.id].append(v)

    # Persist + stream each review as it completes (live council, and completed
    # work survives an interruption) instead of after the whole batch.
    _parallel(lambda t: t[1].invoke_review(t[0], budget=budget, agentic=False), tasks, budget,
              on_result=_persist_incremental)
    db.flush()

    # ---- Phase B: cross-exam (contested) + ruling ----
    for f in findings:
        valid = [v for v in verdicts[f.id] if v.verdict in ("confirmed", "refuted", "disputed")]
        relevant = relevant_map[f.id]

        if not relevant or not valid:
            # No domain expert (or all failed to parse): let the judge adjudicate directly.
            _apply_judge(db, judge, f, valid, iteration, budget)
            continue

        if _contested(valid) and len(relevant) > 1:
            publish_event(db, f.job_id, EventType.DEBATE_CROSS_EXAM, {
                "finding_id": f.id, "experts": [e.name for e in relevant],
            })
            # Cross-examination explores (agentic when the job enables it) — this
            # is a contested finding worth the tool budget.
            cross_tasks = [(f, e) for e in relevant]
            cross = _parallel(
                lambda t: t[1].invoke_review(
                    t[0], peers=_peers_excluding(valid, t[1].persona), budget=budget),
                cross_tasks, budget,
            )
            newv: list[_V] = []
            for (ff, e), res in cross:
                v = _persist_review(db, ff, e, res, iteration, "challenge")
                if v is not None:
                    newv.append(v)
            valid = [v for v in newv if v.verdict in ("confirmed", "refuted", "disputed")] or valid

        if _unanimous_confident(valid) and not _needs_mandatory_judge(f, valid):
            _apply_consensus(db, f, valid, iteration)
        else:
            _apply_judge(db, judge, f, valid, iteration, budget)
    db.flush()


# ---------------------------------------------------------------------------
# Novel-finding discovery (ungated: runs every iteration, incl. iteration 0)
# ---------------------------------------------------------------------------

_CODE_EXT = (".py", ".go", ".js", ".ts", ".jsx", ".tsx", ".java", ".rb", ".php",
             ".cs", ".rs", ".c", ".cpp", ".tf", ".yml", ".yaml",
             # templates + markup: where server-rendered XSS (e.g. {{x|safe}}) lives
             ".html", ".htm", ".jinja", ".jinja2", ".j2", ".ejs", ".erb", ".vue")
_ENTRY_HINTS = ("main", "app", "index", "server", "route", "handler", "api",
                "controller", "view", "template", "auth", "admin", "config", "settings")
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "vendor", "dist", "build"}

# Dangerous-sink patterns, language-agnostic where possible. Novel discovery ranks
# files by where these actually occur (not filename/size) and seeds the experts
# with the code AROUND the sink, so deep sinks (past a truncated head) and the
# right templates get looked at. Deterministic + cheap; the LLM still confirms, so
# a raw pattern hit is only a *lead*, never a finding. (label, weight, regex.)
_SINK_PATTERNS: list[tuple[str, int, re.Pattern]] = [
    ("ssrf", 3, re.compile(
        r"requests\.(?:get|post|put|patch|delete|request|head)\s*\("
        r"|urlopen\s*\(|httpx\.(?:get|post|put|patch|delete|request|Client)")),
    ("deserialization", 3, re.compile(
        r"pickle\.loads?\s*\(|yaml\.load\s*\((?![^)]*Safe)"
        r"|marshal\.loads\s*\(|jsonpickle|readObject\s*\(")),
    ("rce", 3, re.compile(
        r"\beval\s*\(|\bexec\s*\(|os\.system\s*\("
        r"|subprocess\.\w+\([^)]*shell\s*=\s*True|\bPopen\s*\([^)]*shell\s*=\s*True")),
    ("sqli", 3, re.compile(
        r"\.raw\s*\(|\.extra\s*\(|cursor\.execute\s*\([^)]*%|execute\s*\([^)]*\+")),
    ("xxe", 2, re.compile(
        r"feature_external_ges|resolve_entities\s*=\s*True|no_network\s*=\s*False")),
    ("xss", 2, re.compile(
        r"\|\s*safe\b|mark_safe\s*\(|autoescape[\s\"']+off"
        r"|render_template_string\s*\(|dangerouslySetInnerHTML|v-html|\.innerHTML\s*=")),
]
_LABEL_WEIGHT = {label: w for label, w, _ in _SINK_PATTERNS}
_MAX_SCAN_BYTES = 200_000   # cap per-file read for the hotspot scan
_MAX_HOTSPOTS_PER_FILE = 8  # bound windows/prompt size for very sink-dense files


def _scan_hotspots(text: str) -> list[tuple[int, str]]:
    """Return line-numbered sink leads [(line_no, class_label), ...] for `text`."""
    hits: list[tuple[int, str]] = []
    for i, line in enumerate(text.splitlines(), 1):
        for label, _w, rx in _SINK_PATTERNS:
            if rx.search(line):
                hits.append((i, label))
                break  # one label per line is enough
    return hits


def _rank_files(workspace: str, seen: set[str],
                limit: int = 12) -> list[tuple[str, list[tuple[int, str]]]]:
    """Sink-density-prioritized selection of source files not yet sampled.

    Ranks by weighted dangerous-sink hits (entrypoint-name hints only break ties),
    so the files that actually contain SSRF/deser/XSS/etc. sinks get looked at even
    in a large repo. Returns (relpath, hotspots) where hotspots is the capped list
    of (line, class) leads used to window the seed content.
    """
    cands: list[tuple[int, int, str, list[tuple[int, str]]]] = []  # (-score, size, rel, hotspots)
    for root, dirs, files in os.walk(workspace):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fn in files:
            if not fn.endswith(_CODE_EXT):
                continue
            rel = os.path.relpath(os.path.join(root, fn), workspace).replace(os.sep, "/")
            if rel in seen:
                continue
            low = rel.lower()
            try:
                with open(os.path.join(root, fn), encoding="utf-8", errors="replace") as fh:
                    text = fh.read(_MAX_SCAN_BYTES)
                size = len(text)
            except OSError:
                text, size = "", 0
            hotspots = _scan_hotspots(text)
            sink_score = sum(_LABEL_WEIGHT.get(lbl, 1) for _, lbl in hotspots)
            hint_score = sum(1 for h in _ENTRY_HINTS if h in low)
            # Sinks dominate; entrypoint hints only break ties among equal sink scores.
            score = sink_score * 10 + hint_score
            cands.append((-score, size, rel, hotspots[:_MAX_HOTSPOTS_PER_FILE]))
    # highest score first; among equals prefer smaller files (cheaper to read whole)
    cands.sort(key=lambda c: (c[0], c[1]))
    return [(rel, hs) for _, _, rel, hs in cands[:limit]]


# Seed-content shaping: focused windows around sinks beat a truncated file head.
_WINDOW = 15                # lines of context each side of a hotspot
_FALLBACK_HEAD = 60         # lines to show for a hotspot-free entrypoint file
_MAX_FILE_SEED_LINES = 160  # cap per-file seed content (keeps prompt/budget bounded)


def _seed_block(workspace: str, rel: str, hotspots: list[tuple[int, str]]) -> str:
    """Build the seed block for one file: line-numbered windows around each sink
    (labeled), or the file head when no sink was detected. Line numbers are kept so
    the expert can report an accurate line_start."""
    try:
        with open(os.path.join(workspace, rel), encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except Exception:
        return ""
    if not lines:
        return ""
    if hotspots:
        ranges = sorted((max(1, ln - _WINDOW), min(len(lines), ln + _WINDOW))
                        for ln, _lbl in hotspots)
        merged: list[list[int]] = []
        for s, e in ranges:
            if merged and s <= merged[-1][1] + 1:
                merged[-1][1] = max(merged[-1][1], e)
            else:
                merged.append([s, e])
        hint = ", ".join(f"{lbl}-candidate @L{ln}" for ln, lbl in hotspots)
        body, shown = "", 0
        for s, e in merged:
            for i in range(s, e + 1):
                if shown >= _MAX_FILE_SEED_LINES:
                    break
                body += f"{i}: {lines[i - 1]}"
                shown += 1
            body += "  ...\n"
            if shown >= _MAX_FILE_SEED_LINES:
                break
        return f"\n### {rel}\n⚠ hotspots: {hint}\n```\n{body}```\n"
    head = "".join(f"{i + 1}: {lines[i]}" for i in range(min(len(lines), _FALLBACK_HEAD)))
    return f"\n### {rel}\n```\n{head}```\n"


def collect_novel(db: Session, experts, job_id: str, workspace: str, iteration: int,
                  budget: LLMBudget, seen: set[str] | None = None) -> list[Finding]:
    """Ask experts to propose findings the tools missed, over a prioritized file sample.

    Dedupes proposals against existing findings by correlation_key so re-runs and
    tool overlaps don't create duplicates.
    """
    seen = seen if seen is not None else set()
    picked = _rank_files(workspace, seen, limit=12)
    if not picked:
        return []
    files_block = ""
    for rel, hotspots in picked:
        seen.add(rel)
        files_block += _seed_block(workspace, rel, hotspots)

    existing_keys = {
        f.correlation_key for f in db.query(Finding).filter(Finding.job_id == job_id).all()
        if f.correlation_key
    }

    review_experts = [e for e in experts if e.name not in ("judge", "redteam")]
    results = _parallel(lambda e: e.invoke_propose(files_block, budget=budget), review_experts, budget)

    novel: list[Finding] = []
    for expert, res in results:
        # Surface the exploration trace (job-level, not tied to a finding yet).
        for step in getattr(res, "trace", None) or []:
            args = step.get("args", {})
            arg_s = ", ".join(f"{k}={v}" for k, v in args.items())[:120]
            expert._save_debate(db, None, "tool_call", f"{step.get('tool')}({arg_s})",
                                thinking=step.get("result_preview", "")[:300])
            publish_event(db, job_id, EventType.AGENT_STEP, {
                "finding_id": None, "expert": expert.name, "tool": step.get("tool"),
                "args": args, "result_preview": step.get("result_preview", "")[:200],
            })
        if isinstance(res, Exception) or res is None or not getattr(res, "ok", False):
            continue
        for nf in res.obj.novel_findings:
            key = correlation_key(nf.file, nf.line_start, nf.cwe, nf.title)
            if key in existing_keys:
                continue
            existing_keys.add(key)
            f = Finding(
                job_id=job_id,
                hash=stable_finding_hash(nf.file, nf.line_start, f"expert:{expert.name}", nf.snippet),
                correlation_key=key,
                tool=f"expert:{expert.name}",
                rule_id=f"novel-{expert.name}",
                severity=nf.severity, confidence=nf.confidence,
                title=nf.title, description=nf.description,
                file=nf.file, line_start=nf.line_start, line_end=nf.line_end or nf.line_start,
                snippet=nf.snippet, cwe=nf.cwe, recommendation=nf.recommendation,
                status="raw", iteration=iteration,
            )
            db.add(f)
            db.flush()
            novel.append(f)
            publish_event(db, job_id, EventType.FINDING_NOVEL, {
                "finding_id": f.id, "expert": expert.name, "title": f.title, "file": f.file,
            })
    return novel


def build_attack_chains(db: Session, job_id: str, redteam, confirmed: list[Finding],
                        iteration: int, budget: LLMBudget) -> None:
    """Ask the red team to chain confirmed findings; persist AttackChains + per-finding paths."""
    if not confirmed or not budget.take(1):
        return
    res = redteam.invoke_chains(confirmed)
    budget.used += max(0, getattr(res, "llm_calls", 1) - 1)
    if not getattr(res, "ok", False):
        return
    by_id = {f.id: f for f in confirmed}
    per_finding: dict[str, list[dict]] = {}
    for path in res.obj.attack_paths:
        used = [fid for fid in path.findings_used if fid in by_id]
        chain = AttackChain(
            job_id=job_id, goal=path.goal[:256], steps=path.steps,
            likelihood=path.likelihood, iteration=iteration,
        )
        chain.findings = [by_id[fid] for fid in used]
        db.add(chain)
        path_dict = {"goal": path.goal, "steps": path.steps,
                     "likelihood": path.likelihood, "findings_used": used}
        for fid in used:
            per_finding.setdefault(fid, []).append(path_dict)
    # Each confirmed finding carries only the paths it actually participates in.
    for fid, paths in per_finding.items():
        by_id[fid].attack_paths = paths
    db.flush()
    publish_event(db, job_id, EventType.REDTEAM_CHAIN, {
        "chains": len(res.obj.attack_paths), "iteration": iteration,
    })
