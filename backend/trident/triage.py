"""Triage — turn a pile of confirmed findings into a worked, prioritized queue.

For each confirmed finding the LLM assesses factors it can judge FROM THE CODE
(impact, attack vector, exploitability, fix effort — no deployment/arch context),
and a transparent rubric maps those factors to a priority tier P0..P4. Every tier
is explainable ("P0 because remote + unauthenticated + RCE + trivial"), so the
output is an auditable ordering, not a black-box score.

P0 is the "why is this in prod" set: catastrophic impact, reachable remotely
without authentication, trivially exploitable. Findings that participate in an
attack chain are bumped up a tier (jointly worse than alone).
"""

from __future__ import annotations

import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

from loguru import logger
from sqlalchemy.orm import Session

from trident.config import settings
from trident.events.publisher import EventType, publish_event
from trident.llm.base import ChatMessage
from trident.models import AttackChain, Finding, Job
from trident.prompts import TRIAGE_SYSTEM, build_triage_prompt
from trident.reliability.schemas import TriageAssessment
from trident.reliability.structured import chat_structured

# Factor → rank. Higher = worse. The rubric below reads these.
_IMPACT_RANK = {"rce": 4, "auth_bypass": 4, "data_exposure": 3, "data_tampering": 3,
                "ssrf": 3, "injection": 3, "dos": 2, "info_disclosure": 1, "other": 1}
_VECTOR_RANK = {"remote_unauth": 4, "remote_auth": 3, "adjacent": 2, "local": 1, "physical": 0}
_EXPLOIT_RANK = {"trivial": 2, "moderate": 1, "difficult": 0}

EXT_MAP = {
    ".py": "python", ".go": "go", ".js": "javascript", ".ts": "typescript",
    ".jsx": "javascript", ".tsx": "typescript", ".java": "java", ".rb": "ruby",
    ".php": "php", ".cs": "csharp", ".rs": "rust", ".tf": "hcl", ".yaml": "yaml",
    ".yml": "yaml", ".html": "html",
}

# Per-tier "how you work this" playbook — the actual deliverable a team uses.
PLAYBOOK = {
    "P0": {
        "label": "Fix now — critical, remotely exploitable without auth",
        "sla": "Immediate (out-of-band)",
        "how": "Treat as an incident, not a ticket: hotfix out of band now, verify the "
               "fix actually closes it, then review logs for signs it was already exploited.",
    },
    "P1": {
        "label": "Critical — fix this sprint",
        "sla": "~7 days",
        "how": "Assign an owner and commit it to the current sprint. Severe impact and "
               "remotely reachable, but gated by one condition (auth, user interaction, or "
               "not-yet-proven exploitation).",
    },
    "P2": {
        "label": "High — scheduled remediation",
        "sla": "~30 days",
        "how": "Group by component into a remediation epic so one pass fixes several. Real "
               "risk but gated (local access, lower impact, or a mitigating condition).",
    },
    "P3": {
        "label": "Moderate — backlog / batch",
        "sla": "~this quarter",
        "how": "Batch with related work or the next refactor of this component. Limited "
               "impact or hard to reach.",
    },
    "P4": {
        "label": "Low / hygiene",
        "sla": "Opportunistic",
        "how": "Fix opportunistically or risk-accept with a recorded rationale. Best-practice "
               "or defense-in-depth, not an exploitable hole on its own.",
    },
}
TIERS = ["P0", "P1", "P2", "P3", "P4"]


# --- Corpus guard ------------------------------------------------------------
# Uses the CWE profile corpus (built from NVD, EPSS, KEV, ExploitDB, OSV,
# Vulnrichment) to adjust findings the LLM mis-escalates — either too high or
# too low — relative to what the historical vulnerability population says about
# this weakness class.
#
# Bidirectional: same 285k-CVE evidence applies symmetrically.  Applying it
# only to downgrade while ignoring systematic under-escalation is inconsistent:
# a finding buried at P4 when 5,000+ CVEs say P1 is just as wrong as a P0 that
# should be P1.
#
# Properties shared with the class guard:
# - Deterministic: CWE ID → corpus DB lookup, zero LLM calls.
# - Evidence-gated: requires ≥ 200 CVEs in corpus for that CWE.
# - Chain-bump-safe: adjusts factors before tier_for; in_chain bump still runs
#   after, so a finding in a proven attack chain can still reach P0.
#
# _TIER_CEILINGS: (impact, vector) pair that produces AT MOST expected_tier.
# _TIER_FLOORS:   (impact, vector) pair that produces AT LEAST expected_tier.
# Both are excluded for P0 — auto-escalating to incident level is left to the
# attack-chain bump, which requires proven call-graph evidence.
_MIN_CORPUS_CVE_COUNT = 200
_TIER_CEILINGS = {
    # expected_tier: (impact_ceiling, vector_ceiling)
    "P1": ("data_tampering", "remote_auth"),   # rank 3/3 → tier_for → P1
    "P2": ("data_exposure",  "adjacent"),       # rank 3/2 → tier_for → P2
    "P3": ("dos",            "adjacent"),       # rank 2/2 → tier_for → P3
    "P4": ("info_disclosure","local"),          # rank 1/1 → tier_for → P4
}
_TIER_FLOORS = {
    # expected_tier: (impact_floor, vector_floor)
    "P1": ("data_tampering", "remote_auth"),   # rank 3/3 → tier_for → P1
    "P2": ("data_exposure",  "adjacent"),       # rank 3/2 → tier_for → P2
    "P3": ("dos",            "adjacent"),       # rank 2/2 → tier_for → P3
}

_corpus_cache: dict | None = None


def _corpus_profiles() -> dict:
    """Load cwe → {cve_count, expected_tier} from calibration DB (cached)."""
    global _corpus_cache
    if _corpus_cache is not None:
        return _corpus_cache
    try:
        from trident.calibration.corpus.db import get_db as _cal_db
        conn = _cal_db()
        conn.row_factory = None
        rows = conn.execute(
            "SELECT cwe, cve_count, expected_tier FROM cwe_profiles"
        ).fetchall()
        conn.close()
        _corpus_cache = {r[0]: {"cve_count": r[1], "expected_tier": r[2]} for r in rows}
    except Exception:
        _corpus_cache = {}
    return _corpus_cache


def _raise(value: str, ranks: dict, floor: str) -> str:
    """Raise `value` to `floor` if it ranks lower; otherwise leave it."""
    return floor if ranks.get(floor, 0) > ranks.get(value, 0) else value


def apply_corpus_guard(
    f: Finding, a: TriageAssessment, current_impact: str, current_vector: str,
) -> tuple[str, str, str | None]:
    """Adjust (impact, vector) when the CWE corpus disagrees with the LLM's tier.

    Bidirectional: caps over-escalations down AND raises under-escalations up.
    Runs BEFORE the code-grounded guards (class guard, reachability guard) so
    that those guards act as definitive overrides on corpus output — a crypto
    finding raised by corpus is knocked back down by the class guard.

    P0 is excluded from both directions — auto-incident requires chain evidence.
    Returns (new_impact, new_vector, note_or_None).
    """
    cwe = f.cwe
    if not cwe:
        return current_impact, current_vector, None

    profile = _corpus_profiles().get(cwe)
    if not profile or not profile["expected_tier"]:
        return current_impact, current_vector, None
    if profile["cve_count"] < _MIN_CORPUS_CVE_COUNT:
        return current_impact, current_vector, None

    expected = profile["expected_tier"]
    current_tier_num = int(
        tier_for(a, False, impact=current_impact, attack_vector=current_vector)[1]
    )
    expected_tier_num = int(expected[1])

    if expected_tier_num == current_tier_num:
        return current_impact, current_vector, None

    if expected_tier_num > current_tier_num:
        # Over-escalation: cap down to corpus ceiling.
        if expected not in _TIER_CEILINGS:
            return current_impact, current_vector, None
        ref_impact, ref_vector = _TIER_CEILINGS[expected]
        new_impact = _cap(current_impact, _IMPACT_RANK, ref_impact)
        new_vector = _cap(current_vector, _VECTOR_RANK, ref_vector)
        direction = "↓"
    else:
        # Under-escalation: raise up to corpus floor.
        if expected not in _TIER_FLOORS:
            return current_impact, current_vector, None
        ref_impact, ref_vector = _TIER_FLOORS[expected]
        new_impact = _raise(current_impact, _IMPACT_RANK, ref_impact)
        new_vector = _raise(current_vector, _VECTOR_RANK, ref_vector)
        direction = "↑"

    if new_impact == current_impact and new_vector == current_vector:
        return current_impact, current_vector, None

    note = (
        f"corpus-guard{direction}: {cwe} (n={profile['cve_count']:,} CVEs) "
        f"expected {expected}, LLM assessed P{current_tier_num} — "
        f"impact {current_impact}→{new_impact}, vector {current_vector}→{new_vector}"
    )
    return new_impact, new_vector, note


# --- Class guard -------------------------------------------------------------
# Two finding classes are systematically over-rated `remote_unauth` by LLMs
# (both gemma and nemotron do it): hardcoded secrets and best-practice hygiene.
# From code alone their reachability is genuinely ambiguous, so the model defaults
# to the scariest reading and everything lands P0. A deterministic guard caps
# their reachability to what's actually true, so they can't reach P0 without a
# proven attack chain (the chain bump is the "unless reachable" escape hatch).
#
# SECRET: a hardcoded literal secret/key/credential. Exploiting it requires
#   READING THE SOURCE -> vector is local, not a remote request. (We match
#   `hardcod`/gitleaks/`secret-detected` specifically, so genuinely-remote
#   lookalikes like predictable/forgeable tokens are NOT caught.)
# HYGIENE: weak crypto, insecure randomness, missing-CSRF, debug mode,
#   bind-all-interfaces, try/except/pass — defense-in-depth, not a direct hole.
_SECRET_RE = re.compile(
    r"hardcod|secret[- ]?detected|secrets\.security|detected-jwt|jwt-hardcode"
    r"|jwt-python-hardcoded|generic-api-key", re.I)
_HYGIENE_RE = re.compile(
    r"\bmd5\b|\bsha1\b|weak[- ]?(?:md5|hash|crypto|cipher)|pseudo[- ]?random"
    r"|insecure[- ]?random|\bcsrf\b|debug|avoid_app_run|app[-_ ]?run[-_ ]?param"
    r"|all[- ]?interfaces|binding to all|try.{0,5}except.{0,5}pass|\bassert\b", re.I)


def _classify(f: Finding) -> str | None:
    """Return 'secret' | 'hygiene' | None for the class guard. Secret wins ties."""
    hay = f"{f.rule_id or ''} {f.title or ''} {f.cwe or ''}"
    if (f.tool or "") == "gitleaks" or _SECRET_RE.search(hay):
        return "secret"
    if _HYGIENE_RE.search(hay):
        return "hygiene"
    return None


def _cap(value: str, ranks: dict, ceiling: str) -> str:
    """Lower `value` to `ceiling` if it ranks higher; otherwise leave it."""
    return ceiling if ranks.get(value, 0) > ranks[ceiling] else value


def apply_class_guard(
    f: Finding, a: TriageAssessment,
    current_impact: str | None = None,
    current_vector: str | None = None,
) -> tuple[str, str, str | None]:
    """Return (impact, attack_vector, guard_note) after the deterministic cap.

    current_impact / current_vector: values to cap (post-corpus when corpus runs
    first).  Defaults to the LLM assessment values for backwards compatibility.
    guard_note is None when no class matched (factors pass through unchanged).
    """
    imp = current_impact if current_impact is not None else a.impact
    vec = current_vector if current_vector is not None else a.attack_vector
    cls = _classify(f)
    if cls == "secret":
        return (
            _cap(imp, _IMPACT_RANK, "data_exposure"),
            _cap(vec, _VECTOR_RANK, "local"),
            "secret-class: exploiting a hardcoded secret needs source access "
            "(vector capped to local; impact to data_exposure) — not remotely "
            "reachable unauthenticated unless a chain proves otherwise",
        )
    if cls == "hygiene":
        return (
            _cap(imp, _IMPACT_RANK, "dos"),
            _cap(vec, _VECTOR_RANK, "local"),
            "hygiene-class: best-practice/defense-in-depth, not a directly "
            "reachable hole (vector capped to local; impact to dos)",
        )
    return imp, vec, None


def tier_for(a: TriageAssessment, in_chain: bool = False,
             impact: str | None = None, attack_vector: str | None = None) -> str:
    """Transparent rubric: factors -> P0..P4. Chained findings bump up one tier.
    `impact`/`attack_vector` override the assessment's values (used by the class
    guard); exploitability always comes from the assessment."""
    imp = _IMPACT_RANK.get(impact or a.impact, 1)
    vec = _VECTOR_RANK.get(attack_vector or a.attack_vector, 1)
    exp = _EXPLOIT_RANK.get(a.exploitability, 1)
    if imp >= 4 and vec >= 4 and exp >= 2:
        t = 0   # catastrophic + internet-facing unauth + trivially exploitable
    elif imp >= 3 and vec >= 3:
        t = 1   # high impact, remotely reachable
    elif imp >= 3 or (imp >= 2 and vec >= 3):
        t = 2   # high but gated, or medium impact reachable remotely
    elif imp >= 2:
        t = 3   # medium
    else:
        t = 4   # info / hygiene
    if in_chain and t > 0:
        t -= 1  # part of an attack chain -> more urgent than alone
    return f"P{t}"


# Start of a function/method/route — where auth decorators + guards live.
_DEF_RE = re.compile(r"^\s*(async\s+def |def |func |function\b|fun |sub |class )")
_MAX_CTX_CHARS = 4000


def _read_context(workspace: str, path: str, line_start: int, line_end: int, after: int = 12) -> str:
    """Read the ENCLOSING function (with its decorators) around the finding, not just
    a few lines — so triage can see the route's auth guard (@login_required,
    is_authenticated, permission checks) and judge reachability correctly."""
    full = os.path.realpath(os.path.join(workspace, path or ""))
    ws = os.path.realpath(workspace)
    if not full.startswith(ws):
        return ""
    try:
        with open(full, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception:
        return ""
    if not line_start:
        return "".join(f"{i+1}: {lines[i]}" for i in range(min(len(lines), 200)))

    idx = min(line_start - 1, len(lines) - 1)
    start = max(0, idx - 60)  # fallback window if no def found
    for i in range(idx, max(-1, idx - 60), -1):
        if _DEF_RE.match(lines[i]):
            start = i
            # include contiguous decorators / comments / blanks directly above the def
            j = i - 1
            while j >= 0 and (lines[j].lstrip().startswith(("@", "#")) or not lines[j].strip()):
                start = j
                j -= 1
            break
    end = min(len(lines), (line_end or line_start) + after)
    body = "".join(f"{i+1}: {lines[i]}" for i in range(start, end))
    return body[:_MAX_CTX_CHARS]


def _assess(workspace: str, finding: Finding, budget) -> TriageAssessment:
    """DB-free LLM assessment of one finding's triage factors."""
    if budget is not None and not budget.take(1):
        return TriageAssessment()  # out of budget -> conservative default
    snippet = _read_context(workspace, finding.file, finding.line_start, finding.line_end)
    ext = EXT_MAP.get(os.path.splitext(finding.file or "")[1].lower(), "text")
    prompt = build_triage_prompt(finding, snippet, ext)
    res = chat_structured(
        [ChatMessage("system", TRIAGE_SYSTEM), ChatMessage("user", prompt)],
        TriageAssessment, model=settings.llm.triage_model or settings.llm.default_model,
        temperature=0.0,
    )
    return res.obj if res.ok else TriageAssessment()


def run_triage(db: Session, job_id: str, budget=None) -> dict:
    """Assess + prioritize every confirmed finding for a job. Persists priority + factors."""
    job = db.get(Job, job_id)
    workspace = job.workspace_path if job else ""
    findings = db.query(Finding).filter(
        Finding.job_id == job_id, Finding.status == "confirmed"
    ).all()
    if not findings:
        return {"counts": {t: 0 for t in TIERS}, "total": 0}

    chains = db.query(AttackChain).filter(AttackChain.job_id == job_id).all()
    chained_ids = {f.id for c in chains for f in c.findings}

    publish_event(db, job_id, EventType.TRIAGE_START, {"findings": len(findings)})

    # Build the reachability context once for all findings in this job.
    # Fails gracefully to None — every guard call will then return UNKNOWN.
    _reach_ctx = None
    if workspace:
        try:
            from trident.reachability.reach import ReachContext
            _reach_ctx = ReachContext.build(workspace)
        except Exception:
            logger.warning("reachability graph build failed — guard disabled for this run")

    # LLM assessments run DB-free in a bounded pool; persistence on this thread.
    workers = max(1, settings.llm.concurrency)
    assessments: dict[str, TriageAssessment] = {}
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(_assess, workspace, f, budget): f for f in findings}
        for fut in as_completed(futs):
            f = futs[fut]
            try:
                assessments[f.id] = fut.result()
            except Exception:
                logger.exception("triage assessment failed")
                assessments[f.id] = TriageAssessment()

    counts = {t: 0 for t in TIERS}
    for f in findings:
        a = assessments.get(f.id) or TriageAssessment()
        in_chain = f.id in chained_ids

        # Guard 1 — corpus guard: statistical pre-processor on raw LLM output.
        # Bidirectional: raises under-escalations, caps over-escalations.
        # Runs FIRST so code-grounded guards can override its output.
        impact, vector, corpus_note = apply_corpus_guard(f, a, a.impact, a.attack_vector)

        # Guard 2 — class guard: deterministic, monotonic cap for secret/hygiene.
        # Overrides corpus output for known over-escalation classes (e.g. a corpus
        # raise on weak crypto is knocked back down here).
        impact, vector, guard_note = apply_class_guard(f, a, impact, vector)

        # Guard 3 — reachability guard: caps vector to local when no HTTP entry
        # point can reach this function.  Runs last of the code-grounded guards —
        # most specific evidence (this particular function's accessibility).
        from trident.reachability.guard import apply_reachability_guard
        vector, reach_note, reachability = apply_reachability_guard(
            workspace, f.file or "", f.line_start or 0, vector, _reach_ctx
        )

        tier = tier_for(a, in_chain, impact=impact, attack_vector=vector)
        f.priority = tier
        f.triage = {
            "impact": impact, "attack_vector": vector,
            "exploitability": a.exploitability, "fix_effort": a.fix_effort,
            "rationale": a.rationale, "in_chain": in_chain,
            "model_impact": a.impact, "model_attack_vector": a.attack_vector,
            "guard": guard_note,
            "reach_guard": reach_note,
            "reachability": reachability,
            "corpus_guard": corpus_note,
        }
        counts[tier] += 1
    db.commit()
    publish_event(db, job_id, EventType.TRIAGE_COMPLETE, {"counts": counts})
    logger.info(f"triage[{job_id}]: {counts}")
    return {"counts": counts, "total": len(findings)}
