"""Eval matcher — match findings against the ground-truth scorecard.

Strategy (deliberately not line-exact, to avoid gaming):
1. Candidate set per scorecard item: findings in the same file.
2. Semantic confirmation via embeddings cosine similarity, with a bonus when
   the CWE also agrees (so CWE agreement is rewarded, not required).
3. One finding satisfies at most one scorecard item.

Only *planted* items count toward recall. The decoy is scored separately: a
finding that matches the decoy is a false-positive-resistance failure, never a
detection, and missing the decoy is never penalized.
"""

from __future__ import annotations

import hashlib
import math
import os
from dataclasses import dataclass
from typing import Any

from loguru import logger

try:
    import tomllib  # py311+
except ImportError:  # pragma: no cover
    import tomli as tomllib  # type: ignore

import re

from trident.config import settings
from trident.llm.base import llm

# A same-file candidate is accepted when its combined score clears this bar, OR
# when it agrees structurally (same CWE AND overlapping lines). Semantic prose
# similarity alone is unreliable against terse tool messages, so CWE and line
# agreement each contribute a bonus.
ACCEPT_THRESHOLD = 0.75
CWE_BONUS = 0.15
LINE_BONUS = 0.20
LINE_WINDOW = 8  # lines of slack when comparing a finding's range to an item's


@dataclass
class ScorecardItem:
    id: str
    cwe: str
    owasp: str
    severity: str
    title: str
    file: str
    line_start: int
    line_end: int
    description: str
    expected_by: list[str]
    planted: bool
    package: str = ""  # for dependency items: the vulnerable package name


@dataclass
class Scorecard:
    target_id: str
    version: str
    vulns: list[ScorecardItem]


def load_scorecard(path: str) -> Scorecard | None:
    if not os.path.exists(path):
        return None
    with open(path, "rb") as f:
        data = tomllib.load(f)
    target = data.get("target", {})
    vulns = []
    for v in data.get("vulns", []):
        vulns.append(ScorecardItem(
            id=v["id"], cwe=v.get("cwe", ""), owasp=v.get("owasp", ""),
            severity=v.get("severity", ""), title=v.get("title", ""),
            file=v.get("file", ""), line_start=v.get("line_start", 0),
            line_end=v.get("line_end", 0), description=v.get("description", ""),
            expected_by=v.get("expected_by", []), planted=v.get("planted", True),
            package=v.get("package", ""),
        ))
    return Scorecard(target_id=target.get("id", ""), version=target.get("version", ""), vulns=vulns)


# ---- embeddings (cached + batched) -------------------------------------------

_EMB_CACHE: dict[str, list[float]] = {}


def _emb_key(text: str) -> str:
    return hashlib.sha256(text[:1000].encode("utf-8", "replace")).hexdigest()


def prefetch_embeddings(texts: list[str]) -> None:
    """Embed all novel texts in one batched call, populating the cache."""
    uniq: list[str] = []
    seen: set[str] = set()
    for t in texts:
        t2 = (t or "")[:1000]
        if not t2:
            continue
        k = _emb_key(t2)
        if k in _EMB_CACHE or k in seen:
            continue
        seen.add(k)
        uniq.append(t2)
    if not uniq:
        return
    try:
        embs = llm().embed(uniq, model=settings.llm.embedding_model)
        for t, e in zip(uniq, embs):
            _EMB_CACHE[_emb_key(t)] = e
    except Exception as e:  # pragma: no cover - network dependent
        logger.warning(f"Batch embedding failed ({e}); will fall back to token overlap")


def _embed_cached(text: str) -> list[float] | None:
    t = (text or "")[:1000]
    if not t:
        return None
    k = _emb_key(t)
    if k in _EMB_CACHE:
        return _EMB_CACHE[k]
    try:
        emb = llm().embed([t], model=settings.llm.embedding_model)[0]
        _EMB_CACHE[k] = emb
        return emb
    except Exception as e:  # pragma: no cover - network dependent
        logger.warning(f"Embedding failed ({e}); using token overlap")
        return None


def _cosine(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def _semantic_sim(a: str, b: str) -> float:
    """Embedding-based cosine similarity (falls back to token overlap)."""
    if not a or not b:
        return 0.0
    ea, eb = _embed_cached(a), _embed_cached(b)
    if ea is not None and eb is not None:
        return _cosine(ea, eb)
    sa, sb = set(a.lower().split()), set(b.lower().split())
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


# ---- matching ----------------------------------------------------------------

def _same_file(f: dict, item: ScorecardItem) -> bool:
    """Match paths across absolute/relative and Windows/POSIX spellings."""
    ff = str(f.get("file", "") or "").replace("\\", "/").strip()
    expected = str(item.file or "").replace("\\", "/").strip()
    while ff.startswith("./"):
        ff = ff[2:]
    while expected.startswith("./"):
        expected = expected[2:]
    return bool(ff and expected) and (
        ff == expected
        or ff.endswith("/" + expected)
        or expected.endswith("/" + ff)
    )


def _norm_cwe(s: str | None) -> str:
    """Normalize a CWE string to canonical 'CWE-<n>' (strips '.html', prefixes, casing)."""
    if not s:
        return ""
    m = re.search(r"(\d+)", str(s))
    return f"CWE-{m.group(1)}" if m else str(s).strip().upper()


def _line_prox(f: dict, item: ScorecardItem, window: int = LINE_WINDOW) -> bool:
    """True if the finding's line range overlaps the item's, within a slack window."""
    fs = f.get("line_start") or 0
    fe = f.get("line_end") or fs
    is_ = item.line_start or 0
    ie = item.line_end or is_
    if not fs or not is_:
        return False
    return fs <= ie + window and is_ <= fe + window


def _finding_text(f: dict) -> str:
    """Composite text for a finding — richer than the terse tool description alone."""
    rule = str(f.get("rule_id", "")).replace(".", " ").replace("-", " ").replace("_", " ")
    parts = [f.get("title", ""), f.get("description", ""), f.get("narrative", "") or "", rule]
    return " ".join(p for p in parts if p)


def _item_text(item: ScorecardItem) -> str:
    return f"{item.title} {item.description}"


def _best_match(
    item: ScorecardItem, findings: list[dict], used: set[str], accept_threshold: float,
    *, structural_only: bool = False,
) -> tuple[dict | None, float]:
    """Best same-file finding for an item using a multi-signal score.

    A candidate is accepted when it agrees structurally (same normalized CWE AND
    overlapping lines, or the named package) or when semantic similarity plus
    CWE/line bonuses clear the threshold. Line proximity is only ever a
    *contributor*, never sufficient alone.

    With `structural_only`, only structural matches are considered — used for a
    first assignment pass so a weak semantic match can't steal a finding that
    structurally belongs to another item.
    """
    best: dict | None = None
    best_score = 0.0
    pkg_re = re.compile(rf"\b{re.escape(item.package)}\b", re.IGNORECASE) if item.package else None
    for f in findings:
        if f.get("id") in used or not _same_file(f, item):
            continue
        cwe_ok = bool(_norm_cwe(f.get("cwe")) and _norm_cwe(f.get("cwe")) == _norm_cwe(item.cwe))
        line_ok = _line_prox(f, item)
        ftext = _finding_text(f)
        # Dependency items: the vulnerable package named in the same manifest is a
        # decisive match — CVE findings carry per-CVE CWEs (not CWE-1035) and no
        # line, so CWE/line signals don't apply to them. Match the package only
        # against the finding's title (a package name like "requests" is a common
        # English word and shows up incidentally in narrative prose).
        pkg_ok = bool(pkg_re and pkg_re.search(f.get("title", "") or ""))
        structural = (cwe_ok and line_ok) or pkg_ok
        if structural_only and not structural:
            continue
        sim = _semantic_sim(_item_text(item), ftext)
        score = sim + (CWE_BONUS if cwe_ok else 0.0) + (LINE_BONUS if line_ok else 0.0)
        score = min(1.0, score)
        if (structural or score >= accept_threshold) and score > best_score:
            best, best_score = f, (1.0 if structural and score < accept_threshold else score)
    return best, best_score


def match_findings(scorecard: Scorecard, findings: list[dict], *,
                   accept_threshold: float = ACCEPT_THRESHOLD) -> dict[str, Any]:
    """Match findings (dicts) against scorecard items. Returns full eval result.

    `findings` should be the system's *asserted* set (confirmed findings): recall
    and precision are both computed over it.
    """
    # Warm the embedding cache with one batched call.
    prefetch_embeddings(
        [_item_text(it) for it in scorecard.vulns] + [_finding_text(f) for f in findings]
    )

    planted_items = [it for it in scorecard.vulns if it.planted]
    decoy_items = [it for it in scorecard.vulns if not it.planted]

    matched: list[dict] = []
    missed: list[dict] = []
    decoy_hits: list[dict] = []
    used_finding_ids: set[str] = set()
    matches_by_item: dict[str, tuple[dict, float]] = {}

    # Two passes so a weak semantic match can't steal a finding that structurally
    # belongs to another item: assign all structural (CWE+line / package) matches
    # first, then fill remaining items with semantic matches.
    for structural_only in (True, False):
        for item in planted_items:
            if item.id in matches_by_item:
                continue
            best, best_score = _best_match(
                item, findings, used_finding_ids, accept_threshold,
                structural_only=structural_only,
            )
            if best is not None:
                matches_by_item[item.id] = (best, best_score)
                used_finding_ids.add(best["id"])

    # Planted items drive recall.
    for item in planted_items:
        if item.id in matches_by_item:
            best, best_score = matches_by_item[item.id]
            tool = best.get("tool", "?")
            matched.append({
                "scorecard_id": item.id, "finding_id": best["id"], "score": round(best_score, 3),
                "title": item.title, "cwe": item.cwe, "tool": tool,
                "expected_by": item.expected_by, "by_expected": tool in (item.expected_by or []),
            })
        else:
            missed.append({"scorecard_id": item.id, "title": item.title, "cwe": item.cwe,
                           "file": item.file, "description": item.description,
                           "expected_by": item.expected_by})

    # Decoy items: a match is an FP-resistance failure, not a detection.
    for item in decoy_items:
        best, best_score = _best_match(item, findings, used_finding_ids, accept_threshold)
        if best is not None:
            decoy_hits.append({"scorecard_id": item.id, "finding_id": best["id"],
                               "score": round(best_score, 3), "title": item.title})
            used_finding_ids.add(best["id"])

    false_positives = [
        {"finding_id": f.get("id"), "title": f.get("title"), "cwe": f.get("cwe"),
         "file": f.get("file"), "severity": f.get("severity")}
        for f in findings if f.get("id") not in used_finding_ids
    ]

    total_planted = len(planted_items)
    total_detected = len(matched)
    total_findings = len(findings)
    recall = total_detected / total_planted if total_planted else 0.0
    precision = total_detected / total_findings if total_findings else 0.0

    # Attribution: of the planted vulns we caught, how many came from an expected source.
    as_expected = sum(1 for m in matched if m["by_expected"])
    attribution = {
        "as_expected": as_expected,
        "unexpected_source": total_detected - as_expected,
        "accuracy": round(as_expected / total_detected, 4) if total_detected else 0.0,
    }

    per_cwe: dict[str, dict] = {}
    for item in planted_items:
        per_cwe.setdefault(item.cwe, {"planted": 0, "detected": 0})
        per_cwe[item.cwe]["planted"] += 1
    for m in matched:
        per_cwe.setdefault(m["cwe"], {"planted": 0, "detected": 0})
        per_cwe[m["cwe"]]["detected"] += 1
    for cwe, stats in per_cwe.items():
        stats["recall"] = stats["detected"] / stats["planted"] if stats["planted"] else 0.0

    per_tool: dict[str, int] = {}
    per_expert: dict[str, int] = {}
    for m in matched:
        tool = m.get("tool", "?")
        per_tool[tool] = per_tool.get(tool, 0) + 1
        if str(tool).startswith("expert:"):
            per_expert[tool] = per_expert.get(tool, 0) + 1

    return {
        "recall": round(recall, 4), "precision": round(precision, 4),
        "total_planted": total_planted, "total_detected": total_detected,
        "total_findings": total_findings,
        "matched": matched, "missed": missed, "false_positives": false_positives,
        "decoy_hits": decoy_hits, "attribution": attribution,
        "per_cwe": per_cwe, "per_tool": per_tool, "per_expert": per_expert,
    }


def match_with_iterations(scorecard: Scorecard, findings_by_iter: dict[int, list[dict]]) -> dict:
    """Compute cumulative recall per iteration for the loop-value curve.

    The embedding cache makes the repeated cumulative passes cheap.
    """
    per_iteration = []
    cumulative: list[dict] = []
    last: dict | None = None
    for it in sorted(findings_by_iter.keys()):
        cumulative.extend(findings_by_iter[it])
        last = match_findings(scorecard, cumulative)
        per_iteration.append({"iteration": it, "recall": last["recall"],
                              "detected": last["total_detected"]})
    if last is None:
        last = match_findings(scorecard, [])
    last["per_iteration"] = per_iteration
    return last
