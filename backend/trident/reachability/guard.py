"""apply_reachability_guard — the third monotonic cap in the triage pipeline.

Position in the pipeline (run_triage):
  LLM assessment → apply_corpus_guard → apply_class_guard → apply_reachability_guard → tier_for → chain bump

Like apply_class_guard this function is:
  - Cap-only (monotonic): it can lower attack_vector, never raise it.
  - Narrowly scoped: only fires when the analysis returns UNREACHABLE with high
    confidence (single definition site, full graph traversal).
  - Evidence-overridable: the chain bump in tier_for still runs afterwards, so
    a finding that is statically unreachable but participates in a proven attack
    chain still gets promoted by one tier.
"""

from __future__ import annotations

from trident.reachability.reach import ReachContext, Reachability

# Re-use the same rank table and cap helper as triage.py without importing
# the full module (which would create a circular dependency if triage ever
# imports this module at load time).
_VECTOR_RANK: dict[str, int] = {
    "remote_unauth": 4, "remote_auth": 3, "adjacent": 2, "local": 1, "physical": 0,
}


def _cap(value: str, ranks: dict, ceiling: str) -> str:
    return ceiling if ranks.get(value, 0) > ranks[ceiling] else value


def apply_reachability_guard(
    workspace: str,
    file: str,
    line_start: int,
    current_vector: str,
    ctx: ReachContext | None = None,
) -> tuple[str, str | None, str]:
    """Cap attack_vector to 'local' when the finding is statically unreachable
    from every HTTP entry point.

    Parameters
    ----------
    workspace       : absolute path to the scanned repository
    file            : workspace-relative path of the finding
    line_start      : 1-indexed line of the finding
    current_vector  : attack_vector after the class guard has run
    ctx             : pre-built ReachContext (build once per job in run_triage).
                      If None, one is built on demand (slow — for testing only).

    Returns
    -------
    (new_vector, note, status_str)
      new_vector  : the (potentially capped) attack_vector
      note        : human-readable guard note, or None when no cap was applied
      status_str  : raw Reachability value ("reachable"|"unreachable"|"unknown")
    """
    if not workspace or not file:
        return current_vector, None, Reachability.UNKNOWN.value

    try:
        c = ctx if ctx is not None else ReachContext.build(workspace)
        status, path = c.check(file, line_start)
    except Exception:
        return current_vector, None, Reachability.UNKNOWN.value

    if status is Reachability.UNREACHABLE:
        new_vec = _cap(current_vector, _VECTOR_RANK, "local")
        if new_vec != current_vector:
            note = (
                "reachability: no call path from any HTTP entry point to this "
                "function — attack vector capped to local"
            )
            return new_vec, note, status.value
        # Vector already local or lower — cap had no effect, skip the note
        return current_vector, None, status.value

    # REACHABLE or UNKNOWN → no-op (fail-open)
    return current_vector, None, status.value
