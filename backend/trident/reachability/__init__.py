"""Reachability analysis — static call-graph-backed evidence for triage.

This module is intentionally fail-open: it returns UNKNOWN rather than
UNREACHABLE whenever it cannot trace a finding's function through the graph
with confidence.  A false UNREACHABLE cap silently suppressing a real P0 is
far worse than a missed cap on a false positive.

Public API
----------
ReachContext.build(workspace)   → ReachContext   (call once per triage run)
check(ctx, file, line_start)    → (Reachability, path)
apply_reachability_guard(...)   → (new_vector, note | None, status)
"""

from trident.reachability.reach import Reachability, ReachContext, check  # noqa: F401
from trident.reachability.guard import apply_reachability_guard  # noqa: F401
