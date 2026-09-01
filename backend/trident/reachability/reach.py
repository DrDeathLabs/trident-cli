"""Reachability check — BFS from HTTP entry points to a finding's function.

Key invariants
--------------
1. Fail-open: UNKNOWN is returned whenever the graph is incomplete, the target
   function has multiple definition sites (ambiguous), or the BFS budget is
   exceeded.  UNREACHABLE is only returned when the target has EXACTLY ONE
   definition site AND the full graph was traversed without reaching it.
2. Asymmetric error cost: a false UNREACHABLE cap on a real P0 is far worse
   than a missed cap on a false positive.  The BFS budget and the single-def
   requirement are both defences of this invariant.
3. Zero LLM calls — pure static analysis.

Usage
-----
    ctx = ReachContext.build(workspace)          # once per triage run
    status, path = ctx.check(file, line_start)   # per finding
"""

from __future__ import annotations

import os
import re
from collections import deque
from dataclasses import dataclass, field
from enum import Enum

from trident.reachability.entrypoints import EntryPoint, find_entry_points, find_route_files
from trident.reachability.graph import CallGraph, Node, build as build_graph

# Matches function definitions and captures the name.
# Group 1: Python / JS / Kotlin / VB — def|function|fun|sub Name(
# Group 2: Go — func Name(  OR  func (recv T) Name(
_DEF_RE = re.compile(
    r"^\s*(?:async\s+)?(?:def|function|fun|sub)\s+(\w+)\s*[\(:]"
    r"|^\s*func\s+(?:\([^)]{0,120}\)\s+)?(\w+)\s*\(",
    re.M,
)
_MAX_NODES = 10_000   # BFS budget — avoids O(N²) on pathological graphs


class Reachability(str, Enum):
    REACHABLE   = "reachable"
    UNREACHABLE = "unreachable"
    UNKNOWN     = "unknown"     # fail-open: analysis incomplete or ambiguous


@dataclass
class ReachContext:
    """Pre-built graph + entry points for one triage run (one workspace)."""
    workspace:    str
    graph:        CallGraph
    entry_points: list[EntryPoint] = field(default_factory=list)
    route_files:  frozenset[str]   = field(default_factory=frozenset)

    @classmethod
    def build(cls, workspace: str) -> "ReachContext":
        return cls(
            workspace=workspace,
            graph=build_graph(workspace),
            entry_points=find_entry_points(workspace),
            route_files=find_route_files(workspace),
        )

    def check(
        self,
        file: str,
        line_start: int,
        *,
        _func_override: str | None = None,   # test-only; skip file I/O
    ) -> tuple[Reachability, list[str]]:
        """Return (status, call_path) for the finding at (file, line_start).

        call_path is a list of "file::func" strings from entry point to target,
        empty for UNKNOWN and UNREACHABLE.
        """
        func = _func_override or self._enclosing_func(file, line_start)

        # Finding is inside an inline route handler (no named enclosing function)
        # in a file that registers HTTP routes — the whole file is handler territory.
        if func is None and file in self.route_files:
            return Reachability.REACHABLE, [f"{file}::<inline-route-handler>"]

        return _bfs(self, func)

    def _enclosing_func(self, file: str, line_start: int) -> str | None:
        full = os.path.realpath(os.path.join(self.workspace, file or ""))
        ws   = os.path.realpath(self.workspace)
        if not full.startswith(ws):
            return None
        try:
            with open(full, encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except Exception:
            return None
        idx = min(max((line_start or 1) - 1, 0), len(lines) - 1)
        # Scan forward first (up to 4 lines) to handle decorator-line findings:
        # a finding on @app.route(...) is conceptually inside the decorated def,
        # which follows immediately.  Forward scan takes priority if found quickly.
        for i in range(idx, min(len(lines), idx + 4)):
            m = _DEF_RE.match(lines[i])
            if m:
                return m.group(1) or m.group(2)
        # Fall back to backward scan for findings inside a function body.
        for i in range(idx - 1, max(-1, idx - 80), -1):
            m = _DEF_RE.match(lines[i])
            if m:
                return m.group(1) or m.group(2)
        return None


# Module-level alias so callers can do: from trident.reachability import check
def check(
    ctx: ReachContext,
    file: str,
    line_start: int,
    *,
    _func_override: str | None = None,
) -> tuple[Reachability, list[str]]:
    return ctx.check(file, line_start, _func_override=_func_override)


def _bfs(ctx: ReachContext, target_name: str | None) -> tuple[Reachability, list[str]]:
    if not target_name:
        return Reachability.UNKNOWN, []

    cg = ctx.graph

    # Target not found in graph → UNKNOWN (unparse-able file, external dep, etc.)
    if target_name not in cg.defs:
        return Reachability.UNKNOWN, []

    # If the target itself is an entry point → trivially REACHABLE
    for ep in ctx.entry_points:
        if ep.func_name == target_name:
            return Reachability.REACHABLE, [f"{ep.file}::{ep.func_name}"]

    # Named function defined inside a route-registration file — the file is HTTP
    # handler territory, so the function is reachable from inline route handlers
    # in the same file even without a call-graph path to a named entry point.
    target_defs = cg.defs.get(target_name, [])
    if len(target_defs) == 1 and target_defs[0][0] in ctx.route_files:
        return Reachability.REACHABLE, [f"{target_defs[0][0]}::{target_name}"]

    # No entry points detected at all — graph is incomplete; fail-open.
    if not ctx.entry_points:
        return Reachability.UNKNOWN, []

    # BFS from all entry points.
    # IMPORTANT: a function registered in urls.py is DEFINED in views.py, so
    # (urls.py, func_name) won't exist in the call graph.  Resolve each entry
    # point to its actual definition site(s) before seeding the queue.
    visited: set[Node] = set()
    queue: deque[tuple[Node, list[str]]] = deque()

    for ep in ctx.entry_points:
        ep_label = f"{ep.file}::{ep.func_name}"
        # Use definition sites when available (may be 1 or multiple files)
        seeds: list[Node] = cg.defs.get(ep.func_name) or [(ep.file, ep.func_name)]
        for start in seeds:
            if start not in visited:
                visited.add(start)
                queue.append((start, [ep_label]))

    while queue and len(visited) < _MAX_NODES:
        node, path = queue.popleft()
        for callee in cg.callee_nodes(node):
            if callee in visited:
                continue
            visited.add(callee)
            new_path = path + [f"{callee[0]}::{callee[1]}"]
            if callee[1] == target_name:
                return Reachability.REACHABLE, new_path
            queue.append((callee, new_path))

    if len(visited) >= _MAX_NODES:
        return Reachability.UNKNOWN, []   # budget exceeded — fail-open

    # Full traversal complete without finding target.
    # Report UNREACHABLE only when target has exactly ONE definition site.
    target_defs = cg.defs.get(target_name, [])
    if len(target_defs) == 1:
        return Reachability.UNREACHABLE, []

    return Reachability.UNKNOWN, []   # 2+ defs — ambiguous
