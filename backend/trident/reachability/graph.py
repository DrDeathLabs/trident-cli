"""Build a lightweight call graph for a Python / JS / Go workspace.

Design constraints
------------------
- Pure static analysis — no subprocess, no JVM, no external tools.
- Python: ast.parse() for precision; catches def/async def and ast.Call nodes.
- JS/TS: regex-based (simpler, less precise); handles top-level function defs.
- Go: regex-based; handles top-level funcs and receiver methods.
- Fail-open everywhere: a file that fails to parse is skipped (not an error).
- Cross-file call resolution: only when the callee name maps to EXACTLY ONE
  definition site.  Ambiguous names (0 or 2+ defs) are left unresolved — the
  caller gets no edge for them, which is the conservative choice (prevents false
  Unreachable verdicts).

CallGraph.callee_nodes((file, name)) → list[(file, name)]
  Returns only the unambiguously resolvable callees of a given function node.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

_SKIP_DIRS = frozenset({
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "vendor", "dist", "build", ".pytest_cache", "migrations", "alembic",
})
_PY_EXT  = frozenset({".py"})
_JS_EXT  = frozenset({".js", ".ts", ".jsx", ".tsx"})
_GO_EXT  = frozenset({".go"})
_MAX_BYTES = 200_000

Node = tuple[str, str]   # (workspace-relative file, func_name)


@dataclass
class CallGraph:
    # (file, func_name) → set of plain function names called inside that function
    edges:  dict[Node, set[str]] = field(default_factory=dict)
    # func_name → list of (file, func_name) nodes that define it
    defs:   dict[str, list[Node]] = field(default_factory=lambda: {})

    def callee_nodes(self, caller: Node) -> list[Node]:
        """Resolve the callees of `caller` to (file, func_name) tuples.

        Only returns results when the callee name is unambiguous (one definition
        site in the whole workspace).  0 → stdlib/external (skipped); 2+ →
        ambiguous (skipped, fail-open).
        """
        result: list[Node] = []
        for name in self.edges.get(caller, ()):
            targets = self.defs.get(name, [])
            if len(targets) == 1:
                result.append(targets[0])
        return result


def build(workspace: str) -> CallGraph:
    """Walk the workspace and build a call graph."""
    cg = CallGraph()
    root = Path(workspace)
    for path in _walk(root):
        rel = path.relative_to(root).as_posix()
        ext = path.suffix.lower()
        try:
            raw = path.read_bytes()[:_MAX_BYTES]
            text = raw.decode("utf-8", errors="replace")
        except Exception:
            continue
        if ext in _PY_EXT:
            _parse_python(rel, text, cg)
        elif ext in _JS_EXT:
            _parse_js(rel, text, cg)
        elif ext in _GO_EXT:
            _parse_go(rel, text, cg)
    return cg


def _walk(root: Path):
    for p in root.rglob("*"):
        if p.is_file() and not any(part in _SKIP_DIRS for part in p.parts):
            yield p


# ── Python AST ──────────────────────────────────────────────────────────────

def _calls_in(node: ast.AST) -> set[str]:
    """Collect all simple function/method names called anywhere inside `node`."""
    names: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            if isinstance(child.func, ast.Name):
                names.add(child.func.id)
            elif isinstance(child.func, ast.Attribute):
                names.add(child.func.attr)
    return names


class _Collector(ast.NodeVisitor):
    """Register every function def and its outbound calls."""

    def __init__(self):
        # func_name → set of names called inside that function (calls from
        # nested functions are also included — conservative, prevents false
        # Unreachable verdicts for wrapper/decorator patterns)
        self.func_calls: dict[str, set[str]] = {}

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.func_calls[node.name] = _calls_in(node)
        self.generic_visit(node)   # recurse to collect nested defs too

    visit_AsyncFunctionDef = visit_FunctionDef


def _parse_python(rel: str, text: str, cg: CallGraph) -> None:
    try:
        tree = ast.parse(text, filename=rel)
    except SyntaxError:
        return
    c = _Collector()
    c.visit(tree)
    for func_name, calls in c.func_calls.items():
        node: Node = (rel, func_name)
        cg.edges[node] = calls
        cg.defs.setdefault(func_name, []).append(node)


# ── JS / TS (regex-based) ────────────────────────────────────────────────────

_JS_FUNC_DEF = re.compile(
    r"(?:^|\n)\s*(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\("
    r"|(?:^|\n)\s*(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*=>)",
    re.M,
)
_JS_CALL = re.compile(r"\b(\w+)\s*\(", re.M)
_JS_KW = frozenset({
    "if", "for", "while", "switch", "catch", "finally", "function",
    "return", "typeof", "instanceof", "new", "import", "require",
    "console", "Math", "JSON", "Object", "Array", "Promise",
    "async", "await", "class", "extends", "super", "this",
    "module", "exports", "undefined", "null", "true", "false",
})


def _parse_js(rel: str, text: str, cg: CallGraph) -> None:
    # Collect (name, start_offset) for all detected function definitions
    spans: list[tuple[str, int]] = []
    for m in _JS_FUNC_DEF.finditer(text):
        name = m.group(1) or m.group(2)
        if name:
            spans.append((name, m.start()))

    # Each function's "body" is approximated as the text up to the next def
    for i, (name, start) in enumerate(spans):
        end = spans[i + 1][1] if i + 1 < len(spans) else len(text)
        body = text[start:end]
        calls = {
            m.group(1)
            for m in _JS_CALL.finditer(body)
            if m.group(1) not in _JS_KW and m.group(1) != name
        }
        node: Node = (rel, name)
        cg.edges[node] = calls
        cg.defs.setdefault(name, []).append(node)


# ── Go (regex-based) ─────────────────────────────────────────────────────────
# Matches: func Name(   and   func (recv T) Name(
# Receiver group is non-capturing; function name is group 1.
_GO_FUNC_DEF = re.compile(
    r"^func\s+(?:\([^)]{0,120}\)\s+)?(\w+)\s*\(",
    re.M,
)
_GO_CALL = re.compile(r"\b(\w+)\s*\(", re.M)
_GO_KW = frozenset({
    "if", "for", "range", "switch", "select", "case", "default",
    "go", "defer", "return", "type", "var", "const", "make", "new",
    "append", "len", "cap", "close", "delete", "copy", "panic", "recover",
    "print", "println", "func", "import", "package", "interface", "struct",
    "map", "chan", "nil", "true", "false", "string", "int", "int64", "int32",
    "uint", "uint64", "uint32", "byte", "rune", "bool", "float64", "float32",
    "error", "any",
})


def _parse_go(rel: str, text: str, cg: CallGraph) -> None:
    spans: list[tuple[str, int]] = []
    for m in _GO_FUNC_DEF.finditer(text):
        name = m.group(1)
        if name:
            spans.append((name, m.start()))

    for i, (name, start) in enumerate(spans):
        end = spans[i + 1][1] if i + 1 < len(spans) else len(text)
        body = text[start:end]
        calls = {
            m.group(1)
            for m in _GO_CALL.finditer(body)
            if m.group(1) not in _GO_KW and m.group(1) != name
        }
        node: Node = (rel, name)
        cg.edges[node] = calls
        cg.defs.setdefault(name, []).append(node)
