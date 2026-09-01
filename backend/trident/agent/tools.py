"""Read-only, workspace-sandboxed tools an expert agent can call to explore code.

Every tool resolves paths under the job workspace (via commonpath) and refuses
anything outside it, so an agent can never read the host, another job, or the
blinded scorecard. Tools return plain strings (fed back to the model as tool
results). They are DB-free and side-effect-free, safe to run in a thread pool.
"""

from __future__ import annotations

import os
import re

from trident.eval.guard import is_scorecard_filename

_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "vendor",
              "dist", "build", ".mypy_cache", ".pytest_cache"}
_MAX_FILE_BYTES = 200_000
_MAX_READ_LINES = 400
_MAX_GREP_RESULTS = 40

# Definition patterns per language flavor — enough to locate a symbol's declaration.
_DEF_PATTERNS = (
    r"def\s+{s}\b",            # python
    r"class\s+{s}\b",         # python / many
    r"func\s+(\(.*\)\s*)?{s}\b",  # go (incl. methods)
    r"function\s+{s}\b",      # js
    r"(const|let|var)\s+{s}\b",   # js
    r"{s}\s*[:=]\s*(async\s+)?(function|\()",  # js assigned funcs / arrow
    r"(public|private|protected|static|\s)+\w[\w<>\[\]]*\s+{s}\s*\(",  # java/c#
)


class WorkspaceTools:
    """Bundle of exploration tools scoped to one workspace."""

    def __init__(self, workspace: str):
        self.ws = os.path.realpath(workspace)

    # ---- OpenAI tool schemas ---------------------------------------------
    @property
    def schemas(self) -> list[dict]:
        return [
            _fn("read_file", "Read a file (or a line range) from the workspace.", {
                "path": {"type": "string", "description": "Workspace-relative file path"},
                "start_line": {"type": "integer", "description": "1-based start line (optional)"},
                "end_line": {"type": "integer", "description": "1-based end line (optional)"},
            }, ["path"]),
            _fn("grep", "Search the workspace for a regular expression.", {
                "pattern": {"type": "string", "description": "Python regular expression"},
                "path": {"type": "string", "description": "Optional subdirectory or file to limit the search"},
            }, ["pattern"]),
            _fn("list_dir", "List files and subdirectories of a workspace directory.", {
                "path": {"type": "string", "description": "Workspace-relative directory (default root)"},
            }, []),
            _fn("find_definition", "Find where a symbol (function, class, variable) is defined.", {
                "symbol": {"type": "string", "description": "Identifier to locate the definition of"},
            }, ["symbol"]),
            _fn("find_references", "Find where a symbol is used across the workspace.", {
                "symbol": {"type": "string", "description": "Identifier to find references to"},
            }, ["symbol"]),
        ]

    # ---- dispatch ---------------------------------------------------------
    def dispatch(self, name: str, args: dict) -> str:
        try:
            if name == "read_file":
                return self.read_file(args.get("path", ""), args.get("start_line"), args.get("end_line"))
            if name == "grep":
                return self.grep(args.get("pattern", ""), args.get("path"))
            if name == "list_dir":
                return self.list_dir(args.get("path", "."))
            if name == "find_definition":
                return self.find_definition(args.get("symbol", ""))
            if name == "find_references":
                return self.find_references(args.get("symbol", ""))
            return f"[unknown tool: {name}]"
        except Exception as e:  # never let a tool error kill the loop
            return f"[tool error in {name}: {e}]"

    # ---- sandbox ----------------------------------------------------------
    def _resolve(self, path: str) -> str | None:
        real = os.path.realpath(os.path.join(self.ws, path or "."))
        if real != self.ws and os.path.commonpath([real, self.ws]) != self.ws:
            return None
        return real

    def _iter_files(self, base: str):
        for root, dirs, files in os.walk(base):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
            for fn in files:
                if is_scorecard_filename(fn):
                    continue
                yield os.path.join(root, fn)

    # ---- tools ------------------------------------------------------------
    def read_file(self, path: str, start_line=None, end_line=None) -> str:
        real = self._resolve(path)
        if real is None:
            return "[access denied: outside workspace]"
        if not os.path.isfile(real):
            return f"[not a file: {path}]"
        if os.path.getsize(real) > _MAX_FILE_BYTES:
            return f"[file too large: {path}]"
        try:
            with open(real, encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except Exception as e:
            return f"[could not read {path}: {e}]"
        if start_line:
            s = max(1, int(start_line))
            e = min(len(lines), int(end_line) if end_line else s + _MAX_READ_LINES)
        else:
            s, e = 1, min(len(lines), _MAX_READ_LINES)
        body = "".join(f"{i}: {lines[i-1]}" for i in range(s, e + 1))
        suffix = "" if e >= len(lines) else f"\n… ({len(lines)-e} more lines)"
        return f"# {path} (lines {s}-{e} of {len(lines)})\n{body}{suffix}"

    def grep(self, pattern: str, path: str | None = None) -> str:
        if not pattern:
            return "[empty pattern]"
        try:
            rx = re.compile(pattern)
        except re.error as e:
            return f"[bad regex: {e}]"
        base = self._resolve(path or ".")
        if base is None:
            return "[access denied: outside workspace]"
        targets = [base] if os.path.isfile(base) else list(self._iter_files(base))
        hits: list[str] = []
        for fp in targets:
            if os.path.getsize(fp) > _MAX_FILE_BYTES:
                continue
            try:
                with open(fp, encoding="utf-8", errors="replace") as f:
                    for n, line in enumerate(f, 1):
                        if rx.search(line):
                            rel = os.path.relpath(fp, self.ws).replace(os.sep, "/")
                            hits.append(f"{rel}:{n}: {line.strip()[:200]}")
                            if len(hits) >= _MAX_GREP_RESULTS:
                                return "\n".join(hits) + "\n… (more matches truncated)"
            except Exception:
                continue
        return "\n".join(hits) if hits else "[no matches]"

    def list_dir(self, path: str = ".") -> str:
        real = self._resolve(path)
        if real is None:
            return "[access denied: outside workspace]"
        if not os.path.isdir(real):
            return f"[not a directory: {path}]"
        entries = []
        for name in sorted(os.listdir(real)):
            if name in _SKIP_DIRS:
                continue
            full = os.path.join(real, name)
            entries.append(f"{name}/" if os.path.isdir(full) else name)
        return "\n".join(entries) if entries else "[empty directory]"

    def find_definition(self, symbol: str) -> str:
        if not _is_ident(symbol):
            return "[symbol must be an identifier]"
        pats = [p.format(s=re.escape(symbol)) for p in _DEF_PATTERNS]
        rx = re.compile("|".join(f"(?:{p})" for p in pats))
        return self._grep_compiled(rx, label=f"definition of {symbol}")

    def find_references(self, symbol: str) -> str:
        if not _is_ident(symbol):
            return "[symbol must be an identifier]"
        rx = re.compile(rf"\b{re.escape(symbol)}\b")
        return self._grep_compiled(rx, label=f"references to {symbol}")

    def _grep_compiled(self, rx: re.Pattern, label: str) -> str:
        hits: list[str] = []
        for fp in self._iter_files(self.ws):
            try:
                if os.path.getsize(fp) > _MAX_FILE_BYTES:
                    continue
                with open(fp, encoding="utf-8", errors="replace") as f:
                    for n, line in enumerate(f, 1):
                        if rx.search(line):
                            rel = os.path.relpath(fp, self.ws).replace(os.sep, "/")
                            hits.append(f"{rel}:{n}: {line.strip()[:200]}")
                            if len(hits) >= _MAX_GREP_RESULTS:
                                return "\n".join(hits) + "\n… (more truncated)"
            except Exception:
                continue
        return "\n".join(hits) if hits else f"[no {label} found]"


def _fn(name: str, description: str, props: dict, required: list[str]) -> dict:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {"type": "object", "properties": props, "required": required},
        },
    }


def _is_ident(s: str) -> bool:
    return bool(s) and bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", s))
