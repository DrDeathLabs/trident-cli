"""Detect public HTTP entry points (route handler functions) in a workspace.

Supported frameworks
--------------------
Python  — Flask / FastAPI / APIRouter (decorator-based)
Python  — Django (urlpatterns path/re_path/url, CBV methods)
JS/TS   — Express, Fastify, Koa (app/router method routes)
JS/TS   — NestJS (@Get/@Post/… controller decorators)
Go      — net/http HandleFunc/Handle, gorilla/mux, Gin, Echo, Chi, Fiber

Return type is a list of EntryPoint(file, func_name, framework).  False
negatives (missed routes) are acceptable — the caller fails open to UNKNOWN.
False positives would over-count reachable functions, so the patterns are kept
narrow and intentionally miss indirect / programmatic route registration.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

_SKIP_DIRS = frozenset({
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "vendor", "dist", "build", ".pytest_cache", "migrations",
    "alembic", "tests", "test",
})
_PY_EXT  = frozenset({".py"})
_JS_EXT  = frozenset({".js", ".ts", ".jsx", ".tsx"})
_GO_EXT  = frozenset({".go"})
_MAX_BYTES = 200_000

# Matches @app.route / @router.get / @bp.get / @api.post / etc.
_PY_ROUTE_DECO = re.compile(
    r"@\s*\w+(?:\.\w+)*\s*\.\s*"
    r"(?:route|get|post|put|delete|patch|head|options|websocket)\s*\(",
    re.M,
)
# The def/async def that must follow within a short span after the decorator
_PY_DEF_NAME = re.compile(r"^\s*(?:async\s+)?def\s+(\w+)\s*\(", re.M)

# Django urlpatterns = [...] with path()/re_path()/url() inside
_DJANGO_URLPATTERNS = re.compile(r"urlpatterns\s*=", re.M)
_DJANGO_PATH_CALL = re.compile(
    r"(?:^|,|\[)\s*(?:path|re_path|url)\s*\(\s*['\"][^'\"]*['\"],\s*([\w.]+)",
    re.M,
)
_DJANGO_SKIP = frozenset({"include", "admin", "static", "media", "serve", "as_view"})

# Class-based view HTTP method names — these become entry points when found
# as methods with (self, request, ...) signature inside any class body.
_CBV_VERBS = frozenset({"get", "post", "put", "patch", "delete", "head", "options"})
# Matches an indented def with a HTTP verb name whose first param after self is request
_CBV_METHOD_RE = re.compile(
    r"^\s+(?:async\s+)?def\s+(get|post|put|patch|delete|head|options)\s*"
    r"\(\s*self\s*,\s*request",
    re.M | re.I,
)

# Express / Fastify / Koa: receiver.method(path, ..., handler)
# Captures the LAST simple identifier before the closing paren — works for
# named handlers passed by reference.  Inline arrow functions have no name
# and produce no match here, but are handled via route-file detection below.
_JS_ROUTE = re.compile(
    r"(?:app|router|fastify|server|koa)\s*\.\s*"
    r"(?:get|post|put|delete|patch|head|options|use|all|route)\s*\("
    r"(?:[^)]{0,400}?,\s*(\w+))\s*\)",
    re.M,
)
_JS_ROUTE_SKIP = frozenset({
    "function", "async", "req", "res", "next", "err", "ctx",
    "null", "undefined", "true", "false",
})

# Detects that a JS/TS file registers HTTP routes at all — regardless of
# whether the handler is named or inline.  Files matching this are "route
# files": any function defined or any finding located in them is implicitly
# reachable from HTTP (the whole file is handler territory).
_JS_ROUTE_FILE = re.compile(
    r"(?:app|router|fastify|server|koa)\s*\.\s*"
    r"(?:get|post|put|delete|patch|head|options|use|all|route)\s*\(",
    re.M,
)

# NestJS: @Get() / @Post() / @Put() / @Delete() / @Patch() decorator
# followed (within 3 lines) by the method name.
_NEST_DECO = re.compile(
    r"@\s*(?:Get|Post|Put|Delete|Patch|Head|Options|All)\s*\([^)]*\)",
    re.M,
)
_NEST_METHOD = re.compile(r"^\s*(?:async\s+)?(\w+)\s*\(", re.M)

# Go — net/http HandleFunc/Handle, gorilla/mux HandleFunc, Gin/Echo/Chi/Fiber:
#   receiver.Method("path", handlerName)
# Matches any method whose name is a known HTTP verb or HandleFunc/Handle.
# Handler is the last simple identifier before the closing paren.
_GO_ROUTE_CALL = re.compile(
    r"\.\s*(?:HandleFunc|Handle|GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|"
    r"Get|Post|Put|Patch|Delete|Head|Options|Any|Route)\s*"
    r"\(\s*(?:\"[^\"]*\"|`[^`]*`)\s*,\s*(\w+)",
    re.M,
)
_GO_HANDLER_SKIP = frozenset({"nil", "http", "true", "false", "func"})


@dataclass(frozen=True)
class EntryPoint:
    file: str        # workspace-relative, forward-slash separators
    func_name: str
    framework: str


def find_entry_points(workspace: str) -> list[EntryPoint]:
    """Return all detected HTTP route handlers across the workspace."""
    eps: list[EntryPoint] = []
    root = Path(workspace)
    for path in _walk(root):
        rel = path.relative_to(root).as_posix()
        ext = path.suffix.lower()
        try:
            text = path.read_bytes()[:_MAX_BYTES].decode("utf-8", errors="replace")
        except Exception:
            continue
        if ext in _PY_EXT:
            eps.extend(_scan_python(rel, text))
        elif ext in _JS_EXT:
            eps.extend(_scan_js(rel, text))
        elif ext in _GO_EXT:
            eps.extend(_scan_go(rel, text))
    return eps


def _walk(root: Path):
    for p in root.rglob("*"):
        if p.is_file() and not any(part in _SKIP_DIRS for part in p.parts):
            yield p


def _scan_python(rel: str, text: str) -> list[EntryPoint]:
    eps: list[EntryPoint] = []

    # Flask / FastAPI: decorator-based routes
    for m in _PY_ROUTE_DECO.finditer(text):
        after = text[m.end(): m.end() + 300]
        dm = _PY_DEF_NAME.search(after)
        if dm:
            eps.append(EntryPoint(rel, dm.group(1), "flask"))

    # Django: function-based views in urlpatterns
    if _DJANGO_URLPATTERNS.search(text):
        for m in _DJANGO_PATH_CALL.finditer(text):
            raw = m.group(1)
            # Class-based view: SomeView.as_view() → take the CLASS name, not "as_view"
            if "as_view" in raw:
                name = raw.split(".")[0]
                if name and name not in _DJANGO_SKIP:
                    eps.append(EntryPoint(rel, name, "django-cbv-class"))
            else:
                # Function-based view: views.my_view → my_view
                name = raw.rsplit(".", 1)[-1]
                if name not in _DJANGO_SKIP:
                    eps.append(EntryPoint(rel, name, "django"))

    # Class-based view HTTP handler methods (def get/post/... with self, request).
    # These are found in views.py / apis.py files and are the ACTUAL entry points
    # — Django dispatches to them from View.dispatch() at runtime.  Registering
    # them directly avoids the (urls.py, ClassName) → (views.py, method) lookup gap.
    for m in _CBV_METHOD_RE.finditer(text):
        verb = m.group(1).lower()
        eps.append(EntryPoint(rel, verb, "django-cbv-method"))

    return eps


def _scan_js(rel: str, text: str) -> list[EntryPoint]:
    eps: list[EntryPoint] = []

    # Express / Fastify / Koa named-handler routes
    for m in _JS_ROUTE.finditer(text):
        name = m.group(1)
        if name and name not in _JS_ROUTE_SKIP:
            eps.append(EntryPoint(rel, name, "express"))

    # NestJS @Get/@Post/… controller method decorators
    for m in _NEST_DECO.finditer(text):
        after = text[m.end(): m.end() + 200]
        dm = _NEST_METHOD.search(after)
        if dm and dm.group(1) not in _JS_ROUTE_SKIP:
            eps.append(EntryPoint(rel, dm.group(1), "nestjs"))

    return eps


def _scan_go(rel: str, text: str) -> list[EntryPoint]:
    eps: list[EntryPoint] = []
    for m in _GO_ROUTE_CALL.finditer(text):
        name = m.group(1)
        if name and name not in _GO_HANDLER_SKIP:
            eps.append(EntryPoint(rel, name, "go-http"))
    return eps


def find_route_files(workspace: str) -> frozenset[str]:
    """Return workspace-relative paths of JS/TS files that register HTTP routes.

    These are "route files" — the entire file is handler territory whether the
    handler is named or an inline arrow function.  Any finding inside one is
    implicitly reachable from HTTP without needing a named call-graph path.
    """
    route_files: set[str] = set()
    root = Path(workspace)
    for path in _walk(root):
        if path.suffix.lower() not in _JS_EXT:
            continue
        try:
            text = path.read_bytes()[:_MAX_BYTES].decode("utf-8", errors="replace")
        except Exception:
            continue
        if _JS_ROUTE_FILE.search(text):
            route_files.add(path.relative_to(root).as_posix())
    return frozenset(route_files)
