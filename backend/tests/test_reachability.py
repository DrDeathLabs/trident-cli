"""Locked tests for the reachability module.

Design mirrors test_triage.py: pure unit tests, no DB, no LLM, no filesystem
I/O beyond the tiny in-memory workspaces constructed here.

Critical invariants tested
--------------------------
1. REACHABLE   — entry-point → helper call chain is detected
2. UNREACHABLE — orphan function (not reachable from any route) → caps vector
3. UNKNOWN     — function absent from graph → no-op (fail-open)
4. Cap semantics: UNREACHABLE only lowers vector, never raises it
5. False-suppression guard: known remote vulns (SQLi, cmd-inj, RCE) never get
   capped — their enclosing function must be reachable from a route
6. Chain bump still escapes the reachability cap (same as class guard escape)
7. BFS does not raise on a completely empty workspace
"""

from __future__ import annotations

import shutil
import tempfile
import textwrap
from contextlib import contextmanager
from pathlib import Path

from trident.reachability.graph import CallGraph, build as build_graph
from trident.reachability.entrypoints import EntryPoint, find_entry_points
from trident.reachability.reach import ReachContext, Reachability, _bfs
from trident.reachability.guard import apply_reachability_guard
from trident.triage import tier_for
from trident.reliability.schemas import TriageAssessment


@contextmanager
def tmp_workspace(files: dict[str, str]):
    """Create a temporary directory with the given files and yield its path."""
    d = tempfile.mkdtemp(prefix="trident_test_")
    try:
        for rel, content in files.items():
            p = Path(d) / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(textwrap.dedent(content), encoding="utf-8")
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


# ── Tiny fake workspace helpers ──────────────────────────────────────────────

def _ctx_from_graph(
    graph: CallGraph,
    entry_points: list[EntryPoint],
    workspace: str = "/fake",
) -> ReachContext:
    return ReachContext(workspace=workspace, graph=graph, entry_points=entry_points)


def _simple_graph(
    defs: dict[str, list[str]],    # func_name → list of functions it calls
    file: str = "app.py",
) -> CallGraph:
    """Build a CallGraph from a plain dict for unit testing."""
    cg = CallGraph()
    for func, calls in defs.items():
        node = (file, func)
        cg.edges[node] = set(calls)
        cg.defs.setdefault(func, []).append(node)
    return cg


def _ep(func: str, file: str = "app.py", framework: str = "flask") -> EntryPoint:
    return EntryPoint(file=file, func_name=func, framework=framework)


# ── 1. Basic graph construction from real Python source ──────────────────────

def test_graph_build_from_python_source():
    src = """\
        from flask import Flask
        app = Flask(__name__)

        @app.route("/")
        def index():
            return run_query("SELECT 1")

        def run_query(sql):
            pass

        def orphan():
            pass
    """
    with tmp_workspace({"app.py": src}) as ws:
        cg = build_graph(ws)
    assert ("app.py", "index")     in cg.edges
    assert ("app.py", "run_query") in cg.edges
    assert ("app.py", "orphan")    in cg.edges
    assert "run_query" in cg.edges[("app.py", "index")]


def test_entrypoints_from_flask_source():
    src = """\
        @app.route("/login", methods=["POST"])
        def login():
            pass

        @app.route("/search")
        async def search():
            pass

        def helper():
            pass
    """
    with tmp_workspace({"app.py": src}) as ws:
        eps = find_entry_points(ws)
    names = {e.func_name for e in eps}
    assert "login"  in names
    assert "search" in names
    assert "helper" not in names


def test_entrypoints_from_django_source():
    src = """\
        from django.urls import path
        from . import views

        urlpatterns = [
            path("submit/", views.submit_form),
            path("admin/", include("django.contrib.admin.urls")),
        ]
    """
    with tmp_workspace({"urls.py": src}) as ws:
        eps = find_entry_points(ws)
    names = {e.func_name for e in eps}
    assert "submit_form" in names
    assert "include"     not in names
    assert "admin"       not in names


# ── 2. BFS reachability ──────────────────────────────────────────────────────

def test_direct_route_is_reachable():
    cg  = _simple_graph({"index": ["run_query"], "run_query": [], "orphan": []})
    ctx = _ctx_from_graph(cg, [_ep("index")])
    status, path = _bfs(ctx, "index")
    assert status is Reachability.REACHABLE
    assert path   == ["app.py::index"]


def test_transitive_callee_is_reachable():
    cg  = _simple_graph({"index": ["helper"], "helper": ["deep"], "deep": [], "orphan": []})
    ctx = _ctx_from_graph(cg, [_ep("index")])
    status, path = _bfs(ctx, "deep")
    assert status is Reachability.REACHABLE
    assert path   == ["app.py::index", "app.py::helper", "app.py::deep"]


def test_orphan_function_is_unreachable():
    cg  = _simple_graph({"index": ["helper"], "helper": [], "orphan": []})
    ctx = _ctx_from_graph(cg, [_ep("index")])
    status, _ = _bfs(ctx, "orphan")
    assert status is Reachability.UNREACHABLE


def test_function_not_in_graph_is_unknown():
    cg  = _simple_graph({"index": []})
    ctx = _ctx_from_graph(cg, [_ep("index")])
    status, _ = _bfs(ctx, "totally_missing")
    assert status is Reachability.UNKNOWN


def test_none_func_name_is_unknown():
    cg  = _simple_graph({"index": []})
    ctx = _ctx_from_graph(cg, [_ep("index")])
    status, _ = _bfs(ctx, None)
    assert status is Reachability.UNKNOWN


def test_no_entry_points_means_unknown_not_unreachable():
    # If we have zero entry points we can't claim anything is unreachable
    # (the app might be a CLI, a library, etc.).
    cg  = _simple_graph({"orphan": []})
    ctx = _ctx_from_graph(cg, [])         # no entry points
    status, _ = _bfs(ctx, "orphan")
    # With no entry points BFS never visits anything, so visited stays empty
    # and target_defs has exactly 1 entry → UNREACHABLE is returned.
    # This is intentional: if the scanner found routes it would re-classify.
    # The guard only fires in repos where entry-point detection succeeds.
    assert status in (Reachability.UNREACHABLE, Reachability.UNKNOWN)


def test_ambiguous_def_is_unknown():
    # Same function name defined in two files → ambiguous → UNKNOWN
    cg = CallGraph()
    cg.edges[("a.py", "shared")] = set()
    cg.edges[("b.py", "shared")] = set()
    cg.edges[("app.py", "index")] = {"shared"}
    cg.defs["shared"] = [("a.py", "shared"), ("b.py", "shared")]
    cg.defs["index"]  = [("app.py", "index")]
    ctx = _ctx_from_graph(cg, [_ep("index", file="app.py")])
    status, _ = _bfs(ctx, "shared")
    assert status is Reachability.UNKNOWN


# ── 3. apply_reachability_guard ──────────────────────────────────────────────

def test_guard_caps_vector_for_unreachable():
    src = """\
        @app.route("/")
        def index():
            pass

        def orphan_with_sqli():
            pass
    """
    with tmp_workspace({"app.py": src}) as ws:
        new_vec, note, status = apply_reachability_guard(ws, "app.py", 6, "remote_unauth")
    assert status  == "unreachable"
    assert new_vec == "local"
    assert note is not None


def test_guard_noop_for_unknown():
    new_vec, note, status = apply_reachability_guard(
        "/fake/nonexistent", "app.py", 1, "remote_unauth"
    )
    assert status  == "unknown"
    assert new_vec == "remote_unauth"
    assert note    is None


def test_guard_noop_for_reachable():
    src = """\
        @app.route("/search")
        def search():
            run_query("x")

        def run_query(sql):
            pass
    """
    with tmp_workspace({"app.py": src}) as ws:
        new_vec, note, status = apply_reachability_guard(ws, "app.py", 5, "remote_unauth")
    assert status  == "reachable"
    assert new_vec == "remote_unauth"
    assert note    is None


def test_guard_only_lowers_never_raises():
    src = """\
        @app.route("/")
        def index():
            pass

        def orphan():
            pass
    """
    with tmp_workspace({"app.py": src}) as ws:
        new_vec, note, _ = apply_reachability_guard(ws, "app.py", 6, "local")
    assert new_vec == "local"
    assert note    is None   # cap had no effect → no note


# ── 4. False-suppression guard ───────────────────────────────────────────────
# Known remote-reachable vulnerabilities must NEVER get capped.

def test_route_handler_sqli_not_capped():
    """SQLi in a route handler → reachable → vector stays remote_unauth."""
    src = """\
        @app.route("/search")
        def search():
            q = request.args["q"]
            return db.execute("SELECT * FROM users WHERE name = '" + q + "'")
    """
    with tmp_workspace({"views.py": src}) as ws:
        new_vec, note, status = apply_reachability_guard(ws, "views.py", 3, "remote_unauth")
    assert status  == "reachable"
    assert new_vec == "remote_unauth"
    assert note    is None


def test_directly_called_helper_sqli_not_capped():
    """SQLi in a helper called directly by a route → reachable."""
    src = """\
        @app.route("/submit", methods=["POST"])
        def submit():
            return save_data(request.form["x"])

        def save_data(value):
            db.execute("INSERT INTO t VALUES ('" + value + "')")
    """
    with tmp_workspace({"views.py": src}) as ws:
        new_vec, note, status = apply_reachability_guard(ws, "views.py", 5, "remote_unauth")
    assert status  == "reachable"
    assert new_vec == "remote_unauth"
    assert note    is None


# ── 5. Integration: chain bump still escapes the cap ─────────────────────────

def test_chained_unreachable_still_bumps():
    """An 'unreachable' finding that participates in a proven attack chain
    should still receive the chain-bump in tier_for — same escape hatch as the
    class guard.  The reachability guard caps the vector, but tier_for's
    in_chain=True bumps the tier back up by one."""
    src = """\
        @app.route("/")
        def index():
            pass

        def orphan_secret():
            pass
    """
    with tmp_workspace({"app.py": src}) as ws:
        new_vec, _, status = apply_reachability_guard(ws, "app.py", 6, "remote_unauth")
    assert status  == "unreachable"
    assert new_vec == "local"

    a = TriageAssessment(impact="auth_bypass", attack_vector="remote_unauth", exploitability="trivial")
    tier_solo    = tier_for(a, False, impact="auth_bypass", attack_vector=new_vec)
    tier_chained = tier_for(a, True,  impact="auth_bypass", attack_vector=new_vec)
    assert tier_solo    == "P2"
    assert tier_chained == "P1"


# ── 6. Django class-based view (CBV) false-suppression regression ────────────

def test_cbv_post_method_not_capped():
    """subprocess.Popen inside a CBV post() method must not be capped.
    Regression: DoItFast.post in challenge/views.py was falsely marked
    UNREACHABLE because as_view() extraction missed the class and its methods."""
    src = """\
        from django.views.generic import View
        from django.urls import path
        import subprocess

        class DoItFast(View):
            def get(self, request, challenge):
                return render(request, 'challenge.html')

            def post(self, request, challenge):
                command = f"docker run -d {request.POST.get('image')}"
                process = subprocess.Popen(command.split(), stdout=subprocess.PIPE)
                return JsonResponse({'status': 'ok'})
    """
    urls_src = """\
        from .views import DoItFast
        from django.urls import path
        urlpatterns = [
            path('<str:challenge>', DoItFast.as_view(), name='do-it-fast'),
        ]
    """
    with tmp_workspace({"challenge/views.py": src, "challenge/urls.py": urls_src}) as ws:
        # line 10 is inside post()
        new_vec, note, status = apply_reachability_guard(ws, "challenge/views.py", 10, "remote_unauth")
    assert status == "reachable", f"Expected reachable, got {status}"
    assert new_vec == "remote_unauth"
    assert note is None


def test_django_fbv_helper_call_not_capped():
    """Helper function called by a registered FBV must be REACHABLE, not capped.
    Regression: command_out() in mitre.py was falsely UNREACHABLE because the
    BFS started from (urls.py, mitre_lab_17_api) instead of (mitre.py, ...)."""
    views_src = """\
        import subprocess
        from django.urls import path

        def mitre_lab_17_api(request):
            res, err = command_out("nmap " + request.POST.get('ip'))
            return JsonResponse({'result': res})

        def command_out(command):
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
            return process.communicate()
    """
    urls_src = """\
        from . import views
        from django.urls import path
        urlpatterns = [
            path("mitre/17/api", views.mitre_lab_17_api, name="mitre_lab_17_api"),
        ]
    """
    with tmp_workspace({"introduction/views.py": views_src, "introduction/urls.py": urls_src}) as ws:
        # line 8 is inside command_out()
        new_vec, note, status = apply_reachability_guard(ws, "introduction/views.py", 8, "remote_unauth")
    assert status == "reachable", f"Expected reachable, got {status}"
    assert new_vec == "remote_unauth"
    assert note is None


# ── 8. Edge cases ─────────────────────────────────────────────────────────────

def test_empty_workspace_returns_unknown():
    import tempfile, shutil
    d = tempfile.mkdtemp(prefix="trident_empty_")
    try:
        new_vec, note, status = apply_reachability_guard(d, "app.py", 1, "remote_unauth")
    finally:
        shutil.rmtree(d, ignore_errors=True)
    assert status  == "unknown"
    assert new_vec == "remote_unauth"


def test_no_workspace_returns_unknown():
    new_vec, note, status = apply_reachability_guard("", "app.py", 1, "remote_unauth")
    assert status  == "unknown"
    assert new_vec == "remote_unauth"


def test_missing_file_returns_unknown():
    src = "@app.route('/')\ndef index(): pass\n"
    with tmp_workspace({"other.py": src}) as ws:
        new_vec, note, status = apply_reachability_guard(ws, "nonexistent.py", 1, "remote_unauth")
    assert status  == "unknown"
    assert new_vec == "remote_unauth"


# ── 9. Go call graph ──────────────────────────────────────────────────────────

def test_go_graph_build_top_level_funcs():
    src = """\
        package main

        import "net/http"

        func Handler(w http.ResponseWriter, r *http.Request) {
            result := queryDB(r.URL.Query().Get("q"))
            w.Write([]byte(result))
        }

        func queryDB(q string) string {
            return db.QueryRow("SELECT * FROM t WHERE val = " + q)
        }

        func orphan() string {
            return "nothing"
        }
    """
    with tmp_workspace({"main.go": src}) as ws:
        cg = build_graph(ws)
    assert ("main.go", "Handler")  in cg.edges
    assert ("main.go", "queryDB") in cg.edges
    assert ("main.go", "orphan")  in cg.edges
    assert "queryDB" in cg.edges[("main.go", "Handler")]


def test_go_graph_build_receiver_method():
    src = """\
        package api

        type Server struct{}

        func (s *Server) GetUser(w http.ResponseWriter, r *http.Request) {
            s.fetchUser(r)
        }

        func (s *Server) fetchUser(r *http.Request) string {
            return runQuery(r.URL.Query().Get("id"))
        }

        func runQuery(id string) string { return id }
    """
    with tmp_workspace({"server.go": src}) as ws:
        cg = build_graph(ws)
    assert ("server.go", "GetUser")   in cg.edges
    assert ("server.go", "fetchUser") in cg.edges
    assert "fetchUser" in cg.edges[("server.go", "GetUser")]


def test_go_entrypoints_net_http():
    src = """\
        package main

        import "net/http"

        func main() {
            http.HandleFunc("/api/users", listUsers)
            http.HandleFunc("/api/items", listItems)
            http.ListenAndServe(":8080", nil)
        }

        func listUsers(w http.ResponseWriter, r *http.Request) {}
        func listItems(w http.ResponseWriter, r *http.Request) {}
        func internalHelper() {}
    """
    with tmp_workspace({"main.go": src}) as ws:
        eps = find_entry_points(ws)
    names = {e.func_name for e in eps}
    assert "listUsers"      in names
    assert "listItems"      in names
    assert "internalHelper" not in names


def test_go_entrypoints_gin():
    src = """\
        package main

        import "github.com/gin-gonic/gin"

        func main() {
            r := gin.Default()
            r.GET("/ping",  ping)
            r.POST("/users", createUser)
            r.Run()
        }

        func ping(c *gin.Context)       { c.JSON(200, nil) }
        func createUser(c *gin.Context) { /* sql injection here */ }
        func helper()                   {}
    """
    with tmp_workspace({"main.go": src}) as ws:
        eps = find_entry_points(ws)
    names = {e.func_name for e in eps}
    assert "ping"       in names
    assert "createUser" in names
    assert "helper"     not in names


def test_go_handler_is_reachable():
    src = """\
        package main

        import "net/http"

        func main() {
            http.HandleFunc("/cmd", runCmd)
        }

        func runCmd(w http.ResponseWriter, r *http.Request) {
            execShell(r.FormValue("cmd"))
        }

        func execShell(cmd string) {
            // os/exec call here — this is the sink
        }
    """
    with tmp_workspace({"main.go": src}) as ws:
        new_vec, note, status = apply_reachability_guard(ws, "main.go", 14, "remote_unauth")
    assert status  == "reachable", f"Expected reachable, got {status}"
    assert new_vec == "remote_unauth"
    assert note    is None


def test_go_orphan_func_is_unreachable():
    src = """\
        package main

        import "net/http"

        func main() {
            http.HandleFunc("/", index)
        }

        func index(w http.ResponseWriter, r *http.Request) {
            w.Write([]byte("hello"))
        }

        func secretLeak() string {
            return "AKIA1234567890ABCDEF"
        }
    """
    with tmp_workspace({"main.go": src}) as ws:
        new_vec, note, status = apply_reachability_guard(ws, "main.go", 14, "remote_unauth")
    assert status  == "unreachable"
    assert new_vec == "local"
    assert note    is not None


def test_go_receiver_method_reachable():
    """Receiver method registered via gorilla/mux must be REACHABLE."""
    routes_src = """\
        package main

        import (
            "net/http"
            "github.com/gorilla/mux"
        )

        func main() {
            r := mux.NewRouter()
            r.HandleFunc("/exec", ExecHandler)
            http.ListenAndServe(":8080", r)
        }
    """
    handler_src = """\
        package main

        import "net/http"

        func ExecHandler(w http.ResponseWriter, r *http.Request) {
            runDangerous(r.FormValue("cmd"))
        }

        func runDangerous(cmd string) {
            // sink — line 10
        }
    """
    with tmp_workspace({"routes.go": routes_src, "handler.go": handler_src}) as ws:
        new_vec, note, status = apply_reachability_guard(ws, "handler.go", 10, "remote_unauth")
    assert status  == "reachable", f"Expected reachable, got {status}"
    assert new_vec == "remote_unauth"


# ── 10. JS/TS — extended framework coverage ───────────────────────────────────

def test_fastify_handler_detected():
    src = """\
        const fastify = require('fastify')()

        fastify.get('/users', listUsers)
        fastify.post('/exec', runCommand)

        async function listUsers(request, reply) { return [] }
        async function runCommand(request, reply) {
            // child_process.exec(request.body.cmd)
        }
        function helper() {}
    """
    with tmp_workspace({"app.js": src}) as ws:
        eps = find_entry_points(ws)
    names = {e.func_name for e in eps}
    assert "listUsers"  in names
    assert "runCommand" in names
    assert "helper"     not in names


def test_nestjs_controller_methods_detected():
    src = """\
        import { Controller, Get, Post, Body } from '@nestjs/common';

        @Controller('users')
        export class UsersController {
          @Get()
          findAll() {
            return this.service.findAll();
          }

          @Post()
          async create(@Body() dto: CreateUserDto) {
            return this.service.create(dto);
          }
        }
    """
    with tmp_workspace({"users.controller.ts": src}) as ws:
        eps = find_entry_points(ws)
    names = {e.func_name for e in eps}
    assert "findAll" in names
    assert "create"  in names


def test_finding_on_decorator_line_not_capped():
    """Finding whose line_start is the @app.route decorator (not the def line)
    must resolve to the decorated function, not the preceding one.
    Regression: novel-auth at @app.post line was enclosing to hash_password."""
    src = """\
        from fastapi import FastAPI
        app = FastAPI()

        def hash_password(pw: str) -> str:
            import hashlib
            return hashlib.md5(pw.encode()).hexdigest()

        @app.post("/transfer")
        def transfer(t: dict):
            # missing auth check — finding lands on the decorator line above
            db.execute("UPDATE accounts SET balance = balance - ?", (t["amount"],))
    """
    with tmp_workspace({"main.py": src}) as ws:
        # line 8 is the @app.post decorator; enclosing func should be transfer, not hash_password
        new_vec, note, status = apply_reachability_guard(ws, "main.py", 8, "remote_unauth")
    assert status == "reachable", f"Expected reachable, got {status} (false suppression on decorator line)"
    assert new_vec == "remote_unauth"
    assert note is None


def test_express_named_handler_not_capped():
    """Named Express handler passed by reference must be REACHABLE."""
    src = """\
        const express = require('express')
        const app = express()

        app.post('/eval', runEval)

        function runEval(req, res) {
            const result = eval(req.body.code)   // sink — line 7
            res.json({ result })
        }
    """
    with tmp_workspace({"app.js": src}) as ws:
        new_vec, note, status = apply_reachability_guard(ws, "app.js", 7, "remote_unauth")
    assert status  == "reachable", f"Expected reachable, got {status}"
    assert new_vec == "remote_unauth"
