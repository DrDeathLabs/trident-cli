"""Installed-wheel reporting E2E matrix over the real local OpenAI HTTP gateway.

Run with the clean wheel environment's Python.  The CLI process itself resolves
``trident`` from that environment's Scripts directory and communicates with a
real localhost HTTP server; responses are deterministic synthetic model output.
"""

from __future__ import annotations

import json
import hashlib
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.engine import URL
from sqlalchemy.orm import sessionmaker


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend" / "tests"))
from openai_compatible_harness import OpenAICompatibleServer  # noqa: E402

TIERS = ("P0", "P1", "P2", "P3", "P4")
UNRESOLVED = ("unresolved", "unresolved_model_error", "unreviewed")
MODEL_ALIAS = "final-e2e-gateway-alias"
API_KEY = "synthetic-local-key"


def _finding(title: str, rule: str, filename: str, *, cwe: str = "CWE-89",
             severity: str = "high", line: int = 4) -> dict:
    stable = hashlib.sha256(f"{title}|{rule}|{filename}".encode()).hexdigest()
    return {
        "id": stable[:32],
        "hash": stable[:24],
        "correlation_key": None,
        "tool": "synthetic-corpus-scanner",
        "rule_id": rule,
        "severity": severity,
        "scanner_severity": severity,
        "title": title,
        "description": f"Synthetic controlled evidence for {title}.",
        "file": filename,
        "line_start": line,
        "line_end": line,
        "snippet": "return 'synthetic value'",
        "cwe": cwe,
        "owasp": None,
        "recommendation": "Review and remediate the synthetic test case.",
        "raw_outputs": {},
    }


def _priority_assessment(impact: str, vector: str, exploitability: str = "moderate") -> dict:
    return {
        "impact": impact,
        "attack_vector": vector,
        "exploitability": exploitability,
        "fix_effort": "moderate",
        "rationale": "Controlled synthetic assessment for CLI reporting validation.",
    }


def _write_workspace(root: Path, records: list[dict], *, suppress_rule: str | None = None) -> Path:
    workspace = root / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    for index, row in enumerate(records):
        path = workspace / row["file"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "app = object()\n"
            "@app.route('/synthetic')\n"
            f"def endpoint_{index}():\n"
            "    return 'synthetic value'\n",
            encoding="utf-8",
        )
    if suppress_rule:
        (workspace / ".tridentignore").write_text(suppress_rule + "\n", encoding="utf-8")
    return workspace


def _write_corpus(path: Path, records: list[dict]) -> None:
    path.write_text(json.dumps({
        "format": "trident-frozen-scanner-corpus",
        "schema_version": "1",
        "source": {"target": "synthetic-final-e2e", "record_count": len(records)},
        "scanner_subprocesses": "not launched during replay",
        "records": records,
    }, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _parse_terminal(stdout: str) -> dict[str, int]:
    parsed = {}
    for label in (*TIERS, "Total", "Untriaged", "Unresolved"):
        match = re.search(rf"(?m)^{label}:\s+(\d+)\s*$", stdout)
        if not match:
            raise AssertionError(f"installed CLI omitted {label} from actual stdout:\n{stdout}")
        parsed[label] = int(match.group(1))
    return parsed


def _role(call: dict) -> str:
    messages = (call.get("request_body") or {}).get("messages", [])
    system = " ".join(m.get("content", "") for m in messages if m.get("role") == "system").lower()
    if "red team expert" in system:
        return "redteam"
    if "you are the judge" in system:
        return "judge"
    if "security triage lead" in system:
        return "triage"
    for role, phrase in (
        ("injection", "you specialize in injection vulnerabilities"),
        ("auth", "you specialize in authentication & access control"),
        ("crypto", "you specialize in cryptography"),
        ("secrets_config", "you specialize in secrets & configuration"),
        ("dependency", "you specialize in dependency risk"),
    ):
        if phrase in system:
            return role
    return "expert" if "/chat/completions" in call.get("path", "") else "other"


def _tier_counts(report: dict) -> dict[str, int]:
    by_findings = Counter(row.get("priority") for row in report.get("findings", []))
    return {tier: by_findings[tier] for tier in TIERS}


def _sarif_rows(payload: dict) -> list[tuple[str, str | None, str | None]]:
    return sorted(
        (row.get("message", {}).get("text", ""),
         row.get("properties", {}).get("priority"),
         row.get("properties", {}).get("status"))
        for row in payload.get("runs", [{}])[0].get("results", [])
    )


def _report_rows(report: dict) -> list[tuple[str, str | None, str | None]]:
    return sorted((row.get("title", ""), row.get("priority"), row.get("status"))
                  for row in report.get("findings", []))


def _capture_bytes(path: Path, value: bytes) -> str:
    path.write_bytes(value)
    decoded = value.decode("utf-8")
    (path.parent / (path.stem + ".txt")).write_bytes(decoded.encode("utf-8"))
    return decoded


def _make_cases() -> list[dict]:
    matrix = [
        _finding("E2E-CHAIN-P0-A", "E2E-CHAIN-A", "a_route.py"),
        _finding("E2E-CHAIN-P0-B", "E2E-CHAIN-B", "b_route.py"),
        _finding("E2E-PRIORITY-P1", "E2E-PRIORITY-P1", "c_route.py"),
        _finding("E2E-PRIORITY-P2-A", "E2E-PRIORITY-P2-A", "d_route.py"),
        _finding("E2E-PRIORITY-P2-B", "E2E-PRIORITY-P2-B", "e_route.py"),
        _finding("E2E-PRIORITY-P3", "E2E-PRIORITY-P3", "f_route.py"),
        _finding("E2E-PRIORITY-P4", "E2E-PRIORITY-P4", "g_route.py"),
    ]
    return [
        {"name": "priority-matrix-and-gate-1", "records": matrix,
         "fail_on": "P0", "quiet": False, "expected_exit": 1,
         "triage": {
             "E2E-CHAIN-P0-A": _priority_assessment("data_tampering", "remote_auth"),
             "E2E-CHAIN-P0-B": _priority_assessment("data_tampering", "remote_auth"),
             "E2E-PRIORITY-P1": _priority_assessment("data_tampering", "remote_auth"),
             "E2E-PRIORITY-P2": _priority_assessment("data_exposure", "adjacent"),
             "E2E-PRIORITY-P3": _priority_assessment("dos", "adjacent"),
             "E2E-PRIORITY-P4": _priority_assessment("other", "local"),
         }, "required_roles": ("injection", "redteam", "triage"),
         "required_tiers": TIERS, "min_total": 7},
        {"name": "confirmed-untriaged", "records": [
            _finding("E2E-UNTRIAGED-A", "E2E-UNTRIAGED-A", "one.py"),
         _finding("E2E-UNTRIAGED-B", "E2E-UNTRIAGED-B", "two.py"),
         ], "fail_on": "P0", "no_guards": True, "quiet": True,
         "expected_exit": 2, "expected_untriaged": 2, "required_roles": ("injection", "redteam")},
        {"name": "unresolved-triage-http-failure", "records": [
            _finding("E2E-UNRESOLVED-TRIAGE", "E2E-UNRESOLVED-TRIAGE", "unresolved.py"),
         ], "fail_on": "P0", "quiet": False, "expected_exit": 2,
         "failure": ("triage", "E2E-UNRESOLVED-TRIAGE", 500),
         "expected_unresolved": 1, "required_roles": ("injection", "triage")},
        {"name": "orchestration-failure-exit-2", "records": [],
         "fail_on": "P0", "quiet": True, "expected_exit": 2,
         "invalid_corpus": True, "scan_expected_to_fail": True,
         "expected_job_status": "failed", "expected_tiers": {tier: 0 for tier in TIERS},
         "required_roles": ()},
        {"name": "mixed-confirmed-suppressed-disputed-false-positive", "records": [
            _finding("E2E-MIXED-CONFIRMED-INJECTION", "E2E-MIXED-CONFIRMED", "confirmed.py"),
            _finding("E2E-MIXED-SUPPRESSED", "E2E-SUPPRESS-ME", "suppressed.py"),
            _finding("E2E-MIXED-DISPUTED-AUTHENTICATION", "E2E-DISPUTED", "disputed.py", cwe="CWE-287"),
            _finding("E2E-MIXED-FALSE-AUTHENTICATION", "E2E-FALSE", "false.py", cwe="CWE-287"),
         ], "fail_on": "P0", "quiet": True, "expected_exit": 2,
         "suppress_rule": "E2E-SUPPRESS-ME",
         "judge": {
             "E2E-MIXED-DISPUTED-AUTHENTICATION": {"final_verdict": "disputed", "final_confidence": 0.52,
                 "reasoning": "Synthetic holdout remains uncertain."},
             "E2E-MIXED-FALSE-AUTHENTICATION": {"final_verdict": "refuted", "final_confidence": 0.97,
                 "reasoning": "Synthetic controlled false-positive verdict.",
                 "false_positive_reason": "Synthetic test disposition."},
         }, "triage": {"E2E-MIXED-CONFIRMED": _priority_assessment("dos", "adjacent")},
         "expected_dispositions": {"suppressed": 1, "unresolved": 1,
                                    "false_positive": 1},
         "minimum_judge_verdicts": {"disputed": 1, "refuted": 1},
         "required_roles": ("injection", "auth", "judge", "triage")},
        {"name": "empty-no-actionable-findings", "records": [], "fail_on": "P0",
         "quiet": True, "expected_exit": 0, "required_roles": (),
         "expected_tiers": {tier: 0 for tier in TIERS}},
        {"name": "severity-gate-exit-0", "records": [
            _finding("E2E-GATE-LOWER-TIER", "E2E-GATE-LOWER", "lower.py"),
         ], "fail_on": "P0", "quiet": True, "expected_exit": 0,
         "triage": {"E2E-GATE-LOWER": _priority_assessment("other", "local")},
         "expected_tiers": {"P0": 0, "P1": 0, "P2": 0, "P3": 0, "P4": 1},
         "redteam": {"E2E-GATE-LOWER": {"attack_paths": []}},
         "required_roles": ("injection", "triage")},
        {"name": "all-nonactionable-dispositions", "records": [
            _finding("E2E-NONACTIONABLE-SUPPRESSED", "E2E-SUPPRESS-NONACTIONABLE", "suppressed.py"),
            _finding("E2E-NONACTIONABLE-DISPUTED-AUTHENTICATION", "E2E-NONACTIONABLE-DISPUTED", "disputed.py", cwe="CWE-287"),
            _finding("E2E-NONACTIONABLE-FALSE-AUTHENTICATION", "E2E-NONACTIONABLE-FALSE", "false.py", cwe="CWE-287"),
         ], "fail_on": "P0", "quiet": True, "expected_exit": 2,
         "suppress_rule": "E2E-SUPPRESS-NONACTIONABLE",
         "judge": {
             "E2E-NONACTIONABLE-DISPUTED-AUTHENTICATION": {"final_verdict": "disputed", "final_confidence": 0.51,
                 "reasoning": "Synthetic uncertain disposition."},
             "E2E-NONACTIONABLE-FALSE-AUTHENTICATION": {"final_verdict": "refuted", "final_confidence": 0.96,
                 "reasoning": "Synthetic refuted disposition."},
         }, "expected_dispositions": {"suppressed": 1, "unresolved": 1, "false_positive": 1},
         "expected_tiers": {tier: 0 for tier in TIERS},
         "required_roles": ("auth", "judge")},
        {"name": "cli-json-format", "records": [
            _finding("E2E-CLI-JSON", "E2E-CLI-JSON", "json.py"),
         ], "fail_on": "P0", "quiet": True, "expected_exit": 0,
         "format": "json", "triage": {"E2E-CLI-JSON": _priority_assessment("other", "local")},
         "expected_tiers": {"P0": 0, "P1": 0, "P2": 0, "P3": 0, "P4": 1},
         "redteam": {"E2E-CLI-JSON": {"attack_paths": []}},
         "required_roles": ("injection", "triage")},
        {"name": "cli-sarif-format", "records": [
            _finding("E2E-CLI-SARIF", "E2E-CLI-SARIF", "sarif.py"),
         ], "fail_on": "P0", "quiet": True, "expected_exit": 0,
         "format": "sarif", "triage": {"E2E-CLI-SARIF": _priority_assessment("other", "local")},
         "expected_tiers": {"P0": 0, "P1": 0, "P2": 0, "P3": 0, "P4": 1},
         "redteam": {"E2E-CLI-SARIF": {"attack_paths": []}},
         "required_roles": ("injection", "triage")},
    ]


def _run_wheel_smokes(destination: Path) -> list[dict]:
    smoke_dir = destination / "wheel-smoke"
    smoke_dir.mkdir(parents=True, exist_ok=True)
    appdata = smoke_dir / "appdata"
    appdata.mkdir(exist_ok=True)
    env = os.environ.copy()
    for key in (
        "TRIDENT_LLM_MOCK", "TRIDENT_OPENAI_API_KEY", "TRIDENT_OPENAI_BASE_URL",
        "TRIDENT_LLM_BACKEND", "LLM_BACKEND", "OPENAI_BASE_URL", "OPENAI_API_KEY",
        "TRIDENT_SQLITE_PATH", "TRIDENT_LLM_LEDGER_PATH", "TRIDENT_WORKSPACES",
    ):
        env.pop(key, None)
    env.update({"APPDATA": str(appdata), "LOCALAPPDATA": str(appdata),
                "TRIDENT_TOOLS_DIR": ".acceptance/reporting-final-e2e/evidence/wheel-smoke/tools",
                "TRIDENT_DISABLE_EVENTS": "1", "PYTHONIOENCODING": "utf-8"})
    cli_entry = ".\\" + Path(sys.executable).parent.joinpath("trident.exe").relative_to(ROOT).as_posix().replace("/", "\\")
    commands = [
        ("version", [cli_entry, "--version"]),
        ("help", [cli_entry, "--help"]),
        ("config-help", [cli_entry, "config", "--help"]),
        ("config-list", [cli_entry, "config", "list"]),
        ("scan-help", [cli_entry, "scan", "--help"]),
        ("inspect-help", [cli_entry, "inspect", "--help"]),
        ("model-help", [cli_entry, "model", "--help"]),
        ("install-tools-check", [cli_entry, "install-tools", "--check"]),
    ]
    rows = []
    for name, command in commands:
        completed = subprocess.run(command, cwd=ROOT, env=env, capture_output=True,
                                   timeout=120, check=False)
        stdout = _capture_bytes(smoke_dir / f"{name}.stdout.bin", completed.stdout)
        stderr = _capture_bytes(smoke_dir / f"{name}.stderr.bin", completed.stderr)
        row = {"name": name, "argv": command, "exit_code": completed.returncode,
               "stdout_nonempty": bool(stdout), "stderr_nonempty": bool(stderr)}
        if completed.returncode != 0:
            raise AssertionError(f"installed wheel smoke {name} failed: {stdout}\n{stderr}")
        rows.append(row)
    (smoke_dir / "results.json").write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    return rows


def _run_case(case: dict, destination: Path, terminal_entries: list[str]) -> dict:
    from trident.models import AttackChain, Finding, FindingVerdict, Job
    from trident.reporters.exporters import to_json, to_sarif

    name = case["name"]
    case_dir = destination / name
    case_dir.mkdir(parents=True, exist_ok=True)
    _write_workspace(case_dir, case["records"], suppress_rule=case.get("suppress_rule"))
    corpus = case_dir / "scanner-corpus.json"
    if case.get("invalid_corpus"):
        corpus.write_text("{ synthetic malformed corpus", encoding="utf-8")
    else:
        _write_corpus(corpus, case["records"])
    database = case_dir / "scan.sqlite"
    ledger = case_dir / "ledger.sqlite"
    appdata = case_dir / "appdata"
    workspaces = case_dir / "workspaces"
    appdata.mkdir(exist_ok=True)
    workspaces.mkdir(exist_ok=True)
    for database_file in (database, Path(str(database) + "-shm"), Path(str(database) + "-wal"),
                          ledger, Path(str(ledger) + "-shm"), Path(str(ledger) + "-wal")):
        if database_file.exists():
            database_file.unlink()

    env = os.environ.copy()
    for key in (
        "TRIDENT_LLM_MOCK", "TRIDENT_OPENAI_API_KEY", "TRIDENT_OPENAI_BASE_URL",
        "TRIDENT_LLM_BACKEND", "LLM_BACKEND", "OPENAI_BASE_URL", "OPENAI_API_KEY",
        "TRIDENT_SQLITE_PATH", "TRIDENT_LLM_LEDGER_PATH", "TRIDENT_WORKSPACES",
    ):
        env.pop(key, None)
    venv_scripts = Path(sys.executable).parent
    cli_entry = ".\\" + venv_scripts.joinpath("trident.exe").relative_to(ROOT).as_posix().replace("/", "\\")
    env.update({
        "APPDATA": str(appdata),
        "LOCALAPPDATA": str(appdata),
        "TRIDENT_SQLITE_PATH": str(database),
        "TRIDENT_LLM_LEDGER_PATH": str(ledger),
        "TRIDENT_WORKSPACES": str(workspaces),
        "OPENAI_API_KEY": API_KEY,
        "TRIDENT_OPENAI_API_KEY": API_KEY,
        "TRIDENT_LLM_BACKEND": "openai",
        "LLM_BACKEND": "openai",
        "TRIDENT_DISABLE_EVENTS": "1",
        "PYTHONIOENCODING": "utf-8",
    })
    if case.get("scan_expected_to_fail"):
        # Keep the captured failing CLI session complete without embedding the
        # runner's local interpreter/source paths from a Python traceback.
        env["LOGURU_LEVEL"] = "CRITICAL"
        env["LOGURU_FORMAT"] = "{time:YYYY-MM-DD HH:mm:ss.SSS} | {level} | {message}"
    else:
        env.pop("LOGURU_LEVEL", None)
        env.pop("LOGURU_FORMAT", None)

    command = [
        cli_entry, "scan", str((case_dir / "workspace").relative_to(ROOT)),
        "--scanner-corpus", str(corpus.relative_to(ROOT)),
        "--max-iterations", "1", "--fail-on", case["fail_on"],
        "--backend", "openai", "--model", MODEL_ALIAS,
        "--target-name", name,
    ]
    if case.get("no_guards"):
        command.append("--no-guards")
    if case.get("format"):
        command.extend(["--format", case["format"], "--output-file",
                        str((case_dir / f"cli.{case['format']}").relative_to(ROOT))])
    if case.get("quiet"):
        command.append("--quiet")

    with OpenAICompatibleServer(api_key=API_KEY, model_alias=MODEL_ALIAS) as gateway:
        env["OPENAI_BASE_URL"] = gateway.base_url + "/v1/"
        env["TRIDENT_OPENAI_BASE_URL"] = gateway.base_url + "/v1/"
        for marker, content in case.get("triage", {}).items():
            gateway.set_marker_response("triage", marker, content)
        for marker, content in case.get("judge", {}).items():
            gateway.set_judge_sequence(marker, [content])
        for marker, content in case.get("redteam", {}).items():
            gateway.set_marker_response("redteam", marker, content)
        if case.get("failure"):
            role, marker, status = case["failure"]
            gateway.set_marker_failure(role, marker, status)

        completed = subprocess.run(
            command, cwd=ROOT, env=env, capture_output=True, timeout=300,
            check=False,
        )
        stdout = _capture_bytes(case_dir / "stdout.bin", completed.stdout)
        stderr = _capture_bytes(case_dir / "stderr.bin", completed.stderr)
        ansi_re = re.compile(r"\x1B(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1B\\))")
        (case_dir / "stdout.plain.txt").write_bytes(ansi_re.sub("", stdout).encode("utf-8"))
        (case_dir / "stderr.plain.txt").write_bytes(ansi_re.sub("", stderr).encode("utf-8"))
        command_data = {
            "argv": command,
            "windows_command_line": subprocess.list2cmdline(command),
            "working_directory_relative_to_evidence": ". (repository root)",
            "exit_code": completed.returncode,
            "stdout_bytes": len(completed.stdout),
            "stderr_bytes": len(completed.stderr),
            "cli_executable_resolved_from": "clean wheel virtual environment Scripts directory",
            "expected_exit_code": case["expected_exit"],
            "gateway_base_url": gateway.base_url + "/v1",
            "configured_model_alias": MODEL_ALIAS,
            "sanitized_auth_recorded": True,
            "failure_log_format_suppresses_traceback_paths": bool(case.get("scan_expected_to_fail")),
            "failure_logger_level": "CRITICAL" if case.get("scan_expected_to_fail") else "default",
        }
        (case_dir / "command.json").write_text(json.dumps(command_data, indent=2) + "\n", encoding="utf-8")
        (case_dir / "command.txt").write_text(
            f"Actual argv: {json.dumps(command, ensure_ascii=False)}\n"
            f"Windows command line: {command_data['windows_command_line']}\n"
            f"Working directory: {name} (relative to evidence root)\n"
            f"Exit code: {completed.returncode}\n",
            encoding="utf-8",
        )
        calls = list(gateway.calls)
        (case_dir / "localhost-http-call-log.json").write_text(
            json.dumps(calls, indent=2, ensure_ascii=False) + "\n", encoding="utf-8",
        )

    terminal_capture = (
        f"========== SCENARIO: {name} ==========\n"
        f"COMMAND (argv): {json.dumps(command, ensure_ascii=False)}\n"
        f"EXIT CODE: {completed.returncode}\n"
        "----- STDOUT (verbatim process bytes decoded as UTF-8) -----\n"
        + stdout
        + ("" if stdout.endswith("\n") or not stdout else "\n")
        + "----- STDERR (verbatim process bytes decoded as UTF-8) -----\n"
        + stderr
        + ("" if stderr.endswith("\n") or not stderr else "\n")
        + "\n"
    )
    (case_dir / "terminal-session.txt").write_bytes(terminal_capture.encode("utf-8"))
    terminal_entries.append(terminal_capture)

    if completed.returncode != case["expected_exit"]:
        raise AssertionError(
            f"{name}: expected CLI exit {case['expected_exit']}, got {completed.returncode}; "
            f"stdout={stdout!r}; stderr={stderr!r}"
        )

    engine = create_engine(URL.create("sqlite", database=str(database)))
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    with Session() as session:
        jobs = session.query(Job).all()
        if len(jobs) != 1:
            raise AssertionError(f"{name}: expected one real CLI-created job, found {len(jobs)}")
        job = jobs[0]
        report = to_json(session, job.id)
        sarif = to_sarif(session, job.id)
        chains = session.query(AttackChain).filter(AttackChain.job_id == job.id).all()
        finding_verdicts = session.query(FindingVerdict).filter(
            FindingVerdict.job_id == job.id
        ).all()
        db_findings = session.query(Finding).filter(Finding.job_id == job.id).all()
        db_statuses = Counter(f.status for f in db_findings)
        report_json = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
        report_sarif = json.dumps(sarif, indent=2, ensure_ascii=False) + "\n"

        # Preserve the CLI's real JSON or SARIF file verbatim where that format
        # was selected, then materialize the complementary report from this
        # exact same installed-wheel job and database snapshot.
        if case.get("format") == "json":
            cli_bytes = (case_dir / "cli.json").read_bytes()
            (case_dir / "final.json").write_bytes(cli_bytes)
            cli_report = json.loads(cli_bytes)
            report = cli_report
            (case_dir / "final.sarif").write_text(report_sarif, encoding="utf-8")
        elif case.get("format") == "sarif":
            cli_bytes = (case_dir / "cli.sarif").read_bytes()
            (case_dir / "final.sarif").write_bytes(cli_bytes)
            sarif = json.loads(cli_bytes)
            (case_dir / "final.json").write_text(report_json, encoding="utf-8")
        else:
            (case_dir / "final.json").write_text(report_json, encoding="utf-8")
            (case_dir / "final.sarif").write_text(report_sarif, encoding="utf-8")

        final_json = json.loads((case_dir / "final.json").read_text(encoding="utf-8"))
        final_sarif = json.loads((case_dir / "final.sarif").read_text(encoding="utf-8"))

        if case.get("format") is None:
            if case.get("scan_expected_to_fail"):
                if stdout:
                    raise AssertionError(f"{name}: failed scan unexpectedly wrote a report to stdout: {stdout!r}")
                terminal = None
            else:
                terminal = _parse_terminal(stdout)
        else:
            if stdout:
                raise AssertionError(f"{name}: machine-readable --output-file leaked to stdout: {stdout!r}")
            terminal = None

        counts = _tier_counts(final_json)
        summary_counts = {tier: int(final_json["triage"]["summary"]["by_tier"].get(tier, 0) or 0)
                          for tier in TIERS}
        untriaged = int(final_json["triage"]["untriaged"])
        disposition_counts = final_json["dispositions"]["counts"]
        unresolved = sum(int(disposition_counts.get(status, 0) or 0) for status in UNRESOLVED)
        unique_ids = len({row["id"] for row in final_json["findings"]})
        sarif_counts = Counter(row[1] for row in _sarif_rows(final_sarif))
        sarif_tiers = {tier: sarif_counts[tier] for tier in TIERS}
        same_population = _report_rows(final_json) == _sarif_rows(final_sarif)
        sarif_dispositions = final_sarif["runs"][0]["properties"]["dispositions"]["counts"]
        disposition_parity = disposition_counts == sarif_dispositions

        reconciliation = {
            "report_artifact_origin": (
                "CLI emitted selected format; complementary report exported from same job"
                if case.get("format") else
                "post-failure database export; CLI exited before report stage"
                if case.get("scan_expected_to_fail") else
                "same finalized CLI job database exported by installed package"
            ),
            "cli_emitted_machine_report": bool(case.get("format")),
            "terminal_counts": {tier: terminal[tier] for tier in TIERS} if terminal else None,
            "json_counts_from_unique_final_findings": counts,
            "json_summary_counts": summary_counts,
            "sarif_counts": sarif_tiers,
            "terminal_total": terminal["Total"] if terminal else None,
            "json_total": sum(counts.values()),
            "terminal_untriaged": terminal["Untriaged"] if terminal else None,
            "json_untriaged": untriaged,
            "terminal_unresolved": terminal["Unresolved"] if terminal else None,
            "json_unresolved": unresolved,
            "reportable_finding_count": len(final_json["findings"]),
            "unique_finding_ids": unique_ids,
            "all_reportable_findings_confirmed": all(row["status"] == "confirmed" for row in final_json["findings"]),
            "json_sarif_finding_populations_match": same_population,
            "json_sarif_disposition_counts_match": disposition_parity,
            "final_json_schema_keys": sorted(final_json.keys()),
            "sarif_version": final_sarif.get("version"),
            "sarif_schema": final_sarif.get("$schema"),
            "cli_machine_stdout_empty": stdout == "" if case.get("format") else None,
            "cli_exit_code": completed.returncode,
            "expected_exit_code": case["expected_exit"],
            "job_status": job.status,
            "disposition_counts": disposition_counts,
            "database_status_counts": dict(sorted(db_statuses.items())),
            "redteam_analysis": final_json.get("redteam_analysis"),
            "attack_chain_count": len(chains),
            "attack_chain_paths_preserved": sum(len(f.attack_paths or []) for f in db_findings),
            "expert_verdict_rows": sum(v.expert not in {"judge", "redteam"} for v in finding_verdicts),
            "judge_verdict_rows": sum(v.expert == "judge" for v in finding_verdicts),
            "judge_verdict_counts": dict(sorted(Counter(
                v.verdict for v in finding_verdicts if v.expert == "judge"
            ).items())),
        }
        (case_dir / "reconciliation.json").write_text(
            json.dumps(reconciliation, indent=2, ensure_ascii=False) + "\n", encoding="utf-8",
        )

    roles = [_role(call) for call in calls]
    request_evidence = {
        "request_count": len(calls),
        "paths": sorted({call["path"] for call in calls}),
        "models": sorted({call.get("model") for call in calls if call.get("model")}),
        "all_auth_present": bool(calls) and all(call.get("auth_present") for call in calls),
        "role_counts": dict(sorted(Counter(roles).items())),
        "expert_roles_invoked": sorted(role for role in set(roles)
                                       if role in {"injection", "auth", "crypto", "secrets_config", "dependency"}),
    }
    (case_dir / "http-summary.json").write_text(
        json.dumps(request_evidence, indent=2) + "\n", encoding="utf-8",
    )

    with (case_dir / "reconciliation.json").open(encoding="utf-8") as fh:
        recon = json.load(fh)
    if recon["json_counts_from_unique_final_findings"] != recon["json_summary_counts"]:
        raise AssertionError(f"{name}: report summary does not match final findings: {recon}")
    if recon["json_counts_from_unique_final_findings"] != recon["sarif_counts"]:
        raise AssertionError(f"{name}: JSON/SARIF tier population mismatch: {recon}")
    if recon["reportable_finding_count"] != recon["unique_finding_ids"]:
        raise AssertionError(f"{name}: duplicate or missing reportable finding IDs: {recon}")
    if not recon["all_reportable_findings_confirmed"]:
        raise AssertionError(f"{name}: non-confirmed finding leaked into prioritized JSON")
    if not recon["json_sarif_finding_populations_match"] or not recon["json_sarif_disposition_counts_match"]:
        raise AssertionError(f"{name}: final JSON/SARIF population or disposition mismatch: {recon}")
    if recon["sarif_version"] != "2.1.0" or recon["sarif_schema"] != "https://json.schemastore.org/sarif-2.1.0.json":
        raise AssertionError(f"{name}: SARIF contract mismatch: {recon}")
    if terminal:
        if any(terminal[tier] != counts[tier] for tier in TIERS):
            raise AssertionError(f"{name}: actual terminal tier counts mismatch: {recon}")
        if terminal["Total"] != sum(counts.values()) or terminal["Untriaged"] != untriaged or terminal["Unresolved"] != unresolved:
            raise AssertionError(f"{name}: actual terminal aggregate counts mismatch: {recon}")
        if len(stdout.splitlines()) != 9 or any("Sample" in line or "Triage plan" in line for line in stdout.splitlines()):
            raise AssertionError(f"{name}: unexpected/non-numerical content in compact table: {stdout!r}")
    gateway_invalid = bool(calls) and (
        not request_evidence["all_auth_present"] or request_evidence["models"] != [MODEL_ALIAS]
    )
    if gateway_invalid or (case.get("required_roles") and not calls):
        raise AssertionError(f"{name}: gateway auth/model evidence failed: {request_evidence}")
    missing_roles = set(case.get("required_roles", ())) - set(roles)
    if missing_roles:
        raise AssertionError(f"{name}: expected model role(s) were not invoked: {missing_roles}; {request_evidence}")
    if case.get("required_tiers") and not all(counts[tier] > 0 for tier in case["required_tiers"]):
        raise AssertionError(f"{name}: not all required tiers were produced: {counts}")
    if case.get("expected_tiers") and counts != case["expected_tiers"]:
        raise AssertionError(f"{name}: priority vector mismatch: expected {case['expected_tiers']}, got {counts}")
    if case.get("min_total") and sum(counts.values()) < case["min_total"]:
        raise AssertionError(f"{name}: expected multiple prioritized findings: {counts}")
    if case.get("expected_untriaged") is not None and untriaged != case["expected_untriaged"]:
        raise AssertionError(f"{name}: wrong untriaged count: {untriaged}")
    if case.get("expected_unresolved") is not None and unresolved != case["expected_unresolved"]:
        raise AssertionError(f"{name}: wrong unresolved count: {unresolved}")
    if case.get("expected_job_status") and recon["job_status"] != case["expected_job_status"]:
        raise AssertionError(f"{name}: expected job status {case['expected_job_status']}, got {recon['job_status']}")
    for status, expected_count in case.get("expected_dispositions", {}).items():
        if int(disposition_counts.get(status, 0)) != expected_count:
            raise AssertionError(f"{name}: disposition {status} expected {expected_count}, got {disposition_counts}")
    for verdict, minimum in case.get("minimum_judge_verdicts", {}).items():
        if recon["judge_verdict_counts"].get(verdict, 0) < minimum:
            raise AssertionError(f"{name}: expected judge {verdict} verdict; got {recon['judge_verdict_counts']}")
    if name == "priority-matrix-and-gate-1":
        if recon["redteam_analysis"].get("status") != "success" or recon["attack_chain_count"] < 1:
            raise AssertionError(f"{name}: Red-Team analysis/attack chain was not persisted: {recon}")
        if recon["attack_chain_paths_preserved"] < 2:
            raise AssertionError(f"{name}: per-finding attack paths were not retained: {recon}")
    if case.get("format") and recon["cli_machine_stdout_empty"] is not True:
        raise AssertionError(f"{name}: machine-readable format contaminated stdout")

    return {
        "scenario": name,
        "exit_code": completed.returncode,
        "expected_exit_code": case["expected_exit"],
        "pass": True,
        "counts": counts,
        "untriaged": untriaged,
        "unresolved": unresolved,
        "dispositions": disposition_counts,
        "gateway": request_evidence,
        "terminal_output_file": f"{name}/terminal-session.txt",
        "json_file": f"{name}/final.json",
        "sarif_file": f"{name}/final.sarif",
        "reconciliation_file": f"{name}/reconciliation.json",
        "http_log_file": f"{name}/localhost-http-call-log.json",
        "table_summary_present": terminal is not None,
        "reconciliation": recon,
    }


def run(evidence_dir: str) -> dict:
    destination = Path(evidence_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    smoke_results = _run_wheel_smokes(destination)
    cases = _make_cases()
    terminal_entries: list[str] = []
    results = [_run_case(case, destination, terminal_entries) for case in cases]
    (destination / "TRIDENT_CLI_TERMINAL_OUTPUT.txt").write_bytes(
        "\n".join(terminal_entries).encode("utf-8"),
    )
    summary = {
        "harness": "installed-wheel CLI process + real localhost HTTP OpenAI-compatible server",
        "python_executable": "clean wheel virtual environment",
        "model_alias": MODEL_ALIAS,
        "api_key": "synthetic; raw credential not captured in HTTP logs or evidence",
        "scenario_count": len(results),
        "all_scenarios_passed": all(row["pass"] for row in results),
        "wheel_smoke_commands_passed": len(smoke_results),
        "wheel_smoke_results": smoke_results,
        "table_scenarios": sum(row["table_summary_present"] for row in results),
        "machine_format_scenarios": [row["scenario"] for row in results
                                      if row["scenario"] in {"cli-json-format", "cli-sarif-format"}],
        "no_table_summary_scenarios": [row["scenario"] for row in results if not row["table_summary_present"]],
        "cases": results,
    }
    (destination / "final-e2e-results.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8",
    )
    print(json.dumps({"scenario_count": len(results), "all_scenarios_passed": summary["all_scenarios_passed"],
                      "scenarios": [{"name": row["scenario"], "exit": row["exit_code"],
                                     "counts": row["counts"], "untriaged": row["untriaged"],
                                     "unresolved": row["unresolved"], "pass": row["pass"]}
                                    for row in results]}, indent=2, ensure_ascii=False))
    return summary


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: validate_cli_final_e2e.py EVIDENCE_DIR")
    outcome = run(sys.argv[1])
    raise SystemExit(0 if outcome["all_scenarios_passed"] else 1)
