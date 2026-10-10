"""Run the packaged-wheel cross-workstream acceptance scan over localhost HTTP."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
BACKEND = REPO / "backend"
sys.path.insert(0, str(BACKEND))
sys.path.insert(0, str(BACKEND / "tests"))

from openai_compatible_harness import OpenAICompatibleServer  # noqa: E402


def _report(path: Path) -> None:
    results = [
        {
            "ruleId": "SYNTH-SQL-1", "level": "error",
            "message": {"text": "SQL injection in account lookup"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "src/query.py"},
                "region": {"startLine": 18, "endLine": 18},
            }}],
            "properties": {"cwe": "CWE-89"},
        },
        {
            "ruleId": "SYNTH-JWT-1", "level": "error",
            "message": {"text": "JWT signature validation weakness"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "src/tokens.py"},
                "region": {"startLine": 30, "endLine": 30},
            }}],
            "properties": {"cwe": "CWE-347"},
        },
        {
            "ruleId": "SYNTH-SECRET-1", "level": "error",
            "message": {"text": "Hard-coded credential"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "src/config.py"},
                "region": {"startLine": 7, "endLine": 7},
            }}],
            "properties": {"cwe": "CWE-798"},
        },
        {
            "ruleId": "SYNTH-AMBIGUOUS-A", "level": "warning",
            "message": {"text": "Ambiguous A"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "src/one.py"},
                "region": {"startLine": 4, "endLine": 4},
            }}],
            # CWE-20 makes the imported result security-relevant to SARIF
            # ingestion while intentionally providing no specialist routing cue.
            "properties": {"cwe": "CWE-20"},
        },
        {
            "ruleId": "SYNTH-AMBIGUOUS-B", "level": "warning",
            "message": {"text": "Ambiguous B"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "src/two.py"},
                "region": {"startLine": 5, "endLine": 5},
            }}],
            "properties": {"cwe": "CWE-20"},
        },
    ]
    payload = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "SyntheticScanner"}}, "results": results}],
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def run(trident_executable: str, evidence_dir: str) -> dict:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    import platformdirs
    from trident.models import AttackChain, DebateMessage, Finding, Job, JobEvent, FindingVerdict

    destination = Path(evidence_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    sandbox = Path(tempfile.mkdtemp(prefix="gateway-analysis-", dir=destination))
    appdata = sandbox / "appdata"
    appdata.mkdir()
    os.environ["APPDATA"] = str(appdata)
    db_path = sandbox / "scan.sqlite"
    report_path = sandbox / "synthetic.sarif"
    result_path = sandbox / "scan.json"
    triage_path = sandbox / "triage.json"
    config_dir = Path(platformdirs.user_config_dir("Trident"))

    with OpenAICompatibleServer(api_key="synthetic-environment-key") as configured_server, \
         OpenAICompatibleServer(api_key="synthetic-file-key") as persisted_server:
        _report(report_path)
        persisted_config = config_dir / "config.toml"
        persisted_config.parent.mkdir(parents=True, exist_ok=True)
        persisted_config.write_text(
            "[llm]\nbackend = 'ollama'\n"
            f"openai_base_url = '{persisted_server.base_url}/v1'\n"
            "openai_api_key = 'synthetic-file-key'\n"
            "expert_model = 'persisted-expert-alias'\n"
            "judge_model = 'persisted-judge-alias'\n"
            "redteam_model = 'persisted-redteam-alias'\n",
            encoding="utf-8",
        )
        configured_server.set_judge_sequence("Ambiguous A", [
            {"final_verdict": "disputed", "final_confidence": 0.5, "reasoning": "Synthetic first review."},
            {"final_verdict": "refuted", "final_confidence": 0.9, "reasoning": "Synthetic second review."},
        ])
        configured_server.set_judge_sequence("Ambiguous B", [
            {"final_verdict": "disputed", "final_confidence": 0.5, "reasoning": "Synthetic first review."},
            {"final_verdict": "disputed", "final_confidence": 0.5, "reasoning": "Synthetic repeat review."},
            {"final_verdict": "confirmed", "final_confidence": 0.9, "final_severity": "medium",
             "reasoning": "Synthetic final review."},
        ])

        env = os.environ.copy()
        for key in ("TRIDENT_LLM_MOCK", "TRIDENT_OPENAI_API_KEY", "TRIDENT_OPENAI_BASE_URL"):
            env.pop(key, None)
        env.update({
            "APPDATA": str(appdata),
            "TRIDENT_SQLITE_PATH": str(db_path),
            "TRIDENT_LLM_LEDGER_PATH": str(sandbox / "ledger.sqlite"),
            "TRIDENT_LLM_BACKEND": "anthropic",
            "LLM_BACKEND": "anthropic",
            "OPENAI_BASE_URL": f"{configured_server.base_url}/v1/",
            "OPENAI_API_KEY": "synthetic-environment-key",
            "EXPERT_MODEL": "environment-expert-alias",
            "JUDGE_MODEL": "environment-judge-alias",
            "REDTEAM_MODEL": "environment-redteam-alias",
        })
        command = [
            trident_executable, "scan", "--input-file", str(report_path),
            "--input-format", "sarif", "--format", "json",
            "--output-file", str(result_path), "--triage-output-file", str(triage_path),
            "--max-iterations", "4", "--fail-on", "P0", "--quiet",
            "--backend", "openai", "--model", "routed-security-model",
        ]
        completed = subprocess.run(
            command, cwd=sandbox, env=env, capture_output=True, text=True, timeout=180,
        )

        calls = configured_server.calls
        persisted_calls = persisted_server.calls
        log_path = destination / "cross-workstream-http-log.json"
        log_path.write_text(json.dumps(calls, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    engine = create_engine(f"sqlite:///{db_path.as_posix()}")
    session = sessionmaker(bind=engine)()
    job = session.query(Job).order_by(Job.created_at.desc()).first()
    findings = session.query(Finding).filter(Finding.job_id == job.id).order_by(Finding.id).all() if job else []
    verdicts = session.query(FindingVerdict).filter(FindingVerdict.job_id == job.id).all() if job else []
    debates = session.query(DebateMessage).filter(DebateMessage.job_id == job.id).all() if job else []
    chains = session.query(AttackChain).filter(AttackChain.job_id == job.id).all() if job else []
    reuse_events = session.query(JobEvent).filter(
        JobEvent.job_id == job.id, JobEvent.type == "redteam.analysis.reused",
    ).all() if job else []
    routing_events = session.query(JobEvent).filter(
        JobEvent.job_id == job.id, JobEvent.type == "scan.experts.routing",
    ).all() if job else []

    def role_for(call):
        system = " ".join(
            item.get("content", "") for item in call["request_body"].get("messages", [])
            if item.get("role") == "system"
        ).lower()
        if "red team expert" in system:
            return "redteam"
        if "you are the judge" in system:
            return "judge"
        if "security triage lead" in system:
            return "triage"
        for name in ("injection expert", "auth & access control expert", "cryptography expert",
                     "dependency & sbom expert", "secrets & configuration expert"):
            if name in system:
                return name
        return "other"

    roles = [role_for(call) for call in calls]
    redteam_calls = [call for call in calls if role_for(call) == "redteam"]
    routing_details = []
    for event in routing_events:
        payload = event.payload or {}
        decisions = payload.get("decisions", [])
        routing_details.append({
            "finding_title": next(
                (finding.title for finding in findings if finding.id == payload.get("finding_id")),
                "unknown synthetic finding",
            ),
            "iteration": payload.get("iteration"),
            "selected_experts": sorted(
                decision["expert"] for decision in decisions if decision.get("relevant")
            ),
        })
    requested_models = sorted({call.get("model") for call in calls})
    report_payload = json.loads(result_path.read_text(encoding="utf-8")) if result_path.is_file() else {}
    triage_payload = json.loads(triage_path.read_text(encoding="utf-8")) if triage_path.is_file() else {}
    report_valid = bool(report_payload)
    triage_valid = bool(triage_payload)
    redteam_message_fingerprints = sorted({
        hashlib.sha256(json.dumps(
            call["request_body"].get("messages", []),
            ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")).hexdigest()
        for call in redteam_calls
    })
    routed_by_title = {
        (item["finding_title"], item["iteration"]): set(item["selected_experts"])
        for item in routing_details
    }
    report_artifact = destination / "cross-workstream-scan-output.json"
    triage_artifact = destination / "cross-workstream-triage-output.json"
    for source, target in ((result_path, report_artifact), (triage_path, triage_artifact)):
        sanitized = source.read_text(encoding="utf-8")
        for local_path in (
            str(sandbox), str(sandbox).replace("\\", "\\\\"),
            str(sandbox).replace("\\", "/"),
        ):
            sanitized = sanitized.replace(local_path, "[synthetic workspace]")
        target.write_text(sanitized, encoding="utf-8")
    evidence = {
        "installed_cli_exit_code": completed.returncode,
        "cli_stderr_chars": len(completed.stderr),
        "report_valid": report_valid,
        "triage_valid": triage_valid,
        "configured_endpoint_request_count": len(calls),
        "persisted_endpoint_request_count": len(persisted_calls),
        "paths": sorted({call["path"] for call in calls}),
        "all_requests_authenticated": all(call["auth_present"] for call in calls),
        "requested_models": requested_models,
        "routed_experts": sorted({v.expert for v in verdicts if v.expert != "judge"}),
        "judge_calls": roles.count("judge"),
        "cross_examination_calls": sum(
            "PEER REVIEWS" in "\n".join(m.get("content", "") for m in call["request_body"].get("messages", []))
            for call in calls
        ),
        "redteam_calls": len(redteam_calls),
        "redteam_distinct_model_inputs": len(redteam_message_fingerprints),
        "redteam_changed_input_fingerprints": redteam_message_fingerprints,
        "redteam_analysis_status": report_payload.get("redteam_analysis", {}).get("status"),
        "redteam_fingerprints": sorted({
            event.payload.get("fingerprint") for event in reuse_events
            if (event.payload or {}).get("fingerprint")
        } | ({session.get(Job, job.id).profile.get("_redteam_analysis", {}).get("fingerprint")}
             if job and session.get(Job, job.id).profile.get("_redteam_analysis", {}).get("fingerprint")
             else set())),
        "redteam_reuse_events": len(reuse_events),
        "attack_chain_count": len(chains),
        "confirmed_findings": sum(f.status == "confirmed" for f in findings),
        "p0_p4_complete": all(f.priority in {"P0", "P1", "P2", "P3", "P4"} for f in findings if f.status == "confirmed"),
        "expert_verdicts": sorted({v.expert for v in verdicts if v.expert != "judge"}),
        "expert_routing": routing_details,
        "required_gateway_route_checks": {
            "sql_injection": "injection" in routed_by_title.get(("SQL injection in account lookup", 0), set()),
            "jwt_signature": {"auth", "crypto"}.issubset(
                routed_by_title.get(("JWT signature validation weakness", 0), set())
            ),
            "hardcoded_credential": "secrets_config" in routed_by_title.get(("Hard-coded credential", 0), set()),
        },
        "iteration_zero_expert_assignments": sum(
            len(item["selected_experts"]) for item in routing_details if item["iteration"] == 0
        ),
        "cross_exam_debate_rows": sum(message.role == "challenge" for message in debates),
        "attack_paths_on_findings": sum(bool(f.attack_paths) for f in findings if f.status == "confirmed"),
        "http_log": log_path.name,
        "report_artifact": report_artifact.name,
        "triage_artifact": triage_artifact.name,
        "config_precedence_evidence": {
            "persisted_endpoint_unused": len(persisted_calls) == 0,
            "environment_endpoint_used": len(calls) > 0,
            "cli_backend_won_over_environment": bool(calls),
            "cli_model_won_over_environment_and_config": requested_models == ["routed-security-model"],
            "environment_api_key_won_over_persisted": bool(calls) and all(call["auth_present"] for call in calls),
        },
    }
    session.close()
    engine.dispose()
    checks = [
        completed.returncode == 0, report_valid, triage_valid, len(calls) > 0,
        len(persisted_calls) == 0, all(call["path"] == "/v1/chat/completions" for call in calls),
        all(call["auth_present"] for call in calls), requested_models == ["routed-security-model"],
        len(redteam_calls) == 2,
        len(redteam_message_fingerprints) == 2,
        len(reuse_events) >= 1,
        evidence["redteam_analysis_status"] == "success",
        len(chains) > 0,
        evidence["cross_examination_calls"] > 0, evidence["cross_exam_debate_rows"] > 0,
        evidence["confirmed_findings"] >= 3, evidence["p0_p4_complete"],
        evidence["attack_paths_on_findings"] > 0,
        all(evidence["required_gateway_route_checks"].values()),
        completed.returncode == 0,  # --fail-on P0 retains normal CLI gate semantics.
        {"injection", "auth", "crypto", "secrets_config"}.issubset(evidence["expert_verdicts"]),
        evidence["iteration_zero_expert_assignments"] >= 4,
    ]
    evidence["passed"] = all(checks)
    (destination / "cross-workstream-e2e.json").write_text(
        json.dumps(evidence, indent=2) + "\n", encoding="utf-8",
    )
    if not evidence["passed"]:
        raise RuntimeError(json.dumps(evidence, indent=2))
    return evidence


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: validate_gateway_analysis_acceptance.py <installed-trident> <evidence-dir>")
    print(json.dumps(run(sys.argv[1], sys.argv[2]), indent=2))
