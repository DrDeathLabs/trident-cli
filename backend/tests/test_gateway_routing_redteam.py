"""Acceptance coverage for gateway transport, expert routing, and Red-Team reuse."""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from trident import config_manager
from trident.budget import LLMBudget
from trident.config import Settings, settings
from trident.deliberation import build_attack_chains, run_reviews
from trident.experts.auth import AuthExpert
from trident.experts.crypto import CryptoExpert
from trident.experts.dependency import DependencyExpert
from trident.experts.injection import InjectionExpert
from trident.experts.judge import JudgeExpert
from trident.experts.redteam import RedTeamExpert, select_redteam_findings
from trident.experts.routing import RoutingDecision, legacy_expert_match, route_finding
from trident.experts.secrets_config import SecretsConfigExpert
from trident.llm.base import ChatMessage, LLMError, LLMUnavailable, get_llm_backend, set_mock_handler
from trident.llm.openai_backend import OpenAIBackend
from trident.models import AttackChain, Finding, Job, JobEvent
from trident.models import FindingVerdict
from trident.reporters.exporters import to_json, to_sarif, to_triage_json, to_triage_sarif
from trident.reliability.schemas import ReviewVerdict, TriageAssessment
from trident.reliability.structured import chat_structured
from trident.cli import cli
from tests.openai_compatible_harness import OpenAICompatibleServer
from tests.routing_corpus import CASES, finding_for
from tests.routing_holdout import HOLDOUT


def _experts(job_id="route-test"):
    return [
        InjectionExpert(job_id, ""), AuthExpert(job_id, ""), CryptoExpert(job_id, ""),
        DependencyExpert(job_id, ""), SecretsConfigExpert(job_id, ""),
    ]


def _legacy_relevant(expert, finding):
    """Reference the preserved production compatibility function."""
    return legacy_expert_match(finding, expert)


def _redteam_fixture(db, job_id="redteam-test", *, workspace="", **overrides):
    job = Job(id=job_id, target_name="synthetic", source_type="demo", source_ref="",
              workspace_path=workspace, profile={})
    db.add(job)
    finding_values = {
        "id": "finding-red-1", "job_id": job_id, "hash": "synthetic-red-hash",
        "tool": "sarif-import", "rule_id": "SYNTHETIC-1", "severity": "high",
        "confidence": 0.9, "title": "SQL injection in account lookup",
        "description": "Untrusted account input is joined to the database query.",
        "file": "src/account.py", "line_start": 12, "line_end": 12, "cwe": "CWE-89",
        "raw_outputs": {"raw": {"import_format": "sarif", "record": {"ruleId": "SYNTHETIC-1"}}},
        "status": "confirmed",
    }
    finding_values.update(overrides)
    finding = Finding(**finding_values)
    db.add(finding)
    db.commit()
    return job, finding


def _successful_redteam_handler(calls):
    def handler(messages, model):
        calls.append({"model": model, "messages": [(m.role, m.content) for m in messages]})
        prompt = next(m.content for m in messages if m.role == "user")
        ids = [line[3:].split("]", 1)[0] for line in prompt.splitlines()
               if line.startswith("- [") and "] " in line]
        return {"attack_paths": [{
            "goal": "Synthetic access chain", "steps": ["Use the issue to reach the data."],
            "findings_used": ids[:1], "likelihood": "medium",
        }] if ids else []}
    return handler


def test_openai_compatible_local_http_contract_and_alias():
    with OpenAICompatibleServer(api_key="synthetic-env-key", model_alias="routed-security-model") as server:
        backend = OpenAIBackend(
            api_key="synthetic-env-key", base_url=f"{server.base_url}/v1/",
            model="routed-security-model", timeout=2, max_retries=0,
        )
        try:
            health = backend.health()
            response = backend.chat([ChatMessage("user", "Synthetic review")], model="enterprise-sec-model")
            embeddings = backend.embed(["synthetic text"], model="embedding-alias")
        finally:
            backend.client.close()

        assert health["status"] == "ok"
        assert health["expert_model_available"] is True
        assert response.content
        assert embeddings == [[0.25, 0.5, 0.75]]
        assert [call["path"] for call in server.calls] == [
            "/v1/models", "/v1/chat/completions", "/v1/embeddings",
        ]
        assert [call["order"] for call in server.calls] == [1, 2, 3]
        assert server.calls[1]["model"] == "enterprise-sec-model"
        assert server.calls[2]["model"] == "embedding-alias"
        assert all(call["auth_present"] for call in server.calls)
        assert all("Authorization" not in call["request_body"] for call in server.calls)


@pytest.mark.parametrize("url", [
    "http://gateway.example.invalid/v1",
    "".join(('https://', 'synthetic-user', ':', 'synthetic-password', '@gateway.example.invalid/v1')),
    "https://gateway.example.invalid/v1?token=synthetic",
    "file:///tmp/v1",
])
def test_openai_gateway_rejects_unsafe_endpoint_urls(url):
    with pytest.raises(ValueError):
        OpenAIBackend(api_key="synthetic-key", base_url=url)


def test_openai_gateway_does_not_follow_redirect_with_bearer_key():
    with OpenAICompatibleServer() as source, OpenAICompatibleServer() as destination:
        source.set_behavior(
            "/v1/chat/completions", status=302,
            redirect_to=f"{destination.base_url}/v1/chat/completions",
        )
        backend = OpenAIBackend(
            api_key="synthetic-redirect-key", base_url=f"{source.base_url}/v1",
            max_retries=0,
        )
        try:
            with pytest.raises(LLMError, match="302"):
                backend._post(
                    f"{backend.base_url}/chat/completions", {"model": "synthetic"},
                )
        finally:
            backend.client.close()
        assert source.calls[0]["auth_present"] is True
        assert destination.calls == []


def test_config_and_environment_precedence_reaches_real_http_requests(tmp_path, monkeypatch):
    config_file = tmp_path / "config.toml"
    monkeypatch.setattr(config_manager, "_config_path", lambda: config_file)
    monkeypatch.delenv("TRIDENT_LLM_MOCK", raising=False)
    with OpenAICompatibleServer(api_key="synthetic-file-key", model_alias="config-expert") as file_server, \
         OpenAICompatibleServer(api_key="synthetic-env-key", model_alias="environment-expert") as env_server:
        config_file.write_text(
            "[llm]\nbackend = 'openai'\n"
            f"openai_base_url = '{file_server.base_url}/v1'\n"
            "openai_api_key = 'synthetic-file-key'\n"
            "expert_model = 'config-expert'\n"
            "judge_model = 'config-judge'\n"
            "redteam_model = 'config-redteam'\n",
            encoding="utf-8",
        )
        for key in ("OPENAI_BASE_URL", "TRIDENT_OPENAI_BASE_URL", "OPENAI_API_KEY",
                    "TRIDENT_OPENAI_API_KEY", "TRIDENT_OLLAMA_MODEL", "EXPERT_MODEL",
                    "TRIDENT_JUDGE_MODEL", "JUDGE_MODEL", "TRIDENT_REDTEAM_MODEL",
                    "REDTEAM_MODEL", "TRIDENT_LLM_BACKEND", "LLM_BACKEND"):
            monkeypatch.delenv(key, raising=False)

        configured = Settings().llm
        monkeypatch.setattr(settings, "llm", configured)
        file_backend = get_llm_backend()
        file_backend.chat([ChatMessage("user", "config request")], model=configured.model_for("expert"))
        file_backend.client.close()
        assert file_server.calls[-1]["model"] == "config-expert"
        assert file_server.calls[-1]["auth_present"]

        monkeypatch.setenv("OPENAI_BASE_URL", f"{env_server.base_url}/v1/")
        monkeypatch.setenv("OPENAI_API_KEY", "synthetic-env-key")
        monkeypatch.setenv("EXPERT_MODEL", "environment-expert")
        monkeypatch.setenv("JUDGE_MODEL", "environment-judge")
        environment = Settings().llm
        monkeypatch.setattr(settings, "llm", environment)
        env_backend = get_llm_backend()
        for role in ("expert", "judge", "redteam"):
            env_backend.chat(
                [ChatMessage("user", f"environment {role} request")],
                model=environment.model_for(role),
            )
        env_backend.client.close()

        assert [call["path"] for call in env_server.calls] == ["/v1/chat/completions"] * 3
        assert [call["model"] for call in env_server.calls] == [
            "environment-expert", "environment-judge", "config-redteam",
        ]
        assert all(call["auth_present"] for call in env_server.calls)
        assert len(file_server.calls) == 1
        assert len(env_server.calls) == 3


def test_config_secret_cli_masks_output_and_rejects_command_line_values(tmp_path, monkeypatch):
    config_file = tmp_path / "config.toml"
    monkeypatch.setattr(config_manager, "_config_path", lambda: config_file)
    for key in ("OPENAI_API_KEY", "TRIDENT_OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(key, raising=False)
    runner = CliRunner()
    secret = "synthetic-secret-value-9182"

    prompted = runner.invoke(
        cli, ["config", "set", "llm.openai_api_key"],
        input=f"{secret}\n{secret}\n",
    )
    assert prompted.exit_code == 0, prompted.output
    assert secret not in prompted.stdout
    assert secret not in prompted.stderr
    assert "value hidden" in prompted.stdout

    retrieved = runner.invoke(cli, ["config", "get", "llm.openai_api_key"])
    assert retrieved.exit_code == 0
    assert "********" in retrieved.stdout
    assert secret not in retrieved.stdout + retrieved.stderr

    listed = runner.invoke(cli, ["config", "show"])
    assert listed.exit_code == 0
    assert "********" in listed.stdout
    assert secret not in listed.stdout + listed.stderr

    rejected = runner.invoke(
        cli, ["config", "set", "llm.openai_api_key", secret],
    )
    assert rejected.exit_code != 0
    assert "secret configuration value was rejected" in rejected.stderr
    assert secret not in rejected.stdout + rejected.stderr

    stdin_secret = "synthetic-test-key"
    stdin_result = runner.invoke(
        cli, ["config", "set", "llm.openai_api_key", "--stdin"],
        input=f"{stdin_secret}\n",
    )
    assert stdin_result.exit_code == 0
    assert stdin_secret not in stdin_result.stdout + stdin_result.stderr

    def fail_without_disclosure(_key, value):
        raise ValueError(f"invalid credential {value}")

    monkeypatch.setattr(config_manager, "set_value", fail_without_disclosure)
    failure = runner.invoke(
        cli, ["config", "set", "llm.openai_api_key"],
        input=f"{secret}\n{secret}\n",
    )
    assert failure.exit_code == 1
    assert "secret configuration value was rejected" in failure.stderr
    assert secret not in failure.stdout + failure.stderr


@pytest.mark.parametrize("status", [401, 403, 404, 500])
def test_openai_compatible_http_status_failures(status):
    with OpenAICompatibleServer() as server:
        server.set_behavior("/v1/chat/completions", status=status)
        backend = OpenAIBackend(base_url=f"{server.base_url}/v1", max_retries=0)
        try:
            with pytest.raises(LLMError, match=str(status)):
                backend._post(f"{backend.base_url}/chat/completions", {"model": "synthetic"})
        finally:
            backend.client.close()
        assert len(server.calls) == 1


def test_openai_compatible_malformed_json_response():
    with OpenAICompatibleServer() as server:
        server.set_behavior("/v1/chat/completions", malformed_json=True)
        backend = OpenAIBackend(base_url=f"{server.base_url}/v1", max_retries=0)
        try:
            with pytest.raises(LLMError, match="malformed JSON"):
                backend._post(f"{backend.base_url}/chat/completions", {"model": "synthetic"})
        finally:
            backend.client.close()


def test_openai_compatible_malformed_envelope_and_structured_response(monkeypatch):
    with OpenAICompatibleServer() as server:
        server.set_behavior("/v1/chat/completions", response={"choices": []})
        backend = OpenAIBackend(base_url=f"{server.base_url}/v1", max_retries=0)
        try:
            with pytest.raises(LLMError, match="invalid chat completion"):
                backend.chat([], model="security-expert")

            server.set_behavior("/v1/chat/completions", chat_content="not a structured response")
            monkeypatch.setattr("trident.llm.base._llm", backend)
            from trident.config import settings as app_settings
            old_retries = app_settings.llm.max_repair_retries
            app_settings.llm.max_repair_retries = 0
            try:
                result = chat_structured(
                    [ChatMessage("user", "Synthetic schema validation")],
                    ReviewVerdict, model="security-expert",
                )
            finally:
                app_settings.llm.max_repair_retries = old_retries
            assert not result.ok
            assert "schema" in (result.error or "").lower() or "json" in (result.error or "").lower()
        finally:
            backend.client.close()
        assert len(server.calls) == 2


def test_openai_compatible_empty_models_timeout_and_connection_failure():
    with OpenAICompatibleServer(model_alias="enterprise-sec-model") as server:
        server.set_behavior("/v1/models", empty_models=True)
        backend = OpenAIBackend(base_url=f"{server.base_url}/v1", model="missing-alias", max_retries=0)
        try:
            result = backend.health()
            assert result["status"] == "ok"
            assert result["models"] == []
            assert result["expert_model_available"] is False
        finally:
            backend.client.close()

    with OpenAICompatibleServer() as slow_server:
        slow_server.set_behavior("/v1/chat/completions", delay=0.15)
        backend = OpenAIBackend(base_url=f"{slow_server.base_url}/v1", timeout=0.02, max_retries=0)
        try:
            with pytest.raises(LLMUnavailable, match="timed out"):
                backend.chat([], model="security-expert")
        finally:
            backend.client.close()

    failed_server = OpenAICompatibleServer()
    failed_url = failed_server.base_url
    failed_server.close()
    backend = OpenAIBackend(base_url=f"{failed_url}/v1", timeout=0.1, max_retries=0)
    try:
        with pytest.raises(LLMUnavailable, match="unreachable"):
            backend.chat([], model="security-expert")
    finally:
        backend.client.close()


def test_routing_corpus_required_experts_determinism_and_legacy_compatibility():
    experts = _experts()
    rows = []
    for case in CASES:
        finding = finding_for(case)
        decisions = route_finding(finding, experts)
        repeated = route_finding(finding, experts)
        assert decisions == repeated
        selected = {decision.expert for decision in decisions if decision.relevant}
        rows.append((case, selected, decisions))

    required = sum(len(case["required"]) for case in CASES)
    selected_required = sum(
        sum(expert in selected for expert in case["required"])
        for case, selected, _decisions in rows
    )
    assert selected_required == required

    baseline_assignments = optimized_assignments = 0
    for case, selected, _ in rows:
        finding = finding_for(case)
        legacy_selected = {expert.name for expert in experts if _legacy_relevant(expert, finding)}
        baseline_assignments += len(legacy_selected)
        optimized_assignments += len(selected)
        assert selected >= legacy_selected, case["id"]
        assert not (selected & set(case["incorrect"])), case["id"]
    # This correction prioritizes the original review coverage.  Call-count
    # reduction is not an acceptance requirement.
    assert optimized_assignments >= baseline_assignments

    by_id = {case["id"]: selected for case, selected, _ in rows}
    assert by_id["multidomain_injection_auth"] >= {"injection", "auth"}
    assert by_id["jwt_signature"] >= {"auth", "crypto"}
    assert by_id["dependency_crypto_implication"] >= {"dependency", "crypto"}
    assert by_id["exposed_credential_privilege_escalation"] >= {"secrets_config", "auth"}
    assert by_id["configuration_auth_bypass"] >= {"secrets_config", "auth"}

    misleading = {case["id"]: selected for case, selected, _ in rows}
    assert misleading["misleading_auth_keyword"] == {"injection", "auth"}
    assert misleading["crypto_in_package_name"] == {"dependency", "crypto"}
    assert misleading["generic_token_not_secret"] == {"secrets_config"}
    assert misleading["password_in_docs"] == {"secrets_config"}
    assert misleading["cwe_only_sparse"] == {"injection"}
    assert misleading["owasp_only"] == {"injection"}
    assert misleading["sparse_scanner_metadata"] == {"secrets_config"}
    decisions_by_case = {case["id"]: decisions for case, _selected, decisions in rows}
    for case_id, expert_name in (
        ("misleading_auth_keyword", "auth"),
        ("generic_token_not_secret", "secrets_config"),
        ("crypto_in_package_name", "crypto"),
        ("password_in_docs", "secrets_config"),
    ):
        decision = next(d for d in decisions_by_case[case_id] if d.expert == expert_name)
        assert decision.relevant
        assert "legacy compatibility match" in decision.reasons
        assert "semantic rule match" not in decision.reasons


def test_independent_holdout_preserves_legacy_matches_and_required_experts(record_property):
    from types import SimpleNamespace

    experts = _experts()
    baseline_assignments = corrected_assignments = required_selected = required_total = 0
    for case in HOLDOUT:
        finding = SimpleNamespace(
            **{key: value for key, value in case.items() if key not in {"id", "required"}},
            file="src/holdout.py", line_start=1, line_end=1,
            raw_outputs={}, corroborating_tools=[], owasp=None,
        )
        decisions = route_finding(finding, experts)
        assert decisions == route_finding(finding, experts)
        selected = {decision.expert for decision in decisions if decision.relevant}
        baseline = {expert.name for expert in experts if legacy_expert_match(finding, expert)}
        assert selected >= baseline, case["id"]
        assert selected >= case["required"], case["id"]
        required_selected += len(selected & case["required"])
        required_total += len(case["required"])
        baseline_assignments += len(baseline)
        corrected_assignments += len(selected)

    record_property("holdout_required_recall", required_selected / required_total)
    record_property("holdout_baseline_assignments", baseline_assignments)
    record_property("holdout_corrected_assignments", corrected_assignments)
    assert required_selected == required_total
    assert corrected_assignments >= baseline_assignments


def test_full_known_vulnerability_pipeline_coverage_does_not_decrease(
    db, job, monkeypatch, record_property,
):
    import trident.deliberation as deliberation

    known_cases = [case for case in CASES if case["required"]]
    baseline_job_id, optimized_job_id = "route-baseline", "route-optimized"
    baseline_experts = _experts(baseline_job_id)
    optimized_experts = _experts(optimized_job_id)
    db.add_all([
        Job(id=baseline_job_id, target_name="baseline", source_type="demo", source_ref="",
            workspace_path="", profile={}),
        Job(id=optimized_job_id, target_name="optimized", source_type="demo", source_ref="",
            workspace_path="", profile={}),
    ])
    rows_by_job = {baseline_job_id: [], optimized_job_id: []}
    for job_id in rows_by_job:
        for case in known_cases:
            values = finding_for(case).__dict__.copy()
            values.update({
                "id": f"{job_id}-{case['id']}", "job_id": job_id,
                "hash": f"hash-{job_id}-{case['id']}", "status": "raw",
            })
            finding = Finding(**{key: value for key, value in values.items() if not key.startswith("_")})
            db.add(finding)
            rows_by_job[job_id].append((case, finding))
    db.commit()

    original_route = deliberation.route_finding
    invocation_rows = {baseline_job_id: [], optimized_job_id: []}

    def instrument(expert, job_id):
        invoke = expert.invoke_review

        def traced(finding, *args, **kwargs):
            invocation_rows[job_id].append((finding.id, expert.name))
            return invoke(finding, *args, **kwargs)

        expert.invoke_review = traced

    for expert in baseline_experts:
        instrument(expert, baseline_job_id)

    def baseline_route(finding, available):
        selected = {expert.name for expert in available if _legacy_relevant(expert, finding)}
        return [RoutingDecision(e.name, e.name in selected, 1 if e.name in selected else 0,
                                ("baseline rule",) if e.name in selected else ())
                for e in sorted(available, key=lambda item: item.name)]

    def handler(messages, model):
        system = messages[0].content.lower()
        user = messages[-1].content.lower()
        if "you are the judge" in system:
            if "no prior expert verdicts" in user:
                return {"final_verdict": "disputed", "final_confidence": 0.45,
                        "reasoning": "No domain review was available."}
            return {"final_verdict": "confirmed", "final_confidence": 0.95,
                    "reasoning": "Domain evidence was reviewed."}
        return {"verdict": "confirmed", "confidence": 0.95,
                "severity": "high", "narrative": "Synthetic known vulnerability confirmed."}

    set_mock_handler(handler)
    judge = JudgeExpert(job.id, "")
    monkeypatch.setattr(deliberation, "route_finding", baseline_route)
    baseline_findings = [finding for _case, finding in rows_by_job[baseline_job_id]]
    run_reviews(db, baseline_experts, judge, baseline_findings, 0, LLMBudget())
    baseline_covered = sum(f.status == "confirmed" for f in baseline_findings)
    baseline_verdicts = {
        (finding.id.removeprefix(f"{baseline_job_id}-"), verdict.expert): verdict.verdict
        for finding in baseline_findings
        for verdict in db.query(FindingVerdict).filter_by(finding_id=finding.id).all()
    }
    baseline_confirmed = {
        finding.id.removeprefix(f"{baseline_job_id}-")
        for finding in baseline_findings if finding.status == "confirmed"
    }
    for expert in optimized_experts:
        instrument(expert, optimized_job_id)

    monkeypatch.setattr(deliberation, "route_finding", original_route)
    optimized_findings = [finding for _case, finding in rows_by_job[optimized_job_id]]
    run_reviews(db, optimized_experts, judge, optimized_findings, 0, LLMBudget())
    optimized_covered = sum(f.status == "confirmed" for f in optimized_findings)
    optimized_verdicts = {
        (finding.id.removeprefix(f"{optimized_job_id}-"), verdict.expert): verdict.verdict
        for finding in optimized_findings
        for verdict in db.query(FindingVerdict).filter_by(finding_id=finding.id).all()
    }
    optimized_confirmed = {
        finding.id.removeprefix(f"{optimized_job_id}-")
        for finding in optimized_findings if finding.status == "confirmed"
    }

    # Compare the production triage stage too: each run gets the same controlled
    # assessment for every confirmed fixture so priority deltas isolate routing.
    import trident.triage as triage

    monkeypatch.setattr(
        triage, "_assess",
        lambda workspace, finding, budget=None: TriageAssessment(
            impact="data_exposure", attack_vector="remote_auth",
            exploitability="moderate", fix_effort="moderate",
            rationale="Synthetic controlled triage evidence.",
        ),
    )
    triage.run_triage(db, baseline_job_id, LLMBudget())
    triage.run_triage(db, optimized_job_id, LLMBudget())
    baseline_priorities = {
        finding.id.removeprefix(f"{baseline_job_id}-"): finding.priority
        for finding in baseline_findings
    }
    optimized_priorities = {
        finding.id.removeprefix(f"{optimized_job_id}-"): finding.priority
        for finding in optimized_findings
    }

    baseline_calls = {
        (finding_id.removeprefix(f"{baseline_job_id}-"), expert_name)
        for finding_id, expert_name in invocation_rows[baseline_job_id]
    }
    optimized_calls = {
        (finding_id.removeprefix(f"{optimized_job_id}-"), expert_name)
        for finding_id, expert_name in invocation_rows[optimized_job_id]
    }
    assert optimized_calls >= baseline_calls
    corrected_invocations = set(optimized_calls)
    for case_id, required_expert in (
        ("eval_injection", "injection"),
        ("session_weakness", "auth"),
        ("weak_rsa", "crypto"),
        ("sbom_package_finding", "dependency"),
        ("cors_misconfiguration", "secrets_config"),
    ):
        assert (case_id, required_expert) in corrected_invocations
    for key, verdict in baseline_verdicts.items():
        assert optimized_verdicts[key] == verdict
    assert optimized_confirmed == baseline_confirmed == {case["id"] for case in known_cases}
    assert optimized_priorities == baseline_priorities

    record_property("known_vulnerability_baseline_confirmed", baseline_covered)
    record_property("known_vulnerability_optimized_confirmed", optimized_covered)
    record_property("known_vulnerability_fixture_count", len(known_cases))
    record_property("baseline_expert_invocations", len(baseline_calls))
    record_property("corrected_expert_invocations", len(optimized_calls))
    record_property("baseline_priorities", baseline_priorities)
    record_property("corrected_priorities", optimized_priorities)
    assert optimized_covered >= baseline_covered
    assert optimized_covered == len(known_cases)


def test_redteam_exact_duplicate_reuses_paths_and_zero_budget(db):
    job, finding = _redteam_fixture(db)
    calls = []
    set_mock_handler(_successful_redteam_handler(calls))
    redteam = RedTeamExpert(job.id, "")
    first_budget = LLMBudget()
    build_attack_chains(db, job.id, redteam, [finding], 0, first_budget)
    db.commit()
    db.refresh(finding)
    first_paths = list(finding.attack_paths)
    assert first_budget.used == 1
    assert first_paths
    assert db.query(AttackChain).filter_by(job_id=job.id).count() == 1

    second_budget = LLMBudget(limit=1)
    build_attack_chains(db, job.id, redteam, [finding], 1, second_budget)
    db.commit()
    db.refresh(finding)
    assert len(calls) == 1
    assert second_budget.used == 0
    assert finding.attack_paths == first_paths
    assert db.query(AttackChain).filter_by(job_id=job.id).count() == 1
    assert db.query(JobEvent).filter_by(job_id=job.id, type="redteam.analysis.reused").count() == 1


def test_redteam_changed_input_budget_exhaustion_clears_stale_chains_and_report(db):
    job, finding = _redteam_fixture(db)
    calls = []
    set_mock_handler(_successful_redteam_handler(calls))
    redteam = RedTeamExpert(job.id, "")
    build_attack_chains(db, job.id, redteam, [finding], 0, LLMBudget())
    db.commit()
    db.refresh(finding)
    assert finding.attack_paths
    old_fingerprint = (job.profile or {})["_redteam_analysis"]["fingerprint"]

    finding.description = "Changed evidence with a distinct model-visible meaning."
    db.commit()
    changed = redteam.build_model_input([finding])
    exhausted_budget = LLMBudget(limit=0)
    build_attack_chains(db, job.id, redteam, [finding], 1, exhausted_budget)
    db.commit()
    db.refresh(job)
    db.refresh(finding)

    state = (job.profile or {})["_redteam_analysis"]
    assert changed["fingerprint"] != old_fingerprint
    assert state == {
        "fingerprint": changed["fingerprint"],
        "status": "unavailable_budget",
        "paths": 0,
    }
    assert exhausted_budget.used == 0
    assert len(calls) == 1
    assert finding.attack_paths == []
    assert db.query(AttackChain).filter_by(job_id=job.id).count() == 0
    unavailable = db.query(JobEvent).filter_by(
        job_id=job.id, type="redteam.analysis.unavailable",
    ).one()
    assert unavailable.payload["reason"] == "llm_budget_exhausted"
    report = to_json(db, job.id)
    assert report["redteam_analysis"] == {
        "status": "unavailable_budget",
        "fingerprint": changed["fingerprint"],
        "paths": 0,
    }
    assert report["attack_chains"] == []
    assert report["findings"][0]["attack_paths"] == []
    assert to_triage_json(db, job.id)["redteam_analysis"]["status"] == "unavailable_budget"
    assert to_sarif(db, job.id)["runs"][0]["properties"]["redteam_analysis"]["status"] == "unavailable_budget"
    assert to_triage_sarif(db, job.id)["runs"][0]["properties"]["redteam_analysis"]["status"] == "unavailable_budget"


def test_redteam_fingerprint_matches_final_wire_messages(db, monkeypatch):
    import hashlib
    import json

    job, finding = _redteam_fixture(db)
    with OpenAICompatibleServer(api_key="synthetic-redteam-key") as server:
        backend = OpenAIBackend(
            api_key="synthetic-redteam-key", base_url=f"{server.base_url}/v1/",
            timeout=2, max_retries=0,
        )
        monkeypatch.setattr("trident.llm.base._llm", backend)
        try:
            redteam = RedTeamExpert(job.id, "")
            model_input = redteam.build_model_input([finding])
            result = redteam.invoke_chains([finding], model_input=model_input)
        finally:
            backend.client.close()

    assert result.ok
    request = server.calls[0]["request_body"]
    assert request["model"] == model_input["model"]
    assert request["messages"] == model_input["messages"]
    assert request["temperature"] == model_input["temperature"]
    canonical = {
        "model": model_input["model"],
        "messages": model_input["messages"],
        "temperature": model_input["temperature"],
        "response_schema": model_input["response_schema"],
    }
    raw = json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    assert hashlib.sha256(raw.encode("utf-8")).hexdigest() == model_input["fingerprint"]


@pytest.mark.parametrize("change", [
    {"description": "The query now joins a caller-controlled tenant value."},
    {"severity": "critical"},
    {"cwe": "CWE-78"},
    {"file": "src/changed.py"},
    {"line_start": 23},
    {"raw_outputs": {"raw": {"import_format": "sarif", "record": {"message": "new prompt evidence"}}}},
])
def test_redteam_changed_prompt_visible_finding_data_reruns(db, change):
    job, finding = _redteam_fixture(db)
    calls = []
    set_mock_handler(_successful_redteam_handler(calls))
    redteam = RedTeamExpert(job.id, "")
    build_attack_chains(db, job.id, redteam, [finding], 0, LLMBudget())
    db.commit()
    finding_values = {key: value for key, value in change.items()}
    for key, value in finding_values.items():
        setattr(finding, key, value)
    db.commit()
    build_attack_chains(db, job.id, redteam, [finding], 1, LLMBudget())
    db.commit()
    assert len(calls) == 2
    assert calls[0]["messages"] != calls[1]["messages"]


def test_redteam_new_and_removed_confirmed_findings_rerun(db):
    job, first = _redteam_fixture(db)
    calls = []
    set_mock_handler(_successful_redteam_handler(calls))
    redteam = RedTeamExpert(job.id, "")
    build_attack_chains(db, job.id, redteam, [first], 0, LLMBudget())
    db.commit()
    second = Finding(
        id="finding-red-2", job_id=job.id, hash="synthetic-red-hash-2", tool="sarif-import",
        rule_id="SYNTHETIC-2", severity="medium", confidence=0.9,
        title="Exposed credential", description="A committed credential is exposed.",
        file="src/config.py", line_start=9, line_end=9, cwe="CWE-798",
        raw_outputs={"raw": {"import_format": "sarif", "record": {"ruleId": "SYNTHETIC-2"}}},
        status="confirmed",
    )
    db.add(second)
    db.commit()
    build_attack_chains(db, job.id, redteam, [first, second], 1, LLMBudget())
    db.commit()
    second_fp = redteam.build_model_input([first, second])["fingerprint"]
    build_attack_chains(db, job.id, redteam, [first], 2, LLMBudget())
    db.commit()
    assert len(calls) == 3
    assert calls[1]["messages"] != calls[2]["messages"]
    assert (job.profile or {})["_redteam_analysis"]["fingerprint"] != second_fp


def test_redteam_removal_of_last_confirmed_finding_reruns_with_empty_input(db):
    job, finding = _redteam_fixture(db)
    calls = []
    set_mock_handler(_successful_redteam_handler(calls))
    redteam = RedTeamExpert(job.id, "")
    build_attack_chains(db, job.id, redteam, [finding], 0, LLMBudget())
    db.commit()
    build_attack_chains(db, job.id, redteam, [], 1, LLMBudget())
    db.commit()
    assert len(calls) == 2
    assert "SELECTED FINDING IDS: none" in calls[1]["messages"][1][1]
    db.refresh(finding)
    assert finding.attack_paths == []
    assert db.query(AttackChain).filter_by(job_id=job.id).count() == 0


def test_redteam_source_grounded_state_is_fingerprinted(tmp_path, db):
    source = tmp_path / "src" / "account.py"
    source.parent.mkdir()
    source.write_text("def account(): pass\n", encoding="utf-8")
    job, finding = _redteam_fixture(db, workspace="")
    calls = []
    set_mock_handler(_successful_redteam_handler(calls))
    redteam = RedTeamExpert(job.id, "")
    report_only = redteam.build_model_input([finding])
    build_attack_chains(db, job.id, redteam, [finding], 0, LLMBudget())
    db.commit()
    redteam.workspace = str(tmp_path)
    source_grounded = redteam.build_model_input([finding])
    assert report_only["fingerprint"] != source_grounded["fingerprint"]
    build_attack_chains(db, job.id, redteam, [finding], 1, LLMBudget())
    db.commit()
    assert len(calls) == 2
    assert "report_only" in calls[0]["messages"][1][1]
    assert "source_grounded" in calls[1]["messages"][1][1]


def test_redteam_selection_is_stable_with_more_than_limit_and_db_order(db):
    job, _ = _redteam_fixture(db)
    values = []
    for index in range(55):
        values.append(Finding(
            id=f"finding-{index:02d}", job_id=job.id, hash=f"hash-{index:02d}",
            tool="semgrep", rule_id=f"rule-{index}", severity=("critical" if index % 4 == 0 else "high"),
            confidence=0.8, title=f"SQL injection {index}", description=f"Synthetic description {index}",
            file=f"src/file-{index:02d}.py", line_start=index + 1, line_end=index + 1,
            cwe="CWE-89", raw_outputs={}, status="confirmed",
        ))
    ordered = sorted(values, key=lambda finding: finding.id)
    reversed_order = list(reversed(ordered))
    redteam = RedTeamExpert(job.id, "")
    first = redteam.build_model_input(ordered)
    second = redteam.build_model_input(reversed_order)
    assert len(select_redteam_findings(ordered)) == 40
    assert first["selected_finding_ids"] == second["selected_finding_ids"]
    assert first["fingerprint"] == second["fingerprint"]


def test_redteam_reuses_when_db_order_changes_but_visible_input_does_not(db):
    job, first = _redteam_fixture(db)
    second = Finding(
        id="finding-red-2", job_id=job.id, hash="synthetic-red-hash-2", tool="sarif-import",
        rule_id="SYNTHETIC-2", severity="medium", confidence=0.9,
        title="Exposed credential", description="A committed credential is exposed.",
        file="src/config.py", line_start=9, line_end=9, cwe="CWE-798",
        raw_outputs={"raw": {"import_format": "sarif", "record": {"ruleId": "SYNTHETIC-2"}}},
        status="confirmed",
    )
    db.add(second)
    db.commit()
    calls = []
    set_mock_handler(_successful_redteam_handler(calls))
    redteam = RedTeamExpert(job.id, "")
    build_attack_chains(db, job.id, redteam, [first, second], 0, LLMBudget())
    db.commit()
    budget = LLMBudget(limit=1)
    build_attack_chains(db, job.id, redteam, [second, first], 1, budget)
    db.commit()
    assert len(calls) == 1
    assert budget.used == 0
    assert db.query(AttackChain).filter_by(job_id=job.id).count() == 1


def test_redteam_failed_analysis_is_not_cached_and_can_retry(db, monkeypatch):
    from trident.config import settings as app_settings

    job, finding = _redteam_fixture(db)
    outputs = ["malformed response", {"attack_paths": [{
        "goal": "Recovered synthetic chain", "steps": ["Retry succeeds."],
        "findings_used": [finding.id], "likelihood": "low",
    }]}]
    calls = []

    def handler(messages, model):
        calls.append(model)
        return outputs.pop(0)

    set_mock_handler(handler)
    old_retries = app_settings.llm.max_repair_retries
    app_settings.llm.max_repair_retries = 0
    try:
        redteam = RedTeamExpert(job.id, "")
        build_attack_chains(db, job.id, redteam, [finding], 0, LLMBudget())
        db.commit()
        assert "_redteam_analysis" not in (job.profile or {})
        build_attack_chains(db, job.id, redteam, [finding], 1, LLMBudget())
        db.commit()
    finally:
        app_settings.llm.max_repair_retries = old_retries
    assert calls == [redteam.model, redteam.model]
    assert (job.profile or {})["_redteam_analysis"]["status"] == "success"
    db.refresh(finding)
    assert finding.attack_paths


def test_redteam_changed_failure_does_not_leave_stale_prior_fingerprint(db, monkeypatch):
    from trident.config import settings as app_settings

    job, finding = _redteam_fixture(db)
    calls = []

    def handler(messages, model):
        prompt = next(message.content for message in messages if message.role == "user")
        calls.append(prompt)
        if len(calls) == 2:
            return "malformed changed-input response"
        ids = [line[3:].split("]", 1)[0] for line in prompt.splitlines()
               if line.startswith("- [") and "] " in line]
        return {"attack_paths": [{
            "goal": "Synthetic restored-input chain", "steps": ["Retry the identical request."],
            "findings_used": ids[:1], "likelihood": "low",
        }]}

    set_mock_handler(handler)
    old_retries = app_settings.llm.max_repair_retries
    app_settings.llm.max_repair_retries = 0
    try:
        redteam = RedTeamExpert(job.id, "")
        build_attack_chains(db, job.id, redteam, [finding], 0, LLMBudget())
        db.commit()
        finding.description = "Changed evidence that fails to parse."
        db.commit()
        build_attack_chains(db, job.id, redteam, [finding], 1, LLMBudget())
        db.commit()
        assert "_redteam_analysis" not in (job.profile or {})
        finding.description = "Untrusted account input is joined to the database query."
        db.commit()
        build_attack_chains(db, job.id, redteam, [finding], 2, LLMBudget())
        db.commit()
    finally:
        app_settings.llm.max_repair_retries = old_retries

    assert len(calls) == 3
    assert calls[0] == calls[2]
    db.refresh(finding)
    assert finding.attack_paths
    assert db.query(AttackChain).filter_by(job_id=job.id).count() == 1
