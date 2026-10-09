"""Generate deterministic before/after routing evidence for the acceptance handoff."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
sys.path.insert(0, str(BACKEND))
sys.path.insert(0, str(BACKEND / "tests"))

from routing_corpus import CASES, finding_for  # noqa: E402
from trident.experts.auth import AuthExpert  # noqa: E402
from trident.experts.crypto import CryptoExpert  # noqa: E402
from trident.experts.dependency import DependencyExpert  # noqa: E402
from trident.experts.injection import InjectionExpert  # noqa: E402
from trident.experts.routing import legacy_expert_match, route_finding  # noqa: E402
from trident.experts.secrets_config import SecretsConfigExpert  # noqa: E402


def metric_rows(cases: list[dict], experts: list) -> tuple[list[dict], dict]:
    rows = []
    required_count = required_selected = baseline_assignments = corrected_assignments = 0
    baseline_case_coverage = corrected_case_coverage = 0
    incorrect_assignments = 0
    for case in cases:
        finding = finding_for(case)
        decisions = route_finding(finding, experts)
        corrected = sorted(d.expert for d in decisions if d.relevant)
        baseline = sorted(e.name for e in experts if legacy_expert_match(finding, e))
        required = sorted(case["required"])
        selected_required = sorted(set(required) & set(corrected))
        missed = sorted(set(required) - set(corrected))
        incorrect = sorted(set(case["incorrect"]) & set(corrected))
        baseline_assignments += len(baseline)
        corrected_assignments += len(corrected)
        required_count += len(required)
        required_selected += len(selected_required)
        incorrect_assignments += len(incorrect)
        if required and set(required).issubset(baseline):
            baseline_case_coverage += 1
        if required and set(required).issubset(corrected):
            corrected_case_coverage += 1
        rows.append({
            "id": case["id"],
            "required_experts": required,
            "optional_experts": sorted(case["optional"]),
            "incorrect_experts": sorted(case["incorrect"]),
            "baseline_selected": baseline,
            "corrected_decisions": [d.as_dict() for d in decisions],
            "corrected_selected": corrected,
            "required_selected": selected_required,
            "required_missed": missed,
            "incorrect_selected": incorrect,
        })
    assignment_delta = corrected_assignments - baseline_assignments
    return rows, {
        "case_count": len(cases),
        "legacy_expert_assignments": baseline_assignments,
        "corrected_expert_assignments": corrected_assignments,
        "corrected_minus_legacy_assignments": assignment_delta,
        "corrected_invocation_change_percent": round(
            assignment_delta * 100 / baseline_assignments, 2,
        ) if baseline_assignments else 0.0,
        "required_expert_assignments": required_count,
        "required_experts_selected": required_selected,
        "required_expert_recall_percent": round(required_selected * 100 / required_count, 2)
        if required_count else 100.0,
        "incorrect_expert_assignments": incorrect_assignments,
        "baseline_fully_covered_known_findings": baseline_case_coverage,
        "corrected_fully_covered_known_findings": corrected_case_coverage,
        "known_vulnerability_fixture_count": sum(bool(c["required"]) for c in cases),
    }


def main() -> None:
    output = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / ".acceptance" / "expert-routing-metrics.json"
    baseline_path = ROOT / ".acceptance" / "gateway-analysis-baseline-routing.json"
    experts = [
        InjectionExpert("acceptance", ""), AuthExpert("acceptance", ""),
        CryptoExpert("acceptance", ""), DependencyExpert("acceptance", ""),
        SecretsConfigExpert("acceptance", ""),
    ]
    rows, metrics = metric_rows(CASES, experts)
    live_baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    baseline_ids = {row["id"] for row in live_baseline.get("findings", [])}
    same_case_rows = [row for row in rows if row["id"] in baseline_ids]
    same_rows_metrics = metric_rows(
        [case for case in CASES if case["id"] in baseline_ids], experts,
    )[1]
    payload = {
        "corpus": "labelled synthetic routing corpus; per-finding decisions include reasons",
        "routing_quality_priority": True,
        "call_reduction_required": False,
        "same_final_corpus_replay": metrics,
        "corrected_per_finding": rows,
        "initial_live_baseline": {
            key: live_baseline.get(key)
            for key in (
                "state", "corpus_cases", "total_expert_assignments",
                "required_expert_assignments", "required_experts_selected",
                "required_expert_recall",
            )
        },
        "initial_33_case_cohort_corrected_replay": {
            "corrected_metrics": same_rows_metrics,
            "per_finding": same_case_rows,
        },
        "interpretation": (
            "Required-expert recall and known-vulnerability coverage take precedence. "
            "No expert-call reduction is required; any assignment increase is recorded "
            "without treating it as a quality failure."
        ),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output), **metrics}, indent=2))


if __name__ == "__main__":
    main()
