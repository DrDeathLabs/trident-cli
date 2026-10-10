"""Emit legacy-versus-corrected routing decisions for the corrective handoff."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
sys.path.insert(0, str(BACKEND))
sys.path.insert(0, str(BACKEND / "tests"))

from routing_corpus import CASES, finding_for  # noqa: E402
from routing_holdout import HOLDOUT  # noqa: E402
from trident.experts.auth import AuthExpert  # noqa: E402
from trident.experts.crypto import CryptoExpert  # noqa: E402
from trident.experts.dependency import DependencyExpert  # noqa: E402
from trident.experts.injection import InjectionExpert  # noqa: E402
from trident.experts.routing import legacy_expert_match, route_finding  # noqa: E402
from trident.experts.secrets_config import SecretsConfigExpert  # noqa: E402


def _experts():
    return [
        InjectionExpert("acceptance", ""), AuthExpert("acceptance", ""),
        CryptoExpert("acceptance", ""), DependencyExpert("acceptance", ""),
        SecretsConfigExpert("acceptance", ""),
    ]


def _measure(cases: list[dict], experts, *, holdout: bool = False) -> dict:
    rows = []
    legacy_assignments = corrected_assignments = required_assignments = required_selected = 0
    fully_covered = 0
    for case in cases:
        if holdout:
            finding = SimpleNamespace(
                **{key: value for key, value in case.items() if key not in {"id", "required"}},
                file="src/holdout.py", line_start=1, line_end=1,
                raw_outputs={}, corroborating_tools=[], owasp=None,
            )
            required = sorted(case["required"])
        else:
            finding = finding_for(case)
            required = sorted(case["required"])
        legacy = sorted(expert.name for expert in experts if legacy_expert_match(finding, expert))
        decisions = route_finding(finding, experts)
        corrected = sorted(decision.expert for decision in decisions if decision.relevant)
        selected_required = sorted(set(required) & set(corrected))
        missing_legacy = sorted(set(legacy) - set(corrected))
        missing_required = sorted(set(required) - set(corrected))
        legacy_assignments += len(legacy)
        corrected_assignments += len(corrected)
        required_assignments += len(required)
        required_selected += len(selected_required)
        if required and not missing_required:
            fully_covered += 1
        rows.append({
            "id": case["id"],
            "required_experts": required,
            "legacy_selected": legacy,
            "corrected_selected": corrected,
            "legacy_matches_missing_after_correction": missing_legacy,
            "required_experts_missing": missing_required,
            "decisions": [decision.as_dict() for decision in decisions],
        })
    return {
        "finding_count": len(cases),
        "baseline_expert_assignments": legacy_assignments,
        "optimized_expert_assignments": corrected_assignments,
        "assignment_delta_corrected_minus_legacy": corrected_assignments - legacy_assignments,
        "required_expert_assignments": required_assignments,
        "required_experts_selected": required_selected,
        "required_expert_recall_percent": (
            round(100 * required_selected / required_assignments, 2)
            if required_assignments else 100.0
        ),
        "known_vulnerability_findings": sum(bool(case["required"]) for case in cases),
        "fully_covered_findings": fully_covered,
        "legacy_matches_preserved": all(not row["legacy_matches_missing_after_correction"] for row in rows),
        "all_required_experts_selected": all(not row["required_experts_missing"] for row in rows),
        "per_finding": rows,
    }


def main() -> None:
    output = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / ".acceptance" / "corrective-routing-evidence.json"
    experts = _experts()
    payload = {
        "router_contract": "legacy_match OR structured_match",
        "call_reduction_acceptance_required": False,
        "labeled_corpus": _measure(CASES, experts),
        "independent_holdout": _measure(list(HOLDOUT), experts, holdout=True),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in payload.items() if key != "labeled_corpus" and key != "independent_holdout"}, indent=2))
    print(json.dumps({
        "labeled_corpus": {key: value for key, value in payload["labeled_corpus"].items() if key != "per_finding"},
        "independent_holdout": {key: value for key, value in payload["independent_holdout"].items() if key != "per_finding"},
        "output": str(output),
    }, indent=2))


if __name__ == "__main__":
    main()
