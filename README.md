# Trident CLI

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

Trident is a local AI-assisted vulnerability analysis and triage engine for the
command line. It combines twelve established scanners with a council of
specialized LLM reviewers and a novel, evidence-preserving workflow that turns
noisy scanner output into an automatically worked P0-P4 remediation queue.

Trident is built for the part of security work that scanners leave unresolved:
not only finding candidate weaknesses, but determining which candidates are
real, how they can be reached, how urgently each confirmed issue should be
worked in this codebase, and why.

Security tools are already good at producing candidates. The harder problem is
what comes next: hundreds of overlapping alerts, inconsistent severities,
weak reachability context, and false positives that consume the same scarce
engineering attention as real vulnerabilities. Trident is built around that
problem.

> Authorized use only. Scan code you own or have explicit permission to analyze.

## Why Trident is different

Trident separates two questions that ordinary scanner pipelines usually collapse:

1. **Is this candidate a real vulnerability?** Twelve deterministic scanners
   establish a broad recall floor. Correlation collapses duplicate evidence,
   then specialized AI reviewers examine injection, authentication,
   cryptography, dependency, and secrets/configuration findings. A judge
   re-examines high-impact or contested results, while a red-team pass looks
   for attack chains that are easy to miss when findings are considered one at
   a time.
2. **How urgently should this confirmed issue be worked here?** The triage
   pass asks the LLM for explicit, code-legible factors-impact, attack vector,
   exploitability, fix effort, and reachability context-instead of asking it to
   guess a priority label. Deterministic code computes P0-P4 from those
   factors, applies evidence-based correction and reachability analysis, then
   allows attack-chain evidence to raise the final priority when warranted.

This sequence is Trident's novel contribution: scanner recall feeds AI
adjudication, AI factor assessment feeds deterministic priority computation, and
every adjustment remains reconstructable. The result is not an opaque model
score. Trident preserves scanner evidence, council verdicts, reviewer reasoning,
original and adjusted triage factors, correction rationales, attack-chain
context, and final priority in machine-readable reports.

### Triage is the product

Scanner false positives are expected. They are candidates, not failures of the
scanner or proof of a vulnerability. Trident correlates duplicates, challenges
the candidate with multiple expert perspectives, and automatically removes
refuted or rejected candidates from the actionable queue. It does not erase
them: false-positive counts, dispositions, rationales, and source evidence
remain available for audit.

For findings that survive review, Trident answers the operational question that
scanner severity cannot: how urgently should this specific issue be worked in
this codebase? It assesses impact, attack vector, exploitability, fix effort,
reachability, correction adjustments, and attack-chain context, then computes a
transparent P0-P4 priority. The full result is a worked queue rather than a
flat alert list-with rationale, recommended action, service-level guidance,
and a record of what changed between the model assessment and final triage.

This is useful to the wider security community because it connects the tools
people already use to a reviewable decision record. SARIF remains compatible
with code-scanning workflows; JSON supports automation and research; table
output supports humans at the terminal; and the triage sidecar keeps the
complete adjudication trail instead of forcing teams to choose between signal
and auditability.

In one 215-finding PyGoat evaluation, the documented deterministic correction
changed the P0-P4 shape from a scanner/model-driven barbell (47 P0 findings) to
a graded queue with 13 P0 findings. That snapshot also reached exact expert-tier
agreement on 8 of 10 detected planted findings and agreement within one tier on
all 10. These are Trident evaluation results, not universal performance claims;
see the [full triage evaluation snapshot](docs/TRIAGE.md#evaluation-snapshot-from-alert-barbell-to-worked-queue)
for scope and limitations.

Trident is not an autonomous security approval system. Its AI decisions are
untrusted input, its calibration logic is intentionally conservative, and
high-impact results still require qualified human review.

## The scan workflow

1. Ingest a local directory, Git checkout, or ZIP archive.
2. Run the configured deterministic scanners.
3. Correlate and deduplicate overlapping candidates.
4. Ask domain experts, the judge, and red-team review to adjudicate
   candidates and discover supported novel issues.
5. Apply class, reachability, and optional corpus-profile triage adjustments.
6. Run automatic triage on confirmed findings.
7. Write the primary report and, when requested, the complete worked-triage
   sidecar.

## Capabilities

- SAST: Semgrep, Bandit, gosec, and Checkov.
- Software composition analysis: Grype, OSV-Scanner, Trivy, pip-audit,
  npm-audit, and govulncheck.
- Secrets detection: Gitleaks and TruffleHog.
- Correlation, duplicate collapse, expert review, judge review, red-team chain
  analysis, reachability analysis, and automatic evidence-preserving P0-P4 triage.
- Local SQLite state with no network service required by the CLI itself.
- Configurable Ollama, OpenAI, or Anthropic review backends.

## Install and run

Python 3.11 or newer is required. A clean virtual environment is recommended.

```bash
python -m venv .venv

# macOS/Linux/WSL
source .venv/bin/activate

# Windows PowerShell
# .venv\Scripts\Activate.ps1

# Install the wheel downloaded from the GitHub release:
python -m pip install path/to/trident-0.1.0-py3-none-any.whl
trident --version
trident install-tools --verify --warmup
```

For a source checkout, install the package from `backend/`:

```bash
cd backend
python -m pip install .
```

Configure a review backend, then scan an authorized source tree:

```bash
trident config set llm.backend ollama
trident config set llm.base_url http://localhost:11434
trident config set llm.expert_model gemma4:31b-cloud
trident scan /path/to/source
```

The first tool setup downloads managed scanner binaries and installs the
Python-managed scanners into the active Python environment. Node.js/npm is
required for npm-audit; Trident does not install Node.js. Go-based tools use an
existing Go installation or a user-data bootstrap runtime.

The optional corpus-profile triage adjustment is built separately:

```bash
trident model refresh
trident model status
```

## Reports and CI

```bash
trident scan . --format table
trident scan . --format json --output-file results.json
trident scan . --format sarif --output-file results.sarif
trident scan . --format json --output-file results.json \
  --triage-output-file triage.json
```

The primary JSON and SARIF reports include compact triage metadata. The
`--triage-output-file` option writes the full worked queue with P0-P4 groups,
playbooks, SLAs, factors, rationale, attack-chain context, and analyst
overrides when present.

Exit codes are stable for automation:

| Code | Meaning |
| --- | --- |
| `0` | No confirmed finding at or above the configured gate. |
| `1` | At least one confirmed finding is at or above the configured gate. |
| `2` | Scan or ingestion error. |

The repository includes a [SARIF workflow example](trident-scan.yml), a
[CLI CI workflow](.github/workflows/ci.yml), and a tag-triggered package
[release verification workflow](.github/workflows/release.yml).

## Documentation

| Audience | Start with | Then read |
| --- | --- | --- |
| New user | [Installation](docs/INSTALLATION.md) | [Quick start](docs/QUICK_START.md) |
| Scan operator | [Scanning](docs/SCANNING.md) | [Tools](docs/TOOLS.md) |
| Triage reviewer | [Triage](docs/TRIAGE.md) | [Output formats](docs/OUTPUT_FORMATS.md) |
| CI maintainer | [CI and SARIF](docs/CI_CD.md) | [Open-source readiness](docs/OPEN_SOURCE_READINESS.md) |
| Developer | [Development](docs/DEVELOPMENT.md) | [Architecture](docs/ARCHITECTURE.md) |
| Security reviewer | [Limitations](docs/LIMITATIONS.md) | [Security policy](SECURITY.md) |

See [the full documentation map](docs/README.md), [support guidance](SUPPORT.md),
and [third-party notices](THIRD-PARTY-NOTICES.md).

## Project layout

```text
backend/
├── pyproject.toml
├── trident/
│   ├── cli.py
│   ├── config.py
│   ├── orchestrator.py
│   ├── calibration/
│   ├── experts/
│   ├── ingest/
│   ├── reporters/
│   └── tools/
└── tests/
docs/
scripts/
eval/                 # scorecards and evaluation metadata
vulnbank/             # intentionally vulnerable scan fixture
trident-scan.yml      # CI SARIF example
```

## Limitations and security

Trident performs static source and configuration analysis. It is not a
penetration test, runtime monitor, compliance certification, or replacement for
manual review. Coverage depends on the installed scanners, detected manifests,
supported languages and frameworks, and the quality of the configured review
backend. Dynamic dispatch, cross-process behavior, runtime-only weaknesses, and
unsupported source constructs may be missed.

LLM output is untrusted input. Trident validates structured responses and keeps
the deterministic scanner evidence, council verdict, guard adjustments, and
triage rationale available for review. Review P0/P1 findings manually and do
not treat a clean scan as proof of security.

The CLI stores local databases, extracted workspaces, model data, tool binaries,
and credentials under operating-system user-data locations. Protect those paths
with operating-system permissions. A configured cloud review backend may receive
source context; choose a backend and scope appropriate to the sensitivity of
the target. Never scan unauthorized code.

See [Limitations](docs/LIMITATIONS.md), [Security](SECURITY.md), and
[Support](SUPPORT.md) for operational boundaries.

## License

Trident is licensed under [Apache 2.0](LICENSE). The external scanners retain
their own licenses; see [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
