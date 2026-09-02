# Trident CLI

[![License: BSL 1.1](https://img.shields.io/badge/License-BSL_1.1-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

Trident is a local AI-assisted vulnerability analysis and triage engine for the
command line. It combines twelve established scanners with a Council of Experts
(COE): five domain specialists review candidates independently, a judge
challenges high-severity and contested findings, and a red-team reviewer looks
for attack chains across the confirmed findings.

The COE is the review engine. It determines which scanner candidates are
supported by the code, which are duplicates or false positives, and which need
more evidence. Trident preserves those verdicts and the reasoning behind them.
It then applies deterministic triage to the findings that survive review,
using impact, attack vector, exploitability, fix effort, reachability, and
attack-chain context to produce a worked P0-P4 remediation queue.

Scanners are good at producing candidates. The harder problem is what comes
next: overlapping alerts, inconsistent severities, weak reachability context,
and false positives competing with real vulnerabilities for engineering time.
Trident is built to resolve that part of the work.

> Authorized use only. Scan code you own or have explicit permission to analyze.

## How Trident reviews a scan

Trident keeps scanner output, COE review, attack-chain analysis, and triage
separate so each decision can be inspected.

1. **Find candidates.** Twelve scanner adapters establish broad coverage.
2. **Correlate candidates.** Overlapping alerts are grouped so the COE reviews
   the issue once instead of debating the same problem repeatedly.
3. **Run the COE.** The relevant domain experts review candidates independently.
   Contested findings go through cross-examination. The judge rechecks
   high-severity results and disagreements.
4. **Look for attack chains.** The red-team reviewer examines the confirmed
   findings together. If separate weaknesses form a credible attack path, the
   chain is recorded and its findings can be raised one priority tier.
5. **Set priority.** Deterministic triage uses the assessed factors, reachability
   evidence, and chain context to assign P0-P4 and record any adjustment.
6. **Export the result.** Reports contain the confirmed findings, priority,
   rationale, attack-chain context, and the evidence behind each decision.

The result is a queue someone can work, not just a list of alerts. SARIF works
with code-scanning workflows, JSON supports automation, table output is useful
at the terminal, and the triage sidecar preserves the complete decision record.

In one 215-finding PyGoat evaluation, the documented deterministic correction
changed the P0-P4 shape from a scanner/model-driven barbell (47 P0 findings) to
a graded queue with 13 P0 findings. That snapshot also reached exact expert-tier
agreement on 8 of 10 detected planted findings and agreement within one tier on
all 10. These are Trident evaluation results, not universal performance claims;
see the [full triage evaluation snapshot](docs/TRIAGE.md#evaluation-snapshot-from-alert-barbell-to-worked-queue)
for scope and limitations.

Trident is not an autonomous security approval system. Model output is input to
the review process, and high-impact results still require qualified human review.

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
- Council of Experts review, independent domain specialists, judge review,
  cross-examination, red-team attack-chain analysis, reachability analysis, and
  automatic evidence-preserving P0-P4 triage.
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

Trident is licensed under the [Business Source License 1.1](LICENSE). The
Additional Use Grant permits internal, organizational, educational, research,
nonprofit, government, public-sector, community, evaluation, development,
testing, and personal use as described in the license.

The license does not permit hosted or managed services, SaaS, resale,
commercialization as a standalone product, inclusion as a material feature of
another commercial security or GRC product, or paid third-party assessment or
managed security services without separate commercial permission. Each specific
version changes to the MIT License four years after its first public
distribution. See [COMMERCIAL.md](COMMERCIAL.md) for the licensing boundary.

The external scanners retain their own licenses; see
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
