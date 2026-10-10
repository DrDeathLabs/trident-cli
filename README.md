# Trident CLI

[![License: BUSL-1.1](https://img.shields.io/badge/License-BUSL--1.1-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/downloads/)

Trident runs security scanners, imports scanner reports, correlates findings,
asks configured language models to review evidence, and assigns confirmed
findings remediation priorities from P0 through P4. It is a local command-line
application. A scan stores working data and reports on the computer running
Trident; configured remote model services receive the evidence needed for their
review.

Use Trident on source code and reports you own or are authorized to analyze.
Model and scanner results require review by a security practitioner.

## What it does

- Runs twelve scanner integrations across source code, dependencies, IaC, and
  secrets.
- Imports SonarQube, Dependency-Check, SARIF, CycloneDX, and mapped JSON reports.
- Normalizes scanner evidence and provenance, then correlates overlapping
  findings.
- Routes candidates to security experts using legacy rules and deterministic
  structured evidence. Structured routing preserves every legacy expert match
  and can add reviewers; a finding can receive review from several experts.
- Uses judge review for disagreements and selected high-severity decisions.
- Checks confirmed findings for multi-finding attack chains.
- Assigns P0-P4 priorities and records rationale, evidence, and remediation.
- Writes terminal, JSON, and SARIF reports.

See [limitations](docs/LIMITATIONS.md) for unsupported conclusions and known
coverage boundaries.

## Requirements

- Python 3.11 or newer.
- Access to the selected LLM backend and models.
- Scanner runtimes required by the tools you enable. `trident install-tools`
  installs managed tools where supported. npm-audit requires Node.js/npm;
  Go-based scanners can use an installed Go runtime or Trident's managed
  bootstrap.

## Install

Download the current wheel from the [GitHub Releases page](https://github.com/DrDeathLabs/trident-cli/releases),
then install it in a virtual environment. Detailed platform steps are in the
[installation guide](docs/INSTALLATION.md).

```bash
python -m venv .venv
python -m pip install ./trident-*-py3-none-any.whl
trident --version
trident install-tools --verify --warmup
```

## First scan

Configure Ollama, OpenAI-compatible, or Anthropic access. For an OpenAI-style
gateway, set the backend, base URL, and gateway model alias:

```bash
trident config set llm.backend openai
trident config set llm.openai_base_url https://llm-gateway.example.com/v1
trident config set llm.expert_model security-expert
trident config set llm.openai_api_key
trident scan . --backend openai --model security-expert
```

The hostname is reserved for documentation. Replace it with the endpoint
provided by your gateway operator. The API key command uses a hidden prompt.
For no-auth gateways, leave the key unset. See
[Connecting Trident to a Custom LLM Endpoint or Proxy](docs/CONNECTING_LLM_ENDPOINTS.md)
for HTTP and HTTPS examples, authentication, network requirements, and
troubleshooting.

The default terminal report displays numerical counts for P0, P1, P2, P3, P4,
the prioritized total, untriaged findings, and unresolved findings. JSON and
SARIF contain per-finding evidence and triage details:

```bash
trident scan . --format json --output-file results.json
trident scan . --format sarif --output-file results.sarif
```

Exit code `0` means review completed below the configured gate, `1` means a
prioritized finding meets the gate, and `2` means the scan failed or review is
incomplete because findings remain untriaged or unresolved.

## Configuration and reports

CLI options override environment variables, which override persisted config,
which overrides defaults. API keys can be entered at a hidden prompt, read from
stdin, or supplied through a protected environment or secret store. Trident
masks secret values in configuration output and restricts local config-file
permissions. The config file is plaintext, not encrypted.

- [Quick start](docs/QUICK_START.md)
- [Configuration reference](docs/CONFIGURATION.md)
- [LLM backends](docs/LLM_BACKENDS.md)
- [Scanning and report ingestion](docs/SCANNING.md)
- [Council and expert review](docs/AI_COUNCIL.md)
- [P0-P4 triage](docs/TRIAGE.md)
- [Terminal, JSON, and SARIF output](docs/OUTPUT_FORMATS.md)
- [Privacy and data handling](docs/PRIVACY.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [All documentation](docs/README.md)

## Boundaries

Trident performs static analysis and evidence review. It does not execute the
application, prove exploitability, certify compliance, or establish that a
clean scan is secure. Results depend on installed scanners, supported
ecosystems, source context, configured models, and the evidence supplied.
Review important findings and remediation decisions before deployment.

## License

Trident is distributed under the [Business Source License 1.1](LICENSE).
The license describes permitted use and the change license for each version.
See [COMMERCIAL.md](COMMERCIAL.md) for the commercial-use boundary and
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) for scanner notices.
