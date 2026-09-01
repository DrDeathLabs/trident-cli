# Trident CLI documentation

Trident is an AI-assisted local command-line security scanner whose defining
surface is its novel, automatic, evidence-preserving triage workflow. These
documents explain how twelve scanners establish breadth, how specialized AI
reviewers adjudicate noisy candidates, how deterministic triage computes an
operational P0-P4 priority, and how the result becomes a worked queue without
losing the false-positive audit trail. They also document where human review
remains mandatory.

## New users

- [Installation](INSTALLATION.md) - Python setup, scanner tools, prerequisites,
  and local data locations.
- [Quick start](QUICK_START.md) - configure a backend and complete a first scan.
- [Scanning](SCANNING.md) - source types, profiles, options, and exit codes.

## Scan operators and triage reviewers

- [Tools](TOOLS.md) - the twelve scanner adapters and their coverage.
- [AI council](AI_COUNCIL.md) - expert review, consensus, judge, and red team.
- [Triage adjustments](GUARDS.md) - deterministic class, reachability, and
  corpus-profile corrections.
- [Triage](TRIAGE.md) - P0-P4 prioritization, factors, playbooks, and audit data.
- [Attack chains](ATTACK_CHAINS.md) - multi-finding escalation context.
- [Output formats](OUTPUT_FORMATS.md) - table, JSON, SARIF, and triage sidecars.

## Configuration and model reviewers

- [Configuration](CONFIGURATION.md) - persistent settings and environment
  precedence.
- [LLM backends](LLM_BACKENDS.md) - Ollama, OpenAI, and Anthropic setup.
- [Corpus calibration](CORPUS_GUARD_MODEL.md) - feed refresh, profiles, and the
  separately maintained statistical artifact.
- [Agentic mode](AGENTIC_MODE.md) - optional bounded exploratory review.

## CI and release maintainers

- [CI and SARIF](CI_CD.md) - package checks, SARIF upload, and exit-code policy.
- [Open-source readiness](OPEN_SOURCE_READINESS.md) - public-release gates,
  licensing, reproducibility, and known prerequisites.
- [Troubleshooting](TROUBLESHOOTING.md) - installation, tool, backend, and scan
  diagnostics.

## Developers

- [Development](DEVELOPMENT.md) - repository layout and local checks.
- [Architecture](ARCHITECTURE.md) - scan data flow, persistence, and trust
  boundaries.
- [Feature status](FEATURE_STATUS.md) - supported, optional, experimental, and
  unsupported behavior.

## Security and release reviewers

- [Limitations](LIMITATIONS.md) - what Trident cannot establish on its own.
- [Security policy](../SECURITY.md) - vulnerability reporting and sensitive data
  handling.
- [Third-party notices](../THIRD-PARTY-NOTICES.md) - scanner licensing.
- [Internal evaluation notes](internal/) - research and evaluation material,
  not required for ordinary CLI use.

## Capability status

| Capability | Status | Primary documentation |
| --- | --- | --- |
| Local directory, Git, and ZIP scanning | Supported | [Scanning](SCANNING.md) |
| Twelve deterministic scanner adapters | Supported | [Tools](TOOLS.md) |
| LLM council adjudication | Supported with configured backend | [AI council](AI_COUNCIL.md) |
| Automatic P0-P4 triage | Supported | [Triage](TRIAGE.md) |
| Table, JSON, and SARIF reports | Supported | [Output formats](OUTPUT_FORMATS.md) |
| Full triage sidecar reports | Supported | [Output formats](OUTPUT_FORMATS.md) |
| CWE-profile triage adjustment | Optional; requires refresh | [Corpus calibration](CORPUS_GUARD_MODEL.md) |
| Agentic exploratory review | Experimental; opt in | [Agentic mode](AGENTIC_MODE.md) |
| Runtime penetration testing | Unsupported | [Limitations](LIMITATIONS.md) |
| Compliance certification | Unsupported | [Limitations](LIMITATIONS.md) |

## Help topics

The built-in help index is the shortest command reference:

~~~bash
trident help
~~~

The supported deep-dive topics map to these guides:

| Topic | Guide |
| --- | --- |
| setup | [Installation](INSTALLATION.md) and [Quick start](QUICK_START.md) |
| backends | [LLM backends](LLM_BACKENDS.md) |
| ci | [CI and SARIF](CI_CD.md) |
| config | [Configuration](CONFIGURATION.md) |
| output | [Output formats](OUTPUT_FORMATS.md) |
| guards | [Guards](GUARDS.md) |
| experts | [AI council](AI_COUNCIL.md) |
| tools | [Tools](TOOLS.md) |

## Documentation boundary

The CLI is a local, single-operator tool. The documentation does not claim
autonomous security approval, complete vulnerability coverage, runtime testing,
or authoritative LLM decisions. Generated findings and triage guidance require
qualified human review before operational use.
