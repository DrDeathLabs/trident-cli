# Trident documentation

Start with installation, then configure a model provider and run an authorized
scan. The guides below follow that workflow. Product boundaries and privacy
notes are part of operating the tool, not optional background reading.

## Use Trident

1. [Install the CLI and scanner tools](INSTALLATION.md).
2. [Configure Ollama, OpenAI-compatible APIs, or Anthropic](LLM_BACKENDS.md).
3. For custom endpoints, follow
   [Connecting Trident to a Custom LLM Endpoint or Proxy](CONNECTING_LLM_ENDPOINTS.md).
4. [Run source scans or import reports](SCANNING.md).
5. [Read terminal, JSON, and SARIF results](OUTPUT_FORMATS.md).
6. [Review P0-P4 priorities](TRIAGE.md) and
   [Council decisions](AI_COUNCIL.md).
7. [Diagnose failures](TROUBLESHOOTING.md).

Before sending source evidence to a model or gateway, read
[Privacy and data handling](PRIVACY.md). See [Limitations](LIMITATIONS.md) for
what a static scan and model review cannot prove.

## Reference guides

| Topic | Guide |
| --- | --- |
| Settings, secret entry, and precedence | [Configuration](CONFIGURATION.md) |
| Scanner adapters and setup | [Tools](TOOLS.md) |
| Standardized and mapped report input | [JSON ingestion](JSON_INGESTION.md) |
| Expert routing, adjudication, and judge review | [AI Council](AI_COUNCIL.md) |
| Red-Team and attack paths | [Attack chains](ATTACK_CHAINS.md) |
| Deterministic triage adjustments | [Guards](GUARDS.md) |
| CI and SARIF | [CI/CD](CI_CD.md) |
| Agentic expert exploration | [Agentic mode](AGENTIC_MODE.md) |
| Corpus-profile adjustment | [Corpus guard model](CORPUS_GUARD_MODEL.md) |

## Developer and maintainer guides

- [Architecture](ARCHITECTURE.md) describes data flow and trust boundaries.
- [Development](DEVELOPMENT.md) describes local setup and tests.
- [Validation](VALIDATION.md) distinguishes unit, integration, and installed
  package evidence.
- [Open-source readiness](OPEN_SOURCE_READINESS.md) describes licensing and
  repository release checks.
- [Security policy](../SECURITY.md) describes vulnerability reporting.
- [Third-party notices](../THIRD-PARTY-NOTICES.md) lists external tool notices.

Package version identifiers belong in package metadata and release records.
User guides avoid version-specific wheel names so installation instructions
remain current.
