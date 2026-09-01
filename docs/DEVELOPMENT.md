# Development

This guide covers development of the standalone CLI package in this repository.

## Repository layout

~~~text
backend/
├── pyproject.toml
├── README.md
├── trident/
│   ├── cli.py
│   ├── config.py
│   ├── config_manager.py
│   ├── orchestrator.py
│   ├── deliberation.py
│   ├── triage.py
│   ├── experts/
│   ├── agent/
│   ├── reliability/
│   ├── calibration/
│   ├── ingest/
│   ├── tools/
│   └── reporters/
└── tests/
    ├── conftest.py
    └── test_*.py
docs/
scripts/
~~~

## Development environment

Prerequisites are Python 3.11 or later and Git.

From the repository root:

~~~bash
cd backend
python -m venv .venv

# macOS/Linux:
source .venv/bin/activate

# Windows:
.venv/Scripts/activate

python -m pip install -e ".[dev]"
~~~

## Verify changes

~~~bash
trident --version
trident --help
ruff check trident tests
python -m pytest -q
python -m build
~~~

The tests mock the LLM and use in-memory or temporary SQLite databases. They
do not require an LLM service or installed scanner binaries.

## Adding a scanner adapter

Scanner adapters live in backend/trident/tools/. Each adapter should:

1. Declare how the tool is installed or discovered.
2. Build a safe subprocess command.
3. Parse the tool output into normalized findings.
4. Degrade clearly when the external tool is unavailable.
5. Include parser tests in backend/tests/test_tools.py or a focused test module.

Register default tools in backend/trident/config.py and keep installation and
version behavior in backend/trident/tools/installer.py.

## Adding an expert or guard

Experts live in backend/trident/experts/. Review orchestration is in
backend/trident/deliberation.py and backend/trident/orchestrator.py. Guard
logic is in backend/trident/triage.py and backend/trident/reachability/.

Add focused tests for new decisions, especially severity, reachability, output,
and failure behavior.

## Test and documentation expectations

Keep changes focused and preserve exit-code behavior:

- 0: no confirmed finding at or above the configured gate
- 1: at least one confirmed finding at or above the gate
- 2: scan or ingestion error

Update the relevant user document when a command, output field, supported input,
or limitation changes. Do not add platform-specific services or dependencies
to this CLI repository.
