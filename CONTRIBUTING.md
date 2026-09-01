# Contributing to Trident CLI

Contributions are welcome when they keep Trident focused on the standalone CLI
and make security results easier to explain, reproduce, and review.

## Development setup

From the repository root:

```bash
cd backend
python -m venv .venv

# macOS/Linux/WSL
source .venv/bin/activate

# Windows PowerShell
.\.venv\Scripts\Activate.ps1

python -m pip install -e ".[dev]"
```

Run the checks from `backend/`:

```bash
python -m pytest -q
python -m ruff check trident tests
python -m build
python -m twine check dist\*
```

The unit suite mocks LLM responses and scanner processes where appropriate.
Manual end-to-end checks may additionally require the native tools, Node/npm,
Go, network access, and a configured LLM backend.

## Scanner adapters

Scanner adapters live under `backend/trident/tools/`. An adapter should:

- pass target-controlled values as argument-list elements, never interpolated
  shell text;
- produce deterministic, normalized findings with useful source locations;
- handle a missing executable and non-zero scanner exit gracefully;
- preserve scanner diagnostics without turning infrastructure failure into a
  false security conclusion;
- include focused tests for parsing, exit behavior, and malformed output;
- update the supported-tool and third-party-notice documentation.

Trident treats scanner output as candidate evidence. Correlation, council
review, guards, and automatic triage decide what is actionable while retaining
rejected candidates in reports and triage evidence.

## Documentation and test changes

When behavior changes, update the relevant guide, `FEATURE_STATUS.md`, or
`LIMITATIONS.md`. Check command examples against `trident help` and the
command help surfaces. Include JSON, SARIF, table, and sidecar behavior when
report contracts change.

Never commit credentials, proprietary source, customer findings, raw model
context, generated reports, local databases, virtual environments, or scanner
downloads. Use synthetic fixtures or the intentionally vulnerable fixture only
in controlled tests.

## Pull requests

Describe the motivation, scope, tests run, documentation impact, and any
remaining environmental limitation. Keep changes inside this repository and
do not add deployment, server, or unrelated product code.
