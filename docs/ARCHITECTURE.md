# Architecture

Trident is a local, single-process CLI. It uses SQLite for scan state and
in-process task execution; it does not require a server, queue, or external
database.

## Components

| Component | Location | Responsibility |
|-----------|----------|----------------|
| CLI entry point | backend/trident/cli.py | Commands, options, exit codes |
| Configuration | backend/trident/config.py and config_manager.py | Environment and TOML settings |
| Ingest | backend/trident/ingest/ | Local paths, Git URLs, and ZIP archives |
| Scanner adapters | backend/trident/tools/ | Invoke scanners and normalize findings |
| Correlation | backend/trident/correlate.py | Deduplicate corroborating findings |
| Expert review | backend/trident/experts/ and deliberation.py | LLM council review |
| Triage adjustments | backend/trident/triage.py and reachability/ | Deterministic factor correction and reachability evidence |
| Corpus calibration | backend/trident/calibration/ | Optional vulnerability corpus, CWE profiles, and model artifact |
| Exporters | backend/trident/reporters/exporters.py | Table, JSON, SARIF, and triage-sidecar output |
| Persistence | backend/trident/models.py and db.py | SQLite ORM and migrations |

## Scan pipeline

~~~text
workspace
   |
   v
ingest and language detection
   |
   v
scanner adapters -> raw findings
   |
   v
correlation and deduplication
   |
   v
iterative expert review
   |
   +-> judge and cross-examination
   +-> novel finding discovery
   +-> red-team attack-chain analysis
   |
   v
confirmed findings
   |
   v
automatic triage adjustments and P0-P4 computation
   |
   v
table, JSON, SARIF, and optional triage sidecar
~~~

The CLI runs scanner adapters as subprocesses. Missing optional system tools
are reported or skipped according to the adapter; the scan still records the
tool status.

## Persistence and concurrency

SQLite stores jobs, findings, events, and triage metadata. The default database
is in the per-user application-data directory and can be changed with
TRIDENT_SQLITE_PATH. The database is intended for one local operator. Avoid
running concurrent scans against the same database file.

Extracted workspaces are stored separately and cleaned according to
WORKSPACE_RETENTION_DAYS. Sensitive source, findings, credentials, and model
data remain on the local filesystem unless an LLM backend is configured to
receive code context.

## LLM boundary

Ollama, OpenAI, and Anthropic backends implement the same LLM interface.
Cloud backends receive prompts and code excerpts required for review; choose a
backend that matches the sensitivity of the code being scanned.

## Package boundary

The published Python package contains the trident package and its CLI
dependencies. Source-controlled examples and evaluation targets are not
installed as package modules.
