# Architecture

Trident is a local, single-process CLI. It uses SQLite for scan state and
in-process task execution; it does not require a server, queue, or external
database for the standalone workflow.

## Components

| Component | Location | Responsibility |
|-----------|----------|----------------|
| CLI entry point | backend/trident/cli.py | Commands, options, exit codes |
| Configuration | backend/trident/config.py and config_manager.py | Environment and TOML settings |
| Ingest | backend/trident/ingest/ | Local paths, Git URLs, ZIP archives, and supported external JSON |
| Scanner adapters | backend/trident/tools/ | Invoke scanners and normalize findings |
| Normalized findings | backend/trident/models.py and tools/base.py | Common finding contract and preserved raw evidence |
| Correlation | backend/trident/correlate.py | Separate exact duplicates from related evidence |
| Expert review | backend/trident/experts/ and deliberation.py | LLM council review |
| Attack-chain review | backend/trident/experts/redteam.py and orchestrator.py | Review credible multi-finding paths |
| Triage adjustments | backend/trident/triage.py and reachability/ | Deterministic factor correction and reachability evidence |
| Corpus calibration | backend/trident/calibration/ | Optional vulnerability corpus, CWE profiles, and model artifact |
| Exporters | backend/trident/reporters/exporters.py | Table, JSON, SARIF, and triage-sidecar output |
| Persistence | backend/trident/models.py and db.py | SQLite ORM and migrations |

## Scan pipeline

~~~text
Source / Git / ZIP --------------------+
                                      v
Native scanners ----------------> normalized finding model
External JSON -----------------------+  |
  SonarQube / Dependency-Check          v
                                  correlation
                                      |
                              Council of Experts
                                      |
                              Judge / cross-exam
                                      |
                              attack-chain review
                                      |
                                    guards
                                      |
                              deterministic P0-P4 triage
                                      |
                              JSON / SARIF / table reports
~~~

Native scans run scanner adapters as subprocesses. With `--input-file`, the
supported report adapter path is used instead and scanner subprocesses are not
started. Imported records retain report-only evidence unless `--source-dir`
provides source context.

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

Ollama Cloud responses are validated in the application. Trident preserves the
requested and returned model identities, accepts only the exact native identity
for a requested cloud alias, and rejects unrelated substitutions. Malformed,
timed-out, refused, or semantically invalid responses remain unresolved and do
not become positive or negative security verdicts.

## Package boundary

The published Python package contains the trident package and its CLI
dependencies. Source-controlled examples and evaluation targets are not
installed as package modules.
