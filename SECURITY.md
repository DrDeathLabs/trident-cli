# Security policy

## Reporting a vulnerability

Do not open a public issue for a security vulnerability. Use the private
vulnerability-reporting channel when one is configured, or use the private
security contact published with the release. This document does not invent an
email address or other contact detail.

When reporting privately, include a concise impact description, affected
version or commit, reproduction steps using non-sensitive material, and any
proposed mitigation. Redact credentials, private source, customer data, and
live targets.

## Intended use

Trident is a local command-line security-analysis and triage tool. Scan only
code you own or are explicitly authorized to analyze. Do not deploy or expose
local test fixtures or evaluation material.

Trident executes third-party scanner processes and may send code context to
the configured LLM backend. Run it in a trusted environment and select a
backend whose privacy and retention terms are appropriate for the target.

## Local data and credentials

The CLI has no multi-user access-control layer. Trident restricts its default
config/app-data directories and SQLite database/sidecars to the current user
(and SYSTEM/local Administrators on Windows), and atomically writes TOML
configuration. It does not encrypt local databases, workspaces, caches, or
reports. API keys stored in TOML remain plaintext to the current user and
administrator/root processes; prefer environment-injected secrets or a secret
manager where available. Job records and the typed-decision ledger have no
automatic retention policy; source workspaces are swept according to
`WORKSPACE_RETENTION_DAYS` (14 days by default). Review [Privacy](docs/PRIVACY.md)
for data-flow and retention details.

Cloud LLM credentials are read from configuration or environment variables. Do
not commit them, include them in scan targets, or paste them into public issues.
`config get`, `config show`, and `config list` mask configured API keys, and
secret positional arguments are rejected. Use redacted output when diagnosing
setup. Scanner output can contain credential material, so Trident does not
persist raw scanner stdout/stderr events and secret adapters redact matched
values from findings and reports.

## Triage boundary

Scanner output is candidate evidence, not proof that every result is
exploitable. Council review can refute candidates before triage; triage then
prioritizes retained findings for the operational queue and preserves the
review evidence. Guards adjust prioritization factors; they are not false-
positive validity gates. Review high-impact decisions and validate findings in
the authorized target environment.
