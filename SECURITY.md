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

The CLI has no multi-user access-control layer. Its local database, extracted
workspaces, calibration data, caches, reports, and scanner configuration are
not encrypted by Trident. Protect them with normal operating-system
permissions and remove sensitive artifacts after testing.

Cloud LLM credentials are read from configuration or environment variables. Do
not commit them, include them in scan targets, or paste them into public issues.
Use redacted output from `trident config show` when diagnosing setup.

## Triage boundary

Scanner output is candidate evidence, not proof that every result is
exploitable. Automatic triage can reject false positives from the actionable
queue and preserves those candidates as audit evidence. Review high-impact
decisions and validate findings in the authorized target environment.
