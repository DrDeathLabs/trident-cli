# Scanning and analysis

Trident accepts a local source directory, a Git repository, a ZIP archive, or
existing scanner reports. Scanning is for assets you own or are authorized to
assess. Review [Privacy](PRIVACY.md) before sending source evidence to a remote
model.

## Scan source code

Run from a repository or provide its path:

```bash
trident scan .
trident scan ./service --format json --output-file results.json
```

Trident prepares an isolated workspace, identifies available languages and
manifests, runs configured scanner integrations, normalizes and correlates
their records, and sends eligible findings through the configured review and
triage pipeline. A scanner can be skipped if it is missing or does not apply to
the target. Check tool setup with `trident install-tools --check`.

The twelve integrations are Semgrep, Bandit, gosec, Checkov, Grype,
OSV-Scanner, Trivy, pip-audit, npm-audit, govulncheck, Gitleaks, and
TruffleHog. See [Tools](TOOLS.md) for requirements and the evidence each tool
produces.

## Import scanner reports

Provide one or more report files to skip scanner subprocess execution:

```bash
trident scan --input-file sonar.json --format json --output-file results.json
trident scan --input-file sonar.json --input-file dependency-check.json
trident scan --input-file results.sarif --input-format sarif
trident inspect report.json --format json
```

Deterministic adapters support SonarQube, OWASP Dependency-Check, SARIF 2.1.0,
and CycloneDX vulnerability reports. For other JSON structures, provide an
explicit mapping or use bounded schema inference. A generic JSON file is not
assumed to be a vulnerability report.

Use `--mapping FILE` to apply a versioned mapping. `--no-schema-ai` disables
LLM-assisted schema inference. `inspect` normalizes a report for review; it
does not run scanners, persist a scan, or invoke the Council.

An imported report without `--source-dir` is `report_only`. Trident keeps its
original record and provenance and does not claim that a path is present,
reachable, or exploitable. Provide `--source-dir` when the source tree is
available. `--discover-novel` optionally asks experts to inspect selected code
regions beyond the imported records; it requires `--source-dir`.

## Review stages

1. **Normalize:** retain source tool, rule identifiers, locations, package
   identity, scanner severity, and input provenance where supplied.
2. **Correlate:** group duplicate evidence while retaining records that differ
   in vulnerability identity or affected component.
3. **Route and review:** deterministic legacy and structured evidence rules
   select relevant experts. Eligibility is `legacy_match OR structured_match`;
   multiple experts remain eligible when evidence spans domains.
4. **Resolve disagreement:** experts can cross-examine. The judge reviews
   selected high-severity and contested findings. Unresolved decisions remain
   visible and make the scan incomplete.
5. **Check attack chains:** Red-Team analysis evaluates confirmed findings as
   a set. Exact unchanged model-visible input can reuse a successful result;
   changed input clears stale chains and requests fresh analysis. If the call
   budget prevents analysis, the current result is unavailable, not the prior
   chain set.
6. **Triage:** confirmed findings receive a P0-P4 priority when enough evidence
   is available. The report records factors, rationale, reachability, and
   remediation guidance.

These stages assist review; they do not prove runtime exploitability or
completeness. See [Council](AI_COUNCIL.md), [Attack chains](ATTACK_CHAINS.md),
and [Triage](TRIAGE.md) for details.

## Important options

| Option | Use |
| --- | --- |
| `--input-file FILE` | Import a report; repeat for additional reports. |
| `--input-format FORMAT` | Select `auto`, `sonarqube`, `dependency-check`, `sarif`, `cyclonedx`, or `generic-json`. |
| `--source-dir DIR` | Supply source context for imported reports. |
| `--mapping FILE` | Apply an explicit generic JSON mapping. |
| `--no-schema-ai` | Keep schema selection deterministic. |
| `--discover-novel` | Ask experts to inspect selected code regions; requires imported reports and source directory. |
| `--backend NAME` | Override backend for this scan. |
| `--openai-base-url URL` | Override the OpenAI-compatible endpoint; requires the OpenAI backend. |
| `--model ALIAS` | Use one model alias for review roles in this scan. |
| `--max-iterations N` | Override Council iteration limit. |
| `--format FORMAT` | Choose `table`, `json`, or `sarif`. |
| `--output-file FILE` | Write the primary report to a file. |
| `--triage-output-file FILE` | Write the detailed worked-triage report. |
| `--severity-gate LEVEL` | Set the exit-1 threshold (`critical`, `high`, `medium`, `low`). |
| `--fail-on P0..P4` | Set the threshold using priority notation. |
| `--quiet` | Suppress progress messages. |

Run `trident scan --help` for the full option list.

## Database and workspace handling

Trident stores scan state in a local SQLite database by default and uses a
separate workspace for extracted or checked-out source. Database and workspace
paths can be configured with `TRIDENT_SQLITE_PATH` and `TRIDENT_WORKSPACES`.
They may contain source excerpts, scanner output, prompts, model responses,
and finding evidence. Protect and retain them according to your organization's
policy. See [Privacy](PRIVACY.md).

## See also

- [Quick start](QUICK_START.md)
- [Output formats](OUTPUT_FORMATS.md)
- [Custom LLM endpoint guide](CONNECTING_LLM_ENDPOINTS.md)
- [Troubleshooting](TROUBLESHOOTING.md)
