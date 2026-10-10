# Reports and exit codes

Trident can print a compact table or write JSON and SARIF reports. Use the
JSON or SARIF output for per-finding detail. The table is a numerical summary
of the finalized scan report.

## Terminal summary

The default table prints every priority tier, even when its count is zero:

```text
Trident Scan - target
P0: 0
P1: 2
P2: 1
P3: 0
P4: 0
Total: 3
Untriaged: 0
Unresolved: 0
```

This is the report format, not a sample of a particular scan. `Total` is the
sum of prioritized confirmed findings across P0-P4. `Untriaged` counts
confirmed findings that have no valid priority. `Unresolved` counts findings
that remain `unresolved`, `unresolved_model_error`, or `unreviewed`.

The table and exit-code gate use the same finalized JSON report data. Confirmed
findings appear in the actionable findings collection. Suppressed and
false-positive findings are not included in the P0-P4 totals. Dispositions
remain in the report for review. In the production convergence path, an
unresolved expert disagreement is represented as `unresolved` and makes the
review incomplete.

## JSON

Write JSON to a file:

```bash
trident scan . --format json --output-file results.json
```

The report contains job metadata, retained findings, evidence and provenance,
review disposition, triage factors and rationale, attack-chain state, and
disposition counts. Findings include priority and file or component details
when available. Imported original records remain linked to the normalized
finding. JSON is the primary format for automation that needs the full record.

Use `--quiet` when JSON is written to standard output:

```bash
trident scan . --format json --quiet > results.json
```

Progress and status messages are written separately from machine-readable
stdout. With `--output-file`, Trident writes the report to that file.

## SARIF

SARIF output uses version 2.1.0 and maps retained findings to SARIF results.
Priority, rule identity, severity, location, and selected evidence are included
where available:

```bash
trident scan . --format sarif --output-file results.sarif
```

Use the SARIF file with a compatible code-scanning service. Trident's JSON and
SARIF schemas are separate contracts; SARIF is not a complete replacement for
the Trident JSON record.

## Detailed triage sidecar

`--triage-output-file` writes the worked queue independently of the primary
report format:

```bash
trident scan . --format json --output-file results.json \
  --triage-output-file remediation.json
```

The sidecar groups confirmed findings by priority and includes rationale,
fix guidance, attack-chain context, disposition details, provenance, and
analyst overrides when present. A separate text or SARIF sidecar can be
selected by its filename extension.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Review completed below the configured priority gate. Findings may exist below the gate. |
| `1` | At least one prioritized confirmed finding meets or exceeds the configured gate. |
| `2` | Scan, ingestion, or reporting failed, or confirmed findings remain untriaged or unresolved. |

The incomplete-review status (2) takes precedence over the priority gate. This
prevents an incomplete review from appearing successful merely because no
currently prioritized finding crosses the gate. `--severity-gate` uses the
critical/high/medium/low mapping; `--fail-on` selects P0-P4 directly.

The exit status can be used in a shell or CI workflow:

```bash
trident scan . --format sarif --output-file results.sarif --quiet
status=$?
```

In PowerShell, inspect `$LASTEXITCODE` after the command.

## See also

- [Scanning](SCANNING.md)
- [Triage](TRIAGE.md)
- [CI and SARIF](CI_CD.md)
