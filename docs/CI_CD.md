# CI and SARIF integration

Trident runs as a normal command-line step in CI. The exit code lets automation
tell the difference between a clean scan, findings that meet the configured
gate, and a scan failure.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No confirmed findings at or above the severity gate |
| 1 | Confirmed findings at or above the severity gate |
| 2 | Ingestion or scan error |

The default gate is high (P1 and above).

~~~bash
trident scan . --severity-gate high
trident scan . --fail-on P2
~~~

## GitHub Actions

A minimal workflow for a repository using the source checkout is:

~~~yaml
name: Trident Security Scan

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  trident:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install Trident from source
        run: python -m pip install ./backend
      - name: Install scanner tools
        run: trident install-tools
      - name: Scan
        run: trident scan . --severity-gate high
~~~

For a source checkout, install from backend/ instead:

~~~yaml
- name: Install Trident from source
  run: python -m pip install ./backend
~~~

## SARIF upload

Write SARIF to a file, preserve the scan status, upload the file, and then
enforce the status. The upload step must run even when findings are present.

~~~yaml
- name: Scan to SARIF
  id: trident
  shell: bash
  run: |
    set +e
    trident scan . --format sarif --output-file trident-results.sarif --quiet
    code=$?
    echo "exit_code=$code" >> "$GITHUB_OUTPUT"
    exit 0

- name: Upload SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: trident-results.sarif

- name: Enforce scan result
  if: steps.trident.outputs.exit_code != '0'
  run: |
    code="${{ steps.trident.outputs.exit_code }}"
    echo "Trident exited with $code"
    exit "$code"
~~~

GitHub Code Scanning requires the workflow permission
security-events: write. For other CI providers, retain the SARIF file as an
artifact or pass it to that provider's supported SARIF importer.

## JSON output

JSON is useful for custom gates and downstream processing:

~~~bash
trident scan . --format json --output-file trident-results.json --quiet
~~~

The process exit code still carries the gate result; the output file contains
the confirmed findings and triage metadata. To retain the complete worked
queue as a separate artifact, add `--triage-output-file`:

~~~bash
trident scan . --format json \
  --output-file trident-results.json \
  --triage-output-file trident-triage.json \
  --quiet
~~~

The same sidecar option works with `--format sarif` and `--format table`.
Triage is run automatically after the scan; the sidecar is only the choice to
persist the detailed queue separately from the primary scan report.

## Corpus model caching

The optional corpus model is stored in the directory controlled by
CALIBRATION_DATA_DIR. Cache the path reported by trident model path rather than
assuming a fixed operating-system path:

~~~bash
CALIBRATION_DIR="$(trident model path)"
echo "$CALIBRATION_DIR"
~~~

Building the model downloads vulnerability feeds and can take significant
time. It is optional for pull-request scans.

## Operational notes

- Configure an LLM backend before scanning. Cloud backends receive the code
  context required for review.
- Install only the scanner tools needed for the target environment if a full
  tool installation is not practical.
- Use --quiet when stdout must contain only JSON or SARIF.
- Review P0 and P1 findings manually; the council and guards are not
  correctness guarantees.
