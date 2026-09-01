# Scanning

Trident scans an authorized source tree, sends candidates through its review
pipeline, and runs automatic triage on the findings that survive review.

## Basic usage

~~~bash
trident scan [WORKSPACE] [OPTIONS]
~~~

WORKSPACE defaults to the current directory. It can be a local directory, a
single file, a Git URL, or a ZIP archive.

~~~bash
trident scan .
trident scan /path/to/source
trident scan https://example.com/owner/repository.git
trident scan /tmp/source-snapshot.zip
~~~

Only scan sources you own or are authorized to analyze.

## Output

| Option | Default | Description |
|--------|---------|-------------|
| --format | table | table, json, or sarif |
| --output-file FILE | stdout | Write output to FILE |
| --triage-output-file FILE | none | Write the complete automatic triage sidecar |
| --quiet | false | Suppress progress and status messages |

~~~bash
trident scan . --format json --output-file results.json --quiet
trident scan . --format sarif --output-file results.sarif --quiet
trident scan . --format table --output-file results.txt --triage-output-file triage.txt
~~~

The table is intended for terminal review. JSON contains the full confirmed
finding and triage metadata. SARIF 2.1.0 is suitable for code-scanning
upload actions. Triage runs automatically after council review. The selected
output contains confirmed, actionable findings; scanner candidates rejected as
false positives are excluded from that queue but remain represented in audit
counts/evidence and the full triage sidecar.

## Severity gate

| Option | Meaning |
|--------|---------|
| --severity-gate critical | Fail on P0 and above |
| --severity-gate high | Fail on P1 and above |
| --severity-gate medium | Fail on P2 and above |
| --severity-gate low | Fail on P3 and above |
| --fail-on P0 through P4 | Equivalent tier notation |

The default gate is high. A scan returns 0 when no confirmed finding reaches the
gate, 1 when one or more do, and 2 when ingestion or scanning fails.

~~~bash
trident scan . --severity-gate critical
trident scan . --fail-on P2
~~~

## LLM overrides

~~~bash
trident scan . --backend ollama --model gemma4:31b-cloud
trident scan . --backend openai --model gpt-4o
trident scan . --backend anthropic --model claude-sonnet-5
~~~

CLI flags take precedence over environment and config-file values.

## Scan behavior

| Option | Description |
|--------|-------------|
| --max-iterations N | Maximum council debate iterations |
| --target-name NAME | Display name in reports |
| --no-guards | Skip guards for debugging only |

## Confirmed findings

Output formats include confirmed findings only. Raw, disputed, refuted, duplicate,
suppressed, and parse-error records are excluded. See
[OUTPUT_FORMATS](OUTPUT_FORMATS.md) for field definitions and
[TRIAGE](TRIAGE.md) for priority guidance.

## Help

~~~bash
trident scan --help
trident help
trident help ci
trident help output
trident help tools
~~~
