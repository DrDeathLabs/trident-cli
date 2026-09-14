# Scanning

Trident scans an authorized source tree, sends candidates through its review
pipeline, and runs automatic triage on the findings that survive review.

## Basic usage

~~~bash
trident scan [WORKSPACE] [OPTIONS]
~~~

WORKSPACE defaults to the current directory for native scanning. It can be a
local directory, a Git URL, or a ZIP archive.

~~~bash
trident scan .
trident scan /path/to/source
trident scan https://example.com/owner/repository.git
trident scan /tmp/source-snapshot.zip
~~~

Only scan sources you own or are authorized to analyze.

## Import external reports

Use `--input-file` to import external scanner output instead of running
Trident's scanner subprocesses. The option is repeatable, so SonarQube and
OWASP Dependency-Check results can be correlated in one job:

~~~bash
trident scan --input-file sonar-report.json
trident scan --input-file sonar-report.json \
  --input-file dependency-check-report.json
~~~

The supported formats are SonarQube issue JSON and OWASP Dependency-Check JSON
with `reportSchema: 1.1`. Other JSON schemas are rejected rather than converted
implicitly.

Imported findings use the normal correlation, Council, judge, red-team, triage,
report, and exit-code pipeline. A report-only import does not have source code
for agentic investigation or reachability, so those fields are marked
unavailable or `unknown` rather than inferred. Imported records remain scanner
evidence. A finding retained in the output means retained for remediation work,
not proven exploitable from source.

Provide source context without running scanners when code-grounded review is
needed:

~~~bash
trident scan --input-file sonar-report.json --source-dir /path/to/source
~~~

Source context enables code snippets, read-only agent investigation, and static
reachability. Novel discovery remains disabled unless explicitly requested:

~~~bash
trident scan --input-file sonar-report.json \
  --source-dir /path/to/source --discover-novel
~~~

Use `--input-format auto`, `sonarqube`, or `dependency-check` when detection
needs to be explicit. Multiple input files are validated as one import job. A
missing, unreadable, malformed, duplicate, or mismatched input fails the job
with exit code 2 rather than producing a partial result.

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

The table is intended for terminal review and includes the package/version
remediation action rollup for imported dependencies. JSON contains the retained findings,
review provenance, original imported records, and disposition evidence. SARIF
2.1.0 is suitable for code-scanning upload actions and exposes the same evidence
under result properties. Triage runs automatically after council review. The
selected output contains retained, actionable work items; scanner candidates
rejected as false positives are excluded from that queue but remain represented
with their disposition and evidence in JSON, SARIF properties, and the full
triage sidecar.

## Severity gate

| Option | Meaning |
|--------|---------|
| --severity-gate critical | Fail on P0 and above |
| --severity-gate high | Fail on P1 and above |
| --severity-gate medium | Fail on P2 and above |
| --severity-gate low | Fail on P3 and above |
| --fail-on P0 through P4 | Equivalent tier notation |

The default gate is high. A scan returns 0 when no retained finding reaches the
gate, 1 when one or more do, and 2 when import, ingestion, scanning, or report
processing fails. In imported report mode, retained means retained for
remediation work. It does not by itself prove source-level reachability.

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

Output formats place retained findings in the actionable list. Raw, disputed,
refuted, duplicate, suppressed, and parse-error records are excluded from that
list but are described in the `dispositions` object. See
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
