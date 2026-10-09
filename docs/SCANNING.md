# Scanning

Trident scans an authorized source tree, sends candidates through its review
pipeline, and runs automatic triage on the findings that survive review.

## Basic usage

~~~bash
trident scan [WORKSPACE] [OPTIONS]
~~~

WORKSPACE defaults to the current directory for native scanning. It can be a
local directory, a Git URL, or a ZIP archive.

Uploaded ZIP archives reject traversal paths, links, and special filesystem
entries. Extraction is limited to 100,000 members and 4 GiB of expanded file
content. Git source URLs must not embed credentials or query strings; use SSH
agent credentials or the host's credential manager instead. Git transport
errors are summarized without printing the URL or raw Git output.

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

Deterministic first-class formats are SonarQube issue JSON, OWASP
Dependency-Check JSON with `reportSchema: 1.1`, SARIF 2.1.0, and CycloneDX JSON
with vulnerability data. Other heterogeneous security JSON can use automatic
inference or a versioned explicit mapping. See [JSON ingestion](JSON_INGESTION.md).

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

Use `--input-format auto`, `sonarqube`, `dependency-check`, `sarif`,
`cyclonedx`, or `generic-json` when detection needs to be explicit. Use
`--mapping FILE` for a deterministic user mapping and `--no-schema-ai` to
disable optional schema mapping. Multiple input files are validated as one import job. A
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

The default table is a numerical summary with explicit P0-P4 counts, the total
prioritized count, and separate `Untriaged` and `Unresolved` counts. The total
is the sum of the five priority counts; untriaged and unresolved records are
not included in it. Table counts and the severity gate use the finalized JSON
report population. JSON contains retained findings, review provenance, original
imported records, and disposition evidence. SARIF 2.1.0 is suitable for
code-scanning upload actions and exposes the same evidence under result
properties. Triage runs automatically after council review. The
selected output contains retained, actionable work items; scanner candidates
refuted by Council/deliberation are excluded from that queue, while triage
prioritizes only retained/confirmed findings. Their disposition and evidence
remain represented in JSON, SARIF properties, and the full triage sidecar.

## Severity gate

| Option | Meaning |
|--------|---------|
| --severity-gate critical | Fail on P0 and above |
| --severity-gate high | Fail on P1 and above |
| --severity-gate medium | Fail on P2 and above |
| --severity-gate low | Fail on P3 and above |
| --fail-on P0 through P4 | Equivalent tier notation |

The default gate is high. A scan returns 0 when review completed and no retained
finding reaches the gate, 1 when one or more prioritized findings do, and 2
when import, ingestion, scanning, or report processing fails, or confirmed
findings remain untriaged or unresolved. Exit 2 takes precedence over the
severity gate because the analysis is incomplete. In imported report mode,
retained means retained for remediation work. It does not by itself prove
source-level reachability.

~~~bash
trident scan . --severity-gate critical
trident scan . --fail-on P2
~~~

## LLM overrides

~~~bash
trident scan . --backend ollama --model nemotron-3-super:cloud
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

Output formats place retained findings in the actionable list. Raw, refuted,
duplicate, suppressed, and parse-error records are excluded from that list but
are described in the `dispositions` object. A remaining final dispute is
normalized to `unresolved` by production convergence (except SonarQube code
smells, which are out of scope). See
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
