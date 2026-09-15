# JSON vulnerability evidence ingestion

Trident accepts standardized and heterogeneous JSON vulnerability evidence.
Import mode is an evidence-acquisition path: it does not launch scanner
subprocesses, and imported records continue through correlation, Council review,
judge/cross-examination, attack-chain analysis, deterministic guards, and P0-P4
triage.

## First-class formats

The deterministic adapter registry recognizes:

- SonarQube issue JSON;
- OWASP Dependency-Check `reportSchema: 1.1` JSON;
- SARIF 2.1.0 security results; and
- CycloneDX JSON containing a `vulnerabilities` collection.

A CycloneDX component inventory row without a vulnerability is not converted
into a finding.

## Generic JSON

Unknown security report structures can be mapped with
`trident-json-mapping-v1`. The selector language contains only `$`, object
keys, numeric array indexes, and `[*]` array wildcards. It does not evaluate
Python, shell commands, templates, filters, or user code.

```json
{
  "mapping_version": "trident-json-mapping-v1",
  "name": "example-scanner",
  "records": "$.results[*]",
  "tool": {"literal": "example-scanner"},
  "fields": {
    "rule_id": "$.rule.id",
    "title": "$.title",
    "description": "$.message",
    "severity": "$.risk",
    "file": "$.location.file",
    "line_start": "$.location.line"
  }
}
```

`trident inspect report.json` shows the detected format, candidate collection,
mapping, coverage, confidence, warnings, and complete record accounting. Use
`--format json` for automation and `--write-mapping FILE` to save a deterministic
proposal. Use `--mapping FILE` with `scan` when auto inference is not reliable.

```bash
trident inspect report.json --format json
trident inspect report.json --write-mapping report.mapping.json
trident scan --input-file report.json --mapping report.mapping.json --format json
trident scan --input-file report.json --no-schema-ai
```

Automatic inference is bounded and fail-closed. It recognizes common security
aliases, nested finding arrays, package-vulnerability structures, locations,
identifiers, numeric/textual severity, and mixed-quality records. It does not
make every JSON document a vulnerability report. A configured schema-AI
provider may propose a mapping only when explicitly enabled with
`TRIDENT_SCHEMA_AI=1`; the proposal is validated and then executed by the same
deterministic mapper. `--no-schema-ai` disables that path.

## Accounting and provenance

Every record in the selected collection terminates as exactly one of
`mapped`, `partially_mapped`, `out_of_scope`, `skipped`, `malformed`, or
`unsupported`. The input summary enforces that the total equals the sum of
those states. Valid JSON with isolated malformed records can therefore be
audited without silently losing input.

Imported findings retain the original record, report SHA-256, JSON pointer,
mapping identity/hash, per-field source pointer and original value, source
format/tool, identifiers, package identity, CVSS evidence, and whether source
context was available. Normalized severity never replaces the original value.

## Source context

Report-only imports are explicitly marked `report_only`; source reachability is
`unknown` and source exploitability is not claimed. `--source-dir` can add
read-only code context and path mapping without running scanners. Novel source
discovery remains opt-in with `--discover-novel`.

## Scope and limits

This feature targets standardized and heterogeneous software-security JSON. It
does not promise literal support for every arbitrary JSON document, XML, CSV,
YAML, PDF, or HTML. Ambiguous or weakly evidenced structures fail closed and
can be handled with an explicit mapping.
