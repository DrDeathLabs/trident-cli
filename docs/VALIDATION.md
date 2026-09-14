# Validation

## Status

`GREEN`

This page is a public summary of the completed Trident validation program. It
reports repeatability, processing consistency, and accounting within the tested
scope. It is not an autonomous security approval or a guarantee that a future
target will produce the same result.

## Scanner-based validation

The controlled scanner comparison reused identical scanner evidence and
compared the original and current decision pipelines. The current CLI retained
important scanner-backed vulnerability coverage while improving the
representation of relationships between findings.

| Measure | Original | Current |
|---|---:|---:|
| Final-result repeatability | 46.2% | 62.7% |
| Average execution time | approximately 622 seconds | approximately 491 seconds |
| Duplicate representation | 309 | 36 |
| Related representation | not separately represented in the comparison | 273 |

These figures are scoped to the controlled scanner validation and should not be
read as a general benchmark across repositories, models, or scanner versions.

## JSON import validation

Trident accepts SonarQube issue JSON and OWASP Dependency-Check JSON. Repeatable
`--input-file` options allow both supported report types to be processed in one
job. JSON import bypasses Trident scanner subprocesses and preserves the source
report evidence for review.

### SonarQube

- 42 issue records were present.
- 40 `OPEN` records were imported.
- 2 `CLOSED` records were skipped with explicit accounting.
- Repeated outcome consistency was 100% within the tested runs.
- The tested OPEN code-quality set produced no security-priority findings.

### OWASP Dependency Check

- 1,786 vulnerability records were present.
- All 1,786 were imported.
- There was no unexplained input loss or creation.
- Repeated outcome consistency was approximately 98.8%.
- Separate-versus-combined consistency was approximately 98.5%.

Combined SonarQube and Dependency-Check processing remained traceable, and the
scanner-bypass behavior was verified in the tested import workflow.

## Decision and evidence boundaries

Scanner-supplied severity is retained separately from model assessment,
deterministic guard adjustment, and final P0-P4 priority. Correlation records
exact duplicates and related evidence separately. Confirmed, false-positive,
duplicate, related, and unresolved dispositions remain distinguishable in the
reports.

An applicable, confirmed KEV creates a P1 priority floor regardless of
reachability. Product or version applicability must first be established;
identity conflicts or uncertain applicability do not justify blind promotion.

Imported metadata alone does not prove source exploitability. P0 and P1
decisions require qualified human review, and malformed or unresolved model
responses fail closed rather than becoming security verdicts.
