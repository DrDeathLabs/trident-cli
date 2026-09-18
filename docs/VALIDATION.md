# Validation

Universal ingestion validation is layered. Unit tests cover selectors,
mapping validation, inference, adapters, severity and identifier handling,
provenance, source containment, hostile values, and accounting. Integration
tests exercise persistence and prove imported mode does not launch scanner
subprocesses. The exhaustive acceptance corpus is maintained in the isolated
validation workspace rather than shipped as public package data; it covers
top-level arrays, results/findings collections, deep nesting, package
vulnerabilities, rules tables, multiple locations, numeric and textual severity,
mixed quality, partial records, vendor-specific fields, Trivy, Grype, and
Semgrep-shaped JSON.

Run the local checks from `backend/`:

```bash
ruff check trident tests
pytest -q
```

Inspect a holdout without persistence or triage:

```bash
trident inspect <validation-root>/vendor_holdout.json --format json
trident inspect <validation-root>/vendor_holdout.json \
  --mapping <validation-root>/vendor_holdout.mapping.json --format json
```

Actual import-mode CLI validation should use an isolated SQLite path and the
real configured provider/model. Unit-test mocks are not acceptance evidence.
Record requested and returned provider/model identity separately for every live
run.

## Evidence levels

Validation claims must name the layer that produced them:

- **Unit**: focused functions and contracts, including selectors, semantic
  mapping validation, adapters, provenance, and accounting.
- **Integration**: persistence, import-mode scanner bypass, correlation, and
  downstream pipeline behavior using controlled fixtures.
- **Real provider**: a live configured LLM backend, with requested and returned
  model identity and transport outcome recorded. Mock providers do not satisfy
  this level.
- **CLI**: an actual `trident` command, including exit code and generated
  output, rather than a direct Python function call.
- **Package**: a built wheel or sdist installed into a clean environment and
  exercised through its installed CLI entry point.
- **Import acceptance**: real or representative reports checked for semantic
  normalized values, record accounting, provenance, and the complete review and
  triage path. Record consumption alone is not correctness evidence.
- **Scanner workflow**: the native scanner subprocess path, including tool
  applicability, launch/result status, parsing, and downstream review.
- **Public release**: the published GitHub tag, workflow run, release metadata,
  downloaded assets, hashes, clean install, and CLI smoke. A local build or
  passing CI does not prove this level.

The public repository may document how a release is validated, but it must not
claim that a local acceptance run or a limited holdout corpus proves complete
vulnerability coverage. Private validation roots, usernames, machine paths,
credentials, and internal evidence archives are not public validation inputs.

For each fixture, retain the detected format, record total, six terminal
disposition counts, report hash, mapping hash/source, and inspected JSON/SARIF
output. A successful import must have zero unexplained records and must retain
field-level provenance in the resulting evidence package.
