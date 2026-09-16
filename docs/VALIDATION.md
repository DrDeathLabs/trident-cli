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

For each fixture, retain the detected format, record total, six terminal
disposition counts, report hash, mapping hash/source, and inspected JSON/SARIF
output. A successful import must have zero unexplained records and must retain
field-level provenance in the resulting evidence package.
