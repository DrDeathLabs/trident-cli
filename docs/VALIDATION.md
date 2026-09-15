# Validation

Universal ingestion validation is layered. Unit tests cover selectors,
mapping validation, inference, adapters, severity and identifier handling,
provenance, source containment, hostile values, and accounting. Integration
tests exercise persistence and prove imported mode does not launch scanner
subprocesses. The holdout corpus in `eval/universal_ingestion/` covers top-level
arrays, results/findings collections, deep nesting, package vulnerabilities,
rules tables, multiple locations, numeric and textual severity, mixed quality,
partial records, vendor-specific fields, Trivy, Grype, and Semgrep-shaped JSON.

Run the local checks from `backend/`:

```bash
ruff check trident tests
pytest -q
```

Inspect a holdout without persistence or triage:

```bash
trident inspect ../eval/universal_ingestion/vendor_holdout.json --format json
trident inspect ../eval/universal_ingestion/vendor_holdout.json \
  --mapping ../eval/universal_ingestion/vendor_holdout.mapping.json --format json
```

Actual import-mode CLI validation should use an isolated SQLite path and a
configured provider. A mock provider is suitable for exercising the downstream
workflow, but it is not evidence of live provider mapping validation. Record
the provider/model identity separately when a real schema-AI call is made.

For each fixture, retain the detected format, record total, six terminal
disposition counts, report hash, mapping hash/source, and inspected JSON/SARIF
output. A successful import must have zero unexplained records and must retain
field-level provenance in the resulting evidence package.
