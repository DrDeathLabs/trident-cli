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

Gateway, routing, and Red-Team acceptance also runs a real localhost
OpenAI-compatible HTTP server. The deterministic routing corpus records required,
optional, and incorrect reviewers. The preserved legacy matcher is the routing
compatibility floor: final eligibility is `legacy_match OR structured_match`.
Acceptance requires 100% required-expert recall, no decrease in controlled
known-vulnerability coverage, and direct comparison of actual invocations,
verdicts, confirmed findings, and priorities. Reduced assignments are not a
requirement for this correction. An independent holdout includes eval injection,
session weaknesses, weak RSA, SBOM/package findings, and CORS.

In the accepted deterministic full-pipeline comparison, corrected routing made
47 expert invocations versus 44 for the legacy matcher (+3), while all 38
known findings were confirmed in both runs and priorities were identical. This
is evidence for retained coverage on those fixtures, not a call-savings claim
or a guarantee of complete vulnerability coverage.

Red-Team validation changes visible prompt fields individually and checks exact
reuse, retry after parse failure, stable selection, and attack-chain
preservation. A changed input clears old chains before budget handling; exhausted
budget produces an `unavailable_budget` state in the database and final reports.
Packaged-wheel acceptance verifies gateway configuration through actual CLI
requests to the local HTTP server and checks Council and Red-Team behavior.
Corrective evidence is written to `TRIDENT_CORRECTIVE_LOCAL_ACCEPTANCE.md` and
`trident-corrective-local-acceptance.zip`.

Reporting acceptance also seeds all five priority tiers, untriaged confirmed
findings, unresolved model decisions, and non-actionable dispositions. It
reconciles each printed terminal count against the finalized JSON findings,
checks JSON/SARIF population parity and severity-gate exit codes, and repeats
the checks through a freshly installed wheel against the localhost gateway.

Current hardening acceptance includes Windows file ACL checks, credential
redaction in secret-scanner evidence, OpenAI-compatible endpoint URL/redirect
tests, archive traversal and size-limit cases, safe Git URL handling, and
installed-wheel scans through the localhost test gateway. It does not
constitute external-provider testing or broad real-world coverage. Local
release-readiness evidence is generated outside the source package and is not
published by these checks.

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
