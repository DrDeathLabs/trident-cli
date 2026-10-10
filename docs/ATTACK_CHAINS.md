# Red-Team attack-chain analysis

Red-Team analysis considers confirmed findings together and looks for a
plausible sequence where one weakness supplies a condition or capability needed
to exploit another. It is an analysis of available evidence, not an exploit or
a proof that a path works in a deployed system.

## Input selection and evidence

The Red-Team role uses a bounded finding set. Selection is deterministic:
findings are sorted by severity, normalized file path, line, and identifier
before the limit is applied. Each selected record contributes the identifier,
title, severity, CWE, location, a bounded description, prompt evidence, and its
report-only or source-grounded state. The prompt also includes the applicable
system instructions and response schema.

Report-only findings can produce report-derived chain hypotheses. Source-grounded
evidence can provide additional context, but static analysis does not establish
runtime reachability by itself. The report records chain basis and participating
finding identifiers.

## Reuse and changed input

Trident builds a canonical representation of the messages and schema sent to
the model, then fingerprints that representation. If the next iteration has
the identical fingerprint and the prior response parsed successfully, Trident
reuses its persisted chain records and per-finding paths without another model
call or budget charge.

Any change to model-visible content creates a different fingerprint and
requires fresh analysis. This includes a changed description, severity, CWE,
prompt evidence, selected finding set, source-grounding state, or model. Before
checking the call budget, Trident invalidates chains from the old input. If the
budget is exhausted, the new input is marked unavailable and old chains are
not reported as current. A failed or unparsable response is not cached as a
successful result.

## Effect on triage

Confirmed findings used by a stored chain are marked with chain metadata.
Eligible chain evidence can raise a finding by one tier. P0/P1 elevations from
report-derived chains have additional evidence requirements; source-grounded
reachable evidence can satisfy a separate eligibility path. Other guards can
also affect priority. Inspect `chain_basis`, `chain_priority_eligible`,
`chain_priority_suppressed_reason`, and the final triage rationale in JSON.

Do not infer the pre-chain priority by subtracting one from the final tier. The
class, reachability, corpus, KEV, and chain rules may all affect the result.

## Find chain results

The JSON report contains a top-level `attack_chains` collection and
`redteam_analysis` status. Each chain includes its goal, steps, likelihood,
iteration, and participating finding IDs. Findings include paths in their
triage evidence when they participate. A reused successful analysis remains
present in the report. If analysis is unavailable, inspect its status rather
than relying on old output.

```bash
trident scan . --format json --output-file results.json
```

Review each step against the source and deployment before using a chain to
change remediation order. The model may infer a relationship that the
available evidence does not establish.

## See also

- [Council review](AI_COUNCIL.md)
- [Triage](TRIAGE.md)
- [Privacy](PRIVACY.md)
