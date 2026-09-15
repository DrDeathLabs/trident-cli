# Triage - From Alert Flood to Worked Queue

Trident runs automatic triage after council review. This is the step that turns
a retained finding into an operational decision: not just whether it is
severe in the abstract, but how urgently this specific issue should be worked in
this codebase.

The LLM assesses explicit factors: impact, attack vector, exploitability, fix
effort, and reachability context. Deterministic code then applies the triage
rubric, evidence-based correction adjustments, and attack-chain context to
compute one of five operational priority tiers, P0-P4. The model is not asked
to emit an opaque P0-P4 label directly.

Scanner output is intentionally a candidate set: scanner false positives are
expected and are useful recall evidence. Council verdicts and triage remove
rejected candidates from the final actionable queue; false-positive and
out-of-scope quality-finding counts and their evidence remain available in
JSON/SARIF properties and the full triage sidecar. A `confirmed` status is the
workflow's retained-for-remediation state. It is not a universal claim that
the scanner record is factually or source-level proven. Imported SonarQube
`CODE_SMELL` records are classified as `out_of_scope`, not as false positives:
the original Sonar finding may be valid, but it is not a security remediation
item. For report-only imports, the queue is based on imported scanner evidence
and reachability is `unknown`. A triage decision is not a substitute for
authorized human review.
The adjustments described here are triage correction mechanisms. They are not
runtime safety controls, execution blockers, or security approval gates.

---

## Priority tiers

| Tier | Severity | Meaning | SLA |
|------|----------|---------|-----|
| P0 | Critical | Incident-level urgency. Requires source-grounded exposure or qualifying multi-finding chain evidence. | Immediate - out-of-band fix |
| P1 | High | High-impact and remotely reachable, or exact identity-matched KEV evidence supports the floor | Fix this sprint (~7 days) |
| P2 | Medium | High-impact with limited reach, or medium-impact with remote reach | Scheduled remediation (~30 days) |
| P3 | Low | Moderate impact | Backlog / batch this quarter |
| P4 | Info | Informational / hygiene | Opportunistic |

---

## Tier computation rubric

Tiers are computed from three dimensions. The combination of all three determines the final tier.

### Impact ranks

| Impact | Rank | Examples |
|--------|------|---------|
| `rce` | 4 | Remote code execution |
| `auth_bypass` | 4 | Authentication bypass |
| `data_exposure` | 3 | Sensitive data leak |
| `data_tampering` | 3 | Unauthorized data modification |
| `ssrf` | 3 | Server-side request forgery |
| `injection` | 3 | SQL/command/LDAP injection |
| `dos` | 2 | Denial of service |
| `info_disclosure` | 1 | Low-sensitivity information disclosure |
| `other` | 1 | Miscellaneous |

### Attack vector ranks

| Vector | Rank | Meaning |
|--------|------|---------|
| `remote_unauth` | 4 | Exploitable over the network without credentials |
| `remote_auth` | 3 | Exploitable over the network with valid credentials |
| `adjacent` | 2 | Exploitable from an adjacent network segment |
| `local` | 1 | Requires local system access or source code access |
| `physical` | 0 | Requires physical access |
| `unknown` | 0 | The available report evidence does not establish exposure |

### Exploitability ranks

| Exploitability | Rank |
|----------------|------|
| `trivial` | 2 |
| `moderate` | 1 |
| `difficult` | 0 |

### Tier rules

| Tier | Condition |
|------|-----------|
| P0 | impact ≥ 4 AND vector ≥ 4 AND exploitability ≥ 2 |
| P1 | impact ≥ 3 AND vector ≥ 3 |
| P2 | impact ≥ 3 OR (impact ≥ 2 AND vector ≥ 3) |
| P3 | impact ≥ 2 |
| P4 | all else |

### Chain bump

If a finding participates in an attack chain (`triage.in_chain = true`) and is
not already P0, it normally is bumped up one tier. A report-derived chain may
not create P0 or P1 unless it contains multiple distinct confirmed findings or
source-grounded reachable evidence. Trident keeps the path and records the
suppression reason when that condition is not met. A single imported record
cannot become P0 because of a red-team hypothesis.

### Report-only triage rules

Imported reports can support useful prioritization without pretending that
source inspection occurred:

- `reachability` remains `unknown` without a matching source file.
- The final `attack_vector` remains `unknown` when exposure is not established.
- The model's proposed vector is retained in `model_attack_vector`.
- A CVSS vector from the imported record is retained as `reported_attack_vector`.
- Exact package/CPE identity and direct KEV membership can support a P1 floor.
- KEV evidence does not create P0 and does not override an identity conflict.
- Corpus prevalence may adjust impact, but cannot manufacture network exposure.

The deterministic package/CPE check returns `match`, `conflict`, or `unknown`.
Conflicts remain in the Council review and audit trail. They are not silently
discarded.

## Evidence basis

Every retained finding exposes an `evidence` object. Its `basis` is one of:

| Basis | Meaning |
|-------|---------|
| `report_only` | Imported scanner metadata was available, but no matching source file was available |
| `source_grounded` | An imported record was mapped to source context and the reported file was available |
| `scanner_and_source` | A native Trident scan had scanner output and a source workspace |
| `scanner_only` | Scanner output was available without a source workspace |

The original imported record is under `evidence.import.record`. Council and
judge conclusions are under `review.verdicts` and `review.debate`. This lets a
reviewer distinguish scanner evidence, model judgment, source evidence,
reachability, deterministic adjustments, and chain reasoning.

---

## Validation scope

The approved public validation summary, including repeatability and import
accounting, is maintained in [VALIDATION.md](VALIDATION.md). It is evidence
within the stated test scope, not a universal performance or correctness claim.

---

## Triage fields reference

The `triage` object is nested under each finding in JSON output and in the SARIF `properties` block.

| Field | Type | Description |
|-------|------|-------------|
| `impact` | string | Final impact after guard adjustments |
| `attack_vector` | string | Final attack vector after guard adjustments |
| `exploitability` | string | How hard an attacker would find this to exploit |
| `fix_effort` | string | How much work is required to fix this |
| `rationale` | string | LLM's explanation of the triage assessment |
| `in_chain` | bool | Whether this finding is part of a red team attack chain |
| `model_impact` | string | Raw LLM assessment before guard adjustments |
| `model_attack_vector` | string | Raw LLM assessment before guard adjustments |
| `reported_attack_vector` | string or null | Attack vector stated by the imported CVSS record, when present |
| `scanner_severity` | string | Original normalized scanner severity |
| `model_severity` | string or null | Severity proposed by an expert or judge; it does not overwrite scanner severity |
| `guard` | string or null | Class guard note if it applied |
| `reach_guard` | string or null | Reachability guard note if it applied |
| `reachability` | string | `reachable`, `unreachable`, or `unknown` |
| `corpus_guard` | string or null | Corpus guard note if it applied |
| `chain_member_count` | integer | Distinct confirmed findings in the associated chain |
| `chain_priority_eligible` | bool | Whether chain evidence was allowed to affect P0/P1 |
| `chain_priority_suppressed_reason` | string or null | Reason a report-derived high-tier chain bump was blocked |
| `kev_floor` | string or null | Deterministic KEV priority-floor explanation |

Each finding also exposes `import_metadata` with the report format, package and
version when applicable, KEV status, CPE identity status, and raw version
normalization details. `evidence.import.record` remains the complete original
record.

`model_impact` and `model_attack_vector` show the raw LLM assessment before any guard ran. If these differ from `impact` and `attack_vector`, a guard adjusted the rating. The relevant guard field (`guard`, `reach_guard`, or `corpus_guard`) will contain an explanation.

---

## Reading a triage result

```json
{
  "priority": "P1",
  "title": "SQL Injection via unsanitized user input",
  "file": "app/db.py",
  "line_start": 47,
  "triage": {
    "impact": "injection",
    "attack_vector": "remote_unauth",
    "exploitability": "trivial",
    "fix_effort": "moderate",
    "rationale": "User-controlled input flows directly into a raw SQL query with no parameterization. No authentication is required to reach this endpoint.",
    "in_chain": true,
    "model_impact": "injection",
    "model_attack_vector": "remote_unauth",
    "guard": null,
    "reach_guard": null,
    "reachability": "reachable",
    "corpus_guard": null
  }
}
```

This P1 finding has `in_chain: true`, meaning it participates in an attack chain. If it were originally rated P2, the chain bump elevated it to P1.

No guards adjusted this finding (all guard fields are null). The reachability
guard confirmed it is `reachable` from a detected external entry point.

---

## Acting on each tier

| Tier | Recommended action |
|------|--------------------|
| P0 | Verify immediately and fix immediately when the source and deployment confirm the result. Open an incident if the affected code is in production. |
| P1 | Fix before the next production release. Add to the current sprint. |
| P2 | Schedule for the next release cycle. Do not defer more than 30 days. |
| P3 | Add to the backlog. Address in batch with similar findings. |
| P4 | Fix opportunistically during refactoring. Consider as hygiene work. |

---

## See also

- [GUARDS](GUARDS.md) - how guards adjust triage ratings
- [ATTACK_CHAINS](ATTACK_CHAINS.md) - chain bump logic and attack chain structure
- [OUTPUT_FORMATS](OUTPUT_FORMATS.md) - full JSON and SARIF field reference
