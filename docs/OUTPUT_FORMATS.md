# Output Formats

Trident supports three output formats. Select with `--format`:

```bash
trident scan . --format table    # default - terminal summary
trident scan . --format json     # full machine-readable output
trident scan . --format sarif    # SARIF 2.1.0 for GitHub Code Scanning
```

The same output formats are available for imported SonarQube and
Dependency-Check reports. Import mode replaces scanner execution but preserves
the downstream review, triage, sidecar, and exit-code behavior:

```bash
trident scan --input-file sonar.json --format json
trident scan --input-file sonar.json \
  --input-file dependency-check.json --format sarif \
  --triage-output-file triage.sarif
```

All formats contain only **confirmed** findings in their actionable finding
lists. In this context, `confirmed` means retained for remediation work after
the review workflow. It does not mean that source-level exploitability has been
proven, especially for report-only imports. Raw, disputed, refuted, duplicate,
and error-state candidates are not actionable, but their dispositions, evidence,
and counts remain available in the report's `dispositions` object and the full
triage sidecar. This separation is central to Trident's output:
scanner candidates establish recall, while the worked queue shows what survived
review and how urgently it should be addressed.

---

## Table (default)

The table is the default output for interactive use. It shows finding counts
per priority tier with a sample finding for each tier, followed by the triage
playbook for every tier. Triage runs automatically after retained findings are
produced.

```
Trident Scan - my-project
──────────────────────────────────────────────────────────────
  Tier │ Count │ Sample
──────────────────────────────────────────────────────────────
  P0   │     2 │ python.flask.security.insecure-deserialization  (app.py:36)
  P1   │    18 │ yaml.github-actions.security.github-actions-...  (ci.yml:12)
  P2   │    21 │ python.flask.security.audit.app-run-param-co...  (app.py:123)
  P3   │    11 │ yaml.security.configuration.policy...  (manifests/app.yml:21)
  P4   │    10 │ ...
──────────────────────────────────────────────────────────────
  Total confirmed: 62

Triage plan:
  P0: 2 | Critical | SLA: Immediate (out-of-band)
       Immediate action required.
  ...
```

For the per-finding worked queue in terminal form, write a triage sidecar:

```bash
trident scan . --format table --output-file results.txt \
  --triage-output-file triage.txt
```

The triage table groups every retained finding by tier and includes severity,
location, scanner/CWE, evidence basis, attack-vector/impact/exploitability/
fix-effort factors, reachability, attack-chain membership and basis, rationale,
and analyst overrides. It also prints import paths, hashes, and disposition
counts when the job used imported reports.

---

## JSON

The JSON format is the richest output. It contains the full triage metadata,
review verdicts, evidence package, and original imported record for every
retained finding, plus the attack chains the red team generated. The
`dispositions` object contains non-actionable records with their status,
correlation relationship, review rationale, and original evidence.

```bash
trident scan . --format json > results.json
```

### Top-level structure

```json
{
  "job": { ... },
  "import": { ... },
  "findings": [ ... ],
  "remediation_actions": [ ... ],
  "attack_chains": [ ... ],
  "triage": { ... },
  "dispositions": { ... }
}
```

The top-level `triage` object is a compact summary with `summary`, `tiers`,
and `untriaged`. The summary distinguishes the complete accounted/reviewed
record set from the retained triage queue. `triaged` is retained for
backward compatibility and means records assigned a P0-P4 priority; use
`reviewed_records` for records that received a final workflow disposition and
`retained_for_remediation` for the actionable queue size. The separate
top-level `remediation_actions` array groups
retained work by remediation target. Each tier includes its count and the recommended playbook,
SLA, and action. Each finding also retains its detailed `triage` object.

Import metadata retains every source record that was not eligible for active
processing under each input's `skipped` array, including the original raw
record and the deterministic skip reason. For example, a closed SonarQube
vulnerability is skipped from the active queue because it is closed, not
silently treated as a false positive or discarded.

To write the complete worked queue as a separate JSON artifact:

```bash
trident scan . --format json --output-file results.json \
  --triage-output-file triage.json
```

The sidecar has `report_type: "triage"`, the job metadata, import metadata,
summary counts, non-empty P0-P4 tier arrays containing full finding records,
and an `untriaged` array. The `dispositions` object lists rejected, duplicate,
related, disputed, suppressed, out-of-scope, and other non-actionable records
with their evidence. False positives and out-of-scope quality findings are not
included in the retained finding queues.

### `job` object

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | UUID for this scan job |
| `target` | string | Workspace path or display name |
| `status` | string | Job state such as `complete`, `scanning`, or `failed` |
| `languages` | array | Languages detected in the workspace |
| `iterations` | int | Number of council iterations that ran |
| `started_at` | string | ISO 8601 timestamp |
| `completed_at` | string | ISO 8601 timestamp |

### `findings` array - per-finding fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | UUID |
| `priority` | string | `P0`-`P4` |
| `tool` | string | Which scanner first reported this finding |
| `rule_id` | string | Scanner rule identifier |
| `severity` | string | `critical`, `high`, `medium`, `low`, `info` |
| `scanner_severity` | string or null | Severity normalized from the scanner or imported report |
| `model_severity` | string or null | Expert or judge severity assessment, separate from scanner severity |
| `confidence` | float | 0.0-1.0; boosted +0.10 per corroborating tool |
| `title` | string | Short description |
| `description` | string | Full finding description |
| `file` | string | Relative file path (forward slashes on all platforms) |
| `line_start` | int | Starting line number |
| `line_end` | int | Ending line number |
| `cwe` | string | CWE identifier (e.g. `CWE-89`) |
| `owasp` | string | OWASP category if applicable |
| `status` | string | Internal workflow status, normally `confirmed` in this list |
| `disposition` | string | Plain-language status meaning, such as `retained_for_remediation` or `rejected_by_review` |
| `iteration` | int | Council iteration in which this was confirmed |
| `corroborating_tools` | array | Other tools that also flagged this finding |
| `narrative` | string | Council's explanation of the vulnerability |
| `remediation` | string | Recommended fix |
| `exploit_scenario` | string | How an attacker would exploit this |
| `attack_paths` | array | Related attack paths (if in a chain) |
| `review` | object | Council and judge verdicts plus persisted debate rationale |
| `evidence` | object | Evidence basis, source availability, normalized mapping, and original imported record |
| `import_metadata` | object | Imported format, KEV status, package/CPE identity, version normalization, and reported vector |
| `remediation_action_id` | string | Stable package/version action identifier |
| `triage` | object | Triage metadata - see below |

### `triage` object (nested under each finding)

| Field | Type | Values | Description |
|-------|------|--------|-------------|
| `impact` | string | `rce`, `auth_bypass`, `data_exposure`, `data_tampering`, `ssrf`, `injection`, `dos`, `info_disclosure`, `other` | Final impact after triage adjustments |
| `attack_vector` | string | `remote_unauth`, `remote_auth`, `adjacent`, `local`, `physical`, `unknown` | Final attack vector after triage adjustments |
| `exploitability` | string | `trivial`, `moderate`, `difficult` | How hard is this to exploit |
| `fix_effort` | string | `trivial`, `moderate`, `involved` | How hard is this to fix |
| `rationale` | string | - | LLM's text justification for the triage assessment |
| `in_chain` | bool | - | Whether this finding participates in an attack chain |
| `model_impact` | string | same as `impact` | Raw LLM assessment before triage adjustments |
| `model_attack_vector` | string | same as `attack_vector` | Raw LLM assessment before triage adjustments |
| `guard` | string or null | - | Class-correction note if it adjusted this finding |
| `reach_guard` | string or null | - | Reachability-adjustment note if it adjusted this finding |
| `reachability` | string | `reachable`, `unreachable`, `unknown` | Result of the reachability analysis |
| `corpus_guard` | string or null | - | Corpus-profile adjustment note if it adjusted this finding |
| `evidence_basis` | string | `report_only`, `source_grounded`, `scanner_and_source`, `scanner_only` | Evidence available to the decision stages |
| `chain_basis` | string or null | `source_grounded`, `report_derived` | Whether chain reasoning had source context |
| `reported_attack_vector` | string or null | Imported CVSS vector, when available | Scanner evidence, not Trident's final factor |
| `chain_member_count` | integer | - | Distinct confirmed findings in the chain |
| `chain_priority_eligible` | bool | - | Whether chain evidence could affect P0/P1 |
| `chain_priority_suppressed_reason` | string or null | - | Why high-tier report-derived elevation was blocked |
| `kev_floor` | string or null | - | Exact identity-matched KEV floor explanation |

For imported findings, `evidence.import.record` is the original SonarQube
issue or Dependency-Check vulnerability record. Dependency-Check evidence also
includes the package, installed version, parent dependency context, and
vulnerable software match when present. `evidence.import_metadata.kev` and
`evidence.import_metadata.identity` expose normalized KEV and package/CPE
results. The record is untrusted input, not an instruction to the model.

### `remediation_actions`

This backward-compatible section groups retained Dependency-Check findings by
normalized package and version. It contains the highest priority, CVE or rule
list, KEV and identity rollups, stable action ID, evidence basis and evidence /
rationale references, and every affected file as an occurrence. The original
flat `findings` list remains available. Native code findings without package
identity receive one action per finding. `kev_records`, `kev_sources`, and
`kev_dates` preserve the normalized direct KEV assertions for the grouped
records. `duplicate_records` and `related_records` distinguish exact repeats
from distinct advisories grouped under the same package/version action.

### `attack_chains` array - per-chain fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | UUID |
| `goal` | string | What an attacker achieves by executing this chain |
| `steps` | array of strings | Ordered exploitation steps |
| `likelihood` | string | `high`, `medium`, `low` |
| `iteration` | int | Council iteration in which this chain was identified |
| `finding_ids` | array | UUIDs of the findings that make up this chain |

Each finding's `attack_paths` entries include `basis`. `source_grounded` means
matching source context was available. `report_derived` means the red team
reasoned from imported metadata without source code, so the path is a
hypothesis rather than a verified call chain.

### Example - reading a triage block

```python
import json

with open("results.json") as f:
    data = json.load(f)

for finding in data["findings"]:
    t = finding["triage"]
    print(f'{finding["priority"]}  {finding["file"]}:{finding["line_start"]}')
    print(f'  impact={t["impact"]}  vector={t["attack_vector"]}')
    print(f'  fix_effort={t["fix_effort"]}')
    if t.get("guard"):
        print(f'  [class guard] {t["guard"]}')
    if t.get("corpus_guard"):
        print(f'  [corpus guard] {t["corpus_guard"]}')
```

---

## SARIF 2.1.0

SARIF (Static Analysis Results Interchange Format) is the standard format for integrating with GitHub Code Scanning, IDE security extensions, and SAST aggregation platforms.

```bash
trident scan . --format sarif > results.sarif
trident scan . --format sarif --output-file results.sarif
```

### Schema

```
$schema: https://json.schemastore.org/sarif-2.1.0.json
version: "2.1.0"
runs[0]:
  tool.driver:
    name: Trident
    rules: [ ...rule catalog... ]
  results: [ ...findings... ]
```

### Per-result fields

| Field | Description |
|-------|-------------|
| `ruleId` | Scanner rule ID (e.g. `semgrep.python.flask.security.insecure-deserialization`) |
| `ruleIndex` | Index into the `rules` array |
| `level` | `error` (P0/P1), `warning` (P2), `note` (P3/P4) |
| `message.text` | Human-readable finding description |
| `message.markdown` | Markdown description with guard adjustment notes |
| `locations[0].physicalLocation.artifactLocation.uri` | Relative file path |
| `locations[0].physicalLocation.region.startLine` | Starting line |
| `locations[0].physicalLocation.region.endLine` | Ending line |
| `partialFingerprints.primaryLocationLineHash` | Stable hash for deduplication across runs |
| `properties` | Priority, workflow disposition, tool, severity, confidence, review provenance, evidence package, correlation, and `triage{}` |

The scan SARIF run also exposes the compact triage summary at
`runs[0].properties.triage`, import metadata at `runs[0].properties.import`,
remediation actions at `runs[0].properties.remediation_actions`, and
non-actionable dispositions at `runs[0].properties.dispositions`. Each result
also carries scanner/model severity, import metadata, and its remediation
action ID. To
produce a dedicated triage SARIF artifact:

```bash
trident scan . --format sarif --output-file results.sarif \
  --triage-output-file triage.sarif
```

The sidecar remains SARIF 2.1.0, identifies its driver as `Trident (triage)`,
and puts the full triage summary in `runs[0].properties.triage`. Its results
retain per-finding triage factors, rationale, review provenance, original
evidence, and any analyst override.

### Priority → SARIF level mapping

| Priority | Severity | SARIF level |
|----------|----------|-------------|
| P0 | critical | `error` |
| P1 | high | `error` |
| P2 | medium | `warning` |
| P3 | low | `note` |
| P4 | info | `note` |

### Rule catalog

Each scanner rule appears once in `tool.driver.rules` with:

- `id` - rule identifier
- `name` - human-readable rule name
- `shortDescription.text` - one-line description
- `properties.tags` - includes `external/cwe/cwe-NNN` for CWE-tagged rules
- `properties.cwe` - CWE identifier

### GitHub Code Scanning integration

```yaml
- name: Scan with Trident
  run: trident scan . --format sarif --output-file results.sarif

- name: Upload to GitHub Security tab
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

See [CI_CD](CI_CD.md) for a complete workflow example.

---

## See also

- [TRIAGE](TRIAGE.md) - priority tiers and what to do with each
- [CI_CD](CI_CD.md) - exit codes and SARIF upload workflows
- [ATTACK_CHAINS](ATTACK_CHAINS.md) - understanding the `attack_chains` array
