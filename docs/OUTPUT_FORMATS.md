# Output Formats

Trident supports three output formats. Select with `--format`:

```bash
trident scan . --format table    # default - rich terminal table
trident scan . --format json     # full machine-readable output
trident scan . --format sarif    # SARIF 2.1.0 for GitHub Code Scanning
```

All formats contain only **confirmed** findings in their actionable finding
lists. Raw, disputed, refuted, duplicate, and error-state candidates are not
actionable, but their dispositions and counts remain available in scan metadata
and the full triage sidecar. This separation is central to Trident's output:
scanner candidates establish recall, while the worked queue shows what survived
review and how urgently it should be addressed.

---

## Table (default)

The table is the default output for interactive use. It shows finding counts
per priority tier with a sample finding for each tier, followed by the triage
playbook for every tier. Triage runs automatically after confirmed findings are
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

The triage table groups every confirmed finding by tier and includes severity,
location, scanner/CWE, attack-vector/impact/exploitability/fix-effort factors,
reachability, attack-chain membership, rationale, and analyst overrides.

---

## JSON

The JSON format is the richest output. It contains the full triage metadata for every confirmed finding plus the attack chains the red team generated.

```bash
trident scan . --format json > results.json
```

### Top-level structure

```json
{
  "job": { ... },
  "findings": [ ... ],
  "attack_chains": [ ... ],
  "triage": { ... }
}
```

The top-level `triage` object is a compact summary with `summary`, `tiers`,
and `untriaged`. Each tier includes its count and the recommended playbook,
SLA, and action. Each finding also retains its detailed `triage` object.

To write the complete worked queue as a separate JSON artifact:

```bash
trident scan . --format json --output-file results.json \
  --triage-output-file triage.json
```

The sidecar has `report_type: "triage"`, the job metadata, summary counts,
non-empty P0-P4 tier arrays containing full finding records, and an `untriaged`
array. False positives are counted in the summary but are not included in the
confirmed finding queues.

### `job` object

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | UUID for this scan job |
| `target` | string | Workspace path or display name |
| `status` | string | `completed` |
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
| `confidence` | float | 0.0-1.0; boosted +0.10 per corroborating tool |
| `title` | string | Short description |
| `description` | string | Full finding description |
| `file` | string | Relative file path (forward slashes on all platforms) |
| `line_start` | int | Starting line number |
| `line_end` | int | Ending line number |
| `cwe` | string | CWE identifier (e.g. `CWE-89`) |
| `owasp` | string | OWASP category if applicable |
| `status` | string | `confirmed` |
| `iteration` | int | Council iteration in which this was confirmed |
| `corroborating_tools` | array | Other tools that also flagged this finding |
| `narrative` | string | Council's explanation of the vulnerability |
| `remediation` | string | Recommended fix |
| `exploit_scenario` | string | How an attacker would exploit this |
| `attack_paths` | array | Related attack paths (if in a chain) |
| `triage` | object | Triage metadata - see below |

### `triage` object (nested under each finding)

| Field | Type | Values | Description |
|-------|------|--------|-------------|
| `impact` | string | `rce`, `auth_bypass`, `data_exposure`, `data_tampering`, `ssrf`, `injection`, `dos`, `info_disclosure`, `other` | Final impact after triage adjustments |
| `attack_vector` | string | `remote_unauth`, `remote_auth`, `adjacent`, `local`, `physical` | Final attack vector after triage adjustments |
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

### `attack_chains` array - per-chain fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | UUID |
| `goal` | string | What an attacker achieves by executing this chain |
| `steps` | array of strings | Ordered exploitation steps |
| `likelihood` | string | `high`, `medium`, `low` |
| `iteration` | int | Council iteration in which this chain was identified |
| `finding_ids` | array | UUIDs of the findings that make up this chain |

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
| `properties` | All triage fields (priority, tool, severity, confidence, cwe, owasp, triage{}) |

The scan SARIF run also exposes the compact triage summary at
`runs[0].properties.triage`. To produce a dedicated triage SARIF artifact:

```bash
trident scan . --format sarif --output-file results.sarif \
  --triage-output-file triage.sarif
```

The sidecar remains SARIF 2.1.0, identifies its driver as `Trident (triage)`,
and puts the full triage summary in `runs[0].properties.triage`. Its results
retain per-finding triage factors, rationale, and any analyst override.

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
