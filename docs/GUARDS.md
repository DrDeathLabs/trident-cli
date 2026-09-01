# Triage Adjustments (Guards in the CLI and Report Schema)

Guards are post-deliberation triage adjustments that apply deterministic signals
to the AI council's factor assessment. They run after a finding is confirmed and
before the final priority is exported.

These are not runtime protection controls, policy gates, or proof that a target
is safe. They do not block code execution or replace human review. Their job is
to calibrate the council's assessment for the specific finding and preserve a
readable explanation of any adjustment.

---

## Why guards

LLMs overestimate severity consistently in two categories: hardcoded secrets and hygiene findings. They also overestimate reach - a "remote_unauth" rating on a private internal function that is never exposed to the network.

Guards are layered, deterministic, and auditable. Every adjustment they make is recorded in the finding's triage fields so you can see exactly what changed and why.

---

## Execution order

Guards run in this order, and each guard sees the output of the previous:

```
Council deliberation
       │
       ▼
  Corpus guard  ← profile-based calibration (CWE historical data)
       │
       ▼
  Class guard   ← deterministic caps (secrets, hygiene categories)
       │
       ▼
 Reachability guard ← call-graph analysis
       │
   ▼
  Base priority
       |
       v
  Attack-chain bump
       |
       v
  Final triage
```

---

## Corpus guard

The corpus guard is a deterministic, profile-based calibration step. The model
refresh pipeline builds CWE profiles from the local vulnerability corpus. During
triage, the active guard reads a profile's `expected_tier` (derived from median
CVSS) and requires at least 200 CVEs for that CWE before it can adjust a finding.

For each confirmed finding, the corpus guard:
1. Maps the finding to its CWE identifier
2. Loads the local profile's expected tier
3. Computes the current tier from the council's factors
4. Applies deterministic factor ceilings when the current tier is above the expected tier
5. Applies deterministic factor floors when the current tier is below the expected tier
6. Records the adjustment in `triage.corpus_guard`

The corpus adjustment is **bidirectional**: it can cap an over-escalated
assessment or raise an under-escalated one. It does not auto-adjust P0 findings.
The separately trained sklearn artifact is maintained by the model commands and
reported by `model info`; ordinary guard evaluation uses the local profile's
expected tier and makes no live model or network request.

### CWE threshold

The corpus guard requires **at least 200 CVEs** in the historical dataset for a given CWE before it will adjust a finding. If the CWE has fewer than 200 instances, the corpus guard is skipped for that finding (`corpus_guard` is `null`).

This threshold prevents overcorrection based on sparse data. The guard is most effective on common CWEs (SQL injection, XSS, path traversal) where the historical signal is strong.

### When corpus_guard is null

`corpus_guard: null` means one of:
- No qualifying CWE profile is available, or that profile has fewer than 200 CVEs
- The current factor-derived tier already matches the profile's expected tier
- The applicable ceiling or floor was already satisfied, so no factor changed
- The corpus profiles have not been built (`trident model refresh` hasn't run)

If the corpus profiles are not built, all `corpus_guard` fields will be `null`.
See [CORPUS_GUARD_MODEL](CORPUS_GUARD_MODEL.md) for how to build them.

### Corpus guard in the triage block

```json
"corpus_guard": "corpus-guard: CWE-89 (n=12,847 CVEs) expected=P1 current=P0; capped factors"
```

When `corpus_guard` is non-null, `impact` and `attack_vector` may differ from `model_impact` and `model_attack_vector`. The corpus guard note explains the direction and basis of the adjustment.

---

## Class guard

The class guard is a deterministic, rule-based layer that caps severity for specific finding categories where LLMs are known to overrate.

### Secrets and credential findings

Secret detection tools (gitleaks, trufflehog) and SAST rules for hardcoded credentials frequently flag findings that the LLM council rates as P0 or P1. The class guard applies an upper cap:

| Secret class | Max tier |
|-------------|---------|
| API key or token (verified active by TruffleHog) | P1 |
| API key or token (not verified) | P2 |
| Password in test/fixture file | P3 |
| Generic high-entropy string | P3 |
| Certificate private key | P1 |

"Verified active" means TruffleHog's active-verification pass confirmed the secret against the provider API.

### Hygiene findings

Code hygiene findings (missing error handling, deprecated function use, informational patterns) are capped at P3 regardless of the council's rating. These findings are real and worth fixing, but they do not carry the exploitability that a P1 or P0 requires.

### When class guard is null

`guard: null` means the finding was not in a class with a defined cap, or the council's rating was already at or below the cap.

### Class guard in the triage block

```json
"guard": "Secrets class: unverified API key; cap applied at P2 (model rated P1)"
```

---

## Reachability guard

The reachability guard uses call-graph analysis to determine whether a vulnerable code path is reachable from an external entry point.

A finding rated `remote_unauth` on a function that is never called from any HTTP handler, queue consumer, or CLI entry point is not remotely exploitable. The reachability guard downgrades the attack vector from `remote_unauth` to `local` for such findings.

### How reachability is determined

Trident builds a call graph from the entry points it detects in the workspace:

- **Python/Flask/Django/FastAPI**: route handlers (`@app.route`, `@router.get`, etc.)
- **Go**: HTTP handler registrations (`http.HandleFunc`, router definitions)
- **JavaScript/TypeScript (Express)**: route registration expressions

A finding is `reachable` if the vulnerable function appears in the reachable set from any detected entry point.

### Fail-open behavior

If the reachability analysis cannot build a call graph - because the language is not supported, the framework pattern is not recognized, or the source is incomplete - the guard fails open. The finding's `reachability` is set to `unknown` and the council's rating is not adjusted.

The reachability guard **never downgrades a finding it cannot evaluate**. It only acts on findings it can confirm are unreachable.

### Inline handlers (known gap)

Express-style inline arrow functions - `app.get('/route', (req, res) => { ... })` - are treated as implicitly reachable because the handler body is defined inside the route registration call. Trident marks these `reachable` regardless of whether the specific vulnerable code is in the callback body.

### Reachability in the triage block

```json
"reachability": "unreachable",
"reach_guard": "Function db_internal_query() not reachable from any detected HTTP handler; attack_vector downgraded from remote_unauth to local"
```

| `reachability` value | Meaning |
|---------------------|---------|
| `reachable` | Vulnerable path is reachable from an entry point |
| `unreachable` | Call-graph analysis confirmed no reachable path |
| `unknown` | Call-graph analysis was not possible; rating unchanged |

---

## Disabling guards

All three guards can be disabled for a single scan:

```bash
trident scan . --no-guards
```

This is a debugging option. Do not use it in production scans - it removes all statistical and deterministic calibration and produces uncalibrated LLM ratings.

---

## Reading a finding that was adjusted by guards

```json
{
  "priority": "P2",
  "triage": {
    "impact": "data_exposure",
    "attack_vector": "local",
    "model_impact": "data_exposure",
    "model_attack_vector": "remote_unauth",
    "corpus_guard": "CWE-200 median attack_vector=local; adjusted from remote_unauth",
    "guard": null,
    "reachability": "unreachable",
    "reach_guard": "No reachable path from HTTP entry points; attack_vector downgraded"
  }
}
```

In this example, two guards fired:
- The corpus guard downgraded `attack_vector` from `remote_unauth` to `local` based on historical CWE-200 data
- The reachability guard confirmed unreachability and independently would have made the same adjustment

The final `attack_vector` of `local` reflects both adjustments. The `model_attack_vector` field always preserves the pre-guard LLM rating.

---

## See also

- [CORPUS_GUARD_MODEL](CORPUS_GUARD_MODEL.md) - building and maintaining the corpus guard model
- [TRIAGE](TRIAGE.md) - priority tiers and the triage field reference
- [AI_COUNCIL](AI_COUNCIL.md) - how findings are confirmed before guards run
- [OUTPUT_FORMATS](OUTPUT_FORMATS.md) - full triage block schema
