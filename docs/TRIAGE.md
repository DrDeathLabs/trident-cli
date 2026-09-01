# Triage - From Alert Flood to Worked Queue

Trident runs automatic triage after council confirmation. This is the step that
turns a confirmed finding into an operational decision: not just whether it is
severe in the abstract, but how urgently this specific issue should be worked in
this codebase.

The LLM assesses explicit factors-impact, attack vector, exploitability, fix
effort, and reachability context. Deterministic code then applies the triage
rubric, evidence-based correction adjustments, and attack-chain context to
compute one of five operational priority tiers, P0-P4. The model is not asked
to emit an opaque P0-P4 label directly.

Scanner output is intentionally a candidate set: scanner false positives are
expected and are useful recall evidence. Council verdicts and triage remove
rejected candidates from the final actionable queue; false-positive counts and
their evidence remain available in JSON/SARIF properties and the full triage
sidecar. A triage decision is not a substitute for authorized human review.
The adjustments described here are triage mechanisms, not runtime safety
controls, execution blockers, or security approval gates.

---

## Priority tiers

| Tier | Severity | Meaning | SLA |
|------|----------|---------|-----|
| P0 | Critical | Remotely exploitable without authentication, trivially exploitable, catastrophic impact (RCE or auth bypass) | Immediate - out-of-band fix |
| P1 | High | High-impact, remotely reachable | Fix this sprint (~7 days) |
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

If a finding participates in an attack chain (`triage.in_chain = true`) and is not already P0, it is bumped up one tier (P2 → P1, P3 → P2, etc.).

---

## Evaluation snapshot: from alert barbell to worked queue

The following is a Trident evaluation snapshot from one 215-finding OWASP
PyGoat job. It isolates the class-correction experiment: a stronger model was
tested first, then the deterministic correction was applied. It is evidence of
the targeted failure-mode correction and its effect on queue shape-not an
independent benchmark, universal guarantee, or claim that every target will
produce this distribution.

| Configuration | P0 | P1 | P2 | P3 | P4 |
|---|---:|---:|---:|---:|---:|
| Gemma baseline | 47 | 79 | 35 | 2 | 52 |
| Nemotron model swap | 34 | 77 | 27 | 14 | 63 |
| Nemotron + deterministic correction | **13** | 52 | 53 | 43 | 54 |

On the same evaluation, 10 of 13 planted PyGoat vulnerabilities were detected.
Among those 10 detected findings, 8/10 matched the expert-assigned tier exactly,
10/10 landed within one tier, over-escalation was 0, and two findings were
under-escalated by one tier. The ground truth was expert code review rather than
an independently blinded benchmark, so these figures describe consistency with
that review and should be read with that limitation.

The important result is the decision shape: the baseline concentrated alerts at
the extremes, while the triage workflow produced a graded queue in which P0
remained available for genuinely urgent findings and lower tiers carried the
work that should be scheduled rather than escalated indiscriminately.

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
| `guard` | string or null | Class guard note if it applied |
| `reach_guard` | string or null | Reachability guard note if it applied |
| `reachability` | string | `reachable`, `unreachable`, or `unknown` |
| `corpus_guard` | string or null | Corpus guard note if it applied |

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
| P0 | Stop and fix immediately. These are actively exploitable. Open an incident if the affected code is in production. |
| P1 | Fix before the next production release. Add to the current sprint. |
| P2 | Schedule for the next release cycle. Do not defer more than 30 days. |
| P3 | Add to the backlog. Address in batch with similar findings. |
| P4 | Fix opportunistically during refactoring. Consider as hygiene work. |

---

## See also

- [GUARDS](GUARDS.md) - how guards adjust triage ratings
- [ATTACK_CHAINS](ATTACK_CHAINS.md) - chain bump logic and attack chain structure
- [OUTPUT_FORMATS](OUTPUT_FORMATS.md) - full JSON and SARIF field reference
