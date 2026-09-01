# Attack Chains

An attack chain is a multi-step path where several moderate findings combine
into a more serious attack. Trident's red-team reviewer looks for these paths
after each council iteration.

---

## What attack chains are

A finding rated P3 (low priority) alone might be a path traversal that reads files from a constrained directory. A second P3 finding might be a hardcoded internal API key. Together, they allow an attacker to read the key file and escalate to full API access - a critical impact that neither finding individually implies.

Attack chains capture this compounding. The red team reviews all confirmed findings for combinations that create a materially worse attack scenario than the sum of their parts.

---

## How chains are generated

After each council iteration, the red team receives all confirmed findings from that iteration plus all findings confirmed in prior iterations. It evaluates combinations for:

1. **Logical sequencing** - can the output of exploiting finding A feed into finding B? (e.g., steal credential via A, use it for auth bypass in B)
2. **Privilege escalation** - does chaining move the attacker from low-privilege to high-privilege access?
3. **Boundary crossing** - does the chain cross a trust boundary (unauthenticated → authenticated, unprivileged → admin, local → remote)?
4. **Impact amplification** - does the combined impact exceed what any individual finding implies?

When the red team identifies a valid chain, it generates a structured `attack_chain` object and marks each participating finding as `in_chain: true`.

---

## Effect on triage

Findings that participate in an attack chain receive a **+1 tier bump** in priority:

| Original tier | Bumped tier |
|--------------|-------------|
| P4 | P3 |
| P3 | P2 |
| P2 | P1 |
| P1 | P0 |
| P0 | P0 (no change; already maximum) |

The bump reflects that a finding's real-world exploitability and impact are higher when an attacker can chain it with other vulnerabilities in the same codebase.

The chain bump applies before the final output is produced. The `priority` field in the output already reflects the bump. If you want to see the pre-bump tier, subtract one level from the priority and check whether `triage.in_chain` is `true`.

---

## Attack chain JSON structure

Attack chains appear in the top-level `attack_chains` array in JSON output. Each chain object:

```json
{
  "id": "3f8a1c2d-9e4b-4a7f-b3c1-2d8e9f0a1b2c",
  "goal": "Unauthenticated remote code execution via credential theft and API escalation",
  "steps": [
    "1. Exploit path traversal (CVE finding a1b2c3) to read /config/api_key.txt",
    "2. Use harvested API key to authenticate as admin user via the /admin endpoint",
    "3. Submit crafted payload to admin-only /exec endpoint (finding d4e5f6) to execute arbitrary commands"
  ],
  "likelihood": "high",
  "iteration": 2,
  "finding_ids": [
    "a1b2c3d4-...",
    "d4e5f6a7-...",
    "b8c9d0e1-..."
  ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | UUID for this chain |
| `goal` | string | What an attacker achieves at the end of the chain |
| `steps` | array of strings | Ordered exploitation steps |
| `likelihood` | string | `high`, `medium`, or `low` - how plausible the chain is given the codebase |
| `iteration` | int | Council iteration in which this chain was identified |
| `finding_ids` | array | UUIDs of the participating findings |

---

## Likelihood ratings

| Likelihood | Meaning |
|-----------|---------|
| `high` | Prerequisites are satisfied, no significant attacker skill required |
| `medium` | Chain requires some attacker preparation (reconnaissance, account, known environment detail) |
| `low` | Chain is theoretically valid but requires significant preconditions or attacker skill |

---

## Example walkthrough

PyGoat scan, simplified:

**Findings going in:**
- Finding A: Path traversal in `/view` endpoint (P3, `reachability: reachable`)
- Finding B: Hardcoded admin password in `config.py` (P3, class guard capped)
- Finding C: Command injection in admin-only `/report` endpoint (P2, `reachability: reachable`)

**Red team output:**
```
Chain: Use path traversal to read config.py, extract admin password,
authenticate to /admin, invoke command injection on /report.
Goal: unauthenticated RCE.
Likelihood: high.
```

**After chain bump:**
- Finding A: P3 → **P2** (`in_chain: true`)
- Finding B: P3 → **P2** (`in_chain: true`)
- Finding C: P2 → **P1** (`in_chain: true`)

The final output shows 0 P0, 1 P1, 2 P2 - the chain turned a three-P3 scan into findings requiring sprint-level attention.

---

## Viewing chains in output

### JSON

```bash
trident scan . --format json | python -c "
import json, sys
d = json.load(sys.stdin)
for chain in d['attack_chains']:
    print(chain['goal'])
    for step in chain['steps']:
        print(' ', step)
    print('Likelihood:', chain['likelihood'])
    print()
"
```

### Table

The table output does not display chains directly, but chain-bumped findings are shown at their bumped tier. Switch to JSON to inspect the chains that caused the elevation.

---

## See also

- [AI_COUNCIL](AI_COUNCIL.md) - the red team role in the council
- [TRIAGE](TRIAGE.md) - the chain bump logic and `in_chain` field
- [OUTPUT_FORMATS](OUTPUT_FORMATS.md) - full `attack_chains` array schema
