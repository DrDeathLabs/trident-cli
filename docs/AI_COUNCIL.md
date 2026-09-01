# AI Council

## Why a council instead of a single model call

Asking one LLM "find vulnerabilities in this code" produces hallucinations, misses context, and gives you no way to understand why it said what it said. Each domain expert in Trident is scoped to findings it is actually qualified to review. The judge independently challenges high-confidence results. The red team looks at the full picture for chaining opportunities. No single role has final authority.

The result is a multi-perspective deliberation with explicit verdicts (confirmed / disputed / refuted / abstained) that are all persisted, inspectable, and auditable.

The council answers whether a scanner candidate is supported by the code. It
does not directly decide the final P0-P4 priority. Confirmed findings continue
into the separate triage pass, where the model supplies explicit factors and
deterministic code computes and explains the operational priority.

---

## Domain experts

Five domain experts review findings in their area of specialization. Each expert sees only findings in its domain - an injection expert does not vote on crypto findings.

| Expert | Domain | Key CWEs |
|--------|--------|----------|
| **Injection** | SQL injection, command injection, LDAP injection, XPath injection, template injection, path traversal, SSRF, open redirect, XXE, insecure deserialization | 89, 78, 79, 918, 22, 502 |
| **Auth & Access Control** | Authentication bypasses, session management, JWT weaknesses, OAuth flows, privilege escalation, IDOR, missing authorization, broken access control | 287, 639, 862, 863, 269 |
| **Crypto** | Weak ciphers (MD5, SHA1, DES), hardcoded keys, insufficient randomness, certificate validation, TLS misconfigurations, padding oracle | 327, 321, 330, 295 |
| **Dependency & SBOM** | Known CVEs in third-party packages, transitive dependency risks, outdated lockfile entries, across all SCA tool outputs | 1035 |
| **Secrets & Config** | Hardcoded credentials, API keys, private keys, misconfigured cloud storage, exposed debug endpoints, insecure default configurations | 798, 540, 1188 |

---

## Judge

The judge is an independent adversarial reviewer. It re-examines any finding the council would confirm at **high severity or above**, and any finding where the experts disagree.

The judge applies the **"reasonable attacker" test**: given the code in context, would a skilled attacker actually exploit this? If the answer is no - if the finding requires conditions that don't exist in practice - the judge can refute it, reducing false positives on high-severity results.

**When the judge fires:**
- Any finding at `high` severity or above, regardless of expert consensus
- Any finding where experts disagree (contested)

**Consensus shortcut:** If all experts agree AND their average confidence is ≥ 0.75 on a low-severity finding, the judge is skipped to reduce cost. This shortcut does not apply to high+ severity findings - those always go to the judge.

---

## Red team

The red team is a single budgeted LLM call that runs once per iteration over all confirmed findings. It looks for combinations of vulnerabilities that each expert would rate individually lower but together form a critical attack path.

For example: a path traversal (P3 alone) combined with a file read vulnerability and an exposed credential (each P2) might chain into unauthenticated RCE.

When the red team identifies a valid chain:
- It records an `attack_chain` object with goal, steps, likelihood, and the participating finding IDs
- Each participating finding gets `triage.in_chain = true`
- Each chained finding is bumped +1 priority tier (P2 → P1, P3 → P2, etc.)

---

## Deliberation phases

### Phase A - Independent review

All relevant experts review the assigned findings in parallel, with no visibility into each other's reasoning. Each expert produces:
- A verdict: `confirmed`, `disputed`, `refuted`, or `abstain`
- A confidence score (0.0-1.0)
- A rationale explaining the verdict

This parallel-blind approach prevents anchoring, where one expert's early high-confidence verdict dominates the others.

### Phase B - Cross-examination (contested findings only)

If experts disagree on a finding (any mix of confirmed/disputed/refuted), the finding enters Phase B. Experts now see each other's full rationale and can revise their verdict. In agentic mode, experts can also use tool calls to explore the codebase (read files, grep for patterns, trace call paths) before finalizing.

Findings where all experts agree (or abstain) skip Phase B entirely.

---

## Verdict outcomes

| Verdict | Meaning | Appears in output? |
|---------|---------|-------------------|
| `confirmed` | This is a real vulnerability | Yes |
| `refuted` | This candidate is a false positive | No final finding; retained as audit evidence |
| `disputed` | Experts could not agree after all iterations | No final finding; retained as audit evidence |
| `abstain` | Expert has no opinion on this finding | Does not count |
| `parse_error` | LLM response could not be parsed | Treated as abstain |

Only `confirmed` findings appear in the actionable finding list in table, JSON,
and SARIF output. Refuted, disputed, duplicate, and parse-error candidates are
not actionable findings, but their counts and triage evidence remain available
through the scan metadata and full triage sidecar.

---

## Novel discovery

After each iteration's expert review, the system runs a novel-discovery pass. The codebase is analyzed for likely-vulnerable regions using sink pattern scoring (patterns associated with dangerous operations - SQL queries, shell commands, file operations, deserialization calls, etc.). Experts are then given ±15-line windows around high-scoring regions and asked whether there are vulnerabilities the deterministic tools missed.

Novel findings proposed by experts enter the review pipeline in the next iteration and are subject to the same confirmation process.

---

## Convergence

The loop stops when any of these conditions is true:

- No unresolved work remains (no raw or disputed findings awaiting review)
- `max_iterations` is reached (default: 3)
- The LLM-call budget is exhausted (`scan.max_llm_calls`, default: unlimited)
- New confirmed findings drop below `MIN_NEW_FINDINGS` (default: 2) while disputes are not decreasing

---

## Agentic mode

In agentic mode, experts can make tool calls during Phase B to explore the codebase before finalizing a verdict. Available tools include reading files, grep, call-graph tracing, and finding related definitions.

Agentic mode improves accuracy on complex findings (e.g. tracing data flows across multiple files) at the cost of more LLM calls and longer scan time.

```bash
trident scan . --model glm-5.2:cloud
```

Enable globally:
```bash
trident config set scan.agentic true
```

See [AGENTIC_MODE](AGENTIC_MODE.md) for details.

---

## See also

- [GUARDS](GUARDS.md) - how guards adjust the council's triage ratings
- [ATTACK_CHAINS](ATTACK_CHAINS.md) - red team chain structure and effects
- [AGENTIC_MODE](AGENTIC_MODE.md) - tool-calling experts in depth
- [TRIAGE](TRIAGE.md) - how confirmed findings get priority tiers
