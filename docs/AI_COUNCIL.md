# Council of Experts

The Council reviews normalized scanner and imported-report candidates. It
decides whether the supplied evidence supports retaining a finding. It does
not assign the final P0-P4 priority; confirmed findings go to the separate
triage stage.

The Council uses configured models to assess evidence. Its verdicts and
rationales are not proof of exploitability. Check important decisions against
the source, deployment, and scanner evidence.

## Expert domains

| Expert | Main review area |
| --- | --- |
| Injection | SQL, command, template, LDAP and XPath injection; XSS; traversal; SSRF; deserialization and related input handling. |
| Authentication and access control | Authentication flows, sessions, JWT, OAuth, authorization, IDOR, and privilege boundaries. |
| Cryptography | Weak algorithms, keys, randomness, TLS, and certificate handling. |
| Dependency and SBOM | Direct and transitive package advisories, versions, and component evidence. |
| Secrets and configuration | Exposed credentials, secret handling, insecure configuration, IaC, and permissions. |

These are review scopes, not complete vulnerability taxonomies. Findings can
cross domains and receive multiple expert reviews.

## Deterministic routing

Routing does not call an LLM. It evaluates bounded structured evidence such as
CWE and OWASP classifications, scanner identity, file/path context,
corroborating tools, package metadata, and finding semantics. It also preserves
the original legacy tool, CWE, title, description, and rule matching behavior.

Final eligibility is `legacy_match OR structured_match`. Structured routing
can add relevant reviewers but cannot suppress any expert selected by the
legacy matcher. A finding may go to multiple experts when the evidence spans
domains. The routing decision records expert eligibility, a score, and reasons
for inspection. Coverage preservation is the requirement; no reduction in
expert calls is claimed.

The legacy matcher can retain broad keyword matches even where a phrase is
benign. Review the candidate evidence and the routing reasons rather than
assuming that assignment itself means the expert found a vulnerability.

## Review and adjudication

Relevant experts review candidates independently. When their verdicts conflict,
cross-examination can provide the other rationales and allow reviewers to
revise. The judge reviews selected high-severity findings and disagreements.
The judge evaluates whether the supplied evidence supports the claimed
conditions; report-only evidence cannot prove source reachability.

| Decision | Meaning in the scan |
| --- | --- |
| `confirmed` | Retained for triage and remediation review. |
| `refuted` | Rejected as unsupported; disposition evidence is retained. |
| `disputed` | Reviewers did not agree. Production convergence treats a final unresolved dispute as `unresolved`. |
| `abstain` | Reviewer did not provide a verdict. |
| `parse_error` | Structured response could not be parsed; it is not a confirmation. |

Confirmed findings appear in JSON and SARIF. Refuted, duplicate, suppressed,
false-positive, and unresolved records remain represented in disposition or
audit data as applicable. Unresolved review makes the scan incomplete and
returns exit code 2.

## Red-Team and triage

Red-Team reviews a bounded, deterministically ordered set of confirmed
findings for attack chains. It is a separate role from domain expert routing.
An identical canonical model-visible input can reuse a successful analysis;
changed evidence triggers fresh analysis. If the call budget is exhausted,
current analysis is reported unavailable and prior chains are not retained as
current. See [Attack chains](ATTACK_CHAINS.md).

Triage uses model-assessed factors and deterministic adjustments to assign
priorities. Chain membership can affect priority subject to evidence and
reachability guards. See [Triage](TRIAGE.md).

## See also

- [Scanning](SCANNING.md)
- [Configuration](CONFIGURATION.md)
- [Output formats](OUTPUT_FORMATS.md)
- [Limitations](LIMITATIONS.md)
