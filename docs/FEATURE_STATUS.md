# Capability status

This page states what the current CLI implements and where evidence or limits
are documented. “Supported” means the workflow exists; it does not mean every
language, scanner version, model provider, or target is covered.

| Capability | Current behavior | Main limits |
| --- | --- | --- |
| Source scan | Runs installed and applicable scanner adapters on a local directory, Git source, or ZIP. | Scanner coverage depends on installed tools, platform, detected manifests, language support, and databases. |
| Report import | Normalizes SonarQube, Dependency-Check, SARIF, CycloneDX, and mapped JSON evidence. | Generic JSON needs a mapping or bounded schema inference. Imported report data is not source-grounded unless source context is supplied. |
| Correlation | Groups duplicate and related evidence while retaining provenance. | Similarity and source identifiers can be incomplete or ambiguous. |
| Expert routing | Combines preserved legacy matching with deterministic structured evidence; multiple expert reviews are supported. | Rules cannot represent every vulnerability nuance. There is no accepted call-savings claim. |
| Council and judge | Experts assess evidence; the judge reviews selected high-severity and contested decisions. | Model outputs can be wrong or incomplete. Unresolved outcomes remain visible and fail closed. |
| Red-Team | Analyzes confirmed findings for multi-finding attack chains. Exact duplicate input can reuse successful analysis. | Chains are hypotheses over available evidence, not proof of exploitability. Changed input needs a fresh model call and budget. |
| Triage | Applies recorded evidence and deterministic adjustments to assign P0-P4. | Priority is a work-order aid, not a universal severity or SLA guarantee. |
| Reports | Terminal P0-P4 totals, JSON evidence, SARIF 2.1.0, and a detailed triage sidecar. | JSON and SARIF expose different schemas; JSON retains the fuller Trident record. |
| Model backends | Ollama native API, OpenAI-compatible API, and Anthropic. | API features differ. A gateway may not implement every operation or response option. |
| Custom endpoints | HTTP and HTTPS OpenAI-compatible endpoints, custom base paths, auth keys, and model aliases. | HTTP is unencrypted. Use verified HTTPS for production and sensitive traffic. No external-provider claim follows from localhost tests. |
| Runtime security testing | Not provided. | Trident does not execute applications or perform a penetration test. |
| Compliance certification | Not provided. | A Trident report does not establish compliance. |

## Verified behavior and evidence scope

The repository's automated tests exercise routing, review state, gateway
requests, triage, report generation, and security controls. Release acceptance
records identify whether a result came from unit tests, a local HTTP/HTTPS
gateway, or an installed-wheel command. A localhost gateway test demonstrates
the API contract; it does not validate a commercial or organizational provider.

For scan workflow details, see [Scanning](SCANNING.md), [Validation](VALIDATION.md),
and [Limitations](LIMITATIONS.md).
