# Feature status

This table describes the current standalone CLI capabilities.

## Security tools

| Capability | Status | Notes |
|-----------|--------|-------|
| Semgrep | Supported | Multi-language SAST |
| Bandit | Supported | Python SAST |
| Gosec | Supported | Requires Go or bootstrap |
| Checkov | Supported | IaC and configuration |
| Grype | Supported | SCA |
| OSV-Scanner | Supported | SCA |
| Trivy | Supported | SCA and IaC |
| pip-audit | Supported | Python SCA |
| npm-audit | Supported | Requires system Node.js/npm |
| govulncheck | Supported | Requires Go or bootstrap |
| Gitleaks | Supported | Secrets |
| TruffleHog | Supported | Verified secrets; AGPL-3.0 |

## Analysis

| Capability | Status | Notes |
|-----------|--------|-------|
| Five domain experts | Supported | Injection, auth, crypto, dependency, secrets/config |
| Judge and cross-examination | Supported | Applied according to finding severity and disagreement |
| Novel discovery | Supported | Iterative expert review |
| Agentic exploration | Supported, optional | Off by default to limit token use and scan time. Enable with `scan.agentic` or `AGENTIC=true`. |
| Attack-chain analysis | Supported | Chains confirmed findings |
| Class correction | Supported | Deterministic category-specific factor caps |
| Corpus-profile adjustment | Supported | Requires downloaded CWE profiles from model refresh |
| Reachability adjustment | Supported | Static analysis; caps confirmed unreachable paths and fails open when unknown |

## Output

| Capability | Status | Notes |
|-----------|--------|-------|
| Table | Supported | Human-readable terminal output |
| JSON | Supported | Confirmed findings and triage metadata |
| SARIF 2.1.0 | Supported | Compatible with code-scanning upload actions |
| Output file | Supported | Use --output-file or -f; use --triage-output-file for the detailed worked queue |
| Automatic triage sidecar | Supported | Full JSON, SARIF, or table queue with tier, rationale, and false-positive counts |
| Quiet mode | Supported | Suitable for CI logs |

## External JSON input

| Capability | Status | Notes |
|-----------|--------|-------|
| SonarQube JSON import | Supported | Use `--input-file`; native scanner subprocesses are bypassed |
| OWASP Dependency-Check JSON import | Supported | Requires `reportSchema: 1.1` |
| SARIF 2.1.0 import | Supported | Security results and rule/location provenance are preserved |
| CycloneDX vulnerability JSON import | Supported | Vulnerability-bearing BOMs are imported; inventory-only BOMs are not findings |
| Multiple supported JSON inputs | Supported | Repeat `--input-file` for one import job |
| Heterogeneous vulnerability JSON mapping | Supported with bounds | Deterministic inference, optional validated schema-AI proposals, or explicit `trident-json-mapping-v1`; semantic ambiguity and non-security JSON fail closed |
| Native/external JSON evidence | Supported with bounds | Trivy, Grype, and Semgrep-shaped reports use generic mapping; they are not first-class adapters |

## LLM backends

| Capability | Status | Notes |
|-----------|--------|-------|
| Ollama | Supported | Local default |
| OpenAI | Supported | Requires OPENAI_API_KEY |
| Anthropic | Supported | Requires ANTHROPIC_API_KEY |

## Scan inputs

| Input | Status | Notes |
|-------|--------|-------|
| Local directory or file | Supported | Default input form |
| Git URL | Supported | HTTPS and SSH |
| ZIP archive | Supported | Extracted to a temporary workspace |
| Container image | Unsupported | Provide source or configuration files instead |

## CI integration

| Capability | Status | Notes |
|-----------|--------|-------|
| Exit codes 0, 1, and 2 | Supported | Clean, findings, scan error |
| Severity gate | Supported | --severity-gate and --fail-on |
| SARIF file generation | Supported | Upload with the host CI provider |
