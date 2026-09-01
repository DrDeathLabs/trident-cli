# Security Tools

Trident runs twelve open-source scanners in the first stage of a scan. Their
results form the recall floor. Everything the AI council reviews starts here.

> ⚠️ **Authorized use only.** Only scan code you own or have explicit permission to analyze.

---

## Why 12 tools

No single scanner finds everything. Each tool specializes:

- SAST tools find code-level vulnerabilities but miss dependency CVEs
- SCA tools find known CVEs but don't analyze code logic
- Secrets tools find credentials but ignore code quality issues

Running all 12 in parallel maximizes coverage. Trident's correlation layer then deduplicates overlapping findings from different tools before the council reviews them.

---

## SAST - Static Analysis

### Semgrep

Multi-language static analysis using the security-audit, OWASP Top Ten, and secrets rule sets. Covers Python, JavaScript/TypeScript, Go, Java, Ruby, PHP, C/C++, and more.

Finds: SQL injection, XSS, command injection, insecure deserialization, path traversal, hardcoded credentials, SSRF, open redirects, and hundreds of language-specific patterns.

### Bandit

Python-specific static analysis. Focused and low false-positive rate for pure Python codebases.

Finds: SQL injection, command injection, hardcoded passwords, use of insecure functions (`pickle`, `eval`, `exec`), weak cryptography (MD5, SHA1), and subprocess misuse.

### Gosec

Go-specific static analysis.

Finds: SQL injection, path traversal, weak RNG, hardcoded credentials, unsafe use of `exec`, TLS configuration issues, and Go-specific patterns like integer overflow and unhandled errors.

### Checkov

Infrastructure-as-code and configuration scanning.

Finds: Kubernetes misconfigurations, insecure build-manifest settings,
Terraform and CloudFormation policy violations, missing encryption, overly
permissive IAM policies, and exposed secrets in IaC files.

---

## SCA - Software Composition Analysis

### Grype

Multi-ecosystem SCA against the Anchore vulnerability database (NVD, GitHub Advisories, and more).

Covers dependency manifests for Python, Node.js, Go, Java (Maven), Ruby, and
.NET. Produces CVE IDs, CVSS scores, and fix versions.

### OSV-Scanner

Cross-ecosystem SCA via [osv.dev](https://osv.dev). Covers PyPI, npm, Maven, Go modules, crates.io (Rust), NuGet, RubyGems, Packagist, and more.

Particularly strong on Go and Rust ecosystem coverage that other tools miss.

### Trivy

Dependency vulnerability scanning plus IaC misconfigurations. Uses the
[Trivy Advisory Database](https://github.com/aquasecurity/trivy-db), which
aggregates NVD, Red Hat, Ubuntu, Alpine, and OS-level advisories.

Also detects secrets in code and configuration files.

### pip-audit

Python-specific dependency scanning. Reads `requirements.txt`, `pyproject.toml`, and `Pipfile.lock`. Queries the [Python Advisory Database](https://github.com/pypa/advisory-database) and OSV.

Lower noise than general-purpose SCA tools for pure Python projects.

### npm-audit

Node.js dependency scanning. Reads `package-lock.json` and queries the npm advisory registry.

**Note:** npm-audit requires Node.js to be installed on your system. Trident does not install Node.js. If Node.js is absent, this tool is silently skipped.

### govulncheck

Go module vulnerability scanning with **call-graph reachability**. Queries the [Go vulnerability database](https://vuln.go.dev).

Unlike other SCA tools, govulncheck only reports vulnerabilities in packages whose affected functions are actually called by your code - reducing false positives significantly for Go projects.

---

## Secrets Detection

### Gitleaks

Pattern-based credential scanning across all files and git history.

Finds: API keys (AWS, GCP, Azure, GitHub, Stripe, Twilio, and 100+ others), private keys, tokens, passwords, and generic high-entropy secrets using configurable regex patterns.

### TruffleHog

Active credential verification. Scans files and git history for secrets, then attempts to verify them against provider APIs to confirm whether they are live.

Finds: The same patterns as Gitleaks, but only reports credentials that are confirmed active. This produces fewer but higher-confidence results.

---

## Install types

| Tool | Install method | Managed by |
|------|---------------|-----------|
| osv-scanner | GitHub binary release | Trident (downloads to tools dir) |
| trufflehog | GitHub binary release | Trident |
| gitleaks | GitHub binary release | Trident |
| grype | GitHub binary release | Trident |
| trivy | GitHub binary release | Trident |
| gosec | `go install` | Trident (Go bootstrap if needed) |
| govulncheck | `go install` | Trident (Go bootstrap if needed) |
| semgrep | pip | Trident (into active venv) |
| bandit | pip | Trident (into active venv) |
| checkov | pip | Trident (into active venv) |
| pip-audit | pip | Trident (into active venv) |
| npm-audit | system Node.js | System (Trident uses if available) |

---

## Managing tools

```bash
# Install all tools
trident install-tools

# Check status (managed / pip / system / missing) without installing
trident install-tools --check

# Verify each tool executes and report versions
trident install-tools --verify

# Install a single tool
trident install-tools --tool grype

# Pre-download vulnerability databases and warm up rule caches
trident install-tools --warmup
```

---

## Go bootstrap

If `go` is not on your PATH, `trident install-tools` downloads the appropriate Go release from go.dev and extracts it to:

```
<tools_dir>/go_runtime/go/bin/go.exe   (Windows)
<tools_dir>/go_runtime/go/bin/go       (macOS/Linux)
```

This Go binary is used only for `go install gosec` and `go install govulncheck`. It does not modify your system PATH and does not affect any other Go installation on your machine.

The Go runtime itself is stored in `<tools_dir>/go_runtime/`. Remove the
tools directory through the normal operating-system file tools if a clean
bootstrap is required; `trident model reset` resets calibration data, not
scanner tools.

---

## See also

- [INSTALLATION](INSTALLATION.md) - full installation instructions
- [ARCHITECTURE](ARCHITECTURE.md) - how tool output flows into the scan pipeline
- [LIMITATIONS](LIMITATIONS.md) - language and ecosystem coverage gaps
