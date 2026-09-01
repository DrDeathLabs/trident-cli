# Limitations

Read this before relying on Trident for a security decision. Trident is useful
for finding and working security issues, but it cannot establish that software
is secure on its own.

## Coverage

Coverage depends on the scanners that are installed and the manifests present
in the target workspace.

| Language | Typical coverage |
|----------|------------------|
| Python | Semgrep, Bandit, pip-audit, general SCA, secrets |
| JavaScript/TypeScript | Semgrep, npm-audit when npm is available, general SCA, secrets |
| Go | Semgrep, gosec, govulncheck, general SCA, secrets |
| Java, Ruby, PHP, Rust, C/C++ | Primarily Semgrep, SCA where manifests are supported, secrets |

IaC coverage includes Terraform, CloudFormation, and Kubernetes YAML through
Checkov and related scanners. Complex templates and unsupported ecosystems
have limited coverage.

The npm-audit adapter needs Node.js/npm already installed. Trident does not
install Node.js. Go tools need Go or the managed bootstrap runtime.

## LLM limitations

LLMs can invent vulnerabilities, miss vulnerabilities, or provide plausible
but incorrect rationales. The council and triage adjustments reduce noise and
make decisions more inspectable, but do not provide correctness guarantees.
Review P0 and P1 findings manually.

## Calibration limitations

The corpus-profile adjustment only operates for CWEs with enough historical
data. New, uncommon, vendor-specific, and application-logic weaknesses may be
uncalibrated. Class correction is rule-based and intentionally narrow; a
misclassified boundary case could still be adjusted incorrectly.

## Reachability limitations

The reachability guard uses static analysis and can miss dynamic dispatch,
reflection, dynamic imports, unsupported frameworks, and cross-process calls.
When it cannot determine a path, it reports unknown and fails open.

## Local operation

The CLI is designed for one local operator and has no multi-user access-control
layer. SQLite and model files are not encrypted. Protect the user-data
directory and any configured API credentials.

The same SQLite database file should not be used by concurrent scans. Run
separate invocations sequentially or use separate database paths.

## Scope

Trident analyzes source and configuration files. It does not:

- Probe running services or exploit vulnerabilities
- Analyze memory, process state, or runtime-only behavior
- Replace a manual review or a threat model
- Produce compliance certification without additional work
- Treat compiled or packaged artifacts as source unless a scanner explicitly
  supports that input

Only scan code you own or are authorized to analyze.
