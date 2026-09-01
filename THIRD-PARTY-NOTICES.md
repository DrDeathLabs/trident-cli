# Third-party notices

Trident is licensed under the Business Source License 1.1. See [LICENSE](LICENSE).
The CLI runs the
scanner tools as separate processes. They are not statically linked into
Trident, and each tool keeps its own release and license terms.

| Tool | Role | License |
|------|------|---------|
| Semgrep (OSS) | Multi-language SAST | LGPL-2.1 |
| Bandit | Python SAST | Apache-2.0 |
| gosec | Go SAST | Apache-2.0 |
| Trivy | Dependency and IaC scanning | Apache-2.0 |
| Grype | Dependency CVEs | Apache-2.0 |
| gitleaks | Secrets | MIT |
| pip-audit | Python dependencies | Apache-2.0 |
| npm audit | npm dependencies | npm's distributed license terms |
| OSV-Scanner | Multi-ecosystem SCA | Apache-2.0 |
| TruffleHog | Verified secrets | AGPL-3.0 |
| Checkov | IaC and configuration | Apache-2.0 |
| govulncheck | Go vulnerability database | BSD-3-Clause |

The Python package dependencies are declared in backend/pyproject.toml. Review
each upstream license and the exact installed version when distributing a
release. TruffleHog remains an external process, but its AGPL-3.0 terms still
apply to that tool.
