# Scanner integrations

Trident can run twelve scanner integrations during source analysis. Each tool
has its own supported languages, inputs, rules, databases, and network behavior.
Install the tools you need and check their status before scanning. A missing or
inapplicable scanner cannot contribute findings.

## Integrations

| Area | Tool | Typical evidence |
| --- | --- | --- |
| Source analysis | Semgrep | Rule-based source findings and code locations. |
| Source analysis | Bandit | Python-specific security findings. |
| Source analysis | gosec | Go source security findings. |
| Infrastructure | Checkov | IaC and configuration policy findings. |
| Dependencies | Grype | Known vulnerabilities in detected packages and images/manifests supported by the tool. |
| Dependencies | OSV-Scanner | Advisory matches for supported package ecosystems. |
| Dependencies | Trivy | Dependency, secret, and IaC results according to enabled scanners and inputs. |
| Dependencies | pip-audit | Python package advisories. |
| Dependencies | npm-audit | npm dependency advisories. Requires Node.js and npm. |
| Dependencies | govulncheck | Go module vulnerability findings. Requires Go or the managed runtime. |
| Secrets | Gitleaks | Pattern-based secret detections. |
| Secrets | TruffleHog | Secret discovery using the tool's enabled detectors and verification modes. |

The table describes tool categories, not a promise that each target is
covered. Check a tool's own documentation for formats, databases, matching
behavior, and privacy or network settings.

## Check or install tools

```text
trident install-tools --check
trident install-tools --verify
trident install-tools --verify --warmup
```

`--check` reports availability. `--verify` executes installed tools and
reports their versions. The combined `--verify --warmup` path installs managed
tools, verifies them, and warms supported databases and caches. Database
updates require network access. Trident manages supported tools in its user
data directory; Python tools are installed into the active Python environment.

Node.js is not installed by Trident. Go-based tools use an installed Go runtime
or a managed bootstrap. Installation and scanner support can differ by
platform. Inspect the command output rather than assuming every integration is
available.

## Scan a target

```bash
trident scan ./source
```

Trident runs applicable available adapters and correlates their records before
review. Use an existing report instead of running scanner subprocesses with
`--input-file`; see [Scanning](SCANNING.md) and [JSON ingestion](JSON_INGESTION.md).

## Network and data handling

Some tools download releases, rules, or vulnerability databases. Some query
advisory services. Review each tool's configuration and network requirements
for your environment. Scanner output can include paths, package names, and
code-related evidence; local records and reports should be treated as sensitive.
See [Privacy](PRIVACY.md).
