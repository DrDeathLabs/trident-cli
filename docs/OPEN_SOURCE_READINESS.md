# Open-source release readiness

This is the release checklist for Trident CLI. It describes what a public
installation and release must provide. It does not mean that a package has
already been published.

## Installation contract

The current public release channel is a GitHub release artifact. Download the
wheel from the release and install it locally:

```bash
python -m venv .venv
python -m pip install path/to/trident-0.1.0-py3-none-any.whl
```

The PyPI name `trident` is already occupied by another project. A future
package-index release would require a separately chosen distribution name and
explicit owner configuration.

For a source checkout, install the package from `backend/`:

```bash
cd backend
python -m pip install -e ".[dev]"
```

Use Python 3.11 or newer. Windows PowerShell, Linux, and WSL are the validated
development paths. Other Unix-like systems may work but are conditional until
their native tool paths and subprocess behavior are tested.

## Native scanner prerequisites

`trident install-tools --verify --warmup` installs and verifies the twelve
scanner executables managed by the CLI. The tools remain separate programs and
retain their own release, license, and network requirements. The tool set
includes Semgrep, Bandit, gosec, Trivy, Grype, gitleaks, pip-audit, npm audit,
OSV-Scanner, TruffleHog, Checkov, and govulncheck.

The bootstrap process may use Python, Go, and native release downloads. Node.js
and npm are prerequisites for npm audit. Go is required for the Go scanners.
Expect network access, writable tool/cache directories, and enough disk space
for scanner binaries, databases, and extracted workspaces.

## Model feeds

Ordinary scans use the local model state and do not implicitly rebuild the
statistical model. Refreshing feeds is optional and network-dependent:

```bash
trident model status
trident model refresh
trident model build
trident model info
```

Feed contents, upstream availability, and database size can change. A release
should record the feed status used for validation rather than embedding a
claim that a particular database snapshot is permanent.

## Release gates

From `backend/`, release validation includes:

```bash
python -m pytest -q
python -m ruff check trident tests
python -m build
python -m twine check dist\*
```

A clean-environment smoke check must install the wheel and verify:

```bash
trident --help
trident install-tools --check
trident scan --help
trident config --help
trident model --help
```

The version in package metadata, `trident.__version__`, and the release tag
must agree. No release process should publish credentials, private scan data,
generated reports, or unreviewed model artifacts.

## Security and licensing

Only scan code you own or are authorized to assess. The configured LLM backend
may receive code context; its privacy and retention terms are outside Trident's
control. Local databases, extracted workspaces, caches, and reports are not
encrypted by the CLI.

Trident is source-available under the [Business Source License 1.1](../LICENSE),
not an OSI open source license. Its Additional Use Grant permits the internal,
organizational, educational, research, nonprofit, government, public-sector,
community, evaluation, development, testing, and personal uses listed in the
license. Restricted hosted, resale, commercial product, and paid third-party
service uses require separate commercial permission. Each specific version
changes to the MIT License four years after its first public distribution.

Scanner executables are external processes with their own licenses. Review
[THIRD-PARTY-NOTICES.md](../THIRD-PARTY-NOTICES.md) and the exact versions
shipped or downloaded for a release.

## Publication boundary

The release workflow builds and verifies artifacts on version tags. Publication
to a package index requires repository-owner configuration of trusted
publishing and package-index permissions; this repository does not invent or
store those credentials. No package-index URL or repository clone URL is
required to use the source checkout.
