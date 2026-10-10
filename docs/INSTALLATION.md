# Installation

This guide installs the Trident CLI and its scanner tools on a workstation or
CI runner. Trident requires Python 3.11 or newer. A virtual environment keeps
its Python dependencies separate from system packages.

## Install the CLI

1. Open the [GitHub Releases page](https://github.com/DrDeathLabs/trident-cli/releases).
2. Download the wheel asset for your chosen release and save it in a working
   directory.
3. Create a virtual environment and install the downloaded wheel.

Linux or macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install ./trident-*-py3-none-any.whl
trident --version
trident --help
```

Windows PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install (Get-ChildItem .\trident-*-py3-none-any.whl | Select-Object -First 1 -ExpandProperty FullName)
trident --version
trident --help
```

The wildcard expects one matching wheel in the current directory. If several
are present, name the file you downloaded explicitly. The wheel includes
Trident's Python runtime dependencies. It does not bundle the external scanner
programs.

## Install scanner tools

Run the tool installer from the active virtual environment:

```bash
trident install-tools --verify --warmup
trident install-tools --check
```

The first command installs managed scanner binaries, verifies availability,
and warms supported vulnerability databases. The check command reports what is
available without installing tools.

The adapters cover Semgrep, Bandit, gosec, Checkov, Grype, OSV-Scanner, Trivy,
pip-audit, npm-audit, govulncheck, Gitleaks, and TruffleHog. Some tools need an
additional runtime:

| Tool group | Requirement |
| --- | --- |
| Python scanners | Active Python environment; install optional scanner dependencies or use the managed installer. |
| npm-audit | Node.js and npm installed separately. |
| gosec and govulncheck | Go installed or the managed Go bootstrap runtime. |
| Database-backed scanners | Network access during database download or refresh. |

Tool availability depends on platform and scanner support. Review the output
from `trident install-tools --check`; a scan only runs tools available to the
selected workflow. See [Tools](TOOLS.md) for tool-specific behavior.

## Configure an LLM backend

Trident supports Ollama, OpenAI-compatible APIs, and Anthropic. Choose a
backend that is authorized to process the code and reports you will submit.
Configuration and credentials are covered in [LLM backends](LLM_BACKENDS.md)
and [Privacy](PRIVACY.md).

For a custom OpenAI-compatible endpoint, start with the dedicated
[Connecting Trident to a Custom LLM Endpoint or Proxy](CONNECTING_LLM_ENDPOINTS.md)
guide. It covers local HTTP, intentional private-network HTTP, HTTPS, model
aliases, credentials, corporate certificates, and troubleshooting.

## Install from a source checkout

Developers can install the package from the repository's `backend` directory:

```bash
python -m venv .venv
source .venv/bin/activate  # PowerShell: .\.venv\Scripts\Activate.ps1
python -m pip install -e "backend[dev]"
```

See [Development](DEVELOPMENT.md) for tests and build commands.

## Verify the installation

```bash
trident --version
trident --help
trident config --help
trident scan --help
trident install-tools --check
```

Then configure a provider and run a scan against an authorized, small
repository. A successful command confirms the CLI ran; inspect the report and
provider request logs to confirm that the intended scanners and LLM endpoint
were used.

## See also

- [Quick start](QUICK_START.md)
- [Scanning](SCANNING.md)
- [Custom endpoint guide](CONNECTING_LLM_ENDPOINTS.md)
- [Troubleshooting](TROUBLESHOOTING.md)
