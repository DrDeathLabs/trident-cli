# Installation

Install Trident in a virtual environment when possible. The package and its
scanner tools are separate pieces, so package installation alone does not
install every scanner binary.

## Prerequisites

- Python 3.11 or later
- pip
- Internet access when installing the package or downloading scanner tools
- An LLM backend: Ollama locally, or an OpenAI/Anthropic account

## Install the CLI

### From a GitHub release artifact

~~~bash
python -m pip install path/to/trident-0.1.0-py3-none-any.whl
~~~

Download the wheel from the GitHub release, then install that local file.
The first public release is distributed through GitHub artifacts. The PyPI
name `trident` is already used by another project, so `pip install trident`
is not a supported installation command for this release.

### From this repository checkout

The package lives in backend/:

~~~bash
cd backend
python -m pip install .
~~~

For development, use an editable install with the dev dependencies:

~~~bash
cd backend
python -m pip install -e ".[dev]"
~~~

Verify the installation:

~~~bash
trident --version
trident --help
~~~

A virtual environment is recommended:

~~~bash
python -m venv .venv

# macOS/Linux:
source .venv/bin/activate

# Windows PowerShell:
.\.venv\Scripts\Activate.ps1

python -m pip install .
~~~

## Install scanner tools

Install the external scanner tools managed by Trident:

~~~bash
trident install-tools
~~~

The command installs or locates the configured tools:

- Binary releases: osv-scanner, TruffleHog, Gitleaks, Grype, and Trivy
- Python tools: Semgrep, Bandit, Checkov, and pip-audit
- Go tools: gosec and govulncheck, using an existing Go installation or a
  user-data bootstrap runtime
- npm-audit: used when Node.js and npm are already installed; Node.js is not
  installed by Trident

Check tool status without changing anything:

~~~bash
trident install-tools --check
~~~

Verify all twelve tools:

~~~bash
trident install-tools --verify
~~~

Pre-download vulnerability databases and warm caches:

~~~bash
trident install-tools --warmup
~~~

The recommended first-time command combines verification and cache warmup:

~~~bash
trident install-tools --verify --warmup
~~~

The installer scripts in scripts/ create a virtual environment, install the
CLI from backend/, and invoke these scanner-tool commands. They do not build
or copy any other application.

Tools are stored in the platform-appropriate user data directory:

| Platform | Default tools directory |
|----------|-------------------------|
| Windows | %LOCALAPPDATA%/Trident/Trident/bin |
| macOS | ~/Library/Application Support/Trident/bin |
| Linux | ~/.local/share/Trident/bin |

## Configure an LLM

Ollama is the default backend:

~~~bash
trident config set llm.backend ollama
trident config set llm.base_url http://localhost:11434
trident config set llm.expert_model gemma4:31b-cloud
~~~

See [LLM_BACKENDS](LLM_BACKENDS.md) for cloud backend setup and data-handling
considerations.

## Optional corpus model

The corpus guard can be built from vulnerability feeds:

~~~bash
trident model refresh
~~~
This is optional; scans work without it, with the corpus guard inactive.

## Platform notes

The CLI stores its SQLite database, downloaded tools, calibration data, and
temporary workspaces under user data directories. Windows PowerShell, Linux,
and WSL are validated release paths. Other platforms are conditional until
their native tool downloads and subprocess behavior are tested. No fixed
temporary directory is required for CLI scan workspaces.

The optional corpus data location is controlled by
CALIBRATION_DATA_DIR; set it to a writable path when the platform does not
provide the default location:

~~~powershell
$env:CALIBRATION_DATA_DIR = "$env:LOCALAPPDATA\Trident\calibration"
trident model refresh
~~~
