"""Deep-dive help topics for trident help."""

from __future__ import annotations

HELP_TOPICS: dict[str, str] = {
    "setup": """
[bold cyan]Trident CLI setup[/bold cyan]

1. Install the GitHub release wheel: [green]python -m pip install path/to/trident-0.1.0-py3-none-any.whl[/green]
2. Install tools: [green]trident install-tools --verify[/green]
3. Configure Ollama, OpenAI, or Anthropic with the config commands.
4. Scan a local path: [green]trident scan .[/green]

The optional corpus model is built with [green]trident model refresh[/green].
Exit codes are 0 for clean, 1 for findings at the gate, and 2 for scan errors.
""",
    "backends": """
[bold cyan]LLM backends[/bold cyan]

Ollama is the local default:
  [green]trident config set llm.backend ollama[/green]
  [green]trident config set llm.base_url http://localhost:11434[/green]

OpenAI:
  [green]trident config set llm.backend openai[/green]
  [green]trident config set llm.openai_api_key sk-...[/green]

Anthropic:
  [green]trident config set llm.backend anthropic[/green]
  [green]trident config set llm.anthropic_api_key sk-ant-...[/green]

Cloud backends receive the code context required for review. Choose one that
matches the sensitivity of the target.
""",
    "ci": """
[bold cyan]CI integration[/bold cyan]

Exit codes:
  0 = clean, 1 = confirmed findings at or above the gate, 2 = scan error

Install the package and scanner tools, then write machine-readable output:
  [green]python -m pip install path/to/trident-0.1.0-py3-none-any.whl
  trident install-tools
  trident scan . --format sarif --output-file trident.sarif --quiet[/green]

Upload the SARIF file with the CI provider's code-scanning integration. Use
JSON instead for custom processing:
  [green]trident scan . --format json --output-file trident.json --quiet[/green]
""",
    "config": """
[bold cyan]Configuration[/bold cyan]

Show, set, and locate configuration:
  [green]trident config show[/green]
  [green]trident config set llm.backend ollama[/green]
  [green]trident config path[/green]

Resolution order is CLI flag, environment variable, config file, then default.
Important keys include llm.backend, llm.base_url, llm.expert_model,
scan.max_iterations, scan.severity_gate, output.format, and model.data_dir.
""",
    "output": """
[bold cyan]Output formats[/bold cyan]

[bold]table[/bold] — terminal summary, selected by default.
[bold]json[/bold] — confirmed findings, triage metadata, and attack chains.
[bold]sarif[/bold] — SARIF 2.1.0 for code-scanning integrations.

Triage runs automatically after confirmation. Save the complete worked queue
as a sidecar in the selected format:
  [green]trident scan . --format json --output-file results.json \
    --triage-output-file triage.json[/green]
The sidecar groups findings by P0-P4 and includes playbooks, SLAs, factors,
rationale, attack-chain context, and analyst overrides.

Examples:
  [green]trident scan . --format json --output-file findings.json --quiet[/green]
  [green]trident scan . --format sarif --output-file results.sarif --quiet[/green]

Use quiet mode when stdout or an output stream must contain only the selected
machine-readable format.
""",
    "guards": """
[bold cyan]Security guards[/bold cyan]

Class guard applies deterministic caps to finding classes that language models
systematically over-rate. Corpus guard calibrates severity against vulnerability
data after model refresh. Reachability guard uses static call-graph analysis
and fails open when it cannot determine a path.

Disable guards only for debugging:
  [green]trident scan . --no-guards[/green]
""",
    "experts": """
[bold cyan]AI council[/bold cyan]

Domain experts review injection, authentication, cryptography, dependencies, and
secrets/configuration. The judge re-examines important or disputed findings.
The red team identifies multi-finding attack chains. The council can propose
novel findings that deterministic scanners missed.
""",
    "tools": """
[bold cyan]Scanner tools[/bold cyan]

SAST: semgrep, bandit, gosec, checkov
SCA: grype, osv-scanner, trivy, pip-audit, npm-audit, govulncheck
Secrets: gitleaks, trufflehog

Install or inspect them with:
  [green]trident install-tools[/green]
  [green]trident install-tools --check[/green]
  [green]trident install-tools --verify[/green]

npm-audit requires system Node.js/npm. Go tools use system Go or the managed
bootstrap runtime.
""",
}

TOPIC_LIST = list(HELP_TOPICS)


def render_topic(topic: str) -> str:
    """Return the rich markup for a topic, or the topic list."""
    if topic in HELP_TOPICS:
        return HELP_TOPICS[topic]
    return _topic_list()


def _topic_list() -> str:
    return """[bold cyan]Trident help[/bold cyan]

Run [green]trident help <topic>[/green] for details:
  [green]setup[/green]      install and first scan
  [green]backends[/green]   Ollama, OpenAI, and Anthropic
  [green]ci[/green]         exit codes and SARIF
  [green]config[/green]     settings and precedence
  [green]output[/green]     table, JSON, and SARIF
  [green]guards[/green]     calibration guards
  [green]experts[/green]    council roles
  [green]tools[/green]      scanner adapters

Exit codes: 0 clean, 1 findings at the gate, 2 scan error.
"""
