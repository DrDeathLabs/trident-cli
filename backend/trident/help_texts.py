"""Deep-dive help topics for trident help."""

from __future__ import annotations

HELP_TOPICS: dict[str, str] = {
    "setup": """
[bold cyan]Trident CLI setup[/bold cyan]

1. Install the v0.3.4 wheel: [green]python -m pip install path/to/trident-0.3.4-py3-none-any.whl[/green]
2. Install tools: [green]trident install-tools --verify[/green]
3. Ollama is the default backend. The default expert model is
   [green]nemotron-3-super:cloud[/green], an Ollama Cloud-tagged model reached
   through the configured Ollama gateway. Configure it explicitly if needed:
   [green]trident config set llm.backend ollama[/green]
   [green]trident config set llm.expert_model nemotron-3-super:cloud[/green]
4. OpenAI-compatible gateways and Anthropic remain optional alternative backends.
5. Scan a local path: [green]trident scan .[/green]

The optional corpus model is built with [green]trident model refresh[/green].
Exit codes are 0 for complete scans below the gate, 1 for prioritized findings
at the gate, and 2 for scan failures or untriaged/unresolved review.
""",
    "backends": """
[bold cyan]LLM backends[/bold cyan]

Ollama is the default backend:
  [green]trident config set llm.backend ollama[/green]
  [green]trident config set llm.base_url http://localhost:11434[/green]
  [green]trident config set llm.expert_model nemotron-3-super:cloud[/green]

The default model is Ollama Cloud-tagged. The Ollama gateway URL describes the
transport endpoint; it does not imply that this model runs on the local host.

OpenAI-compatible gateway:
  [green]trident config set llm.backend openai[/green]
  [green]trident config set llm.openai_base_url http://127.0.0.1:8000/v1[/green]
  [green]trident config set llm.expert_model security-expert[/green]
  Set [green]OPENAI_API_KEY[/green] in the environment for bearer authentication.
The gateway implements /v1/models, /v1/chat/completions, and /v1/embeddings.
OPENAI_BASE_URL defaults to https://api.openai.com/v1. A trailing slash is
optional, and configured model aliases are passed unchanged. CLI flags take
precedence over environment variables, config file values, and defaults.

Anthropic:
  [green]trident config set llm.backend anthropic[/green]
  [green]trident config set llm.anthropic_api_key[/green]
  Enter the key at the hidden prompt, or set ANTHROPIC_API_KEY in the environment.

Cloud backends receive the code context required for review. Choose one that
matches the sensitivity of the target.
""",
    "ci": """
[bold cyan]CI integration[/bold cyan]

Exit codes:
  0 = complete and below gate, 1 = prioritized finding at/above gate,
  2 = scan failure or incomplete review (untriaged/unresolved)

Install the package and scanner tools, then write machine-readable output:
  [green]python -m pip install path/to/trident-0.3.4-py3-none-any.whl
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
Important keys include llm.backend, llm.base_url, llm.openai_base_url,
llm.expert_model, llm.judge_model, llm.redteam_model,
scan.max_iterations, scan.severity_gate, output.format, and model.data_dir.
""",
    "output": """
[bold cyan]Output formats[/bold cyan]

[bold]table[/bold] — terminal summary, selected by default.
[bold]json[/bold] — retained findings, review evidence, triage metadata, and attack chains.
[bold]sarif[/bold] — SARIF 2.1.0 for code-scanning integrations.

The default table prints numerical P0-P4 counts, including zero-count tiers,
their prioritized total, and separate untriaged and unresolved counts. The
summary and JSON findings use the same finalized report population. Full
per-finding evidence, explanations, and remediation remain in JSON and SARIF.

Triage runs automatically after review. A confirmed finding is retained for
remediation work, not automatically proof of exploitability. Save the complete worked queue
as a sidecar in the selected format:
  [green]trident scan . --format json --output-file results.json \
    --triage-output-file triage.json[/green]
The sidecar groups findings by P0-P4 and includes playbooks, SLAs, factors,
rationale, attack-chain context, evidence basis, review provenance, original
imported records, dispositions, and analyst overrides.

Examples:
  [green]trident scan . --format json --output-file findings.json --quiet[/green]
  [green]trident scan . --format sarif --output-file results.sarif --quiet[/green]

Use quiet mode when stdout or an output stream must contain only the selected
machine-readable format.

Import standardized or heterogeneous JSON without running scanners:
  [green]trident inspect report.json --format json
  trident scan --input-file report.json --format json[/green]
Use [green]--mapping FILE[/green] for an explicit trident-json-mapping-v1
mapping and [green]--no-schema-ai[/green] to keep schema inference deterministic.
""",
"guards": """
[bold cyan]Triage adjustment mechanisms[/bold cyan]

Class guard applies deterministic caps to finding classes that language models
systematically over-rate. Corpus guard calibrates severity against vulnerability
data after model refresh. Reachability guard uses static call-graph analysis
and fails open when it cannot determine a path.

Disable these adjustments only for debugging:
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
  [green]guards[/green]     triage adjustment mechanisms
  [green]experts[/green]    council roles
  [green]tools[/green]      scanner adapters

Exit codes: 0 complete and below gate, 1 prioritized findings at the gate, 2 scan failure
or incomplete review (untriaged/unresolved).
"""
