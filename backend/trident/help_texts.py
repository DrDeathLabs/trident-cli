"""Task-oriented detail shown by ``trident help <topic>``."""

from __future__ import annotations

HELP_TOPICS: dict[str, str] = {
    "setup": """
[bold cyan]Install and scan[/bold cyan]

1. Install the wheel in a Python 3.11+ virtual environment.
2. Install or inspect scanners with [green]trident install-tools --verify[/green]
   and [green]trident install-tools --check[/green].
3. Configure Ollama, an OpenAI-compatible API, or Anthropic.
4. Run [green]trident scan PATH[/green] on a target you may assess.
5. Read P0-P4 and review the JSON or SARIF evidence.

Exit codes: 0 = completed below the gate, 1 = a prioritized finding meets the
gate, 2 = scan error or incomplete review (untriaged or unresolved findings).
See the installation and quick-start guides in the project documentation.
""",
    "backends": """
[bold cyan]Model backends[/bold cyan]

Ollama uses its native API and [green]llm.base_url[/green]. OpenAI-compatible
services use [green]llm.openai_base_url[/green] or [green]OPENAI_BASE_URL[/green].
Anthropic uses its Messages API. These endpoints and authentication settings
are separate.

CLI options take precedence over environment variables, persisted config, and
defaults. A configured OpenAI model alias is sent unchanged. HTTP is accepted
when explicitly configured but is not encrypted; HTTPS with verified
certificates is recommended for remote or sensitive scans.

Run [green]trident help gateway[/green] for endpoint setup.
""",
    "gateway": """
[bold cyan]OpenAI-compatible endpoints[/bold cyan]

Configure a gateway:
  [green]trident config set llm.backend openai[/green]
  [green]trident config set llm.openai_base_url https://llm-gateway.example.com/v1[/green]
  [green]trident config set llm.expert_model security-expert[/green]
  [green]trident config set llm.openai_api_key[/green]
  [green]trident scan . --backend openai --model security-expert[/green]

The key prompt is hidden. Leave the key unset for a no-auth endpoint. A
compatible service uses GET /models, POST /chat/completions, and POST
/embeddings; it may not support every Trident operation. The model alias is
sent as configured. HTTP has no transport encryption. Redirects are disabled
and HTTPS certificate verification stays enabled.

See the project documentation's custom endpoint guide for HTTP, TLS
certificates, proxies, and troubleshooting.
""",
    "ci": """
[bold cyan]CI output and exit codes[/bold cyan]

Write machine-readable output without terminal progress:
  [green]trident scan . --format sarif --output-file trident.sarif --quiet[/green]
  [green]trident scan . --format json --output-file trident.json --quiet[/green]

Exit code 0 means review completed below the priority gate. Exit code 1 means
a prioritized confirmed finding meets the gate. Exit code 2 means scan/report
failure or incomplete review because findings remain untriaged or unresolved.
The P0-P4 terminal counts are taken from the same finalized report population
as JSON. SARIF contains finding locations and priority properties.
""",
    "config": """
[bold cyan]Configuration[/bold cyan]

Resolution order: CLI option, environment, config file, built-in default.

  [green]trident config path[/green]
  [green]trident config list[/green]
  [green]trident config get llm.openai_base_url[/green]
  [green]trident config set llm.backend openai[/green]
  [green]trident config set llm.openai_api_key[/green]

The key command prompts without echo. Secret command-line values are rejected;
use the hidden prompt, --stdin, or a protected environment. Secret output is
masked. The TOML file is plaintext protected by local account permissions.
See [Configuration](../docs/CONFIGURATION.md) for setting names and defaults.
""",
    "output": """
[bold cyan]Reports[/bold cyan]

The default table prints P0, P1, P2, P3, P4, Total, Untriaged, and Unresolved.
Every tier appears, including zero. Total is the sum of prioritized confirmed
findings. JSON contains full review and triage evidence; SARIF 2.1.0 is for
code-scanning tools.

  [green]trident scan . --format json --output-file results.json[/green]
  [green]trident scan . --format sarif --output-file results.sarif[/green]
  [green]trident scan . --format json --triage-output-file queue.json[/green]

Use --quiet with stdout output when only JSON or SARIF should be written there.
Confirmed findings without a priority are untriaged. Unresolved review means
the scan is incomplete and returns exit 2. Suppressed and false-positive
dispositions are not counted in the P0-P4 totals.
""",
    "guards": """
[bold cyan]Triage adjustments[/bold cyan]

The triage pass combines model-assessed impact, attack vector, exploitability,
and fix effort with deterministic class, reachability, and optional corpus
adjustments. Review the recorded rationale and evidence for each priority.

Use [green]--no-guards[/green] only to diagnose an adjustment; it skips all
three guard mechanisms and changes the resulting triage behavior.
""",
    "experts": """
[bold cyan]Council review[/bold cyan]

Deterministic routing sends each candidate to experts whose evidence rules
match. Eligibility is the union of legacy matches and structured evidence, so
structured routing cannot remove a legacy reviewer. Multiple experts can
review a finding that crosses domains. The judge examines selected high-impact
or contested decisions. Red-Team analysis checks confirmed findings for
multi-finding attack chains.

Model decisions are evidence for a human reviewer, not proof of exploitability.
""",
    "tools": """
[bold cyan]Scanner tools[/bold cyan]

SAST: Semgrep, Bandit, gosec
IaC: Checkov
Dependencies: Grype, OSV-Scanner, Trivy, pip-audit, npm-audit, govulncheck
Secrets: Gitleaks, TruffleHog

  [green]trident install-tools --check[/green]
  [green]trident install-tools --verify[/green]
  [green]trident install-tools --verify --warmup[/green]

npm-audit requires Node.js/npm. Go-based tools use an installed Go runtime or
the managed bootstrap. Tool availability depends on platform and setup.
""",
}

TOPIC_LIST = list(HELP_TOPICS)


def render_topic(topic: str) -> str:
    """Return a help topic or the index when the topic is unknown."""
    if topic in HELP_TOPICS:
        return HELP_TOPICS[topic]
    return _topic_list()


def _topic_list() -> str:
    return """[bold cyan]Trident help[/bold cyan]

Run [green]trident help <topic>[/green] for details:
  [green]setup[/green]      installation and first scan
  [green]backends[/green]   Ollama, OpenAI-compatible APIs, and Anthropic
  [green]gateway[/green]    custom OpenAI-compatible endpoints and proxies
  [green]ci[/green]         output formats and exit codes
  [green]config[/green]     settings, secrets, and precedence
  [green]output[/green]     terminal, JSON, and SARIF reports
  [green]guards[/green]     triage adjustment mechanisms
  [green]experts[/green]    Council and Red-Team roles
  [green]tools[/green]      scanner integrations

Exit codes: 0 = completed below the gate, 1 = finding at the gate, 2 = scan
error or incomplete review (untriaged or unresolved findings).
"""
