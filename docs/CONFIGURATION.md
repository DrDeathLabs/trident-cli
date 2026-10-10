# Configuration

Trident reads per-scan CLI options, environment variables, its TOML file, and
built-in defaults. When the same setting is supplied more than once, the order
is:

```text
CLI option > environment variable > persisted config > built-in default
```

For example, `--backend`, `--model`, and `--openai-base-url` override the
corresponding environment or config values for one scan. Environment values
override TOML. A setting omitted from all sources uses its default.

## Config file and secrets

Find the active file with:

```text
trident config path
```

Typical locations are `%LOCALAPPDATA%\Trident\Trident\config.toml` on Windows,
`~/Library/Application Support/Trident/config.toml` on macOS, and
`~/.config/Trident/config.toml` on Linux. `trident config path` is authoritative
for the current platform and any path override.

Use `trident config set` rather than editing TOML by hand. For a secret key,
omit the value so Trident prompts without echoing it:

```text
trident config set llm.openai_api_key
```

For noninteractive use, send a secret over standard input from an approved
secret store. Do not put the secret after the config key on the command line:

```bash
secret-command | trident config set llm.openai_api_key --stdin
```

On Windows PowerShell, use the secret manager's secure output pipeline or the
interactive prompt. Do not paste a credential into a command that will be
saved in shell history.

The config directory and file are restricted to the current account using
platform permissions, and updates use atomic writes. Windows ACLs allow the
current user, SYSTEM, and local Administrators. These measures control local
access; they do not encrypt TOML. Trident refuses config paths that contain a
symbolic link or Windows reparse point in any directory component, including
an ancestor junction. Prefer environment or secret-manager injection where
suitable. `config get`, `config show`, and `config list` mask secret values or
show only their descriptions.

## Config commands

| Command | Behavior |
| --- | --- |
| `trident config list` | List known keys, defaults, and descriptions. |
| `trident config get KEY` | Show one effective value and its source; secrets are masked. |
| `trident config show` | Show effective configuration and sources with secrets masked. |
| `trident config set KEY [VALUE]` | Persist a setting. Secret values require the hidden prompt or `--stdin`. |
| `trident config reset [KEY]` | Restore one setting or all settings to defaults. |
| `trident config path` | Print the active config path. |
| `trident config edit` | Open the config file in the configured editor. |

Examples:

```text
trident config set llm.backend openai
trident config set llm.openai_base_url https://llm-gateway.example.com/v1
trident config set llm.expert_model security-expert
trident config get llm.openai_base_url
trident config reset llm.openai_api_key
```

The gateway hostname is reserved for documentation. Replace it with your
provider's endpoint. For complete endpoint setup, see
[Connecting Trident to a Custom LLM Endpoint or Proxy](CONNECTING_LLM_ENDPOINTS.md).

## LLM configuration

| Key | Default | Environment | Notes |
| --- | --- | --- | --- |
| `llm.backend` | `ollama` | `TRIDENT_LLM_BACKEND`, `LLM_BACKEND` | `ollama`, `openai`, or `anthropic`. |
| `llm.base_url` | `http://127.0.0.1:11434` | `TRIDENT_OLLAMA_HOST`, `OLLAMA_HOST` | Native Ollama API endpoint. |
| `llm.ollama_mode` | `local_gateway` | `TRIDENT_OLLAMA_MODE` | `local_gateway` or `direct_cloud`. |
| `llm.ollama_cloud_host` | `https://ollama.com` | `TRIDENT_OLLAMA_CLOUD_HOST` | Ollama direct-cloud host. |
| `llm.openai_base_url` | `https://api.openai.com/v1` | `OPENAI_BASE_URL`, `TRIDENT_OPENAI_BASE_URL` | OpenAI-compatible API base URL. HTTP and HTTPS are accepted. |
| `llm.openai_api_key` | Empty | `OPENAI_API_KEY`, `TRIDENT_OPENAI_API_KEY` | Optional bearer key; secret output is masked. |
| `llm.anthropic_api_key` | Empty | `ANTHROPIC_API_KEY` | Anthropic secret key. |
| `llm.expert_model` | `nemotron-3-super:cloud` | `TRIDENT_OLLAMA_MODEL`, `EXPERT_MODEL` | Default expert alias. |
| `llm.judge_model` | Empty | `TRIDENT_JUDGE_MODEL`, `JUDGE_MODEL` | Empty uses the expert model. |
| `llm.redteam_model` | Empty | `TRIDENT_REDTEAM_MODEL`, `REDTEAM_MODEL` | Empty uses the expert model. |
| `llm.secondary_model` | `qwen3.5:cloud` | `TRIDENT_OLLAMA_SECONDARY_MODEL` | Secondary model setting. |

The OpenAI-compatible provider uses `/models`, `/chat/completions`, and
`/embeddings` under its base URL. A trailing slash is optional and model aliases
are sent unchanged. A compatible service may not implement every route or
response option. HTTP is unencrypted; use HTTPS for production and sensitive
workloads. See the custom endpoint guide for certificate, proxy, and network
details.

## Scan and report settings

| Key | Default | Environment | Notes |
| --- | --- | --- | --- |
| `scan.max_iterations` | `3` | `MAX_ITERATIONS` | Maximum Council iterations. |
| `scan.max_llm_calls` | `0` | `MAX_LLM_CALLS` | Per-scan LLM call cap; zero means unlimited. |
| `scan.severity_gate` | `high` | `TRIDENT_SEVERITY_GATE` | Prioritized findings at this gate cause exit 1. |
| `scan.agentic` | `false` | `AGENTIC` | Enable optional bounded expert exploration. |
| `output.format` | `table` | None | `table`, `json`, or `sarif`. |
| `output.quiet` | `false` | None | Suppress progress output. |

Other operational variables include `LLM_TIMEOUT`, `LLM_MAX_RETRIES`,
`LLM_CONCURRENCY`, `TRIDENT_LLM_RESPONSE_TIMEOUT`,
`TRIDENT_LLM_REQUEST_DEADLINE`, `TRIAGE_MODEL`, `EMBEDDING_MODEL`,
`TRIDENT_SQLITE_PATH`, `TRIDENT_WORKSPACES`, and `TRIDENT_TOOLS_DIR`. Run
`trident config list` for the installed schema and use `trident scan --help`
for per-scan options.

## Verify the selected values

```text
trident config get llm.backend
trident config get llm.openai_base_url
trident config get llm.openai_api_key
```

The command shows the source of each effective setting. The API key remains
masked. For per-scan overrides, inspect the command and the endpoint's request
log; Trident does not print credentials in diagnostic output.

## See also

- [LLM backends](LLM_BACKENDS.md)
- [Custom endpoint guide](CONNECTING_LLM_ENDPOINTS.md)
- [Scanning](SCANNING.md)
- [Privacy](PRIVACY.md)
