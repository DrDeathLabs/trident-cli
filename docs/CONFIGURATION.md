# Configuration

## Resolution priority

For settings resolved by the CLI configuration manager, when the same setting
appears in more than one place, Trident uses this order:

```
CLI flag  >  Environment variable  >  Config file  >  Built-in default
```

A value set with `--severity-gate critical` on the command line always wins over
a config file setting. Runtime LLM settings follow the same precedence:
`--backend` and `--model` override environment values, which override persisted
configuration, which overrides built-in defaults. `--model` applies to expert,
judge, Red-Team, and triage calls for that scan.

---

## Config file location

```bash
trident config path   # print the config file path
```

| Platform | Default path |
|----------|-------------|
| Windows | `%LOCALAPPDATA%\Trident\Trident\config.toml` |
| macOS | `~/Library/Application Support/Trident/config.toml` |
| Linux | `~/.config/Trident/config.toml` |

The file is TOML format. Use `trident config set` to update settings. Secret
values are entered with a hidden interactive prompt, or can be read from
standard input with `--stdin`; do not put credentials in command-line arguments.
Trident atomically writes this file and restricts the config directory and file
to the current user (POSIX mode 0700/0600; Windows ACL grants the current user,
SYSTEM, and local Administrators). Windows junctions and other reparse-point
redirections are rejected. A failed private write leaves the existing config
file in place. This does not encrypt the secret: it remains plaintext to the
current user and administrator/root processes. Prefer
`OPENAI_API_KEY` or a secret manager when available. The file is plaintext TOML.

---

## Config subcommands

| Command | What it does |
|---------|-------------|
| `trident config set KEY [VALUE]` | Persist a value; secret values use a hidden prompt or `--stdin` |
| `trident config get KEY` | Print the value and source; secrets are masked |
| `trident config show` | Show settings and sources; secrets are masked |
| `trident config list` | List all available keys with descriptions and defaults |
| `trident config reset [KEY]` | Reset one key (or all keys) to built-in defaults |
| `trident config path` | Print the config file path |
| `trident config edit` | Open the config file in `$EDITOR` |

### Examples

```bash
trident config set llm.backend anthropic
trident config set scan.severity_gate critical
trident config set scan.max_iterations 5
trident config get llm.expert_model
trident config reset scan.severity_gate
trident config show
```

Supply an API key without exposing it in shell history or process arguments:

```bash
trident config set llm.openai_api_key
```

Trident prompts twice with input hidden. For automation, provide the value over
standard input from a protected secret source:

```bash
printf '%s\n' "$OPENAI_API_KEY" | trident config set llm.openai_api_key --stdin
```

`config get` and `config show` display only `********` for configured secrets.
Passing a secret as the positional `VALUE` is rejected.

---

## All configuration keys

### LLM settings

The schema records these values for inspection and configuration management.
Runtime reads the persisted values and environment variables directly; per-scan
`--backend` and `--model` options take precedence.

| Key | Default | Env var | Description |
|-----|---------|---------|-------------|
| `llm.backend` | `ollama` | `TRIDENT_LLM_BACKEND` (`LLM_BACKEND` alias) | LLM provider: `ollama`, `openai` (OpenAI-compatible), or `anthropic` |
| `llm.base_url` | `http://127.0.0.1:11434` | `TRIDENT_OLLAMA_HOST` (also `OLLAMA_HOST` in the runtime) | Ollama local gateway base URL |
| `llm.ollama_mode` | `local_gateway` | `TRIDENT_OLLAMA_MODE` | `local_gateway` or `direct_cloud` |
| `llm.ollama_cloud_host` | `https://ollama.com` | `TRIDENT_OLLAMA_CLOUD_HOST` | Direct Ollama Cloud API URL |
| `llm.openai_base_url` | `https://api.openai.com/v1` | `OPENAI_BASE_URL` (`TRIDENT_OPENAI_BASE_URL` alias) | OpenAI-compatible API base URL, including `/v1`; trailing slash is optional. Remote endpoints must use HTTPS; HTTP is allowed for loopback testing only |
| `llm.openai_api_key` | _(empty)_ | `OPENAI_API_KEY` | OpenAI-compatible bearer key. Treated as a secret; not printed in `config show` |
| `llm.anthropic_api_key` | _(empty)_ | `ANTHROPIC_API_KEY` | Anthropic API key. Treated as a secret; not printed in `config show` |
| `llm.expert_model` | `nemotron-3-super:cloud` | `TRIDENT_OLLAMA_MODEL` (`EXPERT_MODEL` alias) | Model name for expert reviewers; OpenAI-compatible aliases are passed unchanged |
| `llm.judge_model` | _(empty)_ | `TRIDENT_JUDGE_MODEL` (`JUDGE_MODEL` alias) | Per-role override for the judge. Blank means use `expert_model` |
| `llm.redteam_model` | _(empty)_ | `TRIDENT_REDTEAM_MODEL` (`REDTEAM_MODEL` alias) | Per-role override for Red-Team. Blank means use `expert_model` |
| `llm.secondary_model` | `qwen3.5:cloud` | `TRIDENT_OLLAMA_SECONDARY_MODEL` | Secondary comparison model |
| `llm.max_repair_retries` | `2` | `TRIDENT_LLM_MAX_REPAIR_RETRIES` | Bounded application-level JSON repair attempts |

### Scan settings

| Key | Default | Env var | Description |
|-----|---------|---------|-------------|
| `scan.max_iterations` | `3` | `MAX_ITERATIONS` | Maximum number of council debate iterations |
| `scan.max_llm_calls` | `0` | `MAX_LLM_CALLS` | Budget cap on total LLM calls per scan. `0` = unlimited |
| `scan.agentic` | `false` | `AGENTIC` | Enable agentic mode globally. Experts use tool calls to explore the codebase before deciding |
| `scan.severity_gate` | `high` | `TRIDENT_SEVERITY_GATE` | CI exit-1 threshold. Valid values: `critical`, `high`, `medium`, `low` |

### Output settings

| Key | Default | Env var | Description |
|-----|---------|---------|-------------|
| `output.format` | `table` | - | Default output format. Valid values: `table`, `json`, `sarif` |
| `output.quiet` | `false` | - | Suppress progress output (same as `--quiet` on the command line) |

### Model settings

| Key | Default | Env var | Description |
|-----|---------|---------|-------------|
| `model.data_dir` | _(platform default)_ | `CALIBRATION_DATA_DIR` | Directory for corpus guard data. Blank = platform user data dir |

---

## Advanced environment variables

These variables are not in the config file but can be set as environment variables for advanced tuning.

| Variable | Default | Description |
|----------|---------|-------------|
| `TRIDENT_REDTEAM_MODEL` (`REDTEAM_MODEL`) | _(same as EXPERT_MODEL)_ | Per-role model override for Red-Team |
| `TRIAGE_MODEL` | _(same as EXPERT_MODEL)_ | Model used for the triage pass |
| `EMBEDDING_MODEL` | `qwen3-embedding:0.6b` | Embedding model for semantic deduplication and eval matching |
| `LLM_TIMEOUT` | `300` | Seconds before an LLM call times out |
| `LLM_MAX_RETRIES` | `3` | Number of retry attempts on LLM failure |
| `LLM_CONCURRENCY` | `4` | Maximum parallel LLM calls during the scan |
| `TRIDENT_LLM_THINK` | `auto` | Ollama thinking mode; `false` disables thinking |
| `TRIDENT_LLM_RESPONSE_TIMEOUT` | value of `LLM_TIMEOUT` | Per-response timeout in seconds |
| `TRIDENT_LLM_REQUEST_DEADLINE` | `LLM_TIMEOUT + 30` | Overall request deadline in seconds |
| `JUDGE_SEVERITY_FLOOR` | `high` | Always send findings at this severity or above to the judge |
| `MIN_NEW_FINDINGS` | `2` | Convergence threshold: stop iterating if fewer than this many new confirmed findings |
| `AGENT_MAX_STEPS` | `6` | Maximum tool-call steps per expert in agentic mode |
| `TRIDENT_SQLITE_PATH` | _(platform default)_ | Custom SQLite database path |
| `TRIDENT_LLM_LEDGER_PATH` | `<sqlite path>.llm-ledger.sqlite` for SQLite | Custom durable LLM request ledger path. SQLite uses an isolated sidecar by default to avoid scan/Council write contention |
| `TRIDENT_WORKSPACES` | _(platform default)_ | Directory where scan workspace files are stored |
| `TRIDENT_TOOLS_DIR` | _(platform default)_ | Directory for managed scanner binaries |
| `WORKSPACE_RETENTION_DAYS` | `14` | Days before workspace files are cleaned up |

---

## Full config reference

```bash
trident help config
```

---

## See also

- [LLM_BACKENDS](LLM_BACKENDS.md) - configuring Ollama, OpenAI, and Anthropic
- [SCANNING](SCANNING.md) - per-scan overrides with CLI flags
- [CI_CD](CI_CD.md) - environment variable patterns for CI
