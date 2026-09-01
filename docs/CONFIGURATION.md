# Configuration

## Resolution priority

When the same setting appears in more than one place, Trident uses this order:

```
CLI flag  >  Environment variable  >  Config file  >  Built-in default
```

A value set with `--severity-gate critical` on the command line always wins over a config file setting.

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

The file is TOML format. Edit it directly or use `trident config set`.

---

## Config subcommands

| Command | What it does |
|---------|-------------|
| `trident config set KEY VALUE` | Persist a value to the config file |
| `trident config get KEY` | Print the current value and its source |
| `trident config show` | Show all settings with their values and sources |
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

---

## All configuration keys

### LLM settings

| Key | Default | Env var | Description |
|-----|---------|---------|-------------|
| `llm.backend` | `ollama` | `LLM_BACKEND` | LLM provider. Valid values: `ollama`, `openai`, `anthropic` |
| `llm.base_url` | `http://localhost:11434` | `OLLAMA_HOST` | Ollama server base URL |
| `llm.openai_api_key` | _(empty)_ | `OPENAI_API_KEY` | OpenAI API key. Treated as a secret; not printed in `config show` |
| `llm.anthropic_api_key` | _(empty)_ | `ANTHROPIC_API_KEY` | Anthropic API key. Treated as a secret; not printed in `config show` |
| `llm.expert_model` | _(backend default)_ | `EXPERT_MODEL` | Model name for all council roles. Blank means use the backend's default model |
| `llm.judge_model` | _(empty)_ | `JUDGE_MODEL` | Per-role override for the judge. Blank means use `expert_model` |

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
| `REDTEAM_MODEL` | _(same as EXPERT_MODEL)_ | Per-role model override for the red team expert |
| `TRIAGE_MODEL` | _(same as EXPERT_MODEL)_ | Model used for the triage pass |
| `EMBEDDING_MODEL` | `qwen3-embedding:0.6b` | Embedding model for semantic deduplication and eval matching |
| `LLM_TIMEOUT` | `300` | Seconds before an LLM call times out |
| `LLM_MAX_RETRIES` | `3` | Number of retry attempts on LLM failure |
| `LLM_CONCURRENCY` | `4` | Maximum parallel LLM calls during the scan |
| `JUDGE_SEVERITY_FLOOR` | `high` | Always send findings at this severity or above to the judge |
| `MIN_NEW_FINDINGS` | `2` | Convergence threshold: stop iterating if fewer than this many new confirmed findings |
| `AGENT_MAX_STEPS` | `6` | Maximum tool-call steps per expert in agentic mode |
| `TRIDENT_SQLITE_PATH` | _(platform default)_ | Custom SQLite database path |
| `TRIDENT_WORKSPACES` | _(platform default)_ | Directory where scan workspace files are stored |
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
