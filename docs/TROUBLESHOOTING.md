# Troubleshooting

Common issues and how to fix them.

---

## Installation

### Installing the `trident` package name gives an unexpected package

The PyPI name `trident` is already occupied by another project and is not the
installation path for this release. Install the wheel downloaded from the
GitHub release, or install the source checkout:

```bash
python -m venv .venv
.venv\Scripts\activate      # Windows
source .venv/bin/activate   # macOS/Linux
python -m pip install path/to/trident-0.1.0-py3-none-any.whl
```

From a source checkout:

```bash
cd backend
python -m pip install .
```

### `trident: command not found` after install

The `trident` script is installed into the venv's `Scripts\` (Windows) or `bin/` (macOS/Linux) directory. Make sure the venv is activated:

```bash
.venv\Scripts\activate      # Windows
source .venv/bin/activate   # macOS/Linux
trident --help
```

---

## Tool installation

### Go bootstrap fails - `SSL certificate error` or `connection refused`

`trident install-tools` downloads Go from `go.dev`. If your environment blocks direct downloads:

1. Download the Go release manually from https://go.dev/dl/
2. Extract it to `<tools_dir>/go_runtime/`
3. Re-run `trident install-tools`; it will detect the existing Go binary

### Tool not found after `trident install-tools`

Run `trident install-tools --verify` to see each tool's status and path:

```bash
trident install-tools --verify
```

If a tool shows `missing`, run:

```bash
trident install-tools --tool <tool-name>
```

If that fails, check whether the download host is blocked by your firewall (`github.com` for binary releases, `pypi.org` for pip tools).

### `npm-audit` always shows `missing`

npm-audit requires Node.js. Trident does not install Node.js. Install it from https://nodejs.org or via your system package manager. After Node.js is on PATH, `npm-audit` will be detected automatically.

---

## Scanning

### Scan hangs and never completes

Most likely cause: the LLM backend is not responding.

1. Check your backend is running: for Ollama, `ollama list` should return models; for cloud backends, verify your API key is set.
2. Check the backend host config:

```bash
trident config show
```

3. Try a minimal scan to isolate whether the issue is the LLM or the tools:

```bash
trident scan . --max-iterations 1 --quiet
```

4. If Ollama is configured, check it is not overloaded:

```bash
ollama ps
```

### `scan error` - exit code 2

Exit code 2 means an unhandled exception during ingest or scan setup. Run with a single iteration and without `--quiet` to see the full traceback:

```bash
trident scan . --max-iterations 1
```

Common causes:
- The workspace path does not exist or is not readable
- Git clone failed (bad URL, auth required, network issue)
- A tool runner produced unexpected output format (update the tool: `trident install-tools --tool <name>`)

---

## Output

### JSON output contains a BOM (`﻿`) on Windows

Some Windows terminals write a UTF-8 BOM at the start of piped output. This breaks `json.load()` in Python.

Use `--output-file` to write directly to a file instead of stdout:

```bash
trident scan . --format json --output-file results.json
```

Then read with:

```python
with open("results.json", encoding="utf-8-sig") as f:
    data = json.load(f)
```

### SARIF upload fails on GitHub Actions - `Invalid SARIF`

Common causes:

1. **Zero-length file**: the scan produced no output (scan error before output was written). Check exit code 2.
2. **BOM prefix**: see above - use `--output-file` instead of stdout redirection.
3. **Schema version mismatch**: Trident produces SARIF 2.1.0. Verify the upload action version:

```yaml
uses: github/codeql-action/upload-sarif@v3
```

---

## Corpus-profile triage adjustment

### `corpus_guard` is always `null`

The local corpus profiles have not been built. Run:

```bash
trident model refresh
```

This downloads the vulnerability feeds, computes CWE profiles, and builds the
local statistical artifact. Expect 20-45 minutes.

After completion, verify:

```bash
trident model status
```

`Status: active` confirms the local corpus calibration state is available and
the corpus-profile triage adjustment can run for qualifying CWEs.

### `trident model refresh` fails partway through

The most common causes are network interruption (downloading large feeds) and disk space. The NVD feed alone is several hundred MB.

Check available disk space, then re-run:

```bash
trident model refresh
```

The command is idempotent - feeds already downloaded are not re-downloaded.

---

## LLM backends

### Ollama - `connection refused` or `timeout`

1. Confirm Ollama is running: `ollama list`
2. Check the host config matches where Ollama is running:

```bash
trident config get llm.base_url
# default: http://localhost:11434
```

3. If Ollama is on a different host:

```bash
trident config set llm.base_url http://192.168.1.50:11434
```

### OpenAI / Anthropic - `Authentication error`

Your API key is missing or invalid.

```bash
# Verify the key is set (shows last 4 chars only for safety)
trident config show | grep api_key
```

Set via environment variable (preferred in CI):

```bash
export OPENAI_API_KEY=sk-...
export ANTHROPIC_API_KEY=sk-ant-...
```

Or via config (stored in your local config file):

```bash
trident config set llm.openai_api_key sk-...
trident config set llm.anthropic_api_key sk-ant-...
```

---

## Getting more diagnostic output

```bash
TRIDENT_LOG_LEVEL=DEBUG trident scan . 2>debug.log
```

The debug log includes tool subcommand output, LLM request/response summaries, guard decisions, and database queries.

---

## See also

- [INSTALLATION](INSTALLATION.md) - complete setup instructions
- [CONFIGURATION](CONFIGURATION.md) - all config keys and environment variables
- [LLM_BACKENDS](LLM_BACKENDS.md) - backend-specific setup
- [LIMITATIONS](LIMITATIONS.md) - known coverage gaps
