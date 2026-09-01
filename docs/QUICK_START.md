# Quick Start

This guide gets you from zero to a completed scan in under 10 minutes, assuming Python 3.11+ is already installed and Ollama is running locally with a model available.

---

## Step 1 - Install Trident

```bash
python -m venv .venv

# macOS/Linux:
source .venv/bin/activate

# Windows PowerShell:
.\.venv\Scripts\Activate.ps1

# Install the downloaded GitHub release wheel, or use the source checkout.
python -m pip install path/to/trident-0.1.0-py3-none-any.whl
trident --help
```

You should see the Trident help output listing the available commands (`scan`, `config`, `model`, `install-tools`, `help`).

---

## Step 2 - Install the 12 security tools

```bash
trident install-tools
```

This takes 3-10 minutes depending on your connection. You will see each tool download and confirm:

```
  osv-scanner: OK -> .../bin/osv-scanner.exe
  trufflehog: OK  -> .../bin/trufflehog.exe
  gitleaks: OK    -> .../bin/gitleaks.exe
  grype: OK       -> .../bin/grype.exe
  trivy: OK       -> .../bin/trivy.exe
  go runtime: OK  -> .../bin/go_runtime/go/bin/go.exe
  gosec: OK
  govulncheck: OK
  semgrep: OK
  bandit: OK
  checkov: OK
  pip-audit: OK

[trident] 12 tool(s) ready
```

Verify everything is working:

```bash
trident install-tools --verify
```

---

## Step 3 - Configure your LLM

Trident works with Ollama (local), OpenAI, or Anthropic. For this quick start, Ollama is assumed.

Pull a model if you have not already:

```bash
ollama pull gemma4:31b-cloud
```

Configure Trident:

```bash
trident config set llm.backend ollama
trident config set llm.base_url http://localhost:11434
trident config set llm.expert_model gemma4:31b-cloud
```

Confirm:

```bash
trident config show
```

For OpenAI or Anthropic, see [LLM_BACKENDS](LLM_BACKENDS.md).

---

## Step 4 - (Optional) Build corpus-profile triage data

The corpus-profile stage adds historical CWE context to automatic triage. It
helps align model factors with the expected tier for well-represented weakness
classes. Skip this step now and run it later - scans still work, but this
optional adjustment stage is inactive.

```bash
trident model refresh
```

This takes approximately 30 minutes. It downloads NVD, EPSS, KEV, ExploitDB,
CWE, CISA VulnRichment, and OSV data, computes local CWE profiles, and builds
the separately reported statistical artifact. Run it once; the local data
persists until you call `refresh` again.

---

## Step 5 - Run a scan

```bash
trident scan /path/to/your/code
```

You will see live progress as each tool runs, then the council deliberation, then the final table:

```
  ✓  semgrep         47 findings  12.1s
  ✓  bandit          18 findings   1.8s
  ✓  trivy           91 findings  22.4s
  ...
  ✓  Council complete  confirmed: 62  refuted: 31
  ✓  Guards complete   P0: 2  P1: 18  P2: 21  P3: 11  P4: 10

Trident Scan - my-project
──────────────────────────────────────────────────────────────
  Tier │ Count │ Sample
──────────────────────────────────────────────────────────────
  P0   │     2 │ python.flask.security.insecure-deserialization  (app.py:36)
  P1   │    18 │ yaml.github-actions.security.github-actions-...  (ci.yml:12)
  P2   │    21 │ python.flask.security.audit.app-run-param-co...  (app.py:123)
  P3   │    11 │ yaml.security.configuration.policy...  (manifests/app.yml:21)
  P4   │    10 │ ...
──────────────────────────────────────────────────────────────
  Total confirmed: 62
```

Exit code 0 means no confirmed finding at or above the severity gate (default:
`high`). Exit code 1 means one or more confirmed findings reached the gate.
Exit code 2 means ingestion or scan failure. Scanner candidates rejected by
the council or automatic triage are retained as audit evidence but are not
final actionable findings.

---

## Step 6 - Explore the results

### JSON output (scan plus triage)

```bash
trident scan /path/to/your/code --format json > results.json
```

The JSON contains a compact top-level triage summary, per-finding triage
metadata (`fix_effort`, `attack_vector`, `exploitability`), and `attack_chains`.
For the complete worked queue grouped by P0-P4, save a triage sidecar:

```bash
trident scan /path/to/your/code --format json \
  --output-file results.json --triage-output-file triage.json
```

### SARIF for GitHub Code Scanning

```bash
trident scan /path/to/your/code --format sarif > results.sarif
```

Upload `results.sarif` to GitHub's Security tab via `github/codeql-action/upload-sarif`.

---

## Next steps

| Goal | Document |
|------|----------|
| Understand what P0-P4 means | [TRIAGE](TRIAGE.md) |
| See the full JSON schema | [OUTPUT_FORMATS](OUTPUT_FORMATS.md) |
| Integrate into GitHub Actions or GitLab CI | [CI_CD](CI_CD.md) |
| Understand why a finding was rated as it was | [GUARDS](GUARDS.md) |
| Use a different LLM | [LLM_BACKENDS](LLM_BACKENDS.md) |
| See all scan options | [SCANNING](SCANNING.md) |
