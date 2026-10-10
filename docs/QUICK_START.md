# Quick start

This walkthrough configures a model backend, runs a scan, and reads its
reports. Install the CLI and the scanner tools first; see
[Installation](INSTALLATION.md).

## 1. Configure a model provider

For an OpenAI-compatible gateway, set its base URL and the model alias that the
gateway recognizes:

```bash
trident config set llm.backend openai
trident config set llm.openai_base_url https://llm-gateway.example.com/v1
trident config set llm.expert_model security-expert
trident config set llm.openai_api_key
```

The hostname is reserved for examples. Replace it with the actual endpoint.
The key command opens a hidden prompt. If the gateway does not require
authentication, leave the key unset or clear a previously saved key with
`trident config reset llm.openai_api_key`.

You can also use Ollama or Anthropic. See [LLM backends](LLM_BACKENDS.md) for
provider setup. For HTTP or HTTPS gateways, read
[Connecting Trident to a Custom LLM Endpoint or Proxy](CONNECTING_LLM_ENDPOINTS.md)
before sending source data.

## 2. Run an authorized scan

From the repository directory:

```bash
trident scan .
```

Trident prepares the workspace, runs available scanners, correlates their
findings, asks the configured model to review candidates, checks for attack
chains, and triages findings that remain confirmed. Scanner and model
availability affects which stages can complete.

To import existing reports without running scanner subprocesses:

```bash
trident scan --input-file sonar-report.json --format table
trident scan --input-file sonar-report.json \
  --input-file dependency-check.json --format json \
  --output-file results.json
```

Without `--source-dir`, imported findings are report-only. Trident preserves
the imported evidence and provenance but cannot infer that the issue is
reachable in the source tree.

## 3. Read the result

The terminal shows counts for P0 through P4, including zeros, followed by the
prioritized total, untriaged count, and unresolved count. These counts use the
finalized finding population. Confirmed findings without a valid priority are
untriaged. Findings for which review could not reach a final disposition are
unresolved. Either state means the review is incomplete.

For per-finding evidence, save JSON or SARIF:

```bash
trident scan . --format json --output-file results.json
trident scan . --format sarif --output-file results.sarif
```

The JSON report contains finding details, review disposition, source
provenance, triage rationale, and chain context. SARIF maps retained findings
to locations and priority metadata. Use `--triage-output-file` to write the
full worked remediation queue.

## 4. Check command status

| Exit code | Meaning |
| --- | --- |
| `0` | Review completed below the configured severity gate. |
| `1` | A prioritized confirmed finding meets the configured gate. |
| `2` | A scan/report error occurred, or confirmed findings remain untriaged or unresolved. |

Exit code 2 indicates incomplete review and takes precedence over the
severity gate. Use `trident config get scan.severity_gate` to inspect the
stored gate. A scan can exit 0 while containing lower-priority findings if
those findings fall below the configured threshold.

## 5. Common checks

- `trident install-tools --check` shows scanner availability.
- `trident config get llm.backend` and `trident config get
  llm.openai_base_url` show effective configured values and their source.
- `trident config get llm.openai_api_key` masks the key.
- `trident scan --help` lists input, output, backend, gate, and per-scan
  options.
- See [Troubleshooting](TROUBLESHOOTING.md) for connection, authentication,
  scanner, and report errors.
