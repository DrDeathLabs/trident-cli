# Troubleshooting

Start with the exact command and exit code. Avoid posting source code, raw
prompts, API keys, private endpoint names, or unredacted reports in a support
request. See [Privacy](PRIVACY.md) before collecting diagnostics.

## OpenAI-compatible gateway errors

| Error | Likely cause and next step |
| --- | --- |
| Connection refused | Check that the host, port, and service are listening. Test reachability from the same machine or container that runs Trident. |
| DNS lookup failure | Check the hostname, VPN connection, and internal DNS from the Trident environment. |
| Certificate verification failure | Confirm certificate expiry and hostname, then install the approved CA chain or set `SSL_CERT_FILE`/`SSL_CERT_DIR`. Keep verification enabled. |
| HTTP 401 or 403 | Verify that the gateway expects a bearer key and that the key is valid. Enter it using `trident config set llm.openai_api_key` or inject it from a secret store. Secret output is masked. |
| HTTP 404 | Confirm the base URL includes the right API prefix and path. Trident appends `/models`, `/chat/completions`, and `/embeddings`. |
| Model rejected | Check the exact alias configured in `llm.expert_model`, `JUDGE_MODEL`, or `REDTEAM_MODEL`. Trident sends the alias unchanged. |
| Invalid response or unsupported feature | Check that the service implements the endpoint and response format required by the failing role. A chat-compatible service may not support embeddings, tool calls, or structured output. |
| Timeout | Check server load, model initialization, and network latency. Adjust `LLM_TIMEOUT` only if the service needs more time. |

Inspect non-secret settings and sources:

```text
trident config get llm.backend
trident config get llm.openai_base_url
trident config get llm.expert_model
trident config get llm.openai_api_key
```

Use `trident scan --backend openai --openai-base-url URL --model ALIAS` for a
single-run override. The option requires the OpenAI backend. Read
[the custom endpoint guide](CONNECTING_LLM_ENDPOINTS.md) for HTTP, HTTPS,
enterprise CA, authentication, and proxy details.

## Ollama errors

- Confirm the Ollama service is running and `llm.base_url` points to its native
  API host.
- Check the model name with `ollama list` or the service's model discovery
  command. Pull the model if it is local and missing.
- A `:cloud` model can involve remote processing even when the API endpoint is
  localhost. Check `llm.ollama_mode` and the model name.
- Ollama does not use `llm.openai_base_url`; configure its own base URL and
  mode.

## Missing scanner or incomplete scan

Run:

```text
trident install-tools --check
trident install-tools --verify
```

Install or repair available tools with `trident install-tools --verify
--warmup`. npm-audit requires Node.js/npm. Go-based tools use system Go or the
managed runtime. Scanner database downloads need network access. A scan can
complete without every adapter when a tool is not installed or not applicable;
inspect the scan's diagnostics before treating its coverage as sufficient.

## Imported reports

- Use `trident inspect FILE --format json` to inspect normalization without
  running a scan.
- Set `--input-format` when automatic detection cannot identify the report.
- Use `--mapping FILE` for a schema that does not have a first-class adapter.
- Use `--no-schema-ai` to disable model-assisted schema inference.
- Imported findings without `--source-dir` are report-only; source reachability
  remains unknown.

## Exit codes and empty results

- `0`: review completed below the priority gate. Lower priority findings may
  still exist.
- `1`: a prioritized confirmed finding meets the configured gate.
- `2`: scan, ingestion, or report error, or incomplete review with untriaged or
  unresolved findings.

An empty P0-P4 total does not mean every candidate was disproved. Check
`Untriaged`, `Unresolved`, disposition counts, and the JSON report. Exit 2 takes
precedence when review is incomplete.

## Useful output for diagnosis

1. Rerun with `--format json --output-file results.json` and keep the exit code.
2. Check whether the configured backend received requests at the intended
   endpoint.
3. Inspect tool status and sanitized error text.
4. Share only synthetic reproductions and redacted metadata.

See [Validation](VALIDATION.md) for the scope of controlled acceptance tests.
