# LLM Backends

Trident uses an LLM for council review, judge review, Red-Team analysis,
automatic triage, and novel discovery. You can use the Ollama backend through
an Ollama gateway, an OpenAI-compatible `/v1` gateway, or Anthropic.

---

## Ollama (default)

Ollama is the default backend. The gateway may be local, while the selected
model may be local or Ollama Cloud-tagged. The default model,
nemotron-3-super:cloud, is cloud-tagged; a local gateway does not mean that
this model executes on the local host.

### Setup

1. Install Ollama from [ollama.com](https://ollama.com) or configure another
   permitted Ollama gateway.
2. The default cloud-tagged model is requested through the gateway; do not
   treat it as a locally executed model. Pull a local model only when you
   intentionally choose a local-only configuration:

```bash
ollama pull gemma3:12b               # example local alternative
ollama pull qwen3-embedding:0.6b    # required for semantic deduplication
```

3. Configure Trident for the current process or scan:

```bash
TRIDENT_LLM_BACKEND=ollama TRIDENT_OLLAMA_HOST=http://localhost:11434 \
EXPERT_MODEL=nemotron-3-super:cloud trident scan .
```

The CLI also accepts `trident scan . --backend ollama --model nemotron-3-super:cloud`.
Use `trident config show` to inspect persisted configuration values and
`trident config set` for configuration-manager settings such as the severity
gate and iteration limit.

For direct Cloud API access instead of the local gateway, set
`TRIDENT_OLLAMA_MODE=direct_cloud` and provide `OLLAMA_API_KEY`; the direct
endpoint defaults to `https://ollama.com`. The local gateway mode is generally
the simplest way to use an Ollama account with cloud-tagged models.

### Model recommendations

| Use case | Recommended model |
|----------|------------------|
| Default scans | `nemotron-3-super:cloud` |
| Agentic mode (deeper analysis) | `glm-5.2:cloud` |
| Faster / smaller footprint | `gemma3:12b` or `qwen2.5:14b` |
| Semantic deduplication | `qwen3-embedding:0.6b` |

### Custom Ollama URL

If Ollama is running on a different host or port:

```bash
trident config set llm.base_url http://127.0.0.1:11434
```

Or with the environment variable:

```bash
TRIDENT_OLLAMA_HOST=http://127.0.0.1:11434 trident scan .
```

### Cloud model identity

When a cloud-tagged request is returned by Ollama with its native model name,
Trident records both values and accepts only that exact one-way alias mapping.
For example, `gemma4:31b-cloud` may return `gemma4:31b`; the requested and
actual identities are both preserved in the decision metadata. An unrelated
returned model is rejected. Trident never silently falls back to another model.

Ollama Cloud does not provide server-enforced JSON schemas through the native
API path. Trident therefore performs typed application-side validation,
bounded JSON repair, semantic validation, and fail-closed unresolved handling.

---

## OpenAI-compatible gateways

The OpenAI backend accepts a generic OpenAI-compatible provider implementing
these endpoints:

```text
GET  <base_url>/models
POST <base_url>/chat/completions
POST <base_url>/embeddings
```

The default `llm.openai_base_url` is `https://api.openai.com/v1`. A custom base
URL should include `/v1`; Trident normalizes an optional trailing slash. Model
names are aliases supplied by the gateway and are sent unchanged. Runtime
settings resolve in this order: CLI options, environment variables, persisted
configuration, then defaults. For the gateway, use `OPENAI_BASE_URL` and
`OPENAI_API_KEY`; role aliases can use `EXPERT_MODEL`, `JUDGE_MODEL`, and
`REDTEAM_MODEL` or their Trident-prefixed equivalents.

Remote custom endpoints must use HTTPS. Trident permits unencrypted HTTP only
for loopback addresses such as `127.0.0.1` or `localhost`, rejects credentials
and query parameters embedded in the URL, and does not follow redirects. These
checks prevent a bearer key from being sent over cleartext transport or to a
redirect destination. The supported endpoints were validated with a real
localhost HTTP test gateway; no external provider was tested in this acceptance.

### Setup with a custom endpoint

```bash
trident config set llm.backend openai
trident config set llm.openai_base_url http://127.0.0.1:8000/v1
trident config set llm.expert_model security-expert
trident config set llm.openai_api_key
```

The API-key command prompts with input hidden. To load credentials from a
protected source without putting them in a command argument, pipe them to
`trident config set llm.openai_api_key --stdin`. `config get` and `config show`
mask configured secrets; positional secret values are rejected. You can instead
provide `OPENAI_API_KEY` through your environment or a secret manager.

Or using environment variables:

```bash
export LLM_BACKEND=openai
export OPENAI_BASE_URL=http://127.0.0.1:8000/v1
export OPENAI_API_KEY
export EXPERT_MODEL=security-expert
trident scan .
```

`OPENAI_BASE_URL` and `OPENAI_API_KEY` override persisted config. The key is
sent as a bearer token and is masked by `trident config get/show`. Any
gateway-specific alias, such as `enterprise-sec-model` or
`routed-security-model`, can be configured as the model name.

---

## Anthropic

### Setup

```bash
trident config set llm.backend anthropic
trident config set llm.anthropic_api_key
trident config set llm.expert_model claude-sonnet-5
```

Or using environment variables:

```bash
export LLM_BACKEND=anthropic
read -rsp 'Anthropic API key: ' ANTHROPIC_API_KEY; echo; export ANTHROPIC_API_KEY
export EXPERT_MODEL=provider-supported-model-id
trident scan .
```

---

## Per-role model overrides

Each council role can use a different model. This is useful when you want to use a larger model for the judge (higher stakes) and a smaller model for routine expert passes.

| Role | Environment variable | Default |
|------|---------------------|---------|
| All experts | `TRIDENT_OLLAMA_MODEL` or `EXPERT_MODEL` | backend default |
| Judge only | `TRIDENT_JUDGE_MODEL` or `JUDGE_MODEL` | same as `EXPERT_MODEL` |
| Red-Team only | `TRIDENT_REDTEAM_MODEL` or `REDTEAM_MODEL` | same as `EXPERT_MODEL` |
| Triage pass | `TRIAGE_MODEL` | same as `EXPERT_MODEL` |

Example: use one gateway model alias for experts and a different judge alias:

```bash
export LLM_BACKEND=openai
export OPENAI_BASE_URL=http://127.0.0.1:8000/v1
export OPENAI_API_KEY="$OPENAI_API_KEY"
export EXPERT_MODEL=security-expert
export JUDGE_MODEL=security-judge
trident scan .
```

---

## Per-scan model override

Override the backend or model for one scan:

```bash
trident scan . --backend openai --model routed-security-model
trident scan . --backend anthropic --model provider-model-alias
```

The resolution order is CLI flags, environment, persisted config, then defaults.
`--model` applies to expert review, judge, Red-Team, and triage calls for the
scan.

---

## Embedding model

The embedding model is used for semantic deduplication of findings across tools and for the eval matching system. It is not a council role and does not affect finding verdicts.

```bash
EMBEDDING_MODEL=qwen3-embedding:0.6b   # default, Ollama required
```

If you are using OpenAI or Anthropic as your LLM backend, you still need Ollama available for the embedding model unless you override it with a different embedding provider.

---

## See also

- [CONFIGURATION](CONFIGURATION.md) - full config key reference
- [AGENTIC_MODE](AGENTIC_MODE.md) - model recommendations for agentic scans
- [AI_COUNCIL](AI_COUNCIL.md) - what each role does
