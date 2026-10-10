# LLM backends

The configured model is used for expert review, judge review, Red-Team analysis,
triage, and selected ingestion tasks. Requests can contain source excerpts,
scanner evidence, paths, model prompts, and earlier review rationale. Read
[Privacy](PRIVACY.md) before choosing a remote service.

Trident supports Ollama's native API, the OpenAI Chat Completions API (including
compatible gateways), and Anthropic's Messages API. These backends have separate
URLs, authentication, and API formats. Ollama URL restrictions or routes do not
describe the OpenAI-compatible backend.

## OpenAI-compatible API

The configured `llm.openai_base_url` defaults to
`https://api.openai.com/v1`. Trident calls `/models`, `/chat/completions`, and
`/embeddings` below the base path. A trailing slash is optional. HTTPS
certificate and hostname verification remain enabled; redirects are not
followed. Explicit HTTP endpoints are also accepted, so use HTTP only after
evaluating its lack of encryption.

The gateway receives the configured model alias unchanged. It must map that
alias to the intended upstream model and support the API operations and response
features used by the workflow. A gateway that supports chat completions may not
support model discovery, embeddings, tool calls, or structured response modes.

Configure a provider using the
[custom endpoint and proxy guide](CONNECTING_LLM_ENDPOINTS.md). The short setup
is:

```bash
trident config set llm.backend openai
trident config set llm.openai_base_url https://llm-gateway.example.com/v1
trident config set llm.expert_model security-expert
trident config set llm.openai_api_key
trident scan . --backend openai --model security-expert
```

The example hostname is reserved and must be replaced. The key prompt is hidden.
For a gateway with no authentication, clear any saved key and unset key
environment variables. `config get` and `config show` mask secrets.

The environment names are `OPENAI_BASE_URL` and `OPENAI_API_KEY`; Trident
prefixed aliases `TRIDENT_OPENAI_BASE_URL` and `TRIDENT_OPENAI_API_KEY` are also
accepted. CLI settings take precedence over environment, persisted config, and
defaults.

## Ollama

Ollama uses the native `/api/chat`, `/api/embed` or `/api/embeddings`, and model
discovery APIs. Its base URL is configured by `llm.base_url` and defaults to
`http://127.0.0.1:11434`. Trident's default expert alias is
`nemotron-3-super:cloud`; the `:cloud` suffix means Ollama may process the
request remotely even when the Ollama gateway is on localhost.

For a local Ollama model, pull a supported model and set its exact name:

```bash
ollama pull gemma3:12b
ollama pull qwen3-embedding:0.6b
trident config set llm.backend ollama
trident config set llm.base_url http://127.0.0.1:11434
trident config set llm.expert_model gemma3:12b
trident scan . --backend ollama --model gemma3:12b
```

Use `TRIDENT_OLLAMA_HOST` or `OLLAMA_HOST` to override the Ollama endpoint in
the environment. `TRIDENT_OLLAMA_MODE=direct_cloud` selects the supported
direct-cloud mode; its credentials and host are separate from OpenAI-compatible
settings. See [Configuration](CONFIGURATION.md) for those keys.

Ollama cloud models may report a provider model identifier that differs from
the requested cloud alias. Trident accepts only its defined alias mapping and
does not silently substitute an unrelated model.

## Anthropic

Anthropic uses its Messages API, not the OpenAI `/v1` routes. Configure the
backend and enter the API key at a hidden prompt:

```bash
trident config set llm.backend anthropic
trident config set llm.anthropic_api_key
trident config set llm.expert_model provider-model-id
trident scan . --backend anthropic --model provider-model-id
```

Use `ANTHROPIC_API_KEY` for environment-based authentication. Anthropic's
backend does not expose provider embeddings through this interface; Trident's
matching code uses its fallback behavior when embeddings are unavailable.

## Model selection by role

The scan option `--model` assigns one alias to experts, judge, Red-Team, and
triage for that scan. Without it, role-specific environment or persisted
settings may select different models.

| Role | Environment variable | Persisted key |
| --- | --- | --- |
| Backend | `TRIDENT_LLM_BACKEND` (`LLM_BACKEND` alias) | `llm.backend` |
| Expert model | `TRIDENT_OLLAMA_MODEL` (`EXPERT_MODEL` alias) | `llm.expert_model` |
| Judge | `TRIDENT_JUDGE_MODEL` (`JUDGE_MODEL` alias) | `llm.judge_model` |
| Red-Team | `TRIDENT_REDTEAM_MODEL` (`REDTEAM_MODEL` alias) | `llm.redteam_model` |
| Triage | `TRIAGE_MODEL` | No separate persisted key |

For an OpenAI-compatible API, the gateway must recognize each configured alias.
Trident sends the alias as written and does not select another model if the
gateway rejects it.

## Embeddings

OpenAI-compatible gateways use `POST /embeddings` with the configured
`EMBEDDING_MODEL` (default `qwen3-embedding:0.6b`). Ollama uses its native
embedding routes. Embeddings support semantic finding matching; if a request
fails, the matcher logs a sanitized warning and falls back to token overlap.
Anthropic returns a no-op vector because its API does not provide embeddings
through this backend.

## See also

- [Connecting Trident to a Custom LLM Endpoint or Proxy](CONNECTING_LLM_ENDPOINTS.md)
- [Configuration](CONFIGURATION.md)
- [AI Council](AI_COUNCIL.md)
- [Privacy](PRIVACY.md)
