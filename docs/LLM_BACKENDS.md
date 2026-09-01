# LLM Backends

Trident uses an LLM for council review, judge review, red-team chaining,
automatic triage, and novel discovery. You can use Ollama locally, OpenAI, or
Anthropic.

---

## Ollama (default)

Ollama runs models locally on your machine. This is the default backend and the recommended choice for privacy-sensitive code.

### Setup

1. Install Ollama from [ollama.com](https://ollama.com)
2. Pull a model:

```bash
ollama pull gemma4:31b-cloud        # recommended - default council model
# ollama pull glm-5.2:cloud         # stronger for agentic mode
ollama pull qwen3-embedding:0.6b    # required for semantic deduplication
```

3. Configure Trident:

```bash
trident config set llm.backend ollama
trident config set llm.base_url http://localhost:11434
trident config set llm.expert_model gemma4:31b-cloud
```

### Model recommendations

| Use case | Recommended model |
|----------|------------------|
| Default scans | `gemma4:31b-cloud` |
| Agentic mode (deeper analysis) | `glm-5.2:cloud` |
| Faster / smaller footprint | `gemma3:12b` or `qwen2.5:14b` |
| Semantic deduplication | `qwen3-embedding:0.6b` |

### Custom Ollama URL

If Ollama is running on a different host or port:

```bash
trident config set llm.base_url http://192.168.1.50:11434
```

Or with the environment variable:

```bash
OLLAMA_HOST=http://192.168.1.50:11434 trident scan .
```

---

## OpenAI

### Setup

```bash
trident config set llm.backend openai
trident config set llm.openai_api_key sk-...
trident config set llm.expert_model gpt-4o
```

Or using environment variables:

```bash
export LLM_BACKEND=openai
export OPENAI_API_KEY=sk-...
export EXPERT_MODEL=gpt-4o
trident scan .
```

The API key is treated as a secret and is never printed by `trident config show`.

### Model recommendations

| Use case | Recommended model |
|----------|------------------|
| Default scans | `gpt-4o` |
| Cost-sensitive | `gpt-4o-mini` |
| Maximum reasoning | `o3` |

---

## Anthropic

### Setup

```bash
trident config set llm.backend anthropic
trident config set llm.anthropic_api_key sk-ant-...
trident config set llm.expert_model claude-sonnet-5
```

Or using environment variables:

```bash
export LLM_BACKEND=anthropic
export ANTHROPIC_API_KEY=sk-ant-...
export EXPERT_MODEL=claude-sonnet-5
trident scan .
```

---

## Per-role model overrides

Each council role can use a different model. This is useful when you want to use a larger model for the judge (higher stakes) and a smaller model for routine expert passes.

| Role | Environment variable | Default |
|------|---------------------|---------|
| All experts | `EXPERT_MODEL` | backend default |
| Judge only | `JUDGE_MODEL` | same as `EXPERT_MODEL` |
| Red team only | `REDTEAM_MODEL` | same as `EXPERT_MODEL` |
| Triage pass | `TRIAGE_MODEL` | same as `EXPERT_MODEL` |

Example: use GPT-4o for most roles, `o3` for the judge:

```bash
export LLM_BACKEND=openai
export OPENAI_API_KEY=sk-...
export EXPERT_MODEL=gpt-4o
export JUDGE_MODEL=o3
trident scan .
```

---

## Per-scan model override

Override the model for a single scan without changing configuration:

```bash
trident scan . --model gpt-4o-mini
trident scan . --backend anthropic --model claude-haiku-4-5
```

CLI flags take precedence over config and environment variables.

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
