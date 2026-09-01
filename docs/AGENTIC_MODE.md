# Agentic Mode

Standard mode gives each council expert a fixed code window around the flagged
location. Agentic mode changes only Phase B, the cross-examination of contested
findings. In that phase, experts can explore the scanned workspace before they
finish their verdict.

---

## What agentic mode enables

In Phase B (cross-examination of contested findings), experts can use tool calls to:

- Read any file in the workspace
- Search for patterns across the codebase (grep)
- Trace call chains to find where a function is called from
- Find related definitions (where is this variable assigned, where is this function defined)

This is most valuable when a finding requires understanding data flow across multiple files - something a fixed code window cannot provide.

**Example:** A council expert is reviewing a potential SQL injection. The flagged line uses `user_input` directly. In standard mode, the expert sees only the 30 lines around that call. In agentic mode, the expert can trace where `user_input` originates, whether it was sanitized before reaching this function, and whether the function is exposed via an HTTP handler - producing a more accurate verdict.

---

## When to use agentic mode

| Situation | Recommendation |
|-----------|---------------|
| Large codebase with complex data flows | Use agentic mode - experts can trace across files |
| Simple single-file project | Standard mode is sufficient |
| CI scan where cost and time matter | Standard mode (faster, fewer LLM calls) |
| High-stakes audit where accuracy matters most | Agentic mode |
| Finding with `reachability: unknown` | Agentic mode can help experts determine reachability manually |

Agentic mode increases the number of LLM calls, which increases both cost and scan time. It is most valuable on contested findings in complex codebases.

---

## Enabling agentic mode

### Persistent config

```bash
trident config set scan.agentic true

Or enable it for one shell invocation:

```bash
AGENTIC=true trident scan .
```
```

### Recommended model

Agentic mode is most effective with a model that performs well at multi-step reasoning and tool use. For local models:

```bash
trident config set llm.expert_model qwen2.5-coder:32b
```

For cloud:

```bash
trident config set llm.backend anthropic
trident config set llm.expert_model claude-sonnet-5
```

---

## Available tools in agentic mode

These tools are available to experts during Phase B when agentic mode is active:

| Tool | Description |
|------|-------------|
| `read_file` | Read the contents of any file in the workspace |
| `search_pattern` | Grep for a pattern across the workspace |
| `find_definition` | Find where a symbol is defined |
| `find_callers` | Find all call sites for a function |
| `list_directory` | List the contents of a directory |

Tool calls are bounded - experts cannot read files outside the scanned workspace. There is no network access from agentic tool calls.

---

## Performance and cost tradeoffs

| Dimension | Standard mode | Agentic mode |
|-----------|--------------|-------------|
| LLM calls per contested finding | 2-4 | 5-20+ (depends on exploration depth) |
| Scan time for a medium codebase | 3-8 min | 8-25 min |
| Verdict accuracy on complex findings | Good | Better |
| Cost on cloud LLM (e.g. Anthropic) | Low | Higher |

Agentic mode does not change Phase A (independent review). It only activates during Phase B for contested findings. If all findings are uncontested (all experts agree), agentic mode adds no cost.

---

## Limiting agentic tool calls

To cap the number of tool calls per finding:

```bash
AGENT_MAX_STEPS=10 trident scan .
```

The default is six steps per expert. A lower cap reduces cost at the risk of
incomplete exploration on complex findings; a higher cap may increase scan time.

---

## See also

- [AI_COUNCIL](AI_COUNCIL.md) - Phase A and Phase B deliberation
- [CONFIGURATION](CONFIGURATION.md) - `scan.agentic` and related config keys
- [LLM_BACKENDS](LLM_BACKENDS.md) - recommended models for agentic mode
