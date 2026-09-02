# Agentic exploration

Standard mode gives each reviewer the code around a finding. Agentic
exploration is an optional second step for contested findings: the reviewer can
inspect more of the scanned workspace before reaching a verdict.

## What it does

During cross-examination, reviewers can:

- read files in the workspace;
- search for patterns across the codebase;
- trace where a function is called; and
- find related definitions and references.

This helps when the answer depends on code in more than one file. For example,
the reviewer can trace user input back to its source, check whether it was
sanitized, and see whether the flagged function is reachable from an endpoint.

Agentic exploration is supported, but it is off by default. That keeps ordinary
scans from spending extra tokens and time on findings that do not need deeper
context.

## When to use it

| Situation | Recommendation |
|-----------|----------------|
| Large codebase with complex data flows | Use agentic exploration |
| Simple single-file project | Standard mode is usually enough |
| CI scan where cost and time matter | Use standard mode |
| High-impact or disputed finding | Consider agentic exploration |
| Finding with `reachability: unknown` | Use it when more context may resolve reachability |

Agentic exploration increases LLM calls, scan time, and cost. It is most useful
when a fixed code window is not enough to settle a finding.

## Enable it

### Persistent config

```bash
trident config set scan.agentic true
```

Or enable it for one shell invocation:

```bash
AGENTIC=true trident scan .
```

## Model choice

Use a model that handles multi-step reasoning and tool use well. For local
models:

```bash
trident config set llm.expert_model qwen2.5-coder:32b
```

For cloud:

```bash
trident config set llm.backend anthropic
trident config set llm.expert_model claude-sonnet-5
```

## Available tools

These tools are available during cross-examination when agentic exploration is active:

| Tool | Description |
|------|-------------|
| `read_file` | Read the contents of a file in the workspace |
| `search_pattern` | Search for a pattern across the workspace |
| `find_definition` | Find where a symbol is defined |
| `find_callers` | Find all call sites for a function |
| `list_directory` | List the contents of a directory |

Tool calls are bounded. Reviewers cannot read files outside the scanned
workspace, and the exploration tools have no network access.

## Cost and limits

| Dimension | Standard mode | Agentic exploration |
|-----------|---------------|---------------------|
| LLM calls per contested finding | 2-4 | 5-20+ (depends on exploration depth) |
| Scan time for a medium codebase | 3-8 min | 8-25 min |
| Verdict accuracy on complex findings | Good | Better |
| Cost on cloud LLM | Low | Higher |

Agentic exploration does not change the independent review phase. It activates
only during cross-examination. If findings are uncontested, it adds no calls.

## Limit exploration

To cap the number of tool calls per finding:

```bash
AGENT_MAX_STEPS=10 trident scan .
```

The default is six steps per reviewer. A lower cap reduces cost but may leave a
complex finding unresolved. A higher cap can increase scan time.

## See also

- [AI council](AI_COUNCIL.md) - independent review and cross-examination
- [Configuration](CONFIGURATION.md) - `scan.agentic` and related config keys
- [LLM backends](LLM_BACKENDS.md) - model setup
