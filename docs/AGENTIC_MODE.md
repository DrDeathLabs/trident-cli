# Agentic expert exploration

Agentic mode lets an expert inspect more of the scanned workspace during
cross-examination. It can read files, search for patterns, find definitions,
and inspect callers. Use it when a disputed decision depends on context beyond
the fixed evidence window.

Agentic mode is off by default. It adds model requests and can lengthen a scan.
It only applies to the configured review workflow; it does not run the
application or access the network through its file-inspection tools.

## Enable exploration

Persist the setting:

```text
trident config set scan.agentic true
```

Or set it in the environment for one process:

```bash
AGENTIC=true trident scan .
```

`AGENT_MAX_STEPS` limits the number of tool steps per reviewer. The default is
six. Reducing the value limits exploration; increasing it allows more file
queries and model work. Review the final decision and the files cited by the
model.

## Available inspection tools

| Tool | Operation |
| --- | --- |
| `read_file` | Read a workspace file or bounded line range. |
| `search_pattern` | Search workspace text with a bounded pattern. |
| `find_definition` | Locate a symbol definition. |
| `find_callers` | Find detected callers. |
| `list_directory` | List workspace entries. |

Access is constrained to the scan workspace. Static call and definition search
can miss dynamic dispatch, reflection, generated code, and framework-specific
entry points. The expert can still misinterpret the files it reads.

## See also

- [Council review](AI_COUNCIL.md)
- [Scanning](SCANNING.md)
- [Privacy](PRIVACY.md)
- [Configuration](CONFIGURATION.md)
