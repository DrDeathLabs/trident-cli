# Support

Trident CLI is a local-first security scanner. A useful support request gives
enough sanitized detail to reproduce a CLI problem without exposing source
code, credentials, private findings, or customer data.

## Before opening a request

Check the relevant guide in [the documentation map](docs/README.md), then
collect:

- operating system and version;
- Python version and Trident version;
- the exact command, with paths and secrets redacted;
- the configured LLM backend/model, if applicable;
- the exit code;
- `trident install-tools --check` output;
- a short, sanitized stderr or debug-log excerpt.

Use a small public fixture or a synthetic example when a scan target is
needed. Do not upload proprietary source, raw credentials, full private scan
reports, model prompts containing source context, or unredacted environment
output.

## Security issues

Do not report a suspected vulnerability in a public issue. Use the repository's
private vulnerability-reporting channel when one is configured, or contact the
maintainers through the private channel published with the release. If no
private channel is available, state that limitation in a minimal public issue
without including exploit details, then wait for maintainer direction.

## Scope and expectations

Support covers the CLI, scanner-tool bootstrap, configuration, model feeds,
reports, and documented local execution paths. Trident does not guarantee that
every scanner finding is exploitable or that a triage decision is a substitute
for human review. Scanner availability, upstream feed changes, LLM behavior,
network access, and local permissions can affect results.
