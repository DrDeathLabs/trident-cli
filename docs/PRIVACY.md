# Privacy and data handling

Trident is a local, single-operator CLI. Its local files are not encrypted by
Trident. Use it only on systems and code you are authorized to analyze, and
protect reports and data directories under your organization's retention rules.

## Data sent to model providers

When an LLM backend is enabled, Trident sends the prompts required for review.
Depending on the workflow and available context, this can include finding
titles, descriptions, source snippets, file paths and line numbers, scanner
metadata, evidence excerpts, prior reviewer rationale, report-only/source-
grounded indicators, triage inputs, and bounded agentic file excerpts. Red-Team
receives its selected finding IDs and the evidence visible in its prompt.
Provider-side processing, logging, human access, and retention are governed by
that provider and gateway operator; Trident cannot verify those policies.
Use local inference or an approved provider for sensitive repositories. A
configured gateway URL and API key do not make the gateway private.

The OpenAI-compatible backend requires HTTPS for non-loopback endpoints and
rejects credentials, query strings, and fragments in the base URL. Cleartext
HTTP is allowed only for loopback testing. HTTP redirects are not followed, so
the bearer key is not forwarded to a redirect destination. A user-configured
trusted TLS proxy can still inspect traffic. Avoid logging full request bodies
in production gateway infrastructure; Trident's acceptance harness uses only
synthetic inputs and records auth presence, not the credential.

Scanner output, imported reports, repository files, and model responses are
untrusted data. Prompt instructions ask models to treat supplied material as
evidence rather than instructions, but prompt injection cannot be eliminated
by text prompting. Agentic tools are bounded and read-only; do not enable them
for untrusted sources unless the environment is appropriately isolated.

For Git scans, do not embed credentials in the repository URL. Trident rejects
HTTP(S)/git URL user information, password-bearing SSH URLs, query strings, and
fragments; the conventional `git@host:path` SSH identity remains supported.
Errors do not include the full URL or raw Git stderr. Uploaded ZIP extraction rejects
traversal paths and links and is bounded to 100,000 members and 4 GiB of
expanded file content.

## Data stored locally

The default Trident app-data directory and config directory are restricted to
the current user (POSIX 0700 directories and 0600 files; Windows ACLs grant the
current user, SYSTEM, and local Administrators). Config updates use an atomic
write. SQLite databases and their WAL/SHM sidecars are similarly restricted.
Custom SQLite paths have their database files restricted, but the operator
chooses the parent directory. PostgreSQL deployments use the operator's
server-side controls and require an explicit `POSTGRES_PASSWORD`; Trident does
not ship a shared default password.

Credentials stored through `trident config set` remain plaintext TOML on disk.
Permissions reduce exposure to other local accounts but do not encrypt the
value or protect it from the current user, administrator/root, malware running
as that user, backup software, or a compromised machine. Prefer
`OPENAI_API_KEY`/`ANTHROPIC_API_KEY` environment injection or a secret manager
when the environment can provide them safely. Avoid putting secrets in shell
arguments, terminal transcripts, or source workspaces.

Finding evidence, imported records, debate/rationale text, attack-chain results,
reports, and structured LLM request metadata are stored in the local database.
The typed-decision ledger stores hashes of requests rather than prompts, but it
does retain raw model responses, parsed decisions, validation errors, and
transport metadata. A response may quote source context. There is no automatic
retention or deletion policy for job records or the ledger. Workspace source
copies are swept after `WORKSPACE_RETENTION_DAYS` (default 14 days); setting it
to `0` disables that sweep. Deleting a source workspace does not delete report
records or the separate LLM ledger. To remove local records, stop Trident and
remove the relevant database, ledger, reports, caches, and workspace files
according to local policy.

Scanner stdout and stderr are held in process memory for parsing and are not
persisted as job events. Credential-specific Gitleaks, TruffleHog, Trivy,
Semgrep, Bandit, gosec, and Checkov findings omit matched values from their
normalized descriptions/snippets and raw finding metadata. Other normalized
scanner evidence may still contain source-derived strings; treat reports as
sensitive.

Gateway logs, reverse-proxy logs, shell history, crash dumps, backup snapshots,
and operating-system telemetry are outside Trident's control. Do not enable
full request/response logging on production gateways unless the logged prompts
and responses have an approved retention policy.

## Reports and diagnostics

JSON and SARIF intentionally contain finding evidence, paths, rationales,
remediation, and disposition data; they are sensitive scan outputs. Do not
attach them to public issues. Config commands mask API keys, and secret values
are rejected as positional arguments. Errors from the OpenAI-compatible
transport omit response bodies and bearer headers. Config path output can
identify a local username; review command output before sharing it.

Use the security guidance in [SECURITY.md](../SECURITY.md) and review the
provider's current privacy and retention terms before sending code.
