# Privacy and data handling

Trident runs on the local computer, but a configured language model or
scanner can communicate with remote services. Before a scan, decide which
code, reports, paths, and metadata each endpoint is allowed to receive.
Analyze only data you are authorized to process.

## Data sent for model review

Depending on the scan stage and backend, Trident may send:

- source-code excerpts and surrounding lines;
- file paths, language, scanner names, rule identifiers, and package metadata;
- vulnerability descriptions, severity, CWE or advisory identifiers, and
  correlated evidence;
- expert prompts, prior reviewer rationale, judge input, Red-Team context,
  triage factors, and structured response requests.

The exact fields vary by stage and by the evidence available. A report-only
import can still send imported descriptions and metadata. Supplying source
context can add excerpts. Trident cannot control a provider's retention,
training, support access, regional processing, or gateway logging. Review the
provider's terms and the gateway operator's data-handling policy before use.

## Gateway transport

OpenAI-compatible gateways can be configured over HTTP or HTTPS. HTTPS is
recommended for production and sensitive traffic. HTTP has no encryption; an
observer may read or modify credentials, code excerpts, vulnerability evidence,
prompts, responses, and repository metadata. A private network address does not
provide encryption. Trident accepts explicit HTTP configuration, including
private and public hosts; the operator chooses the endpoint and accepts the
transport risk.

Trident verifies HTTPS certificates and hostnames and does not follow redirects.
HTTPS protects traffic only between Trident and its configured endpoint. Review
the gateway's upstream connection, request logs, storage, retention, and
administrator access separately. See
[Connecting Trident to a Custom LLM Endpoint or Proxy](CONNECTING_LLM_ENDPOINTS.md).

Ollama uses its native API and separate host/mode settings. A localhost Ollama
gateway can still forward a cloud-tagged model request remotely. Check the
selected model and Ollama mode rather than assuming that localhost means local
inference.

## Credentials

API keys can be entered at a hidden prompt, piped through `--stdin`, or supplied
through environment variables or a secret manager. Secret values passed as
positional command-line arguments are rejected. Configuration output masks
secret values. Trident restricts its config directory and file to the local
account and uses atomic writes, but the TOML file stores credentials in
plaintext. Local administrators or root can read the file. Prefer environment
or secret-manager injection where your environment supports it, and rotate keys
according to your provider's policy.

Do not include keys in issue reports, shell history, CI logs, screenshots, or
diagnostic bundles. Review proxy logs because HTTP forward proxies and API
gateways have different visibility into request traffic.

## Local records and retention

The SQLite database, model ledger, workspaces, scanner logs, and exported
reports can retain:

- source metadata and bounded code context;
- normalized and original imported findings;
- scanner output and tool diagnostics;
- prompts, model responses, review rationales, and errors;
- attack-chain and triage analysis.

The default workspace cleanup policy is 14 days. This does not automatically
delete the scan database, model ledger, exported reports, config file, or
backups. Use the configured data paths and your operating-system retention
controls to inspect and remove records when policy permits. Treat reports and
diagnostic output as sensitive security data.

## Scanner and model boundaries

Scanners may upload or query dependency data according to their own design and
configuration. Their network behavior is separate from LLM processing. Review
the tool's documentation and organizational policy. LLM output can be wrong,
incomplete, or manipulated by untrusted source text. Trident validates response
formats and preserves evidence, but it does not prove that a finding is
exploitable or that a scan found every vulnerability.

## Operational checklist

1. Confirm authorization and the data classification of the target.
2. Choose a local model or provider/gateway approved for that data.
3. Use HTTPS for non-local sensitive traffic and review upstream handling.
4. Supply credentials through the hidden prompt, protected stdin, environment,
   or a secret manager.
5. Restrict access to databases, workspaces, logs, and exported reports.
6. Review unresolved and untriaged findings; do not treat a clean exit as proof
   of security.
