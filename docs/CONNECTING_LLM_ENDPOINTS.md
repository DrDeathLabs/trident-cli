# Connecting Trident to a Custom LLM Endpoint or Proxy

Trident can send review requests to a self-hosted inference server, an
organization's LLM gateway, or an API-compatible proxy. The service must
implement the OpenAI Chat Completions request and response format. This guide
covers OpenAI-compatible APIs. Ollama uses its native API and separate settings;
see [LLM backends](LLM_BACKENDS.md).

The configured URL can name a local service, a private-network address, an
internal DNS name, or a public host. Trident validates URL syntax and uses the
configured host through the standard httpx networking stack; it does not
restrict requests by address class or replace the configured hostname.

An OpenAI-compatible API proxy is an endpoint that accepts OpenAI-style API
routes and model requests. It is different from a conventional HTTP forward
proxy, which relays network traffic. Trident addresses the API endpoint directly.
httpx can also use standard proxy environment variables when the network
requires an upstream forward proxy.

## Required API operations

Trident uses these routes under the configured base URL:

| Request | Purpose |
| --- | --- |
| `GET /models` | Endpoint health check and model discovery. The scan uses the configured alias; discovery does not rewrite it. |
| `POST /chat/completions` | Expert, judge, Red-Team, and triage requests. |
| `POST /embeddings` | Semantic matching when embeddings are available. Failures fall back to token matching. |

The full URL is the base URL plus the route. For example,
`http://127.0.0.1:8000/v1` produces
`http://127.0.0.1:8000/v1/chat/completions`. Trident accepts a trailing slash
and removes it. Include the API prefix and any gateway path exactly once.

Not every compatible service supports all operations or structured response
options. A service may accept chat completions but reject model discovery,
embeddings, tool calls, or a response format used by a particular review.
Confirm those features with the gateway operator before using it for a full
scan.

## Configure an HTTP endpoint

The following address is reserved for documentation. Replace it with a
reachable gateway address before running these commands:

```bash
trident config set llm.backend openai
trident config set llm.openai_base_url http://192.0.2.10:8000/v1
trident config set llm.expert_model security-expert
trident config set llm.openai_api_key
trident scan . --backend openai --model security-expert
```

`192.0.2.10` belongs to the RFC 5737 documentation range. It is not a usable
gateway. `config set llm.openai_api_key` starts a hidden prompt and asks for the
key twice. The key is not placed in shell history or process arguments.

For a gateway with no authentication, leave the key unset. If a key was
previously stored, run `trident config reset llm.openai_api_key` and unset
`OPENAI_API_KEY` and `TRIDENT_OPENAI_API_KEY` in the current environment.
Trident omits the Authorization header when no key is configured.

For a service on the same computer, a typical URL is
`http://127.0.0.1:8000/v1`. For an internal DNS service, use a name such as
`http://llm-gateway.internal.example.com:8000/v1`. The `.example.com` name is
reserved for examples. Replace it with the name supplied by your network
administrator.

You can override the stored endpoint for one scan:

```bash
trident scan . --backend openai --openai-base-url http://127.0.0.1:8000/v1 \
  --model security-expert
```

The `--openai-base-url` option requires `--backend openai` or an OpenAI backend
selected by environment or persisted configuration.

## Configure an HTTPS endpoint

```bash
trident config set llm.backend openai
trident config set llm.openai_base_url https://llm-gateway.example.com/v1
trident config set llm.expert_model security-expert
trident config set llm.openai_api_key
trident scan . --backend openai --model security-expert
```

`llm-gateway.example.com` is a reserved example hostname. Replace it with the
hostname and base path assigned by the gateway operator. Trident verifies the
server certificate and hostname using httpx's default TLS verification. Do not
turn off certificate validation to work around a certificate error.

For an enterprise certificate authority, install the approved CA certificate
in the operating system trust store or point httpx to a PEM CA bundle using
`SSL_CERT_FILE` (or a CA directory using `SSL_CERT_DIR`). Keep the gateway
hostname in the URL so certificate hostname checks can succeed. If a reverse
proxy terminates TLS, verify the certificate and access controls at that
immediate endpoint. Separately review the proxy's connection to its upstream
model service.

The key is sent as a bearer credential when configured. The configured model
alias, such as `security-expert`, is sent unchanged in API requests. The
gateway must map that alias to an available model. `OPENAI_API_KEY` and
`TRIDENT_OPENAI_API_KEY` are the environment names for the key.

If the host can reach the endpoint only through an upstream forward proxy, set
the standard `HTTPS_PROXY` or `HTTP_PROXY` environment variable and, where
needed, `NO_PROXY`. These variables configure httpx's network route; they do not
change Trident's OpenAI API base URL.

## Security Considerations: HTTP vs. HTTPS

HTTP provides no transport encryption. A network observer on the path could
read or modify API credentials, source-code excerpts, vulnerability evidence,
model prompts and responses, and repository metadata. A private IP address does
not encrypt traffic or authenticate the gateway.

Use HTTPS for production and sensitive workloads. HTTP can be a deliberate
choice for a local service, an isolated test network, or an internal gateway
when the operator has evaluated and accepted the network risk. Trident permits
explicitly configured HTTP URLs; it does not infer that a private address is
safe.

HTTPS protects traffic between Trident and the configured endpoint. It does
not by itself protect an upstream proxy connection, gateway logs, gateway
storage, provider retention, or administrative access to the service. Review
those systems separately. Redirects are not followed, so the configured
endpoint cannot redirect a bearer key to another host.

## Windows PowerShell

Set process-scoped environment variables for one PowerShell session:

```powershell
$env:TRIDENT_LLM_BACKEND = "openai"
$env:OPENAI_BASE_URL = "https://llm-gateway.example.com/v1"
$env:EXPERT_MODEL = "security-expert"
trident scan .
Remove-Item Env:TRIDENT_LLM_BACKEND, Env:OPENAI_BASE_URL, Env:EXPERT_MODEL
```

For a gateway requiring a key, enter it at the hidden prompt with
`trident config set llm.openai_api_key`, or inject `OPENAI_API_KEY` from an
approved secret store. Avoid writing a key as a PowerShell command argument.
To use a per-scan endpoint instead of the environment value:

```powershell
trident scan . --backend openai --openai-base-url "http://127.0.0.1:8000/v1" `
  --model security-expert
```

## Linux and macOS shells

Set variables for the current shell, or prefix them on a single command:

```bash
export TRIDENT_LLM_BACKEND=openai
export OPENAI_BASE_URL=https://llm-gateway.example.com/v1
export EXPERT_MODEL=security-expert
trident scan .
```

Persist the endpoint with `trident config set llm.openai_base_url URL`. For a
one-command override, use `--openai-base-url`. CLI values take precedence over
environment variables, persisted configuration, and defaults. Environment
values take precedence over persisted configuration. The default base URL is
`https://api.openai.com/v1`.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Connection refused | Confirm the gateway is listening on the host and port, the route is reachable from the machine running Trident, and a firewall allows the connection. |
| DNS resolution fails | Check the hostname from the same shell and network context used by Trident. Confirm VPN or internal DNS access. |
| Certificate verification fails | Check certificate validity, hostname match, system trust, and the configured enterprise CA bundle. Do not disable TLS verification. |
| HTTP 401 or 403 | Check the key with the gateway administrator. Re-enter it through the hidden prompt or provide it through the approved secret environment. `config get` masks the stored value. |
| HTTP 404 | Confirm the base URL includes the correct API prefix, such as `/v1`, and that the gateway exposes the required route. |
| Model not found | Confirm the exact alias is enabled at the gateway. Trident sends the alias unchanged. |
| Invalid response or unsupported format | Check whether the service supports the response structure and options used by the failing review operation. Inspect sanitized Trident errors and gateway-side diagnostics. |
| Request timeout | Check gateway load, model startup time, route capacity, and `LLM_TIMEOUT`. Increase the timeout only when the gateway needs more time. |

Inspect `trident config get llm.openai_base_url` and
`trident config get llm.expert_model` to verify effective configured values
and their source. Secret values remain masked. Run a small authorized scan
and check the gateway's request log to confirm that the intended API route and
model alias were used.

## See also

- [LLM backends](LLM_BACKENDS.md) for Ollama and Anthropic configuration.
- [Configuration](CONFIGURATION.md) for all settings and precedence.
- [Privacy](PRIVACY.md) for prompt data and local retention.
- [Troubleshooting](TROUBLESHOOTING.md) for scanner and scan failures.
