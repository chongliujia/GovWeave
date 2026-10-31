# Model gateway and application integration

**English** | [简体中文](zh-CN/model-gateway.md)

The current gateway implements one OpenAI-compatible Chat Completions adapter. It uses Go's standard HTTP transport for connection pooling, TLS, timeouts, and cancellation. It does not provide automatic model selection, billing, protocol conversion, or a general agent runtime.

For the Docker-to-first-call workflow and non-streaming examples, start with [Application onboarding](application-onboarding.md). The console can check application identity and policy configuration locally, then run one explicit model request and match its audit record.

## Connections, aliases, and identities

A **connection** binds an upstream base URL and model ID to a unique service alias. An **application** has its own API key and explicit grants to connection IDs. An empty `allowed_connections` list denies all model access and supports a [tool-only application](tool-governance.md). Model requests authenticate with that application key and specify an allowed alias.

For example:

| Setting | Example |
| --- | --- |
| Gateway root URL | `https://ai.example.com` |
| Application base URL | `https://ai.example.com/v1` |
| Upstream base URL | `http://model-server:8000/v1` |
| Upstream model ID | The model ID served by your provider |
| Application-facing alias | `internal-assistant` |

The hostname examples are placeholders. The gateway appends `/chat/completions` or `/models` to the upstream base URL. Keep any provider base path such as `/v1`; do not append the operation path yourself. The gateway does not discover or guess API versions.

Use separate connections for multiple models from one provider. An alias is configured by your administrator; names such as `internal-assistant` do not invoke an automatic router. Changing an alias requires updating callers. Grants and policy scopes reference the connection ID, so editing that connection's target changes where future authorized calls go.

Three credentials serve different purposes:

| Credential | Used by | Purpose |
| --- | --- | --- |
| Administrator password and session | Operators | Configure the instance through the console or management API |
| Application API key | Application backend or agent model client | Call an authorized model through GovWeave |
| Upstream provider credential | GovWeave's HTTP transport | Authenticate with the configured provider |

Application keys are displayed once on creation or rotation. Rotation invalidates the old key; revocation disables application access. Grant edits, key changes, and connection disabling affect subsequent admission checks. Already admitted requests continue with their accepted configuration.

## Supported interfaces

| Interface or feature | Implemented behavior |
| --- | --- |
| `GET /v1/models` | Lists enabled aliases granted to the calling application; no upstream request |
| `GET /v1/integration/check?model=<alias>` | Checks the authenticated application's model grant and local policy/audit status; no provider request or call record |
| `POST /v1/chat/completions` | Requires a model alias, a non-empty array of message objects, and an optional boolean `stream`; other JSON parameters pass through |
| Ordinary response | Reads bounded JSON and validates a `choices` array; returns the provider's response |
| Streaming response | Accepts SSE, validates and forwards bounded complete events, and requires `[DONE]` for successful completion |
| `tools` / `tool_calls` in Chat Completions | Passthrough without output protection; protected mode supports only the declared read_resource contract. This endpoint never executes tools |
| `POST /v1/tools/{alias}/invoke` | Separate [controlled read-tool adapter](tool-governance.md); explicit application/resource grants and credential output checks |
| Administrator connection check | Calls upstream `GET /models` and checks for the configured model ID; no inference |
| Responses, Embeddings, Realtime, native Anthropic, Azure-specific authentication, MCP | Not implemented; reserved model/MCP paths return `501` |

Upstream responses can expose the actual provider model name. The gateway rewrites the request's model alias but does not normalize every provider response field or model-specific option.

Compatibility claims are limited to the implemented behavior and tests. The checked-in SDK smoke test has been run with OpenAI Python SDK 1.53.0 against local mock providers. This is not certification of every SDK version, provider, model, or framework.

## Application and agent integration

Configure the application's existing model client with:

- Your gateway base URL, ending in `/v1`.
- An application API key issued by GovWeave.
- A service alias granted to that application.

The following environment names are conventions for your application, not server settings:

```bash
export GOVWEAVE_BASE_URL='http://127.0.0.1:8080/v1'
export GOVWEAVE_MODEL='internal-assistant'
```

Supply `GOVWEAVE_API_KEY` through your application's environment or secret-management system. Use an actual reachable enterprise URL for remote callers. Keep application keys in your backend rather than browser-delivered code.

### Python SDK

Use an installed OpenAI Python SDK that supports the Chat Completions interface. This example follows the same client calls exercised by `tests/sdk-smoke.py`:

```python
import os
from openai import OpenAI

with OpenAI(
    base_url=os.environ["GOVWEAVE_BASE_URL"],
    api_key=os.environ["GOVWEAVE_API_KEY"],
    max_retries=0,
    timeout=130.0,  # Example for a connection with a 120-second upstream timeout.
) as client:
    stream = client.chat.completions.create(
        model=os.environ.get("GOVWEAVE_MODEL", "internal-assistant"),
        messages=[{"role": "user", "content": "Summarize this document."}],
        stream=True,
    )
    for chunk in stream:
        if chunk.choices:
            print(chunk.choices[0].delta.content or "", end="", flush=True)
```

For an ordinary response, set `stream=False` and read `response.choices[0].message.content`. The connection's upstream timeout is configurable from 1 to 300 seconds. Coordinate client and proxy timeouts with that setting and allow for local checks and storage latency.

The example disables SDK retries. Client retries can still produce repeated inference or charges; the gateway has no idempotent result cache and does not automatically replay inference POSTs.

### Any HTTP client

Go, Rust, TypeScript, and other clients can use the same HTTP endpoints without a GovWeave-specific SDK. List the application's available aliases:

```bash
curl --fail-with-body "${GOVWEAVE_BASE_URL%/}/models" \
  -H "Authorization: Bearer $GOVWEAVE_API_KEY"
```

Send a streaming request with curl's output buffering disabled:

```bash
curl --no-buffer --fail-with-body "${GOVWEAVE_BASE_URL%/}/chat/completions" \
  -H "Authorization: Bearer $GOVWEAVE_API_KEY" \
  -H "Content-Type: application/json" \
  --data '{"model":"internal-assistant","messages":[{"role":"user","content":"Summarize this document."}],"stream":true}'
```

### Agents and MCP

An agent can route its **model requests** through GovWeave if its client supports a configurable OpenAI-compatible base URL and the supported Chat Completions interface. Frameworks that require Responses, a native provider protocol, or another authentication format are outside the current adapter.

Passing `tools` or `tool_calls` through the model API does not put the later action behind GovWeave. To govern a read tool, the application or Agent platform must explicitly send its invocation through [the read-tool endpoint](tool-governance.md). Other tools, direct upstream calls, and write actions remain outside this boundary.

The [bounded knowledge Agent](knowledge-agent.md) executes the supported read_resource proposal through this authorized tool endpoint and correlates model/tool request IDs without retaining content.

The model-request credential policy can inspect tool argument text present in that request. It does not inspect model response content or automatically intercept subsequent tool operations. The separate read-tool adapter checks its own returned text. Neither path acts as an MCP server/proxy or records a complete agent trace. The generated `/mcp` address is a planned endpoint and currently returns `501`. There is no separate GovWeave Python, Go, Rust, or TypeScript SDK package to install in this release.

## Upstream transport

The gateway supplies only its configured provider Bearer credential, Content-Type, Accept, a fixed User-Agent, and a generated request ID. It does not forward the application's Authorization header, cookies, arbitrary headers, or idempotency header. It does not follow upstream redirects or automatically retry inference POSTs.

Administrator-configured private and loopback provider addresses are allowed. Link-local, multicast, and unspecified addresses are rejected; DNS results are checked again before connecting to the selected IP. These checks are not a replacement for an enterprise network egress policy.

HTTPS verifies provider certificates using trusted CAs. Private CA configuration is described in [deployment](deployment.md#container-deployment). The transport does not use proxy environment variables. An unencrypted HTTP provider requires the administrator's explicit HTTP opt-in.

## Streaming, timeouts, and errors

A stream is forwarded one complete SSE event at a time, without waiting for the full model answer. Each event is validated before forwarding so malformed or error events do not expose raw upstream error details. Cancellation propagates to the upstream request.

The configured 1–300 second timeout covers the upstream call and response reading. It starts after request checks and the initial audit write, so it is not an end-to-end latency guarantee. The transport also has a 30-second response-header timeout. Server request reading is bounded by a 15-second read timeout.

Before a response starts, errors use a structured JSON envelope with a stable `error.code` and a request ID. The response includes `X-Request-ID` for looking up call records.

| HTTP status | Typical `error.code` | Meaning |
| --- | --- | --- |
| `400` | `invalid_request` | Invalid alias/messages/stream structure |
| `401` | `invalid_api_key` | Missing, invalid, or revoked application key |
| `403` | `model_not_allowed`, `connection_disabled` | Access is not granted or the connection is disabled |
| `403` | `policy_blocked` | Credential policy matched in block mode; no upstream call |
| `413` | `request_too_large` | Request exceeds 1 MiB |
| `415` | `unsupported_media_type` | Use `application/json` |
| `429` | `gateway_busy` | All execution slots are occupied |
| `502` | `upstream_unreachable`, `upstream_error`, `invalid_upstream_response`, `response_too_large` | Provider, protocol, or response-size failure |
| `503` | `audit_unavailable`, `credential_unavailable`, `policy_unavailable` | Required logging, credential access, or request checking is unavailable |
| `504` | `upstream_timeout` | Upstream request timed out |

Upstream `400`, `422`, and `429` responses keep their status but use a fixed `upstream_error` message instead of exposing the provider's raw error body. Refer to [OpenAPI](../api/openapi.yaml) and the returned error code for programmatic handling; the table is not an exhaustive list of every transport outcome.

After streaming headers have been sent, the HTTP status cannot change. A timeout, error event, premature EOF, or limit violation aborts the stream and records failure. **HTTP 200 alone does not mean a stream completed successfully.** Clients must handle read errors and incomplete output. There is no output-content policy and previously delivered content cannot be recalled.

For SSE behind a reverse proxy, disable response buffering and use suitable timeouts. GovWeave sets `X-Accel-Buffering: no`, but the actual proxy configuration still determines delivery behavior.

## Request credential policy

The optional [credential egress policy](runtime-policies.md) runs after model access authorization and before upstream I/O. It is disabled by default and supports scoped observe/block modes. For stream requests, a block returns ordinary JSON with `403 policy_blocked`; no SSE stream starts.

Access authorization and credential checking are independent. A record may show `decision: allow` together with `content_policy.result: block`: the application was authorized for the model, but its request matched a blocking rule.

## Request records and archival

`calls.jsonl` stores fixed metadata: request ID, known application and connection IDs, configured alias, configuration revision, operation, access decision, outcome, status codes, upstream-attempt flag, streaming flag, timing, fixed error code, and optional credential-policy or read-tool governance assessments. Tool records include the tool ID, revision and metadata hash, authorization, configured sensitivity, fixed content-rule IDs and decision reasons; resource IDs and text are excluded.

It excludes prompts, responses, matched secrets, arbitrary headers, upstream URLs, and raw provider errors. Unknown or unauthorized caller-supplied aliases are not logged. The start and finish events share a request ID.

Before upstream I/O, the gateway synchronously appends and syncs a start event and reserves capacity for the finish event. A blocking policy result follows the same start/reservation process. If this step fails, the gateway returns `503` without contacting the provider. For model calls, if a finish write fails after a response has been sent, that response cannot be recalled; the service reports incomplete audit coverage and stops further upstream requests.

After a crash, an unmatched start event is shown as an unknown/incomplete outcome. It is not reported as a successful model call. Historical records without a credential assessment remain readable and show the policy as not evaluated.

### Reading a record

| Field | Meaning |
| --- | --- |
| `decision` | Access authorization: `allow`, `deny`, or `not_evaluated` |
| `policy_revision` | Legacy field name for the connection/application configuration revision |
| `content_policy.revision` | Independent credential policy revision actually used for this request |
| `content_policy.ruleset_version` | Version of the compiled detector definitions |
| `content_policy.result` | Disabled, outside scope, no matches, observed match, block, or error |
| `content_policy.check_duration_us` | Local policy snapshot and evaluation time, in microseconds |
| `upstream_attempted` | Whether the gateway attempted the provider request |
| `duration_ms` | Request handler duration, including local work and upstream processing |
| `first_byte_ms` | Time from request start to the first upstream body read, including local overhead |

The management API returns up to 100 of the latest 1,000 indexed records and supports application filtering. The console's overview uses the latest 100 records; it is not a full historical or daily analytics system.

This is an operational record store, not a tamper-evident evidence repository. Credential policy snapshots can be resolved by `content_policy.revision` through the [policy history API](runtime-policies.md#policy-history-and-migration). There are no signatures, hash chains, WORM storage, complete administrator change history, connection/application configuration history, or legal-control mappings.

### Capacity and archival

The record file is limited to 128 MiB. Monitor `available`, `bytes`, and `max_bytes` in `GET /api/v1/requests`. Near capacity, or when durable writes fail, new upstream requests stop. Unauthenticated attempts also generate bounded metadata, so account for unwanted traffic in capacity planning.

To archive: stop the service, copy `calls.jsonl` to protected archival storage, verify the copy, then move the active file out of the data directory and restart. Preserve private permissions. The new active file starts empty; archived records are not indexed by the console. There is no automatic deletion or retention scheduler.

## Fixed limits

| Resource | Limit |
| --- | --- |
| Model connections | 256 |
| Applications | 1,024 |
| Credential policy | One built-in policy; up to 64 selected application IDs and 64 selected connection IDs, or all |
| Concurrent execution slots | 64, shared by policy checks/upstream model calls and connection checks |
| Application request body | 1 MiB |
| Ordinary upstream response | 8 MiB |
| SSE event / total stream | 1 MiB / 64 MiB |
| Persisted connection/application configuration | 4 MiB |
| Management mutation body | 16 KiB |
| Audit file / in-memory index / response page | 128 MiB / 1,000 records / 100 records |

Synchronous audit writes add storage latency before upstream execution. Streaming, cancellation, timeouts, and limits are covered by local tests; production concurrency, provider compatibility, and latency percentiles require deployment-specific validation. A detector microbenchmark is not an end-to-end SLA.

Optional [sensitive output protection](sensitive-output.md) adds a separate application-scoped policy for complete non-streaming assistant text. It canonicalizes supported JSON, checks up to 8192 UTF-8 bytes, and durably records the verdict before release. Protected streaming, tool-call completions and unsupported or incomplete output are withheld. The default disabled mode retains the forwarding behavior described above.
