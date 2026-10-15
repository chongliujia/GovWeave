# GovWeave

**English** | [简体中文](README.zh-CN.md)

An open-source, self-hosted AI governance gateway for model access, request credential checks, and metadata-only call records.

Deploy GovWeave on your own infrastructure, connect an OpenAI-compatible model endpoint, and give each application its own key and model grants. Applications use your gateway URL and an administrator-defined model alias. No GovWeave cloud account is required.

**Status: 0.2.0-dev preview.** The current implementation is a single-process, single-organization gateway. It is not a complete GRC platform or a legal compliance certification service.

## What works today

| Capability | Current behavior |
| --- | --- |
| Model connections | Configure an upstream base URL, credential, model ID, and service alias |
| Application access | Issue, rotate, and revoke application keys; grant access to specific connections |
| Model API | `POST /v1/chat/completions` with JSON or SSE; `GET /v1/models` |
| Runtime policies | Local request checks for private key markers and selected API key patterns; disabled, observe, or block |
| Request records | Request ID, authorization, policy revision and matches, execution outcome, and timing; no prompt or response bodies |
| Administration | Set an initial administrator password; use a browser session to manage the instance |
| Languages | English by default, with an offline Simplified Chinese option |
| Distribution | Go binary, locally built container image, and offline archive |

General PII detection, response content checks, MCP tool execution, approval workflows, EU/US regulatory mappings, SSO, and high availability are **not implemented**. See [supported interfaces and limits](docs/model-gateway.md).

## Quick start

Run these commands from the repository root. Building from source requires Go 1.24 or later; this repository's Docker build pins Go 1.26.9. No database, Node runtime, or frontend build is required to run the gateway.

```bash
go run ./cmd/govweave -config examples/deployment.json
```

Open **http://127.0.0.1:8080**. The example configuration stores data in `./data`.

1. Set and confirm the initial administrator password, using 12–128 characters. There is no default password. Complete setup before opening access to other users.
2. Under **Deployment & access**, set the organization name and the root URL applications can reach. For this local setup, use `http://127.0.0.1:8080`.
3. Under **Model connections**, add your provider's base URL, actual model ID, and a service alias such as `internal-assistant`. Supply an upstream key if required. Explicitly allow HTTP only when using an unencrypted provider on a trusted network.
4. Under **Applications & keys**, create an application, select its allowed models, and save the one-time application key.
5. Under **Deployment & access**, select that application to obtain an example with your actual base URL and an authorized alias.
6. Send a request and open **Request logs** to inspect the result. A connection check only reads the upstream model list; it does not test inference.

Alternatively, with Docker and Compose installed:

```bash
docker compose build
docker compose up -d --no-build
```

Compose also publishes http://127.0.0.1:8080 by default. Use one startup method at a time. Its data lives in a named Docker volume, separate from the source-run `./data` directory. See [deployment](docs/deployment.md) for remote access, HTTPS, persistent storage, and offline installation.

## Make an application request

Set the following in the application's environment:

| Variable | Value |
| --- | --- |
| `GOVWEAVE_BASE_URL` | The gateway root URL plus `/v1`, for example `http://127.0.0.1:8080/v1` |
| `GOVWEAVE_API_KEY` | The application's key, not the administrator password or upstream credential |

These are **application-side conventions**, not gateway server configuration variables. The alias below must exist and be granted to the application.

```bash
curl --fail-with-body "${GOVWEAVE_BASE_URL%/}/chat/completions" \
  -H "Authorization: Bearer $GOVWEAVE_API_KEY" \
  -H "Content-Type: application/json" \
  --data '{"model":"internal-assistant","messages":[{"role":"user","content":"Summarize this document."}],"stream":false}'
```

See [application and agent integration](docs/model-gateway.md#application-and-agent-integration) for a Python SDK example, streaming behavior, and the tool execution boundary.

## Request protection and data handling

In **Runtime policies**, configure the built-in credential egress policy. It starts **disabled**. **Observe** records matching rule IDs and forwards the request, including matched credentials. **Block** rejects matching requests before contacting the model provider. Both application and model scopes must match.

Checks run locally. Audit records exclude prompts, responses, matched secrets, and raw upstream errors. Configuration and records stay in your data directory; allowed requests are sent to the model provider you configure. Self-hosting the gateway does not make a cloud model local.

Upstream credentials are encrypted with a local key; application keys are stored as hashes and identifying prefixes. The current record store is not tamper-evident. A rule match or lack of matches is not a legal compliance determination. Read [runtime policies](docs/runtime-policies.md) before enabling enforcement.

## Documentation

- [Documentation index](docs/README.md)
- [Deployment, backup, recovery, and troubleshooting](docs/deployment.md)
- [Model API, application integration, and request records](docs/model-gateway.md)
- [Runtime policy configuration and detection limits](docs/runtime-policies.md)
- [Development and verification](docs/development.md)
- [Architecture decisions](docs/README.md#architecture-decisions)
- [OpenAPI contract](api/openapi.yaml) and [JSON schemas](schemas/)

## Development

```bash
make test
make check
make build
make package
```

`make test` runs Go's race detector and needs a C compiler and permission to listen on local test ports. `make check` also needs Node for JavaScript validation. Browser, SDK, and container tests are documented separately; their dependencies are development-only.

English is the default documentation language. Chinese documentation lives in `README.zh-CN.md` and `docs/zh-CN/`. Keep examples and capability statements consistent with the code and API contracts.

## License

[Apache-2.0](LICENSE). Distribution dependency notices are in [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES).
