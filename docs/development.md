# Development and verification

**English** | [简体中文](zh-CN/development.md)

GovWeave currently uses the Go standard library and embedded HTML/CSS/JavaScript. There are no third-party Go modules, frontend package installation steps, or database services required to build the gateway. UI changes require rebuilding and restarting the Go executable.

## Prerequisites and commands

| Task | Requirements |
| --- | --- |
| Build or run | Go 1.24 or later; the repository's distribution build pins 1.26.9 |
| Go race tests | A C compiler and permission to listen on local ephemeral ports |
| Static checks | Go tools and Node for JavaScript syntax and translation checks |
| Browser smoke test | Playwright resolvable by Node and a Chrome executable |
| SDK smoke test | Python 3 with `openai` and `httpx` available |
| Container verification | Docker, Compose, and Python 3 |

From a source checkout:

```bash
make test
make check
make build
make package
```

| Target | Result |
| --- | --- |
| `make run` | Starts the source with `examples/deployment.json` |
| `make test` | Runs `go test -race ./...` |
| `make check` | Runs `go vet`, gofmt checks, JS syntax checks, and `tests/i18n-check.cjs` |
| `make build` | Produces `bin/govweave` with embedded console assets |
| `make package` | Produces an OS/CPU-specific binary archive and checksum in `dist/` |

Use a separate data directory and unused port when running a development instance alongside another instance. Do not point tests at real credentials or shared instance data. Integration fixtures create temporary data and local model servers; they do not call cloud models.

## Repository map

| Path | Responsibility |
| --- | --- |
| `cmd/govweave/` | CLI flags, startup, instance lock, and shutdown |
| `internal/config/` | Strict deployment parsing, environment overrides, and validation |
| `internal/instance/` | Saved instance settings and single-process file locking |
| `internal/auth/` | Password hashing, authentication, rate limits, and sessions |
| `internal/gateway/` | Connections, applications, credentials, transport, policy evaluation, streaming, and audit records |
| `internal/server/` | HTTP routes, management authorization, and static asset serving |
| `internal/server/web/` | Embedded console, styling, and local translation catalog |
| `internal/storage/` | Random identifiers and private atomic file writes |
| `api/` and `schemas/` | OpenAPI and JSON schemas |
| `tests/` | Browser, SDK, container, and locale smoke checks |
| `docs/adr/` | Accepted architecture decisions |

The historical product draft is [archived](zh-CN/archive/initial-design.md). Do not create its proposed Eval, GRC, Python, or TypeScript directory structure as if those components already exist.

## Go test coverage

Unit and local integration tests cover configuration precedence and validation, deployment-managed fields, revision conflicts, private persistence, invalid state, instance locking, password setup and migration, rate limits, session behavior, management authentication, and origin checks.

Gateway tests cover credential encryption and key hashing, model grants and revocation, normal and SSE forwarding, cancellation, timeouts, protocol errors, input/output limits, concurrency admission, audit reservations, interrupted-call recovery, privacy, and fail-closed behavior when durable logging is unavailable.

`go test -race ./...` needs loopback socket access because integration tests start real local HTTP servers. A sandbox that prohibits sockets cannot run these fixtures without the appropriate local permission. No external provider account is needed.

## Browser verification

The optional browser test uses an independent headless Chrome profile and Playwright; it does not automate a personal browser session. These dependencies are not included in the product runtime, image, or offline binary archive.

Make `require('playwright')` available to Node, for example through a separate development dependency directory and `NODE_PATH`. The local verification environment used Playwright 1.62.1. The default Chrome executable is `/usr/bin/google-chrome`.

```bash
make build
node tests/browser-smoke.cjs
```

| Environment variable | Purpose |
| --- | --- |
| `GOVWEAVE_BROWSER_PATH` | Alternate Chrome executable |
| `GOVWEAVE_TEST_PORT` | Alternate gateway test port; default `18081` |
| `GOVWEAVE_TEST_BINARY` | Candidate executable instead of `bin/govweave` |
| `NODE_PATH` | Optional path to separately installed development dependencies |

The script starts its own gateway and mock provider, exercises the console, restarts the gateway to verify persistence, and cleans up its processes and temporary data. It covers initial password setup, login/logout, validation, concurrent edits, configuration export, model connections, application grants and key changes, actual inference, request details, policy enforcement, and desktop/mobile layouts.

Language checks verify English defaults even with a Chinese browser locale, Chinese switching, preference persistence, storage-disabled fallback, draft preservation, one-time key preservation, and localized messages. The test also checks that the browser makes no external requests, that secrets are not stored in localStorage/sessionStorage, and that session cookies have the intended properties.

Screenshots are saved under the ignored `dist/browser-smoke/` directory. They use synthetic fixtures and exclude real credentials. Review screenshots when changing layout; a test pass alone does not establish good visual design.

## SDK verification

With the development-only Python packages installed:

```bash
make build
python3 tests/sdk-smoke.py
```

The script exercises the installed OpenAI Python SDK against a local gateway and mock provider. It verifies model listing, ordinary and streaming responses, authorization denial, key revocation, and metadata privacy. It uses no real API key and generates no provider charges.

The previously verified SDK version is 1.53.0. Run the test for any additional SDK version you intend to claim as supported. SDK and HTTP client packages are development dependencies, not gateway dependencies.

## Container verification

Build the image before running its smoke test:

```bash
docker compose config --quiet
docker compose build
python3 tests/container-smoke.py
```

The test creates a separate temporary Compose project and volume, then checks startup, password authentication, persisted settings and gateway records after restart, private credential responses, CA certificates, non-root/read-only execution, and startup without network access. It removes its test project and volume afterward.

Valid Compose YAML alone does not prove the image starts or that persistence works. Likewise, `--network none` only demonstrates isolated startup; it does not demonstrate inference against a model outside the container.

## Policy verification and performance

`internal/gateway/policy_test.go` covers disabled defaults, observe/block behavior, scope intersection, JSON escapes, duplicate fields, tool arguments, rule selection, zero upstream calls for blocked ordinary/SSE requests, clean streaming, privacy, concurrent snapshots, revision conflicts, failed saves, and invalid persisted state. Server tests cover policy API authentication, strict JSON, origin rules, and stale writes. Browser tests exercise real policy saves, evidence display, and restart persistence.

Run the detector benchmark without the test suite:

```bash
go test ./internal/gateway -run '^$' -bench BenchmarkCredentialPolicy -benchmem
```

This synthetic benchmark measures local policy evaluation. It excludes audit file sync, networking, model processing, and proxy overhead. Do not present its result as gateway throughput or an end-to-end latency SLA. Production testing should cover representative payloads, concurrent traffic, storage latency, failure behavior, and cancellation.

## Console and localization conventions

The console uses a light, compact layout with real configuration and request data. Empty instances show empty states. Overview counts come from the latest 100 request records; connection diagrams show configured relationships, not proven provider connectivity.

`internal/server/web/i18n.js` uses English message IDs and a centralized Simplified Chinese catalog. Supported locales are `en` and `zh-CN`, with English as the default. HTML explicitly marks product text using `data-i18n-parts` and translated attributes. JavaScript uses `t(message, values)`; dynamic values remain unchanged and are inserted through `textContent`.

Do not translate arbitrary user content or construct translated HTML with untrusted interpolation. Language switching should rerender labels and cached data without refetching configuration, clearing drafts, or discarding a displayed application key. Keep language controls usable inside native dialogs. All fonts and translation resources remain local.

When changing copy, update the English source and Chinese catalog together, then run:

```bash
node tests/i18n-check.cjs
```

This check is also part of `make check`. It verifies literal message coverage, English default markup, interpolation, unsupported-locale fallback, and behavior when preference storage is blocked.

## Documentation and change scope

English is the canonical documentation language. Use `README.md` and unqualified files in `docs/` for English; keep Chinese counterparts under `README.zh-CN.md` and `docs/zh-CN/`. Each maintained guide has a language switch linking to its counterpart. Update both versions when changing commands, supported behavior, storage, or limits.

Keep examples consistent with `api/openapi.yaml`, `schemas/`, and the actual code. Check relative links, heading anchors, and example syntax when editing docs. The offline packager includes both languages; verify archive contents if changing the documentation layout or packaging manifest.

Run checks appropriate to the change. Documentation edits generally need link/example/package verification, not a repeat of every runtime test. Changes to authentication, request admission, persistence, or forwarding require the relevant behavior and failure tests. Never report a check as passed if it could not run.

## Verification limits

Linux is the primary validated platform. macOS locking and packaging still need platform-specific testing; Windows is unsupported by the current lock implementation. No CI workflow is currently checked into this repository.

MCP execution, regulatory mappings, production-scale performance, HA, and comprehensive live-provider compatibility have not been implemented or validated. A local mock test is evidence for the behavior it exercises, not for every enterprise deployment.
