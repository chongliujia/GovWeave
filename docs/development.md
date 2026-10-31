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
| `internal/governance/` | Product profiles, gateway evidence adapter, bounded event worker and freshness-aware latest results |
| `internal/compliance/` | Declarative plugin loading, typed evidence, applicability and advisory technical assessments |
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

## Read-tool verification

`python3 tests/tool-client-test.py` checks the standard-library Python reference client without opening network connections: backend-bound identity, argument validation, output evidence consistency, response bounds, redirect rejection and sanitized errors. `make demo-agent` runs that client against the real gateway and scripted provider, then evaluates and archives three rule-pack stages. `python3 tests/agent-smoke.py` verifies retained historical findings and replay without provider calls. Python is an example/test dependency, not a gateway runtime requirement.

`make demo-tools` builds the gateway and runs a local read service through the real HTTP API. `python3 tests/tools-smoke.py` additionally verifies the fixture protocol. No model API key is needed. Unit tests cover pre-execution grants, key changes during body reading, credential output blocking/observe, immutable in-flight snapshots, invalid and oversized output, timeouts, and audit failure before admission or output release. See [Read-tool governance](tool-governance.md).

## Canary measurement

`make validate-canary` measures the frozen labelled corpus without network access; exit success means measurement completed, not zero misses. After building, `python3 tests/canary-smoke.py` separately verifies random marker injection and encoded exposure through the real binary and a local fixture. See [Canary validation](canary-validation.md).

`make benchmark-canary` separately measures exact, normalized, one-layer and two-layer stages on both corpora with one/two workers. Quality counts unique cases once; timed replay records local call P50/P95/P99 and private fresh reports. See [Canary benchmark](canary-benchmark.md) for the measurement boundary, parameters and interpretation.

## Active assessment verification

`make demo` runs the reusable scripted support application and exports actual synthetic assessment results. `python3 tests/demo-smoke.py` verifies batch/interactive behavior and the fixture's input boundaries. See [Local demonstration](local-demonstration.md).

After `make build`, run `python3 tests/active-smoke.py` for both lifecycle phases, regressions, persisted periodic execution after restart, private evidence and replay without inference, using the real binary and a local mock model. `--output-dir dist/active-demo/new-run` retains synthetic results. See [Active assessment](active-assessments.md).

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
| `GOVWEAVE_TEST_PORT` | Alternate gateway test port for `browser-smoke.cjs`; default `18081` |
| `GOVWEAVE_TEST_BINARY` | Candidate executable instead of `bin/govweave` |
| `NODE_PATH` | Optional path to separately installed development dependencies |

The script starts its own gateway and mock provider, exercises the console, restarts the gateway to verify persistence, and cleans up its processes and temporary data. It covers initial password setup, login/logout, validation, concurrent edits, configuration export, model connections, application grants and key changes, actual inference, request details, policy enforcement, and desktop/mobile layouts.

Language checks verify English defaults even with a Chinese browser locale, Chinese switching, preference persistence, storage-disabled fallback, draft preservation, one-time key preservation, and localized messages. The test also checks that the browser makes no external requests, that secrets are not stored in localStorage/sessionStorage, and that session cookies have the intended properties.

Screenshots are saved under the ignored `dist/browser-smoke/` directory. They use synthetic fixtures and exclude real credentials. Review screenshots when changing layout; a test pass alone does not establish good visual design.

Run `node tests/onboarding-smoke.cjs` with the same browser dependencies for the application onboarding flow. It uses dynamic loopback ports and an isolated gateway with a synthetic model provider. It checks model selection, non-streaming examples, configuration checks without provider I/O, application-key identity, one explicit inference with a matching audit record, invalid responses, missing evidence, output blocking, cancellation, key clearing and bilingual mobile layouts. Reports and screenshots go to a fresh private directory under `dist/onboarding-smoke/`. This test does not exercise Docker or a real model provider.

`node tests/evidence-smoke.cjs` uses the same development-only browser dependencies and dynamic loopback ports to check opt-in content capture, original blocked output, redacted/raw review with access records, application isolation, protected mutations, prepared output, caller-declared trace relationships, restart persistence and private storage. It also checks complete and prematurely ended SSE streams, bounded content and frame manifests, metadata mode, and bilingual stream timelines. Task evidence tests cover explicit multi-application scope, missing captures, capture drilldown, and late responses after a scope change. Snapshot checks cover changed-view rejection, exact-scope historical reads after restart, JSON byte checksums, Markdown downloads and stale-response download-link clearing. Go tests additionally cover content expiry, file tampering, wrong keys, unsafe permissions and archive capacity. It saves metadata-only test reports and screenshots under a fresh `dist/evidence-smoke/` directory and removes its synthetic content vault afterward. No real provider or Docker deployment is exercised. See [Risk evidence](risk-evidence.md) for capture and integrity limits.

`go test -run '^$' -bench '^BenchmarkEvidenceCapture$' -benchtime=20x -benchmem ./internal/gateway` measures the local evidence vault alone for disabled, metadata and full modes, with four 8 KiB or near-1 MiB objects per capture. The fixed 20-operation limit avoids measuring capacity exhaustion. Enabled modes include HMAC, serialization, encryption and synchronous disk writes. These serial means exclude the model, ordinary audit, detectors and networking; they are not P95/P99 or an end-to-end SLA. Full capture adds storage latency and memory allocations.

`go test -run '^$' -bench '^BenchmarkEvidenceStreamFrames$' -benchtime=100x -count=3 -benchmem ./internal/gateway` separately compares SSE parsing with evidence capture disabled, metadata only and full capture. Each iteration processes 32 or 1,024 frames of 1 KiB plus a completion marker, with a 64 KiB content cap. It includes frame parsing, manifests, incremental HMAC and bounded in-memory retention, but excludes network I/O, model time, policy checks, ordinary audit and final vault writes. These serial CPU/allocation samples do not measure first-token latency or concurrent production throughput.

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

`internal/gateway/policy_test.go` covers disabled defaults, observe/block behavior, scope intersection, JSON escapes, duplicate fields, tool arguments, rule selection, zero upstream calls for blocked ordinary/SSE requests, clean streaming, privacy, concurrent snapshots, revision conflicts, failed saves, and invalid persisted state. Server tests cover policy API authentication, strict JSON, origin rules, and stale writes. History tests in `internal/gateway/policy_history_test.go` cover immutable reads, stable pagination, restart persistence, legacy migration, missing revisions, corruption, failed writes, and capacity limits. Browser tests exercise real policy saves, historical request snapshot inspection, missing-history retry, language switching, and restart persistence.

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

MCP execution, comprehensive reviewed regulatory coverage, production-scale performance, HA, and comprehensive live-provider compatibility have not been implemented or validated. A local mock test is evidence for the behavior it exercises, not for every enterprise deployment.

Compliance tests cover three-valued logic, applicability, exact decimal comparisons, evidence freshness/provenance/types, invalid expressions, plugin isolation and startup failures, version pinning, concurrent evaluation, and authenticated API boundaries. Evidence fixtures are synthetic. A narrow source-backed EU draft tests routing and manual/evidence distinctions; no comprehensive or reviewer-approved legal coverage is claimed. Governance tests cover product persistence, revision conflicts, runtime override rejection, coalesced events without polling-triggered repair, source invalidation, evidence expiry, restart and missing-pack behavior. The local smoke test also checks the registered-product pipeline, EU draft findings, immutable captures, fixed-time replay, plugin/profile changes and restart. Archive tests cover private persistence, corruption, bounds, write failures, concurrent capture and unsupported evaluator versions.

`make validate-routing` measures the fixed fast/deep policies through the version-pinned detector registry on the fresh 60-case corpus. It records authored-label quality and reference agreement separately; gate-skipped deep work remains unknown. See [Detector plugins and routing](detector-routing.md) for the interface, source-freeze process, invocation counts and timing boundary.

`make validate-sensitive` compares immutable v1/v2 detectors on the original 80-case and new 64-case frozen synthetic sets without provider calls. `make demo-sensitive` checks both plain v1 and obfuscated v2 real HTTP enforcement using local model fixtures. Only the explicit `python3 scripts/demo-sensitive.py --kimi` opt-in sends three short synthetic requests to Moonshot and prompts for its key without echo; it uses temporary encrypted configuration and writes metadata-only results. See [sensitive output](sensitive-output.md).

`make demo-output-governance` verifies the draft sensitive-output pack with eight model calls, two tool calls, 11 retained reports and replay without provider I/O. Go tests cover unavailable/missing evidence, scope/category gaps, old revisions, the maximum fact budget and background reassessment without read-triggered repair. See [the pack guide](sensitive-output-governance.md).

`python3 tests/redaction-smoke.py` verifies the real reference client against local HTTP tool redaction, whole-output credential replacement, independent blocking, unknown handling and audit privacy. The detector corpora and frozen source identities are unchanged by redaction.

`make demo-output-assessment` verifies 35 local model calls, eight active runs and nine product reports under sensitive-output pack 1.1.0. See [active output-control assessment](output-control-assessments.md).

`make demo-tool-assessment` verifies 43 local tool calls, ten active runs and nine reports under `sensitive-tool-governance@1.0.0`, including permission drift and legacy credential-block precedence. See [active read-tool assessment](tool-control-assessments.md).

`make demo-application-assessment` verifies two named plans in one product, 38 local calls, nine runs and nine reports. It checks plan-specific evidence invalidation, shared policy invalidation and replay. See [combined application assessment](application-assessments.md).

`make evaluate-agent` runs 12 frozen synthetic cases in permissive/protected conditions, preserving separate development/evaluation metrics and actual request-ID traces. `python3 tests/knowledge-agent-test.py` tests proposal validation, terminal denial, limits, privacy, failures and unknown-rate accounting. See [knowledge Agent evaluation](knowledge-agent.md).

`make evaluate-agent-controls` runs the separately frozen v2 corpus with original and additional controls. The latter enables explicit tool-instruction checking and exact public-email permissions. Keep both report groups, including the quoted-training false block.

`make evaluate-agent-reviews` separates instruction v1, v2, and v2 plus exact-document permission effects on frozen v3 cases. `python3 tests/document-review-test.py` checks the bounded local review-metadata helper. Detector versions and review settings are explicit; use all three reports to distinguish syntax coverage from operator permissions.

`make accept-agent` runs all seven frozen acceptance cases under three protected profiles. `python3 tests/agent-acceptance-test.py` checks planned denominators, attribution, global admission budgets, private credential files and sanitized provider preflight without external calls. The acceptance entry also supports bounded repeats and an explicit live mode; local and bounded Moonshot observations are documented separately. Pacing is tested with a fake clock and a real local HTTP run; no automatic retries are added. See [Agent acceptance](knowledge-agent.md#bounded-acceptance-across-three-profiles).

`make validate-sensitive-v3` measures the frozen 45-case format/encoding corpus with v2 and v3, then v3 against both historical corpora. V1/v2 sources remain frozen; new implementation lives in `internal/sensitive/v3.go`, selected through the `Scan`/`Supports` registry. `go test ./internal/sensitive -run '^$' -fuzz FuzzV3BoundedFindings -fuzztime=5s -parallel=2` checks arbitrary-input offsets and bounds. The acceptance runner accepts `--sensitive-detector sensitive-text-v3`; its default stays v2.

`make validate-task-grading` measures frozen scorer fixtures without model calls. `python3 tests/task-grading-test.py` covers the development partition, evidence prerequisites, bounds and metadata privacy. The acceptance report retains literal scoring and adds `task-facts-v1` as a separate assessment; preserve its [source freeze](../tests/testdata/task-grading-v1-source-freeze.json) when adding future grading versions.

`python3 tests/support-agent-test.py` verifies the independent support application, private traces, credential separation, evidence attribution, call admission and actual local knowledge-service authentication. It requires temporary loopback ports. `make demo-support-agent` runs the nine-case trial and 20 local timing pairs; the known hexadecimal failure produces exit 3. See the [trial guide](support-agent-trial.md) for separate local/live evidence.

`make demo-multi-agent-trace` runs a synthetic Python/Node process example through an isolated local gateway: five tool calls, three upstream reads, two denials, a join, a retry and application-isolated queries. `python3 tests/trace-client-test.py` checks immutable propagation, per-call and per-Agent-run isolation, server receipts and model → tool → model chaining. Go tests cover all three correlated endpoints, authorization changes, audit failures, retained history, restart and record-size limits. These checks do not establish framework compatibility or full-task correctness. See [heterogeneous Agent tracing](agent-tracing.md).

The optional [real-framework trial](framework-tracing-trial.md) pins LangGraph and Pydantic AI in an isolated environment. After installing its requirements, run `make trial-framework-trace FRAMEWORK_PYTHON=/path/to/venv/bin/python`. Use that interpreter for `tests/async-trace-client-test.py`, `tests/framework-adapters-test.py` and `tests/framework-trial-test.py`. The latter checks failure cleanup, full-queue shutdown and private failure reports. This suite does not add framework dependencies to the Go runtime or ordinary Python examples.
