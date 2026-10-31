# GovWeave contributor and coding agent guide

**English** | [简体中文](docs/zh-CN/contributing.md)

This guide describes the current repository. The original Chinese product and architecture draft is preserved in the [archive](docs/zh-CN/archive/initial-design.md); its Eval-first roadmap and assumed existing GRC product are superseded by the [architecture decisions](docs/README.md#architecture-decisions).

## Current scope

Build a self-hosted AI gateway for model access, controlled read-tool calls, local credential checks, optional bounded sensitive model/tool output protection and retrieved-instruction checks, metadata-only call records, and an independent declarative technical-control evaluator. See [Sensitive output](docs/sensitive-output.md) for the shared detector, application evaluation endpoint, policy history, and frozen validation boundaries. See [Read-tool governance](docs/tool-governance.md) for the application/Agent platform API, resource grants, output checks and execution boundaries. See [Compliance engine](docs/compliance-engine.md) and [Product assessments](docs/product-assessments.md) for runtime evidence. See [EU draft and report snapshots](docs/eu-transparency-reports.md) for the unreviewed narrow mapping, retained inputs and replay boundaries. See [Active assessment](docs/active-assessments.md) for bounded test execution, opt-in operation scheduling, private test evidence and partial NIST AI RMF lifecycle support. See [Canary validation](docs/canary-validation.md) for the narrowly scoped detector, frozen authored corpus, measured misses and evidence limits. The implementation is a single Go process with embedded HTML/CSS/JavaScript and private file storage. It has no existing GRC backend, Python runtime service, standalone GovWeave SDK, MCP executor, or regulatory enforcement catalog.

Use the [README](README.md), [development guide](docs/development.md), [OpenAPI contract](api/openapi.yaml), and accepted ADRs as the current references. Describe future features as planned rather than implemented.

[Heterogeneous Agent tracing](docs/agent-tracing.md) adds explicit bounded correlation to gateway calls. Application scope is authenticated; Agent labels and relationships remain caller declarations. Trace access must preserve application isolation, metadata-only storage and incomplete-history reporting.

[Risk evidence](docs/risk-evidence.md) separately supports explicit, application-scoped encrypted content capture. Keep original and prepared output distinct, preserve capture and detector versions, record privileged content access before release, and never copy vault content into ordinary audit records, graphs, reports or diagnostics. Capture is supplementary; unavailable content must remain unknown. Application-declared links and matching fingerprints are not independent causal proof.

## Working principles

- Complete a useful end-to-end behavior before broadening feature scope. Keep schemas, implementation, UI, examples, and documentation aligned.
- Preserve the separation between administrator identity, application keys, and upstream credentials. Model grants and credential scopes serve different purposes.
- Keep secrets, prompts, responses, arbitrary caller headers, and raw provider errors out of call records. Do not commit live instance data or credentials.
- Perform request blocking before upstream I/O. Respect the existing audit reservation and fail-closed logging behavior; do not replace it with silent event loss.
- Keep input, output, concurrency, and persistence bounded. Measure performance with representative payloads and distinguish detector timing from end-to-end latency.
- Use versioned, immutable policy snapshots. A technical check or access decision is not a legal conclusion. Any future regulatory interpretation and enforceable mapping need explicit provenance and human review.
- Preserve the offline runtime and embedded assets. Add dependencies only when their value justifies the installation and maintenance cost.
- Keep console and documentation defaults in English, with Simplified Chinese translations. Never translate user-provided names, aliases, identifiers, URLs, or secrets.
- Verify the changed behavior and meaningful failure cases. Report test scope and limitations accurately; synthetic fixtures are not production evidence.

## Documentation layout

`README.md` and unqualified `docs/*.md` files are canonical English. Chinese copies live in `README.zh-CN.md` and `docs/zh-CN/`. Maintain language links and update both versions for behavior, commands, and limits. Historical material under `docs/zh-CN/archive/` is explicitly marked as superseded.

For build commands, optional test dependencies, repository ownership, and release limitations, use [Development](docs/development.md). This guide does not replace the user's current task instructions.
