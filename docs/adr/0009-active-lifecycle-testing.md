# ADR 0009: Bounded active lifecycle testing

**English** | [简体中文](../zh-CN/adr/0009-active-lifecycle-testing.md)

Status: Accepted

## Decision

Add versioned declarative test suites, revisioned per-product plans, asynchronous pre-deployment runs and opt-in recurring operation runs. Execute through the gateway with an internal administrator-authorized application identity. Preserve grants, revocation, credential policy, transport restrictions and fail-closed audit admission. Do not expose this identity mechanism over HTTP. Label synthetic operations separately.

Separate test suites from rule packs. Execute bounded literal checks without scripts, regexes, LLM judges or inference retries. Reuse the rule engine with retained product/gateway facts and server-owned testing facts. Unknown evidence cannot become a pass. Pin source versions and compare matching configurations.

Reserve private bounded evidence before model I/O and recover unfinished jobs as inconclusive. Raw assistant text requires explicit plan opt-in, separate from call records. Replay recomputes rules without model requests. The NIST AI RMF 1.0 mapping is draft, partial support with human review, not certification or framework-wide satisfaction.

## Consequences

Administrators can test configured endpoints and periodically retest during operation without a new frontend or runtime dependency. Enabled plans may incur provider costs. See [Active assessment](../active-assessments.md) for limits. Browser interactions, semantic detectors, production content monitoring, stakeholder feedback, incident response and release approvals remain separate capabilities. This extends ADR 0001's initial gateway-first scope.

## Extension: two target plans per product

A product now supports one model plan and one read-tool plan, counting any original default plan. Named plans use explicit IDs, independent revisions/schedules and shared per-product concurrency. Current product reports merge the two separate evidence namespaces; each run remains about its own plan. Legacy default plans and run serialization remain compatible. See [combined application assessment](../application-assessments.md).
