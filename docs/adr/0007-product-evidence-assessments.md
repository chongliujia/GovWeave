# ADR 0007: Registered products and gateway evidence

**English** | [简体中文](../zh-CN/adr/0007-product-evidence-assessments.md)

Status: Accepted

## Decision

Extend ADR 0006 with a bounded, private product registry. Bind each product to application IDs and one exact rule pack version. Persist administrative facts explicitly, reserve the `runtime.*` namespace for a gateway adapter, and distinguish administrative evidence claims from server-observed configuration and sampled call metadata.

Use nonblocking coalesced notifications after management changes and gateway operation completion, plus a periodic clock pass. Advisory assessment must not block inference or change audit reservation behavior. Recheck source revisions before publishing; invalidate cached assessments on source changes and known time boundaries. Pending/error responses must not carry an old passing assessment.

Keep latest reports in bounded memory and rebuild them at startup. Save profiles atomically with private permissions and revision conflicts. Preserve the metadata-only boundary: do not collect model text, credentials or arbitrary request headers. The request sample is the latest 100 global indexed entries, not a complete or per-product history.

## Consequences

Products can be assessed automatically against current gateway evidence. This is advisory continuous assessment with bounded scheduling intervals, not a latency guarantee, independent verification of administrative facts, durable report history, or law-driven enforcement. The existing stateless evaluation API continues to accept caller-supplied facts. See [Product assessments](../product-assessments.md) for interfaces and exact boundaries.

Explicit durable report capture was subsequently added in [ADR 0008](0008-regulatory-draft-report-snapshots.md); automatic latest results remain memory-only.
