# ADR 0002: Model access and minimal call records

**English** | [简体中文](../zh-CN/adr/0002-model-gateway.md)

- Status: Accepted, 2026-10-15.
- Extends: The deployment foundation in [ADR 0001](0001-gateway-first.md).

## Decision

Add one OpenAI-compatible Chat Completions adapter to the existing Go service. Reuse the standard HTTP transport instead of introducing another runtime or proxy service. Rewrite the model alias and pass through other JSON parameters. Do not claim automatic support for every model provider. The current contract is documented in [Model gateway](../model-gateway.md).

Provide connection creation, editing, disabling, explicit model-list checks, application grants, key generation/rotation/revocation, and request inspection. Connections and applications have per-record revisions to reject stale writes. Administrator credentials cannot be used for inference.

Keep file storage during the preview. `gateway.json`, mode `0600`, stores connections and applications. Application keys are random high-entropy values persisted as hashes. Provider credentials use AES-256-GCM encryption with the connection ID as additional authenticated data. The local encryption key lives in a separate private `gateway.key`, which must be backed up with the configuration. This does not defend against an attacker controlling the process and data directory, and it is not external KMS integration.

## Durability and latency

Persist and sync a start event before each authorized upstream call, then record its terminal outcome. Stop new upstream calls when logging fails or capacity is insufficient. Buffer only a bounded SSE event before flushing, rather than the entire answer. Propagate cancellation and timeouts; do not automatically retry inference POSTs.

File sync is a deliberate part of the first-byte path, so performance depends on storage. Future durable batching or database transactions must be evaluated for latency percentiles, overload, and crash recovery. An unbounded asynchronous queue is not an equivalent delivery guarantee. The 128 MiB record cap and manual archival are preview limitations, not a final retention system.

Access allow/deny decisions are not legal findings. Records are operational metadata without tamper evidence. Complete administrator history, historical policy snapshots, correlated traces, and reviewed legal-control mappings are future capabilities rather than implied properties of this store.

## Verification boundary

Local mock providers and SDK tests cover authorization, credential persistence, ordinary/SSE forwarding, cancellation, timeouts, redacted errors, resource limits, and restart behavior. Live-provider compatibility, HA, MCP execution, regulatory checks, and production performance need separate implementation and validation.
