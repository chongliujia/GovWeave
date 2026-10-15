# ADR 0004: Local request credential policy

**English** | [简体中文](../zh-CN/adr/0004-request-credential-policy.md)

- Status: Accepted, 2026-10-15.
- Extends: The request path and metadata records in [ADR 0002](0002-model-gateway.md).

## Decision

Add local, synchronous credential-pattern checks between model authorization and upstream I/O. The first version provides one `credential-egress` policy. It introduces no remote inspector, user regex, dynamic script, legal decision engine, or approval executor.

The policy defaults to disabled and supports observe and block. Observe forwards the original request, including matching content, while adding fixed match metadata. Block returns `403` before provider I/O, including for streaming requests. Application and connection scopes intersect; an empty list means all current and future objects. Access grants remain independent.

Each request uses an immutable policy snapshot. Saves use atomic file replacement and an independent revision, without interrupting accepted requests. `policies.json` retains the latest configuration. The rule-set version identifies the compiled detector definitions; changes to their meaning require a version update. Historical reconstruction and complete administrator-change attribution are not implemented.

Inspect all JSON string tokens, including tool arguments, extension fields, duplicate fields, and keys. Decode the current JSON layer through the standard library. Limit detection to private-key markers and selected credential prefixes. Encoded attachments, recursively escaped strings, split/obfuscated secrets, and model outputs remain outside scope. Keep the 1 MiB request cap and run evaluation inside the existing 64 execution slots.

## Evidence and failure behavior

Keep `content_policy` separate from model-access authorization and the connection/application configuration revision. Record only fixed policy ID, revision, rule-set version, mode, result, matched rule IDs, and check duration. Do not store matching text, field positions, or secret fingerprints.

Blocking requests also require a durable start record and reserved finish capacity. If logging is unavailable, return `503` without provider I/O. Per-request check timing supports later analysis; it does not establish a production latency claim.

## Consequences

This provides one measurable enforcement point for model-request text while retaining the existing streaming response path. Pattern detection has false positives and gaps, documented in [Runtime policies](../runtime-policies.md).

Multiple policies, richer detectors, complete historical snapshots, and MCP action controls can follow real deployment feedback. EU/US regulatory mappings require separate design and human review; a pattern match cannot establish legal compliance.
