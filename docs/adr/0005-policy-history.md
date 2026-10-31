# ADR 0005: Immutable credential policy history

**English** | [简体中文](../zh-CN/adr/0005-policy-history.md)

Status: Accepted

## Context

Call records identify `content_policy.revision`, but keeping only the latest policy prevents inspection of the rules and scope used by an older request. Historical configuration must remain available without storing request content or introducing a database.

## Decision

Persist the active policy and immutable snapshots in one schema-2 `policies.json` file. A successful save atomically appends a revision and activates the last entry; failed saves publish neither. Keep revision checking, private file permissions, bounded reads, and startup validation. Retain at most 1024 snapshots or 8 MiB, reject saves when full, and never silently evict history. Rejected requests and upstream admission retain the existing audit behavior.

Expose administrator-only read APIs for newest-first cursor pagination and exact revision lookup. Use the credential assessment revision, rather than the separate connection/application revision, for request attribution. Retain revision 0 for new instances. Read legacy schema 1 without rewriting it and use its latest revision as the baseline; migrate on the next successful save. Missing older versions return 404.

Backend APIs and tests are the primary implementation. Reuse the existing request inspector for a minimal read-only snapshot view; no separate history management page is required.

## Consequences

Policy history survives restarts, and concurrent evaluations retain consistent snapshots. No prompts, responses, or matched credentials enter this file. Capacity exhaustion preserves enforcement but stops further policy saves. Operators must back up the instance before migration because older binaries cannot read schema 2. This is configuration history, not tamper evidence, administrator attribution, historical model grants, a rollback engine, or legal compliance evidence.
