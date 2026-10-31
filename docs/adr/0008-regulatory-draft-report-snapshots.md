# ADR 0008: Source-backed draft and retained assessment inputs

**English** | [简体中文](../zh-CN/adr/0008-regulatory-draft-report-snapshots.md)

Status: Accepted

## Decision

Provide one narrow EU customer-support interaction-transparency mapping from official sources. Keep it explicitly draft and advisory. Distinguish mapped legal obligations from supporting assurance practice. Add manual assessment methods that cannot be automatically approved, and findings separating technical gaps, evidence gaps and human review actions. Do not infer whole-product compliance or inspect an interface from gateway traffic.

Add explicit administrator-only report capture. Retain an independent product profile, complete rule pack, structured factual input, runtime source revisions, evaluator version, evaluation time, findings and results. Store private bounded files with immutable IDs; no API updates or silently prunes them. Periodic reevaluation stays memory-only and never automatically consumes archive capacity.

Replays use retained rules/input/time, without consulting current installed packs. Unsupported evaluator semantics return a version error. Supported-version file reads reproduce the evaluation and verify its content against the running checksum index. File checksums are not signatures or tamper-proof storage. Capture persists governance fact values intentionally; model text and credentials are not collected by the adapter.

## Consequences

This yields a reviewable regulatory example and reproducible historical reports, while human legal review, external evidence verification and enforcement remain separate. The initial bounds are 256 snapshots, 1 MiB each, 64 MiB total and 8 archive/replay operations. Invalid persisted evidence is rejected rather than dropped. Full scope, source provenance and interfaces are documented in [EU draft and report snapshots](../eu-transparency-reports.md).
