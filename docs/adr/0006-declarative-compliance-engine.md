# ADR 0006: Generic evaluator with declarative rule pack plugins

**English** | [简体中文](../zh-CN/adr/0006-declarative-compliance-engine.md)

Status: Accepted

## Context

GovWeave should support continuous assessment of AI products as regulatory requirements evolve. Hard-coding a jurisdiction into the gateway or equating credential checks with whole-product compliance would prevent this. Requirements need product context and evidence that model traffic alone cannot establish.

## Decision

Provide an independent, deterministic Go evaluator with JSON rule packs loaded from the instance's `rule-packs/` directory at startup. Packs identify their framework type, sources, versions, review metadata, effective dates, applicability and controls. Use bounded expressions and typed evidence, without executing plugin code or fetching URLs. Pin each assessment to an exact pack ID/version and content digest.

Use three-valued predicate logic and explicit per-control applicability. Missing or unusable evidence remains unknown. Return technical results and evidence references without fact values; never return a whole-product legal conclusion. Review metadata is an operator attestation; it is not a verified approval workflow. All packs, including reviewed ones, remain advisory in this slice.

Expose administrator-only catalog and stateless evaluation APIs. Add no management page. Product persistence, trusted evidence adapters, automatic event-driven reevaluation, report storage and enforcement mapping are separate increments. Existing credential policy enforcement remains independent.

## Consequences

Maintainers can install additional versions and express new controls without rebuilding when existing predicates and evidence suffice. New legal concepts or measurements may require new adapters or engine capabilities. Startup rejects invalid packages. Operators preserve pack files, input evidence and results externally for reproducibility; plugin digests are not signatures or a history store. The bundled package is a synthetic draft internal policy and provides no regulatory coverage.

Product registration and gateway evidence were subsequently added by [ADR 0007](0007-product-evidence-assessments.md).
