# Declarative compliance evaluation engine

**English** | [简体中文](zh-CN/compliance-engine.md)

GovWeave supports a generic, local technical-control evaluator with installable JSON rule packs. A pack describes applicability, requirements and evidence expectations; it does not execute code. The initial implementation is backend-only and independent of the synchronous model-request policy.

## Install a rule pack

Place pack files directly inside `<data_dir>/rule-packs/` and restart GovWeave. Multiple versions can coexist using different filenames and distinct `(id, version)` pairs. No rebuild, package download or cloud connection is required. A missing directory gives an empty catalog. Files already loaded remain unchanged until restart.

For the example deployment (`data_dir: ./data`):

```bash
mkdir -p data/rule-packs
cp examples/rule-packs/demo-ai-governance.json data/rule-packs/
go run ./cmd/govweave -config examples/deployment.json
```

The original `demo-ai-governance` pack is a **synthetic internal policy demonstration**, with `review.status: draft`. It is not a regulatory interpretation, production control catalog or certification. It checks an assessment-sourced AI disclosure indicator and runtime-sourced credential-policy mode/scope indicators. Merely setting a block mode does not prove the policy covers the product or that all sensitive data is detected.

The loader accepts at most 32 JSON packs, 256 KiB per file, and 64 total directory entries. Symlink pack files, invalid JSON, unknown fields, unsupported schema versions, duplicate identities or invalid expressions stop startup. Each pack allows 64 controls, 512 total expression nodes and depth 8. There is no hot reload, marketplace, remote installer or pack-upload API.

## Package contract

The draft [sensitive-output technical-control pack](sensitive-output-governance.md) provides eight server-evidence checks for model/tool output protection, including current-revision execution and retained sample findings. Install it independently; loading a pack never enables blocking or redaction.

See [the example pack](../examples/rule-packs/demo-ai-governance.json) and [JSON Schema](../schemas/compliance.schema.json). Each pack includes:

- `schema_version`, stable `id`, `version`, display `name`, and `framework_kind` (`internal_policy`, `law`, `regulation`, `standard`, or `voluntary_framework`).
- Versioned `sources` with titles and optional HTTPS links; external frameworks require links. Links are metadata and are never fetched during evaluation.
- `review` metadata, including reviewer and time when marked `reviewed`. This is the operator's assertion, not a verified signature or a built-in approval workflow. Draft packs can be evaluated; all packs remain advisory.
- Optional `effective_from` and `effective_to` timestamps (inclusive start, exclusive end). Authoring and verifying legal applicability dates remain the pack maintainer's responsibility.
- Controls with stable IDs, titles, citations, severities, optional `applies_when`, and mandatory `requirement` expressions.

Expressions support `all`, `any`, `not`, and fact predicates using `exists`, `eq`, `neq`, `in`, `gt`, `gte`, `lt`, and `lte`. Predicate `source` can require declared, runtime, document or assessment evidence. `max_age_seconds` can require freshness (1–31536000; omitted/0 means no age limit). `in` accepts 1–32 values of the same scalar type. Ordered comparisons require numbers. Numeric JSON is limited to 64 characters and exponents from -100 to 100; comparisons use exact rational values.

Example requirement:

```json
{
  "fact": "runtime.credential_policy_mode",
  "operator": "eq",
  "value": "block",
  "source": "runtime",
  "max_age_seconds": 300
}
```

New requirements expressible with these predicates can be added as data. A requirement needing a new detector, external service, document interpretation, or previously unavailable evidence needs an additional reviewed evidence adapter or engine capability. A natural-language law cannot become a reliable executable control merely by being copied into a JSON file.

## Evaluate a product

Use an administrator session to call:

| Endpoint | Behavior |
| --- | --- |
| `GET /api/v1/compliance/packs` | Lists installed versions, framework kind, review status, control count and content SHA-256 |
| `POST /api/v1/compliance/evaluations` | Evaluates the exact requested pack version against supplied product facts |

POST requires JSON, `X-GovWeave-Request: console`, and the existing origin protections. Application inference keys cannot access these APIs. Requests are limited to 16 KiB and 160 facts, with 64 concurrent evaluations; overload returns `429 compliance_busy`. Send the structure in [the example evaluation](../examples/compliance-evaluation.json), supplying the product ID/version and each fact's scalar `value`, `evidence_id`, `source`, `observed_at`, and optional `expires_at`.

Facts should be small governance indicators, not prompts, generated answers, credentials or document bodies. **Every submitted value and provenance label is caller-supplied; the API does not independently authenticate its evidentiary origin.** Trusted adapters and document review must establish those facts outside this first slice. The example intentionally omits disclosure evidence, so its expected overall status is `insufficient_evidence`.

The server uses its current UTC time for assessment. Missing, expired, stale, future, incorrectly typed, or source-incompatible evidence remains unknown. `not` does not turn unknown evidence into a pass. A false branch can determine `all` and a true branch can determine `any`; issues in other examined branches remain visible.

| Control status | Meaning |
| --- | --- |
| `pass` | The supplied evidence satisfies this technical requirement |
| `fail` | The supplied evidence contradicts this technical requirement |
| `unknown` | Applicability or the requirement cannot be determined from usable evidence |
| `not_applicable` | An explicit applicability condition is false, or the pack is outside its effective window |

Overall status is `gaps_detected` if any control fails, otherwise `insufficient_evidence` if any is unknown, otherwise `satisfied` if any passes, otherwise `not_applicable`. Always inspect individual controls: a known gap does not remove unknown requirements. Every response sets `evaluation_only: true` and `legal_compliance: not_determined`, including when all technical checks pass.

## Real-time integration and evidence boundaries

Call the API when product metadata, runtime configuration or collected evidence changes. Local deterministic evaluation introduces no LLM call or regulatory retrieval. There is no measured latency SLA yet.

Registered products now support [gateway-owned evidence and automatic reassessment](product-assessments.md). Their saved administrative profiles are combined with current gateway configuration and a bounded request sample. The stateless endpoint described here still evaluates caller-supplied evidence. Explicit [report snapshots and a narrow EU transparency draft](eu-transparency-reports.md) are also available. Independent document verification and runtime blocking from these packs remain unimplemented; credential-egress enforcement stays independently configured.

Results identify product version, pack version, canonical parsed-pack SHA-256, review status, assessment time, control citations, evidence references and issue codes. They exclude fact values. The stateless engine writes neither facts nor reports to disk. The separate explicit capture API persists governance fact values, exact rules and results in private report snapshots for replay. Changing a file without changing its version still changes its digest after restart; digests identify content but do not provide signatures. Historical inputs are retained only when explicitly captured. Include rule packs in instance backups.

The design keeps binding law separate from voluntary guidance: the [European Commission describes the AI Act as a risk-based framework](https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai), while [NIST describes AI RMF as voluntary](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-ai-rmf-10). Neither source supplies a ready-made GovWeave rule pack. Regulatory packs need sourced, versioned mappings and human review; different laws may need multiple packs and additional evidence capabilities.

Run `make build` followed by `python3 tests/compliance-smoke.py` for the local binary/plugin/API smoke test. It uses only the Python standard library, temporary instance data and synthetic facts; no external provider or regulatory service is contacted.
