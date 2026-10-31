# EU customer-support transparency draft and retained reports

**English** | [简体中文](zh-CN/eu-transparency-reports.md)

This increment combines a narrow, source-backed regulatory draft with explicit report retention. It provides a reviewable example for a provider of an AI customer-support interface serving EU users. It does not classify an entire product, verify the interface automatically, certify compliance or enforce legal rules.

## Sources and review status

The draft maps selected interaction-notice requirements in [AI Act Article 50(1) and (5)](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-50). Those provisions address notice of AI interaction, its timing and presentation, including applicable accessibility requirements. [Article 2](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-2) and [Article 3](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-3) inform the separate scope/role review. The application-date gate follows [Article 113](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-113) and the [Commission's transparency FAQ](https://digital-strategy.ec.europa.eu/en/faqs/transparency-obligations-under-article-50-ai-act).

Sources were checked on **2026-10-28**. The official Service Desk identifies its displayed text as consolidated at 2026-07-27. The package uses the published application date, 2026-08-02, as a UTC evaluation gate; a reviewer remains responsible for temporal and territorial applicability. No live legal lookup occurs during evaluation.

**`review.status` is `draft`.** Source verification is not expert legal approval. No reviewer or approval timestamp is invented. The pack excludes synthetic-output marking under Article 50(2), paragraphs (3)/(4), high-risk/GPAI obligations, GDPR and other laws. A customer-support product may have additional obligations outside this package.

## Six reviewable controls

| Control | Method | Basis and boundary |
| --- | --- | --- |
| `EU50-SCOPE` | Manual | Scope, provider role and exceptions; supporting assurance practice, not a separately asserted duty to write a scope document |
| `EU50-NOTICE` | Evidence | Selected Article 50(1) notice indicators |
| `EU50-TIMING` | Evidence | Selected Article 50(5) first-interaction timing indicator |
| `EU50-CLARITY` | Manual | Contextual clarity/distinguishability assessment |
| `EU50-ACCESSIBILITY` | Manual | Applicable accessibility basis and assessment |
| `EU50-RELEASE-EVIDENCE` | Evidence | Current-release verification; explicitly supporting practice, not an additional statutory deadline |

The routing facts `product.market`, `product.operator_role`, `product.use_case`, `product.is_ai_system`, and `product.direct_interaction` select this deliberately narrow scenario. `scope.article50_1_exception_claimed` routes disclosure checks but **does not approve an exception**. Scope review stays manual even when other items are routed out of scope. Missing routing evidence leaves applicability unknown.

Evidence predicates inspect supplied assessment indicators. They do not open the connected product, inspect screenshots, run browser accessibility tests or authenticate an assessor. `assessment_method: manual` always yields `unknown` / `manual_review_required` when applicable, even if the caller submits a positive review indicator. There is no workflow to turn an interpretive review into a verified approval in this release.

Findings include a control ID, citation, basis, severity, action and affected evidence-fact IDs:

- `control_gap`: supplied evidence fails a technical predicate; it is not automatically a legal violation.
- `evidence_gap`: missing or unusable evidence prevents a determination.
- `manual_review`: a human judgement or applicability review is still needed.

Detailed issues remain on each control. A finding has one primary category, so a manual review may also identify missing evidence. `basis: supporting_practice` keeps assurance recommendations distinct from mapped legal obligations. Reports always retain `evaluation_only: true` and `legal_compliance: not_determined`.

## Install and exercise the package

```bash
mkdir -p data/rule-packs
cp examples/rule-packs/eu-ai-act-chatbot-transparency.json data/rule-packs/
go run ./cmd/govweave -config examples/deployment.json
```

Adjust the data path for your deployment. The pack ID is `eu-ai-act-chatbot-transparency`, version `0.1.0`. Its complete [definition](../examples/rule-packs/eu-ai-act-chatbot-transparency.json) includes sources, dates, limits and actions. The authenticated `GET /api/v1/compliance/packs/{id}/versions/{version}` returns the installed definition.

Create a model connection and application, replace the application placeholder in [the product example](../examples/eu-customer-support-product.json), then register it through the [product API](product-assessments.md). The initial example intentionally lacks interface evidence. Add current synthetic/real assessment indicators only when you actually have the relevant evidence; do not treat the example scope declarations as a legal conclusion.

The synthetic acceptance scenario is: missing indicators → evidence gaps and manual review; a negative notice indicator → a control gap; positive notice/timing/release indicators → those predicates pass while the three manual items remain unknown. This validates software behavior, not a real customer's interface or legal status.

## Capture an immutable report snapshot

All routes require an administrator session. POST requires JSON, `X-GovWeave-Request: console`, and existing origin protections. An inference key cannot read archived profile evidence.

| Endpoint | Behavior |
| --- | --- |
| `POST /api/v1/compliance/products/{id}/reports` with `{}` | Freshly assess and retain an independent report snapshot |
| `GET /api/v1/compliance/products/{id}/reports` | List retained summaries, newest capture first |
| `GET /api/v1/compliance/reports/{report}` | Read the historical snapshot and its checksum |
| `POST /api/v1/compliance/reports/{report}/replay` with `{}` | Recompute using retained rules, facts and evaluation time |

Each saved snapshot contains the exact product profile/revision, complete parsed rule pack and source metadata, input evidence indicators, runtime-source revisions, evaluator version, assessment time, control results, and remediation findings. Later profile changes, plugin replacement, expiry and restart do not replace these historical inputs. Replays do not consult the current plugin catalog or current gateway state. Unsupported evaluator versions return `409 replay_version_unsupported`; the document remains readable if its schema is supported. A newer evaluator cannot silently claim to reproduce older semantics.

**Capture explicitly persists governance fact values**, including administrative claims and gateway-derived indicators, for reproducibility. Live assessment responses still omit those values. The adapter never copies model request/response bodies or credentials; do not place such content into administrative profile facts. Archived results describe their retained evaluation time, not the product's current state. Read the live evaluation endpoint for current status.

## Storage and failure behavior

Snapshots are private `assessment-reports/rpt_*.json` files: directory mode `0700`, file mode `0600`. Bounds are **256 reports**, **1 MiB per report**, **64 MiB total**, and **8 concurrent archive/replay operations**. No API mutates or deletes an existing snapshot. Periodic assessment does not automatically fill the archive. Capacity exhaustion returns `409 archive_capacity` and preserves prior reports; write errors do not publish an index entry. Advisory assessment and the gateway's existing audit admission remain separate.

Startup validates saved files and rebuilds the bounded index. Malformed, insecure, structurally inconsistent or unsupported-schema files are rejected rather than silently dropped. Reads check the exact file checksum against the running index; supported-version reads also reproduce the saved evaluation. Back up this directory with profiles, rules and the other instance files.

`pack_sha256` identifies the serialized parsed rule definition. Summary `sha256` identifies the exact archived file bytes. These are integrity references, **not signatures, a hash chain or WORM storage**. A privileged operator can rewrite local files; preserve expected checksums externally when auditing file changes across restarts.

Use `make test`, `make check`, `make build`, then `python3 tests/compliance-smoke.py`. The smoke test uses temporary data and synthetic evidence, covers report history and replay after profile/plugin changes and restart, and makes no provider calls. The [report schema](../schemas/reports.schema.json) and [OpenAPI contract](../api/openapi.yaml) define the payloads.
