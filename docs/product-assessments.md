# Product registration and continuous advisory assessment

**English** | [简体中文](zh-CN/product-assessments.md)

Registered products combine administrative profile facts with gateway-owned runtime evidence. A background worker reassesses them when a product is saved, a connection/application/key/credential policy/read-tool configuration changes through the management API, or a gateway operation finishes. This backend feature uses the existing [declarative evaluator](compliance-engine.md); it adds no management page. A separate [source-backed EU draft](eu-transparency-reports.md) can be installed for a narrow scenario.

## Register and assess

1. Install a rule pack and restart the service. Configure the product's applications and their model grants or [read-tool grants](tool-governance.md). Tool-only applications may have an empty model grant list.
2. Start from [the product example](../examples/product.json). Replace `application_ids` with actual application IDs and select an installed `pack_id` and exact `pack_version`.
3. Submit `POST /api/v1/compliance/products` with revision `0`. Provide small product facts such as purpose, market or user-facing status; facts may also reference administrative document/assessment claims. These claims are not independently verified by the server.
4. Poll `GET /api/v1/compliance/products/{id}/evaluation`. `state: pending` means no current result is available; `ready` includes an assessment; `error` includes an error code and no passing assessment.
5. Update the product with `PUT /api/v1/compliance/products/{id}` and its current revision. An older revision returns `409` rather than replacing a newer profile.

All product routes require an administrator session. Writes additionally require JSON, `X-GovWeave-Request: console`, and the existing browser-origin protections. Inference application keys cannot read or change product profiles.

| Endpoint | Behavior |
| --- | --- |
| `GET /api/v1/compliance/products` | List saved profiles and their administrative facts |
| `POST /api/v1/compliance/products` | Register a profile and schedule assessment |
| `GET /api/v1/compliance/products/{id}` | Read a profile |
| `PUT /api/v1/compliance/products/{id}` | Save a replacement profile with revision checking |
| `GET /api/v1/compliance/products/{id}/evaluation` | Read the latest current result, or pending/error state |
| `POST /api/v1/compliance/products/{id}/evaluate` with `{}` | Explicitly refresh from current gateway state; accepts no evidence overrides |

Products bind 1–64 known applications. A product references one exact rule pack version; additional versions remain independent. The registry holds at most 64 products, each with up to 112 administrative facts. Requests retain the 16 KiB management-body limit. Profile names are 1–100 characters and versions use the identifier format in [the schema](../schemas/products.schema.json).

## Gateway evidence adapter

Registered profiles cannot define `runtime.*` or `testing.*` keys or any fact with `source: runtime`. The adapter alone creates that namespace for product assessments. The older stateless `POST /api/v1/compliance/evaluations` still evaluates caller-supplied facts and does not authenticate their provenance; use product routes for server-collected runtime evidence.

| Fact | Meaning |
| --- | --- |
| `runtime.credential_policy_mode` | Current credential-egress mode |
| `runtime.credential_policy_revision` | Exact credential policy revision |
| `runtime.gateway_revision` | Current connection/application configuration revision |
| `runtime.credential_private_key_rule_enabled` | Private-key detector selected in current policy |
| `runtime.credential_api_key_rule_enabled` | API-key detector selected in current policy |
| `runtime.applications_active` | All bound application IDs exist and none is revoked |
| `runtime.credential_policy_covers_product` | Policy scope covers every bound application and every configured model grant |
| `runtime.audit_available` | Call logging currently has reliable write availability and reservation capacity |
| `runtime.sample.request_count` | Finished Chat Completion requests in the product's bounded sample |
| `runtime.sample.policy_block_count` | Sample requests with `error_code: policy_blocked` |
| `runtime.sample.observed_match_count` | Sample requests whose content policy result is `observe` |
| `runtime.sample.failed_count` | Sample requests with outcome `failed` |
| `runtime.sample.incomplete_count` | Sample requests recovered as incomplete after restart |

Coverage checks use the application's entire configured grant list, including disabled connections and revoked applications. A missing application/connection or a grantless application leaves coverage unknown; it does not count as vacuous protection. Mode and detector selection are separate facts: coverage alone does not establish blocking or detection completeness. A current active flag does not establish upstream availability.

The sample is the **latest 100 global indexed request entries**, then filtered to the product's applications and Chat Completions. It is not the latest 100 requests per product, a clock-time window, a full history, or a throughput measure. In-progress records are excluded from finished counts. If audit availability is lost, sample counters are omitted so dependent requirements remain unknown. A zero count means none in this bounded sample, not that no such incident ever occurred.

The adapter reads gateway configuration, policy state and metadata-only call records. It never reads prompt/response bodies or copies provider credentials, application keys, headers, model URLs, matched text or raw provider errors into reports. Runtime fact timestamps identify when the current configuration/sample was read. Evidence IDs reference configuration revisions or the current audit byte position; they are not tamper-proof evidence signatures.

## Controlled read-tool evidence

Tool governance uses the same product registration, evaluator, automatic refresh and explicit report APIs. Bind the application's ID and select the [read-tool example pack](../examples/rule-packs/read-tool-governance.json), version `1.0.0`. It is an `internal_policy` draft for bounded technical controls, not a law, reviewed compliance catalog or certification. The [tool product example](../examples/read-tool-product.json) has no administrative facts; the server collects all facts used by this pack.

| Fact | Meaning |
| --- | --- |
| `runtime.tools.revision` | Global tool-store revision used for this assessment |
| `runtime.tools.granted_tool_count` | Distinct enabled tools with at least one resource granted to a bound application |
| `runtime.tools.applications_covered` | Every bound known application has at least one enabled tool resource grant |
| `runtime.tools.output_blocking_covers_product` | All bound applications have grants, and every enabled granted tool uses `block` output mode |
| `runtime.tools.sample.request_count` | Finished `tools.invoke` requests for the bound applications |
| `runtime.tools.sample.completed_count` | Tool requests whose recorded outcome is `completed` |
| `runtime.tools.sample.authorization_denied_count` | Requests rejected with `tool_not_allowed` before provider execution |
| `runtime.tools.sample.output_block_count` | Requests with `tool_output_blocked`, after execution but before text release |
| `runtime.tools.sample.observed_release_count` | Completed tool requests that release an observed legacy credential pattern (including contact-only redaction that leaves that credential). Instruction-only observations are excluded |
| `runtime.tools.sample.failed_count` | Tool requests whose recorded outcome is `failed` |
| `runtime.tools.sample.cancelled_count` | Tool requests whose recorded outcome is `cancelled` |
| `runtime.tools.sample.incomplete_count` | Tool requests recovered as incomplete after restart |
| `runtime.tools.sample.output_checked_count` | Finished, attempted tool requests with an `observed` or `not_observed` output finding |
| `runtime.tools.sample.unknown_output_count` | Finished, attempted tool requests with an unknown, absent or unsupported output finding |

Tool coverage does not count absent grants as protection: a known application without an enabled resource grant makes coverage false. A missing bound application makes coverage unknown. Coverage describes grants; `runtime.applications_active` independently checks whether the applications are still active. Sensitivity labels do not grant access, and unrelated or disabled tools do not count as enabled granted tools. These facts do not change the existing model-policy facts or Chat Completion counters.

Tool counters use the **same latest 100 global indexed request entries**, filtered to the product's applications and `tools.invoke`, not a separate 100-entry sample per tool or product. In-progress entries do not count as finished requests. Audit unavailability omits sample counters, keeping dependent requirements unknown instead of supplying zeros. Counts contain no resource IDs or text. High traffic from other applications or operations can displace older tool evidence from the sample.

The example pack requires active applications, resource-grant coverage, blocking mode on every enabled granted tool, available audit capacity, at least one inspected output, and no observed credential releases, unknown outputs or incomplete calls in this bounded sample. The inspected-output requirement prevents a configuration with no executed output checks from passing solely on zero incident counts. A denied unauthorized request or a successfully withheld credential output is evidence of an enforced control; neither alone makes the pack fail.

Changing a tool from `observe` back to `block` fixes the current configuration fact. It does **not** remove an earlier observed release: `TOOL-SAMPLE-RELEASES` still fails while that record remains in the sample. Once traffic displaces it, the current sample no longer describes that older event; an explicitly archived report retains its original evidence and result. Do not treat a later clean sample as erasure of the incident or assurance over all historical traffic. The pack does not inspect retrieved text itself, prove broad semantic safety, or automatically configure runtime blocking.

See [the tool integration guide](tool-governance.md#product-assessment-and-retained-reports) for installation and registration commands. `make demo-agent` demonstrates permitted and denied Agent calls, an operator-controlled change to observation mode, restoration of blocking, and retained report replay without additional tool execution. The proposals and provider responses are scripted; no real model or external API key is required.

## Freshness, failures and lifecycle

The [sensitive-output technical-control pack](sensitive-output-governance.md) adds configuration coverage, selected categories, current-policy execution evidence and bounded model/tool release findings. Its guide defines the `runtime.output_*` and `runtime.sample.output_*` facts. A policy revision change invalidates the assessment and requires its own execution evidence; past releases remain in the bounded sample.

Events use a coalesced nonblocking signal. The worker normally waits 250 ms to combine bursts, then evaluates current state; signals arriving during work schedule another pass. A 30-second periodic pass covers expiry and other time changes. These are scheduling intervals, not an end-to-end latency guarantee.

Every result records product revision, gateway revision, policy revision, tool-store revision, audit bytes/availability, rule pack digest, and evaluation time. A tool configuration change invalidates the cached result even when the model configuration is unchanged. Input snapshots are checked again before publication; unstable inputs are retried up to three times. A forced refresh can return `429 assessment_busy` when inputs keep changing. Evaluator errors appear as `state: error`, including an exact pinned pack removed at restart; the service never substitutes another version. `snapshot.tool_revision` may be omitted for tool revision zero or reports archived before tool evidence existed; its absence does not establish current tool coverage.

Reading the cached result checks its source revisions, a maximum 30-second refresh deadline, and any earlier known clock boundary (`reevaluate_at`) such as evidence expiry, future evidence becoming current, detector max-age or pack effective dates. Invalid results return `pending` **without an old evaluation payload** and schedule work. A discovered requirement gap remains a technical-control result; responses still carry `evaluation_only: true` and `legal_compliance: not_determined`.

Profiles are saved atomically in private `products.json` (mode `0600`, maximum 4 MiB). Failed saves preserve the old profile. Malformed/unsupported/insecure registry files prevent startup. Administrative fact values are deliberately persisted as part of the profile: do not submit prompts, secrets or personal data as governance indicators. Include this file and the rule packs in consistent instance backups.

Only the latest profiles are stored. **Automatic latest results are bounded and memory-only**; restart rebuilds them from saved profiles and current gateway state. Independent [explicit report capture](eu-transparency-reports.md) retains historical snapshots on disk; periodic reevaluation does not archive every result. Profile history, independent document verification, external evidence adapters, multi-pack aggregation, alerts and enforcement from these packs remain future work. The existing credential policy continues to enforce its separately saved mode/scope.

`go test -race ./...` includes registry, adapter, event refresh and freshness cases. `make build` followed by `python3 tests/compliance-smoke.py` exercises a real temporary gateway, synthetic blocked requests, policy changes, profile persistence and restart reassessment without contacting a provider.

See [Active assessment](active-assessments.md) for pre-deployment and periodic operation testing. Combined test evidence is retained in separate private test runs. The two `testing.output.*.passed` facts from current qualifying output-control runs also enter product assessments and report snapshots; see [active output assessment](output-control-assessments.md).
