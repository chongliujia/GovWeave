# Active assessment and lifecycle testing

**English** | [简体中文](zh-CN/active-assessments.md)

GovWeave can execute bounded test suites against a configured Chat Completions connection or read tool through the existing gateway. Administrators register a test plan, request a pre-deployment or operation run, and inspect private evidence plus an evaluation from the existing rule engine. There is no additional console page or runtime dependency.

## Install and run

Without a real target, use the [local scripted demonstration](local-demonstration.md) to exercise known faults with the real gateway and evaluator.

Install both kinds of declarative plugin into the instance data directory and restart:

```bash
mkdir -p data/test-suites data/rule-packs
cp examples/test-suites/chat-contract-smoke.json data/test-suites/
cp examples/rule-packs/nist-ai-rmf-lifecycle.json data/rule-packs/
```

Register a product using the existing product API, binding its application IDs and the exact `nist-ai-rmf-lifecycle` / `0.1.0` rule pack. Replace `application_id` and `model_alias` in [the plan example](../examples/test-plan.json) with an authorized application bound to that product and an enabled model alias. Use an explicit target release identifier and context describing the intended use and measurement boundary. `target_version` is an administrator label, not independently detected model weights or application code.

All endpoints below require an administrator session; mutations also require `Content-Type: application/json`, `X-GovWeave-Request: console`, and the existing origin checks. Application inference keys cannot invoke them.

| Endpoint | Purpose |
| --- | --- |
| `GET /api/v1/compliance/test-suites` | Installed test suite versions and content hashes |
| `GET /api/v1/compliance/test-suites/{id}/versions/{version}` | Exact installed suite |
| `GET, PUT /api/v1/compliance/products/{id}/test-plan` | Read or save the legacy default plan; initial revision is zero |
| `GET /api/v1/compliance/products/{id}/test-plans` | List up to two plans, including any legacy default |
| `GET, PUT /api/v1/compliance/products/{id}/test-plans/{plan}` | Read/save named `model` or `read_tool` plans; one plan per target kind |
| `POST /api/v1/compliance/products/{id}/test-runs` | Start asynchronous testing; select a named plan with `plan_id` and a phase; omission selects the legacy default; returns `202` |
| `GET /api/v1/compliance/products/{id}/test-runs` | Historical run summaries, newest first |
| `GET /api/v1/compliance/test-runs/{run}` | State, case results, captured versions, evidence and rule evaluation |
| `POST /api/v1/compliance/test-runs/{run}/replay` | Body `{}`; replay the saved rule decision without calling the target |

Poll the returned run ID until `state` is no longer `running`. `status: passed` means only that every selected check passed. `failed` means at least one check failed; other cases may still be unknown. `inconclusive` means the evidence did not establish all outcomes. Request errors, gateway blocks on endpoint-output cases, unsupported responses, tool calls, empty output and `finish_reason` other than `stop` remain unknown. Cancellation or a product/plan/gateway/policy change during execution produces an error without an evaluation. A new run makes new target requests; replay does not.

## Test and rule plugins

`canary_absent` adds a versioned detector with fresh per-case synthetic markers. See [Canary validation](canary-validation.md) for the template contract, measured recall, known misses, evidence handling and versioned runner compatibility.

Test suites describe messages, measurement scope and a bounded check for each case. Supported checks are exact `equals`, case-sensitive `contains` / `not_contains`, `json_valid`, `manual`, `canary_absent`, and `credential_block`. The credential check verifies the gateway's `403 policy_blocked` response and must use `scope: gateway_control`. These remaining cases use `scope: endpoint_output`; a gateway block cannot establish how the upstream model would have answered. A manual check always stays unknown. JSON validity does not prove a JSON schema or semantic correctness. Keyword checks do not establish general safety, privacy or fairness.

The additional `output_protected` and `output_allowed` checks use `scope: gateway_control` and an audited gateway execution receipt. The bundled `sensitive-output-controls` suite covers three category challenges plus a benign control. Its current pre-deployment and operation evidence can enter product reports with rule pack 1.1.0; see [active output-control assessment](output-control-assessments.md). These checks never retain returned text, even when `retain_responses` is enabled; category challenges retain no response digest, while the benign check retains a digest for exact comparison.

Read-tool suites use `target_kind: read_tool`, `resource_id` instead of messages, and only `output_protected`, `output_allowed` or `tool_denied`. Plans use `tool_alias` without model fields; the denial check requires a committed resource rejection before upstream I/O. See [active read-tool assessment](tool-control-assessments.md) for the five-case suite, separate product facts and grant-drift behavior.

A product can keep one plan of each target kind, including its legacy default. To select a named plan, send `{"plan_id":"model","phase":"operation"}` or use `read_tool`. [Combined application assessment](application-assessments.md) explains the shared report, duplicate-target rejection and compatibility. Current reports can contain all four model/tool phase facts; individual test-run evaluations remain specific to their own plan.

The shipped `chat-contract-smoke` suite tests a literal marker and JSON syntax using two synthetic prompts. It is an executable example, not a representative risk benchmark. Each case runs once, with temperature zero and the plan's output-token budget. Providers may ignore sampling controls, and results may vary between runs. There is no LLM judge or automatic test generation.

Rule packs retain their existing role: applicability, source-backed requirements and evidence conditions. They contain no network calls or executable scripts. Active runs combine the captured product and gateway facts with server-generated `testing.test_set_documented`, `testing.pre_deployment.passed`, and `testing.operation.passed` facts, then invoke the same deterministic evaluator. Product profiles cannot define `testing.*`. The stateless evaluation endpoint still trusts caller-supplied provenance.

Lifecycle facts can be shared only across runs with the same product revision, plan ID/revision, suite hash, gateway and policy revisions, retained tool-configuration revision, connection identity/revision and rule pack content. Tool targets additionally pin their tool identity/revision and runner generation. Tool edits during a run produce `test_source_changed` and suppress its evaluation. Runs captured before tool facts existed remain replayable and comparable to other legacy runs, but are not used as baselines for runs with tool evidence. The latest comparable failed/incomplete run prevents reusing an earlier pass for that phase. Pre-deployment evidence expires after 30 days; operation evidence expires after twice the plan interval. These are product defaults, not NIST-prescribed deadlines. A historical report records its evaluation time; it is not a live deployment approval. The combined evaluation is retained in the **test run**. The product `/evaluation` endpoint also imports the two current phase facts from qualifying output-control suites: `testing.output.*.passed` for models or `testing.tools.output.*.passed` for tools, as described in [active output-control assessment](output-control-assessments.md).

## Operation scheduling and changes

`schedule_enabled` defaults to false in the example. Explicitly enabling it authorizes recurring calls to the configured model or tool while this instance is running. The interval must be 300–2592000 seconds. First execution is due after one interval; enabling a plan does not immediately call the target. Manual runs reset the next due time when scheduling is enabled. The one-second scheduler starts operation runs, records the next due time before execution, and resumes persisted plans after restart. Missed intervals are coalesced into one due run; there is no historical backfill or automatic retry of a failed inference.

Each plan schedules independently. Due plans are considered oldest first; a plan waiting on a busy product remains due. There are at most two concurrent runs globally and one per product across both plans; each contains at most 16 sequential requests. Per-case timeouts are 1–30 seconds and a whole run is limited to five minutes. Model output budgets are 1–1024 tokens. Tool tests retain the adapter’s 8192-byte text limit and the shorter of the plan and tool timeouts; no model token budget applies. These request limits cannot guarantee a provider's billing or token accounting. Revoked applications, withdrawn grants and disabled targets prevent execution. Synthetic requests retain normal credential enforcement, audit admission, transport restrictions and upstream credentials. Their call records use `assessment.chat.completions` or `assessment.tools.invoke`, so they are excluded from production chat/tool/output sample counts; they still occupy entries in the bounded global audit index.

Comparable runs record pass-to-fail regressions and fail-to-pass recoveries. Changes in the captured versions reset comparison; the software does not infer a model or prompt change that is invisible behind an unchanged external endpoint. Scheduled-start failures are visible in `test-plan.last_error`; completed case outcomes are in `last_run_id`. There are no external notifications, incident workflow or automatic deployment gate.

## Evidence storage and recovery

`test-plans.json` and `test-runs/test_*.json` are private `0600` files; the run directory is `0700`. A run is saved as `running` before outbound execution. On restart, an unfinished run becomes `interrupted` / `inconclusive`, never a pass. The plan store is at most 256 KiB and contains at most two plans per product (128 total). Existing default plans retain their original serialization. Runs are limited to 128 retained files, 512 KiB each (64 MiB maximum); capacity stops new runs and is exposed as an error, without deleting evidence. Archive or remove old run files only while stopped, then restart. Include plans, runs, test suites, rule packs and existing instance files in backups.

Runs retain the exact test suite, product governance facts, rule pack, runner version, source revisions, input facts and evaluation. Test case results include the request ID, status and duration; ordinary model checks also retain assistant-text SHA-256. Response content is omitted by default. Explicit `retain_responses: true` retains at most 8192 UTF-8 bytes per assistant response in this separate private evidence store, not in call records. Receipt-based output/denial checks never retain returned text, and only their benign control keeps a text digest. Use synthetic prompts/resources and avoid personal or secret data. Provider error bodies, upstream credentials and application keys are never added to test evidence. Test suite messages, configured resource IDs and expected literals are always retained as part of the suite snapshot.

Saved content hashes detect in-process changes; they are not signatures or tamper-resistant storage. Replay validates the retained deterministic **rule evaluation**, not the remote model or a detector result from a hash alone. Corrupt, insecure or unsupported evidence prevents startup rather than silently discarding history.

## NIST AI RMF scope

The [official AI RMF 1.0 Core](https://airc.nist.gov/airmf-resources/airmf/5-sec-core/) calls for testing before deployment and during operation, documenting measurement tools and methods, and considering deployment context and independent review. It spans GOVERN, MAP, MEASURE and MANAGE; its actions are not a certification checklist. The linked source also notes that a revision is in progress; this example pins **1.0 (2023)**.

The `nist-ai-rmf-lifecycle` draft provides partial technical support for recorded test sets and the two phases. It retains manual items for context, metric adequacy, independent review, representativeness and monitoring/response arrangements. These do not automatically pass even if claimed documents exist. Organizational governance, risk tolerance, real-user feedback, appropriate risk coverage and human release decisions require additional work. Technical test success does not mean NIST certification, comprehensive framework satisfaction or a legal conclusion.

## Verification

```bash
make test
make check
make build
python3 tests/active-smoke.py
```

Tests use local mock providers and synthetic data. They exercise actual inference, both phases, periodic dispatch, regression/unknown outcomes, authorization, version isolation, private evidence, restart, replay and failure paths. Live-provider compatibility, real-product risk effectiveness and production scale need separate validation.
