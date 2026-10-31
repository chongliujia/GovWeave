# Active output-control assessment

**English** | [简体中文](zh-CN/output-control-assessments.md)

The optional `sensitive-output-governance@1.1.0` pack extends the eight [runtime controls](sensitive-output-governance.md) with two active-test requirements. The planned model target must have usable output-protection evidence from both pre-deployment and operation runs. Version 1.0.0 keeps its original eight controls; existing products do not upgrade automatically.

## Install and configure

```bash
mkdir -p data/rule-packs data/test-suites
cp examples/rule-packs/sensitive-output-governance-v1.1.json data/rule-packs/
cp examples/test-suites/sensitive-output-controls.json data/test-suites/
```

Restart the instance to load these local JSON plugins. Use [the product example](../examples/sensitive-output-assessment-product.json) to register a product bound to your application and pack version 1.1.0, or update an existing product with its current revision. Use [the plan example](../examples/sensitive-output-test-plan.json) with the bound application ID and allowed model alias. Save it through `PUT /api/v1/compliance/products/{id}/test-plan`.

Configure `sensitive-output` separately with the intended detector generation, all three categories and application scope. Blocking or redaction can satisfy the protection tests. The independent request credential policy still applies: the bundled credential challenge asks for two concatenated fragments so it can reach the model without sending a complete credential-shaped string in its prompt.

Start each phase through `POST /api/v1/compliance/products/{id}/test-runs`, with `{"phase":"pre_deployment"}` or `{"phase":"operation"}`, then read the returned run ID until complete. Each new run makes four model requests; replay makes none. Periodic operation testing uses the existing explicit `schedule_enabled` setting and may incur provider usage; the example leaves it disabled. See [active assessment](active-assessments.md) for authentication, limits and scheduling.

## What the four cases establish

| Check | Required evidence |
| --- | --- |
| Credential `output_protected` | Gateway observes the selected category and actually blocks or completes redaction |
| Email `output_protected` | Same requirement for email |
| Mainland China phone `output_protected` | Same requirement for phone |
| `output_allowed` | Gateway allows an exact benign response without a sensitive finding or transformation |

Both new checks use `scope: gateway_control`. `output_protected` requires `category: credential`, `email` or `phone`, and accepts no expected literal. `output_allowed` requires an exact `expected` literal and accepts no category. Their verdicts use an in-process gateway receipt and confirmed terminal audit, not a model's assertion or an upstream HTTP error claiming that a block happened.

Observation releases fail. Disabled protection fails after execution. Request rejection before model execution, unavailable audit, provider failures and unknown detection remain inconclusive. If the model refuses or produces no detectable challenge of the required category, that case is **unknown**, even if no sensitive output reaches the caller. For the benign control, an unrelated model response also remains unknown; a confirmed output block or transformation fails that control.

The suite must include all three category challenges and a benign control. A partial suite cannot supply lifecycle evidence. Each case executes once; four successful authored probes do not estimate accuracy, attack success rates or real-world recall. Coverage is limited to the application/model in the current plan. Other models, bound applications, tools and routes need their own validation. [Active read-tool assessment](tool-control-assessments.md) provides a separate tool target and evidence namespace. A product can keep one model plan and one read-tool plan; see [combined application assessment](application-assessments.md).

## Product reports and evidence lifetime

The server merges these facts into current product assessments and explicit report snapshots:

| Fact | Lifetime |
| --- | --- |
| `testing.output.pre_deployment.passed` | 30 days after the qualifying run finishes |
| `testing.output.operation.passed` | Twice the plan's operation interval after the qualifying run finishes |

They use `source: assessment`, the run ID as evidence ID, and the original completion/expiry times. The same facts are available in active-run rule evaluations. Profiles cannot supply or override them. A completed determinate run yields true or false; missing, expired, running, interrupted, failed-to-execute or inconclusive latest runs yield no usable phase verdict. The adapter selects the latest run per phase and never searches backward for an older success.

Evidence must match the current product revision, plan revision, suite digest, rule-pack digest, runner generation, model connection, and gateway/request-policy/tool/output-policy configuration. Any such change invalidates old success. Plan saves, run starts and completion trigger background reassessment; reading stale cached results returns pending without the old evaluation. The source stamp's optional `test_evidence_revision` is a process-local cache generation, not a cross-restart evidence identifier. Restart reloads retained runs and reconstructs current evidence.

Active requests remain `assessment.chat.completions` and **do not increase production execution counters**. Thus a product can pass all four probes yet still lack the separate runtime execution evidence required by the first eight controls. Tests still occupy entries in the shared last-100-record audit index and can displace older production samples. Reports remain advisory; no deployment gate or automatic policy change is introduced.

## Retention, replay and verification

Runner `bounded-chat-tests-v4` adds these checks while retaining earlier runner versions for read/replay. Canary detector v2 remains unchanged. Different runner generations do not share lifecycle evidence. Output-control cases retain only bounded gateway decision metadata; returned text is never retained for these cases, even with `retain_responses: true`. The benign case retains a text digest and byte count for exact-return verification; category probes retain neither. Suite prompts and expected literals are still retained, so use synthetic data.

Archived reports retain their scalar test facts and run references; separate test-run files contain the case evidence. Preserve both when backing up. Replay recomputes the saved rule decision, without executing the model or claiming detector revalidation from metadata alone. Private-file hashes detect changes but are not signatures.

```bash
make demo-output-assessment
```

The isolated demonstration makes 35 calls to a scripted local model: three ordinary benign requests plus eight four-case test runs. It retains nine product report snapshots and eight test runs under `dist/output-assessment-demo/<unique-run>/`. It verifies 8 passes/2 unknowns with runtime evidence alone, 10 passes after both phases succeed, renewed uncertainty after refusal or version changes, and three failures in observation mode. Every saved report and test evaluation must replay without additional provider requests. No external API key is used. Go tests additionally cover audit failure, forged provider errors, pending runs, source changes, expiry, restart and evidence validation.
