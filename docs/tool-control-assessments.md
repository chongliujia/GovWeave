# Active read-tool assessment

**English** | [简体中文](zh-CN/tool-control-assessments.md)

The optional `sensitive-tool-governance@1.0.0` pack connects active read-tool tests to product reports. Its eleven technical controls cover the eight [runtime output controls](sensitive-output-governance.md), enabled resource-grant coverage, and current pre-deployment/operation tool tests. It is an internal policy draft, not a regulatory determination.

## Install and configure

```bash
mkdir -p data/rule-packs data/test-suites
cp examples/rule-packs/sensitive-tool-governance.json data/rule-packs/
cp examples/test-suites/read-tool-output-controls.json data/test-suites/
```

Restart to load the plugins. Configure a [read tool](tool-governance.md) with five dedicated synthetic resources: `probe-credential`, `probe-email`, `probe-phone`, `probe-benign` and `probe-denied`. Grant the testing application access to the first four and leave it ungranted on the last. The provider should return the corresponding synthetic credential/email/Mainland China mobile challenge, the exact `GOVWEAVE_TOOL_READY` benign literal, or restricted synthetic content respectively. Use a provider that implements the documented read protocol; an arbitrary HTTP endpoint is not proven free of side effects.

Register [the product example](../examples/sensitive-tool-product.json) with the application ID. Save [the plan example](../examples/read-tool-test-plan.json) through `PUT /api/v1/compliance/products/{id}/test-plan`, replacing `application_id` and `tool_alias`. Set `target_kind: read_tool`; omit `model_alias` and `max_output_tokens`. Tool-only applications need no model grant. The suite must also have `target_kind: read_tool`; each case uses `resource_id` instead of `messages`.

Configure `sensitive-output` to cover the application, the intended detector generation and all three categories, with `block` or `redact`. The tool's independent legacy credential check retains precedence: `output_mode: block` can withhold a credential before redaction. That case is explicitly recorded as `legacy_tool_credential_blocked`, never as completed redaction. To exercise credential redaction, intentionally configure the legacy check to `observe` while keeping the separate output policy in `redact` mode.

Start each phase through `POST /api/v1/compliance/products/{id}/test-runs` with `{"phase":"pre_deployment"}` or `{"phase":"operation"}`. Poll the returned run ID. The same administrator authentication and [active-test limits](active-assessments.md) apply. Scheduling is opt-in and disabled in the example; enabling it authorizes recurring tool requests. A product can keep one model plan and one read-tool plan, including any legacy default. See [combined application assessment](application-assessments.md) to configure both and select a named plan explicitly.

## What the five cases establish

| Check | Required evidence |
| --- | --- |
| Credential, email and phone `output_protected` | Each category is observed and actually blocked or successfully redacted |
| `output_allowed` | The exact benign text is returned unchanged without a sensitive finding |
| `tool_denied` | The configured resource is denied before upstream execution, with a committed terminal audit |

Every case uses `scope: gateway_control`. Admission requires a known resource for each case and existing grants for the four output probes. The denial resource may have become granted: that is an intentional test condition, so the test runs and fails with `tool_resource_was_authorized`. In this situation the real grant permits a provider request; use synthetic resources. With correct grants, the five cases cause only four upstream reads. No application key or caller-supplied identity is invented to bypass permission checks.

Verdicts use an internal gateway receipt and confirmed terminal audit. A provider's fabricated rejection cannot establish an authorization denial or output block. Observation releases fail protection checks. A missing challenge, unavailable audit or unverified execution stays unknown; a harmless response alone does not prove a sensitive challenge was protected. Each case executes once. These probes cover the chosen resources on one configured tool, not all tools, autonomous Agent trajectories, semantic correctness, general privacy or measured detector accuracy.

## Product evidence and replay

| Fact | Expiry after completion |
| --- | --- |
| `testing.tools.output.pre_deployment.passed` | 30 days |
| `testing.tools.output.operation.passed` | Twice the configured interval |

Both use `source: assessment` and the original run ID/timestamps. Complete coverage of all five checks is required. Model facts under `testing.output.*` cannot satisfy these requirements, and tool facts cannot satisfy model requirements. The latest run of each phase must be completed and determinate; running, interrupted, expired, failed-to-execute or inconclusive results do not fall back to earlier success. Product, plan, suite, pack, runner, application/gateway, request policy, tool and output-policy revisions must still match. Changes trigger reassessment and invalidate cached success. Restart reconstructs current evidence from retained runs.

Tool runs use `bounded-tool-tests-v1` and retain `tool_id`/`tool_revision`; their model `connection_id` is empty and `connection_revision` is zero. Existing model runners and historical read/replay formats remain supported. The audit operation is `assessment.tools.invoke`, excluded from production tool/output counts. It still occupies the shared latest-100-entry audit index and can displace old production samples. Passing active tests therefore does not replace the pack's separate runtime evidence requirement.

Returned tool text is never retained by these checks, even with `retain_responses: true`. Only the benign case keeps a response digest/byte count. The private suite snapshot retains configured resource IDs and expected literals; per-case receipts retain bounded decisions and revisions, not returned sensitive text. Preserve both test runs and product reports in backups. Replay recomputes the saved rule evaluation without tool I/O; it does not re-execute the detector or prove current behavior. Reports remain advisory and `legal_compliance` remains `not_determined`.

## Local verification

```bash
make demo-tool-assessment
```

The isolated demo makes 43 local provider calls: two ordinary benign reads and ten five-case runs, with one deliberately expanded denial-resource grant. It retains ten test runs and nine reports in `dist/tool-assessment-demo/<unique-run>/`. It verifies 9 passes/2 unknowns before testing, all 11 passes after both phases, failed authorization after grant expansion, unknown evidence after a missing challenge, and evidence invalidation after policy changes. All nineteen artifacts replay without provider calls. No external model or key is needed. Go tests additionally cover tool-only identities, revocation, audit failure, provider-error spoofing, changes during execution, restart and malformed plans.
