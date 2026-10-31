# Sensitive-output technical-control pack

**English** | [简体中文](zh-CN/sensitive-output-governance.md)

The draft internal policy [`sensitive-output-governance@1.0.0`](../examples/rule-packs/sensitive-output-governance.json) connects [output protection](sensitive-output.md) to product assessment and retained reports. It evaluates server-owned configuration and metadata from actual model/tool calls. It does not enable a policy, modify its mode, or claim compliance with a law or external framework.

## Install and register

Copy the pack into the instance's rule-pack directory, then restart. For the example deployment:

```bash
mkdir -p data/rule-packs
cp examples/rule-packs/sensitive-output-governance.json data/rule-packs/
go run ./cmd/govweave -config examples/deployment.json
```

Use [`examples/sensitive-output-product.json`](../examples/sensitive-output-product.json) with actual application IDs to register a product through `POST /api/v1/compliance/products`. See [product registration](product-assessments.md) for authentication and endpoints. Registered profiles cannot supply `runtime.*` facts; the adapter derives them from the gateway. The separate stateless evaluation API still accepts caller-supplied provenance and is not a substitute for trusted collection.

Administrators separately configure `sensitive-output`: select `block` or `redact`, select credential/email/phone, and include every bound application. The detector generation remains an explicit versioned policy choice. After a change, make authorized synthetic model/tool calls to verify that revision. Standalone text evaluations cannot establish execution evidence.

## Eight controls

| Control suffix (`OUTPUT-…`) | Requirement |
| --- | --- |
| `APPLICATIONS-ACTIVE` | Every bound application exists and is active |
| `PROTECTIVE-MODE` | Output policy mode is `block` or `redact` |
| `SCOPE-COVERAGE` | Enabled policy covers every bound application |
| `CATEGORY-COVERAGE` | Credential, email and Mainland China mobile-number checks are all selected |
| `AUDIT-AVAILABLE` | Durable audit writes and reservation capacity are available |
| `CURRENT-EVIDENCE` | At least one inspected model/tool output belongs to the current policy revision and detector version |
| `SAMPLE-RELEASES` | No observed selected-category releases and no releases without all three category checks in the bounded sample |
| `SAMPLE-COMPLETENESS` | No unknown output assessments or recovered incomplete calls in that sample |

The last two controls can pass on an empty sample, but `CURRENT-EVIDENCE` fails, so the overall result cannot be satisfied without execution evidence. Unavailable audit omits sample facts; their controls become `unknown`, while audit availability fails. A missing bound application leaves its configuration coverage unknown.

One inspected output does **not** validate every application, category, model, tool or route, and does not measure detector recall. Blocking supported observed output and successfully redacting it can both provide execution evidence. Failed checks, pending work and standalone redaction recommendations cannot.

## Evidence contract

All keys below have the `runtime.` prefix and source `runtime`. Configuration evidence references the gateway and output-policy revisions. Sample evidence references the captured audit byte position; current-policy check evidence also references the policy revision.

| Fact suffix | Meaning |
| --- | --- |
| `output_policy_revision`, `output_policy_mode` | Exact saved revision and mode |
| `output_policy_covers_product` | Enabled policy scope covers every bound application; category and mode requirements remain separate |
| `output_detector_version` | Pinned sensitive-text detector generation |
| `output_credential_enabled`, `output_email_enabled`, `output_phone_enabled` | Individually selected categories |
| `sample.output_current_checked_count` | Finished, attempted model/tool calls with complete observed/not-observed checks under the current policy revision and detector generation |
| `sample.output_block_count` | Calls withheld with `content_output_blocked`; independent legacy tool blocks have their own counter |
| `sample.output_redacted_count` | Completed releases with `redacted` result and completed redaction evidence |
| `sample.output_observed_release_count` | Completed releases whose output-policy result is `observe` |
| `sample.output_unchecked_release_count` | Completed releases missing a complete sensitive-output check or any of the three required categories; includes historical legacy, disabled and out-of-scope calls |
| `sample.output_unknown_count` | Finished calls whose output-policy result is `error`, including unsupported streams and unavailable output |
| `sample.output_incomplete_count` | Bound model/tool calls recovered as incomplete after restart |

Sample facts filter the **last 100 global audit records** to this product's applications and `chat.completions`/`tools.invoke`. They exclude `content.evaluate` and `assessment.chat.completions`. They are neither time-window counts nor a complete history. Traffic from other applications can displace older evidence; these indicators are not a permanent incident register. In-progress calls have no final verdict yet. Aggregate observation timestamps describe collection time, not a claim that sampled calls are recent.

Earlier releases remain in this bounded sample after a policy change. Historical checks cannot satisfy current-revision execution evidence. A release without a check is an evidence gap, not proof of sensitive disclosure; unknown output can have been safely withheld. Only explicitly captured report snapshots retain past evidence after it leaves the live sample.

## Run the local demonstration

```bash
make demo-output-governance
```

The command runs isolated local services with temporary private instance data: eight scripted model calls, one standalone evaluation, and two tool calls. It archives 11 phases under `dist/output-governance-demo/<unique-run>/`, with a summary and immutable report snapshots. It uses no external API or live key, retains metadata only, and checks every archive again after later policy changes. All replays must match without additional provider requests.

| Selected phase | Pass / fail |
| --- | --- |
| Disabled, no calls | 5 / 3 |
| Block, standalone evaluation only | 7 / 1 |
| Block, actual inspected output | 8 / 0 |
| New redact revision before calls | 7 / 1 |
| Redact, actual transformed output | 8 / 0 |
| Observe with a synthetic email release | 6 / 2 |
| Restore blocking after that release | 7 / 1 |
| Tool block / tool redact, independent clean sample | 8 / 0 each |

The tool demonstration explicitly selects legacy credential observation so the new policy's block/redact action is exercised. Legacy credential blocking still takes precedence when configured. The model demonstration also checks a disabled unchecked release and preserves that gap after restoring protection. Reports always carry `evaluation_only: true`, `legal_compliance: not_determined`, and draft pack status. These tests verify integration and evidence semantics, not real-world detector effectiveness or legal certification.

Optional version 1.1.0 adds current-plan pre-deployment and operation probe requirements. See [active output-control assessment](output-control-assessments.md) and run `make demo-output-assessment`; version 1.0.0 below stays unchanged.
