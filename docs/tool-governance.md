# Controlled read tools for application and Agent developers

**English** | [简体中文](zh-CN/tool-governance.md)

GovWeave can execute a configured read tool through `POST /v1/tools/{alias}/invoke`. The application authenticates with its application key; GovWeave checks an operator-owned resource grant before calling the tool, checks the returned text for the fixed credential patterns, and saves the terminal decision before releasing text. This is an API integration for application backends and Agent platforms; it does not require a new frontend.

The first adapter deliberately uses a small protocol: read one configured resource and return text. It is separate from Chat Completions `tools`/`tool_calls` passthrough. To govern an Agent action, its executor must actually call this endpoint. Direct calls to a database, filesystem, MCP server or another tool bypass this control.

For bounded pre-deployment and operation probes of resource denial, sensitive output and benign reads, use [active read-tool assessment](tool-control-assessments.md). Its evidence enters product reports through a separate tool-specific namespace.

## Execution and decision

1. Authenticate the application key and validate the bounded request. Caller-supplied identities, grants, sensitivity, URLs and commands are rejected as unknown fields.
2. Recheck key validity after reading the body and resolve the enabled tool and resource grant together. Unknown tools, unknown resources and missing grants all return `403 tool_not_allowed`, without an upstream call.
3. Reserve durable audit capacity before executing the configured HTTP request. The accepted immutable tool revision governs this call; later edits, revocation or rotation affect subsequent admission checks.
4. Buffer and validate the complete tool response. Inspect its `text` against `credentials-v1` (`private_key` and `api_key`). An observed match in `block` mode returns `403 tool_output_blocked` without releasing the text. `observe` mode releases it with a finding. Invalid or unavailable output is withheld in both modes.
5. Persist the final metadata record before sending any tool text. A failed terminal audit write returns `503 audit_unavailable` and withholds the text.

The response separates the evidence dimensions:

| Dimension | Source | First-version behavior |
| --- | --- | --- |
| Authorization | Authenticated application and configured resource grants | Missing grant blocks before execution |
| Data sensitivity | Operator classification: `public`, `internal`, `restricted` | Context for review; does not independently grant or deny access |
| Action | Adapter-defined `read` | Only the read protocol is exposed |
| Output credential finding | Fixed compiled `credentials-v1` patterns | `block` withholds a match; `observe` returns it with the finding |
| Evidence availability | Protocol, time/size limits and durable audit | Failure withholds output |

Every resource needs an explicit application grant, including `public` resources. An empty `allowed_applications` list denies all applications. A `restricted` resource may be read when the administrator explicitly grants the application access. This version does not calculate a risk probability, infer sensitivity, authorize individual end users, or make legal compliance conclusions.

`not_observed` means that these credential patterns were not found. It is not a general safety verdict. Patterns cover private-key headers and selected token prefixes; they do not cover arbitrary secrets, general PII, prompt injection, harmful language, encoded or obfuscated disclosures, or the semantic correctness of retrieved documents. The offline canary experiments are not substituted for these runtime checks.

## Upstream read protocol

The administrator configures a complete, fixed `endpoint`, such as `https://retrieval.internal/read`. GovWeave sends:

```http
POST /read
Content-Type: application/json
Accept: application/json
Authorization: Bearer <configured upstream credential, if any>

{"resource_id":"support-handbook"}
```

The provider must return HTTP `200`, `Content-Type: application/json`, and exactly one string field:

```json
{"text":"Support hours are 09:00–18:00."}
```

The resource ID is forwarded as JSON, never substituted into a path. The adapter supplies no free-form query, write operation, command or caller-controlled URL. Deploy a provider that implements this read-only contract; the HTTP method alone cannot prove that an arbitrary upstream service has no side effects. GovWeave supplies only the configured provider credential and its own fixed headers/request ID. It does not forward application credentials, cookies or arbitrary caller headers.

Redirects and automatic POST retries are disabled. HTTPS verifies certificates. Private and loopback endpoints are permitted for operator-controlled integrations; link-local, multicast and unspecified addresses are rejected, including during DNS resolution. HTTP requires explicit `allow_insecure_http: true`. Use network egress controls appropriate to your deployment.

## Configure and invoke

Use an existing authenticated administrator cookie jar for management calls. Keep it and generated key files private. Set `GOVWEAVE_ROOT` to the service root, without `/v1`, and `GOVWEAVE_COOKIE_JAR` to that private cookie-jar path. The following example requires Python 3 only to assemble JSON and read the returned IDs.

Create a tool-only application. An empty model grant list does not grant access to any model:

```bash
umask 077
curl --fail-with-body "$GOVWEAVE_ROOT/api/v1/applications" \
  --cookie "$GOVWEAVE_COOKIE_JAR" \
  -H 'X-GovWeave-Request: console' -H 'Content-Type: application/json' \
  --data '{"name":"Support agent","allowed_connections":[]}' > application.json
export GOVWEAVE_APP_ID="$(python3 -c 'import json; print(json.load(open("application.json"))["application"]["id"])')"
export GOVWEAVE_API_KEY="$(python3 -c 'import json; print(json.load(open("application.json"))["api_key"])')"
```

The key is returned only on creation or rotation. Keep it in the application backend's secret store. It cannot access management APIs; an administrator session cannot invoke tools.

Read the current tool-store revision and configure the local example provider's endpoint. `revision` is the global revision from this GET, not a gateway configuration revision or an individual tool's revision:

```bash
curl --fail-with-body "$GOVWEAVE_ROOT/api/v1/tools" \
  --cookie "$GOVWEAVE_COOKIE_JAR" > tools-current.json
export GOVWEAVE_TOOL_ENDPOINT='http://127.0.0.1:8001/read'
python3 - <<'PY'
import json, os
config = {
    "revision": json.load(open("tools-current.json"))["revision"],
    "name": "Support retrieval",
    "alias": "support",
    "endpoint": os.environ["GOVWEAVE_TOOL_ENDPOINT"],
    "enabled": True,
    "allow_insecure_http": True,
    "timeout_seconds": 5,
    "output_mode": "block",
    "resources": [{
        "resource_id": "support-handbook",
        "sensitivity": "internal",
        "allowed_applications": [os.environ["GOVWEAVE_APP_ID"]],
    }],
}
with open("tool.json", "w") as output:
    json.dump(config, output)
PY
curl --fail-with-body "$GOVWEAVE_ROOT/api/v1/tools" \
  --cookie "$GOVWEAVE_COOKIE_JAR" \
  -H 'X-GovWeave-Request: console' -H 'Content-Type: application/json' \
  --data-binary @tool.json > tool-saved.json
```

Replace the endpoint with your reachable read provider. The HTTP opt-in above is for this local example; use HTTPS for an encrypted connection. If the provider needs authentication, add its secret as `api_key` in the private configuration input. Responses and history expose only `has_credential`. On updates, omitted or `null` `api_key` retains the credential and an empty string clears it.

The application or Agent executor makes this call when it needs the resource:

```bash
curl --fail-with-body "$GOVWEAVE_ROOT/v1/tools/support/invoke" \
  -H "Authorization: Bearer $GOVWEAVE_API_KEY" \
  -H 'Content-Type: application/json' \
  --data '{"resource_id":"support-handbook"}'
```

A successful response contains `request_id`, `text`, and `governance`. The latter includes `policy_version: read-tool-governance-v1`, `ruleset_version: credentials-v1`, the tool revision/hash, the evidence dimensions, a final `allow`, `observe` or `redact` decision, and fixed reason codes. Only use `text` after a successful response. Errors contain `error` and governance evidence but no provider text; do not retry a blocked action through an ungoverned route.

For an Agent platform, expose a read tool whose only argument is `resource_id`, and implement its executor using this HTTP call. Bind the application key on the server. Never let the model supply or select credentials, endpoint addresses, application IDs or grants. Application-level isolation does not implement delegated end-user authorization; use separate applications/grants for the boundaries represented by this release.

## Python reference client

The standard-library [reference client](../examples/python/govweave_tools.py) can be copied into an application or imported from `examples/python`. It is a runnable example, not an installed GovWeave SDK package. `GovernedToolClient(root_url, api_key, alias, timeout=5, allow_insecure_http=False)` binds the service origin, application identity and configured alias in backend code. `invoke(resource_id)` and `execute({"resource_id": ...})` return `ToolResult` with `text`, `request_id` and `governance`.

For a local integration using the variables from the earlier example:

```bash
export GOVWEAVE_TOOL_ALIAS='support'
python3 examples/python/read_resource.py support-handbook --allow-insecure-http
```

The CLI requires `GOVWEAVE_ROOT`, `GOVWEAVE_API_KEY` and `GOVWEAVE_TOOL_ALIAS`. It prints only the request ID and governance decision by default; use `--show-text` explicitly to print retrieved text. Omit `--allow-insecure-http` for HTTPS deployments. The client does not follow redirects, inherit proxy environment settings, retry requests or fall back to an ungoverned endpoint.

An Agent executor can use the same interface:

```python
import os
from govweave_tools import GovernedToolClient, ToolCallError

client = GovernedToolClient(
    os.environ["GOVWEAVE_ROOT"],
    os.environ["GOVWEAVE_API_KEY"],
    os.environ["GOVWEAVE_TOOL_ALIAS"],
    timeout=10,
    allow_insecure_http=True,  # Explicit opt-in for this local HTTP example.
)
arguments = {"resource_id": "support-handbook"}  # Parsed tool arguments.
try:
    result = client.execute(arguments)
except ToolCallError as error:
    print({"error_code": error.code, "request_id": error.request_id})
else:
    # Supply result.text to the intended application workflow; avoid logging it.
    print({"request_id": result.request_id, "governance": result.governance})
```

Run the example with `examples/python` on your Python module path or copy the reference module into your own project. `execute` accepts only the resource ID field; extra identity, URL or permission fields produce `invalid_arguments` locally. Server denials produce `ToolCallError` with a fixed `code`, `request_id` and `http_status`. Invalid or unsupported response contracts are rejected. `observe` mode is a successful response that can include a credential finding and text; application code must decide how to handle it. The client's timeout is 1–60 seconds, enforced through a socket timeout and elapsed-time checks during body reading. Allow time beyond the provider's configured deadline for local checks; this is not an absolute DNS/whole-process latency guarantee.

## Product assessment and retained reports

Tool decisions now feed the existing product evaluator through server-owned configuration and audit facts. Install the [read-tool technical-control pack](../examples/rule-packs/read-tool-governance.json) in the instance's rule-pack directory. For a deployment using `./data`:

```bash
mkdir -p data/rule-packs
cp examples/rule-packs/read-tool-governance.json data/rule-packs/
```

Restart the service to load the pack, then establish a new administrator session/cookie jar. The pack is `read-tool-governance`, version `1.0.0`, and is an internal-policy **draft**. It requires active applications, enabled resource-grant coverage, output blocking for all enabled granted tools, available audit capacity, at least one inspected output, and a bounded sample without observed credential releases, unknown outputs or incomplete calls. It does not convert those technical checks into a legal conclusion.

Register the application from the earlier example using the [tool product template](../examples/read-tool-product.json):

```bash
umask 077
python3 - <<'PY'
import json, os
product = json.load(open("examples/read-tool-product.json"))
product["application_ids"] = [os.environ["GOVWEAVE_APP_ID"]]
with open("read-tool-product.json", "w") as output:
    json.dump(product, output)
PY
curl --fail-with-body "$GOVWEAVE_ROOT/api/v1/compliance/products" \
  --cookie "$GOVWEAVE_COOKIE_JAR" \
  -H 'X-GovWeave-Request: console' -H 'Content-Type: application/json' \
  --data-binary @read-tool-product.json > product-saved.json
export GOVWEAVE_PRODUCT_ID="$(python3 -c 'import json; print(json.load(open("product-saved.json"))["id"])')"
curl --fail-with-body "$GOVWEAVE_ROOT/api/v1/compliance/products/$GOVWEAVE_PRODUCT_ID/evaluate" \
  --cookie "$GOVWEAVE_COOKIE_JAR" \
  -H 'X-GovWeave-Request: console' -H 'Content-Type: application/json' --data '{}'
```

The profile deliberately has no submitted runtime facts: callers cannot set `runtime.*`. Actual tool calls and configuration changes trigger background reassessment. A newly configured tool with no inspected output in the sample fails the output-evidence requirement, so merely enabling blocking cannot produce a complete passing result. Denied unauthorized requests and correctly withheld credential outputs do not themselves cause a control failure.

Inspect `controls`, `findings`, and the overall technical status. Responses still say `evaluation_only: true` and `legal_compliance: not_determined`. Tool facts are derived from configuration and the latest **100 global** indexed request entries, filtered to bound applications and `tools.invoke`. This is not a full history or a per-product 100-request window. Audit failure leaves sample facts unavailable/unknown. See [product evidence](product-assessments.md#controlled-read-tool-evidence) for every fact and its scope.

Capture a report explicitly when you need retained evidence:

```bash
curl --fail-with-body "$GOVWEAVE_ROOT/api/v1/compliance/products/$GOVWEAVE_PRODUCT_ID/reports" \
  --cookie "$GOVWEAVE_COOKIE_JAR" \
  -H 'X-GovWeave-Request: console' -H 'Content-Type: application/json' --data '{}' > report-saved.json
export GOVWEAVE_REPORT_ID="$(python3 -c 'import json; print(json.load(open("report-saved.json"))["summary"]["id"])')"
curl --fail-with-body "$GOVWEAVE_ROOT/api/v1/compliance/reports/$GOVWEAVE_REPORT_ID/replay" \
  --cookie "$GOVWEAVE_COOKIE_JAR" \
  -H 'X-GovWeave-Request: console' -H 'Content-Type: application/json' --data '{}'
```

Replay uses the retained rule pack, fact values and evaluation time. It does not invoke the tool or verify live output again. Reports retain technical metadata and indicators; the adapter does not copy resource IDs, endpoints, credentials or retrieved text. Replaying a past report does not assert that the current application is in the same state.

## Management, history and audit

| Endpoint | Authentication | Result |
| --- | --- | --- |
| `GET /api/v1/tools` | Administrator session | Current tool-store revision and metadata |
| `POST /api/v1/tools` | Administrator session and mutation header | Create tool; `201` |
| `PUT /api/v1/tools/{id}` | Administrator session and mutation header | Replace configuration using current global revision; `200` |
| `GET /api/v1/tools/{id}/history` | Administrator session | Immutable metadata snapshots, newest first |
| `POST /v1/tools/{alias}/invoke` | Application Bearer key | Execute the accepted read operation |
| `GET /api/v1/requests?application_id=...` | Administrator session | Recent metadata records, including `tools.invoke` |

Management mutations require `X-GovWeave-Request: console` and JSON, use the existing origin checks, and reject stale revisions with `409 revision_conflict`. Resource grants may reference only existing active applications when saved. To disable a tool, update it with `enabled: false`; there is no deletion or pruning endpoint. Retained history remains available after edits.

`calls.jsonl` records `operation: tools.invoke` with a `tool_governance` object. It excludes resource IDs, retrieved text, matched values, upstream URLs/credentials, caller metadata and raw provider errors. Resolve its `tool_id`/`tool_revision` against the history API and compare `snapshot_sha256` to inspect the configuration used. The hash covers public tool metadata with the hash field empty; it is a consistency check, not a signature or tamper-proof evidence store. Private tool credential snapshots are encrypted with the instance's `gateway.key`; preserve that key when backing up `tools.json`.

Started records have `decision: pending` inside `tool_governance`; a missing finish after interruption is incomplete, not an allowed result. A finish-write failure can leave evidence incomplete, but no tool output is released. Authorization denials are recorded without making a provider request. The existing 128 MiB audit limit and archival procedure apply.

| HTTP status | Error code | Meaning |
| --- | --- | --- |
| `400` / `413` / `415` | `invalid_tool_request` / `request_too_large` / `unsupported_media_type` | Invalid request or input limit |
| `401` | `invalid_api_key` | Missing, rotated or revoked application key |
| `403` | `tool_not_allowed` | Tool/resource access denied before execution |
| `403` | `tool_output_blocked` | Provider was called, but matched output was withheld |
| `429` | `gateway_busy` | Shared execution slots are occupied |
| `502` | `upstream_error`, `upstream_unreachable`, `invalid_upstream_response`, `response_too_large` | Provider or protocol failure; output withheld |
| `503` | `audit_unavailable`, `credential_unavailable` | Required evidence or provider credential unavailable |
| `504` | `upstream_timeout` | Configured timeout exceeded |

## Bounds and validation

Requests are limited to 4 KiB and exactly one `resource_id` string. Aliases/resource IDs use 1–100 ASCII letters, digits, dots, underscores or hyphens, starting with a letter or digit. Responses have a 64 KiB JSON-envelope limit and an 8192-byte UTF-8 text limit. The provider timeout is 1–30 seconds, covering the upstream request and response reading after local admission. Model and tool calls share 64 concurrent execution slots.

Management input is limited to 16 KiB. The private configuration file is limited to 4 MiB, 32 tools and 128 total immutable revisions across all tools, with 1–32 resources per tool and up to 32 application grants per resource. Capacity exhaustion rejects changes; it does not silently drop history. There is no automatic history deletion, content retention, output streaming, write-tool execution, MCP adapter or automatic remediation.

Run the isolated local demonstration without a real model or external API key:

```bash
make demo-tools
```

This builds `bin/govweave`, starts a temporary instance and a scripted read provider, and checks six paths: an authorized read, a forbidden resource, matched output withholding, caller-supplied identity fields, a missing key and a revoked key. Only the authorized read and the output-block case contact the provider. A private `dist/tool-demo/.../summary.json` records statuses and call counts without resource IDs, text or credentials. The temporary instance is removed when the run ends. Run `python3 tests/tools-smoke.py` after building to verify the demonstration itself.

The developer-to-report workflow has a separate demonstration:

```bash
make demo-agent
```

It runs scripted Agent tool proposals through the Python reference client and evaluates the installed pack in three phases. First, authorized/forbidden/credential-output calls exercise enforcement and all six technical controls pass. Second, an explicit operator change to `observe` releases a matching fixture, so both the blocking-configuration and sampled-release controls fail. Third, the operator restores `block`; the configuration control passes again, while the earlier observed release keeps the sample control failing. The script archives and replays each phase without any additional provider call during replay. It does not use a model or perform automatic repair. Private results go to `dist/agent-demo/.../`; `python3 scripts/demo-agent.py --binary bin/govweave --output-dir <new-directory>` selects a fresh output location.

Tests cover configuration history and credential omission, management authentication, permitted reads, denial before provider calls, output withholding, malformed responses and audit failures. Local synthetic fixtures validate these enforcement paths; they do not establish general model safety accuracy or production reliability. See [OpenAPI](../api/openapi.yaml) and the [JSON schema](../schemas/tools.schema.json) for the contract.

Optional [sensitive output protection](sensitive-output.md) can redact recognized selected categories before release. Legacy credential blocking still wins. Upgrade the Python reference integration before enabling redact mode, because completed transformations add versioned evidence and a `redact` decision.

## Opt-in retrieved instruction checks

Add `"instruction_policy": {"version": "tool-instructions-v1", "mode": "block"}` to the complete tool create/update body. `observe` records matches and permits otherwise valid text; omitted/null disables this additional check. A PUT replaces settings, so copy this field when preserving it. The tool revision and snapshot digest pin the setting for each admitted call, including across concurrent edits. Old snapshots without the field keep their original hashes and behavior.

V1 scans up to 8192 UTF-8 bytes for three fixed rule IDs: `task_override`, `authority_spoof`, and `role_delimiter`. It recognizes explicit English/Chinese task overrides and selected authority/role syntax. It does not call a model. A blocking match returns `403 tool_instruction_blocked` before the result reaches the Agent; an incomplete check returns `502 tool_instruction_unavailable`, including in observe mode. Resource authorization still precedes provider I/O, the legacy credential block takes precedence, and terminal audit must commit before any text is released.

`governance.instruction_policy` contains version, mode, state, rule IDs, decision, duration and optional review evidence; the existing tool revision/digest identifies its immutable configuration. The audit retains no matched text or resource ID. An instruction observation in observe mode contributes to the overall `observe` decision; completed sensitive-output redaction takes the overall `redact` decision while retaining instruction evidence.

This is a conservative syntax control, not general prompt-injection recognition. Quoted attack examples also match; an untrusted document cannot bypass the check by declaring itself a safe example. Indirect instructions, encoding, other languages and obfuscations remain coverage gaps. It is opt-in so operators can measure their own normal documents before choosing block mode. See the [Agent comparison](knowledge-agent.md#additional-controls-and-the-v2-comparison) for observed misses and a training-document false block.

## Instruction v2 and exact document reviews

Choose `"instruction_policy": {"version": "tool-instructions-v2", "mode": "block"}` in the full tool configuration to opt in. V1 remains frozen. V2 retains the three v1 signals and adds `answer_manipulation` for selected English/Chinese directives aimed at the assistant's reply, including patterns such as adding a phrase to the final answer or returning only specified text. Work remains bounded to 8192 bytes and four rule IDs, with no provider call or external dependency. This is syntax detection: legitimate reply-format instructions and quotations can match; encoding, alternative wording and semantic intent remain gaps.

An operator can attach optional `instruction_review` to an individual resource. It contains `version: exact-instruction-review-v1`, the explicit `detector_version`, `content_sha256` of the complete decoded UTF-8 tool text, and one to four named `rule_ids` to exempt. The review applies only to that resource and its authorized applications. Omitting the review or setting it to null removes it on replacement; an empty object is invalid. The detector version must equal the tool's instruction policy; upgrading that policy requires explicitly reviewing/removing old review settings. Disabling the instruction policy also requires removing reviews.

Prepare metadata from a **previously inspected local source document**, preserving exact bytes including final newlines:

```bash
python3 scripts/review-tool-document.py --file reviewed-training.txt \
  --detector tool-instructions-v2 --rule task_override
```

The helper reads at most 8193 bytes, rejects documents over 8192 bytes, invalid UTF-8 and nonregular files, and prints only the review JSON. Put that JSON in the intended resource's `instruction_review` field in the full tool PUT with its current global revision. The helper does not judge safety, send data, or change the server. Do not generate approvals automatically from newly returned untrusted content. A digest is a version pin for an operator permission, not proof that a model will treat the text safely.

Before release, the gateway compares the exact original text bytes with the pinned review. Changed text receives **no rule exceptions**; if its ordinary checks find nothing, it may still be released. A match exempts only the explicitly reviewed rules; other matches keep their configured action. For example, a review of `task_override` does not waive a new `answer_manipulation` match. Input limits, unknown scans, resource denial, credential/PII checks and audit failures remain independent. Review does not grant access or suppress the raw observed rules.

`governance.instruction_policy.review` records `version`, `state` (`matched`, `mismatch`, or `unavailable`) and `exempted_rule_ids`. A fully excepted observation can have `state: observed` with `decision: allow`; the overall reason is `instruction_review_applied` unless another control determines the outcome. Partial reviews retain block/observe for remaining matches. Audit stores neither the runtime content hash nor excerpts; the existing tool revision and snapshot digest identify the operator configuration. The configured document hash is retained in private admin tool history. The Python reference client validates these combinations and fails closed on inconsistent evidence. Update copied reference clients before enabling v2 or reviews; older strict clients reject the new metadata.

The [v3 Agent comparison](knowledge-agent.md#v3-instruction-and-review-comparison) separately measures detector expansion and exact-document permissions. Existing compliance packs do not attest general injection resistance or the adequacy of an operator's review.

Sensitive-output v3 is an explicit policy choice shared by tool and model output: bounded paired email markup, one-layer Base64 detection, whole-token redaction and `encoding_limit` unknowns. Update the strict Python reference client before enabling it. See [v3 boundaries](sensitive-output.md#explicit-v3-formatted-email-boundaries-and-single-layer-base64).
