# Runtime credential policies

**English** | [简体中文](zh-CN/runtime-policies.md)

GovWeave currently provides one built-in policy, **Credential egress** (`credential-egress`). It checks request text for recognizable credential patterns before a model call. It runs locally without an LLM, cloud inspection service, custom scripts, or user-provided regular expressions.

The policy is **disabled by default**. It does not grant model access, inspect model responses, or determine legal compliance.

## Configure the policy

1. Configure a model connection and an application under **Model connections** and **Applications & keys**.
2. Open **Runtime policies** and select a mode.
3. Select **Private key markers**, **API key patterns**, or both. At least one rule must remain selected, even when the mode is disabled.
4. Choose the application and model scopes. Each can cover all objects or a selected list.
5. Select **Save policy**. The saved-mode badge and revision identify the configuration in effect. Unsaved edits do not affect traffic.
6. Send a request through an authorized application, open **Request logs**, and select its request ID to inspect the assessment.

Switching the console language preserves the current form draft. **Reload saved policy** replaces the draft with the server's current configuration. A stale save returns a revision conflict rather than overwriting another administrator's update.

## Modes

| Mode | Checks request text? | Behavior on a match |
| --- | --- | --- |
| `disabled` | No | No credential enforcement; ordinary application access checks still run |
| `observe` | Yes, within scope | Record matching rule IDs and forward the request, including matched credentials |
| `block` | Yes, within scope | Return HTTP `403` with `error.code: policy_blocked`; no upstream request |

For an out-of-scope request, the policy records `not_applicable` and skips scanning. An in-scope request with no match records `allow`. Neither result proves the request is free of sensitive data.

Observe mode is useful for reviewing possible false positives, but it does not redact or withhold a match. Use synthetic, non-sensitive test values when evaluating forwarding behavior.

The same policy applies to ordinary and streaming Chat Completions. A blocked streaming request returns JSON before any SSE headers or provider request. Model listing and administrator connection checks do not pass through this request-content detector.

## Scope

Application and model scopes are joined with **AND**: both must match.

| Application scope | Connection scope | Requests checked |
| --- | --- | --- |
| All | All | Every admitted Chat Completions request |
| Selected | All | Requests from the selected applications |
| All | Selected | Requests targeting the selected connections |
| Selected | Selected | Only the intersection of both selections |

Scopes use IDs, not display names or model aliases. Each selected list can contain up to 64 unique, existing IDs. Empty lists in the API mean all objects, including ones created later. The console requires at least one selection when you choose a selected scope, so an empty selection does not silently become all.

Renaming an application or connection does not change its scope membership. Changing a connection's provider or model also retains that membership. Model grants are evaluated independently; a policy never grants a previously unauthorized model.

## Included rules

Rule set: **`credentials-v1`**.

| Rule ID | Matching behavior |
| --- | --- |
| `private_key` | PEM private-key start markers: generic, RSA, EC, DSA, OPENSSH, and ENCRYPTED |
| `api_key` | Selected prefixed patterns: `sk-` plus at least 20 token characters; `gw_app_` plus 43 token characters; selected GitHub-style token prefixes; `AKIA` plus 16 uppercase letters/digits |

For `sk-` and `gw_app_`, token characters are ASCII letters, digits, underscores, or hyphens. The GitHub-style patterns are `ghp_`, `gho_`, `ghu_`, `ghs_`, or `ghr_` followed by at least 30 alphanumeric characters, and `github_pat_` followed by at least 40 letters, digits, or underscores. The implementation uses word-boundary checks around the relevant prefixes; full detector definitions live in `internal/gateway/policy.go` in a source checkout.

These are pattern detectors, not credential verification. They do not contact providers, validate private-key material, or prove that a key is active. Documentation examples and synthetic keys can match. Other formats and future provider format changes may not match. A private-key header alone is enough to trigger its rule.

## Inspection boundary

The detector reads every string token in the original request JSON, including object keys, duplicate fields, messages, tool arguments, and extension fields. The standard JSON decoder resolves escapes at that level.

It does not:

- Recursively decode JSON strings that themselves contain escaped JSON.
- Decode Base64, inspect images or binary attachments, or download referenced URLs.
- Reassemble credentials split across fields or identify every obfuscation.
- Inspect model output or intercept later agent/MCP tool execution.
- Detect general personal data, commercial secrets, prompt injection, or legal violations.

Requests retain the 1 MiB limit. Checks use the gateway's bounded execution slots and do not introduce another response buffer or remote call. Per-request check duration is recorded in microseconds. For a development-only benchmark, see [Development](development.md#policy-verification-and-performance).

## Records and failures

A Chat Completions record that reaches policy evaluation contains a `content_policy` object. An illustrative blocking assessment is:

```json
{
  "id": "credential-egress",
  "revision": 2,
  "ruleset_version": "credentials-v1",
  "mode": "block",
  "result": "block",
  "matched_rules": ["api_key"],
  "check_duration_us": 80
}
```

The duration above is example data, not a performance target. Records store fixed identifiers only: no matched text, field paths, offsets, secret fingerprints, or credential hashes. The assessment's revision is separate from the legacy top-level `policy_revision`, which tracks connection/application configuration.

| `result` | Meaning |
| --- | --- |
| `disabled` | Policy was disabled |
| `not_applicable` | Application or connection was outside scope |
| `allow` | In-scope check completed without a match |
| `observe` | One or more rules matched; policy permitted forwarding |
| `block` | One or more rules matched; policy prevented forwarding |
| `error` | Check could not complete; no upstream request |

A request can have access `decision: allow` and policy `result: block`. Requests rejected before evaluation, model-list/connection-check operations, and older records may have no assessment; the console displays **Not evaluated**.

An observed match does not guarantee a successful provider call. Likewise, a blocking assessment can accompany `503 audit_unavailable` if the gateway cannot reliably persist the required start record and reserve finish capacity. In both that case and `503 policy_unavailable`, no provider call is made. Inspect the overall outcome, HTTP status, error code, and `upstream_attempted` alongside the policy result.

## Management API and persistence

Authenticated management endpoints:

| Method and path | Purpose |
| --- | --- |
| `GET /api/v1/policies/credential-egress` | Read the current policy, revision, and rule-set version |
| `PUT /api/v1/policies/credential-egress` | Validate and atomically save a replacement configuration |

Use an administrator session, `Content-Type: application/json`, and `X-GovWeave-Request: console` for writes. Browser requests must pass origin checks. Application keys cannot manage policies. See the [OpenAPI contract](../api/openapi.yaml) for the complete schema and authentication flow.

An illustrative update body for a fresh policy is:

```json
{
  "revision": 0,
  "mode": "observe",
  "rules": ["private_key", "api_key"],
  "application_ids": [],
  "connection_ids": []
}
```

Read the current revision before each update; `0` is only the initial revision. The server returns the saved configuration with an incremented revision. A stale revision returns `409`; invalid modes, rules, or scope IDs return `400`. On persistence failure, the existing policy stays active.

The latest configuration is saved in `policies.json` with private permissions. Corrupt or unsupported state prevents startup. A missing file initializes the disabled default, so disabling a policy should be an explicit saved configuration, not file deletion. Include the file in [instance backups](deployment.md#persistent-data-and-backups).

Each request uses one immutable policy snapshot. Changes affect new evaluations; already checked requests retain the revision they used. Only the latest configuration is retained: historical policy reconstruction, complete change attribution, approval workflows, multiple separately scoped policies, and legal-control mappings are future work.
