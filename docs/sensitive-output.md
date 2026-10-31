# Sensitive text observations and output protection

**English** | [简体中文](zh-CN/sensitive-output.md)

Versioned sensitive-text detectors identify bounded credential, email-address and Mainland China mobile-number candidates. An application can inspect text through `POST /v1/content/evaluations`. Operators can enable the `sensitive-output` policy to use the same detector on non-streaming model answers and configured read-tool output. The detector reports observations; the server-owned policy separately decides whether selected categories cause observation, blocking or redaction.

This is a technical content control. A syntactically matching email or number does not prove personal ownership, confidentiality or a legal violation. `not_observed` means that this version did not find its supported patterns; it is not a general safety verdict.

## Detection scope

| Category | Fixed rule IDs | What version 1 checks |
| --- | --- | --- |
| `credential` | `private_key`, `api_key` | Private-key headers and the existing selected credential-like token prefixes; no credential validity checks |
| `email` | `email_address` | A practical ASCII email syntax subset with bounded local/domain lengths and label checks |
| `phone` | `cn_mobile_phone` | Mainland China mobile-number shape, with an explicit `+86` prefix or nearby phone-related context for a bare number |

Spaces and hyphens in the supported phone forms can be recognized. This is not a global telephone-number classifier. Encoded or obfuscated disclosures, unsupported international formats, non-ASCII email syntax, contextual ownership and general semantic risks can be missed. No external model, NER service, network lookup, entropy service or confidence probability is used by this detector. V2 adds the bounded formatting variants below; further recognizers require versioned implementation and validation.

The detector accepts at most 8192 UTF-8 bytes and retains at most 32 findings. Each finding contains the category, fixed rule ID and an exclusive byte span in the original input; it contains no matched value. Invalid UTF-8, oversized detector input and finding-capacity exhaustion produce `unknown`. Finding-capacity exhaustion is marked `truncated: true`; partial findings do not become a complete clean result. Empty text is permitted and yields no observations.

## Select a detector generation

Initial policy snapshots use `sensitive-text-v1`. Upgrading the binary does not change existing policies. Omitting `detector_version` on save preserves the current generation. Administrators may explicitly set `"detector_version": "sensitive-text-v2"`, or select v1 again in a new revision. History, standalone evaluations and model/tool audit records retain the selected version; in-flight calls keep their pinned generation. Applications cannot select a detector in the evaluation request or override the server policy.

V2 preserves raw v1 detection and adds bounded normalization: full-width ASCII U+FF01–U+FF5E, ideographic space U+3000, five zero-width characters U+200B/U+200C/U+200D/U+2060/U+FEFF, and email `[at]`/`[dot]` tokens (case insensitive with adjacent spaces/tabs). Newlines and ordinary at/dot words are preserved. Bracket replacement contributes only email findings. Additional observations have `normalized_` rule IDs and offsets into the original input. Observe mode returns the original text, never a rewritten version. Overlapping findings across views are merged under the same 32-finding budget; exhaustion remains unknown.

Normalization can turn ordinary text into a candidate, so evaluate application-specific false positives. V2 does not implement arbitrary Unicode confusable recognition, semantic recognition of arbitrary secrets, Base64 decoding, international phone formats or non-ASCII email syntax.

## Inspect text through the application API

Set `GOVWEAVE_ROOT` to the gateway origin, without `/v1`, and supply a valid application key in `GOVWEAVE_API_KEY` through the application's secret store. A tool-only application with no model grants can use this endpoint. Administrator sessions cannot replace an application key.

```bash
curl --fail-with-body "$GOVWEAVE_ROOT/v1/content/evaluations" \
  -H "Authorization: Bearer $GOVWEAVE_API_KEY" \
  -H 'Content-Type: application/json' \
  --data '{"text":"Contact the synthetic user at alex@example.com."}'
```

The strict JSON object accepts only `text`; application identity, categories and policy decisions cannot be supplied by the caller. The JSON envelope is limited to 64 KiB, and decoded text to 8192 UTF-8 bytes. Invalid input returns `400`/`413`/`415` as appropriate. The application key is checked again after reading the body. The endpoint uses the shared bounded execution slots and durable metadata audit, and makes no provider request.

A successful evaluation returns `request_id`, `detection` and `policy`. `detection` always runs all supported categories, including when enforcement is disabled or the application is outside its scope. `policy` records the exact policy revision, selected categories, matched categories/rules and the decision. The input text is not echoed.

**HTTP `200` means evaluation completed.** It can contain an observed risk, an unknown detection, or `policy.result: block`/`redact`. The standalone endpoint does not execute a subsequent operation or redact text; application code must consume the result and enforce its own next action. The gateway's model/tool paths perform their own enforcement below.

## Configure output protection

Use an authenticated administrator cookie jar in `GOVWEAVE_COOKIE_JAR`. First read the current policy, then save using that revision. This policy is initially **disabled** and is independent of the model-request `credential-egress` policy and the read tool's legacy credential mode.

```bash
umask 077
curl --fail-with-body "$GOVWEAVE_ROOT/api/v1/policies/sensitive-output" \
  --cookie "$GOVWEAVE_COOKIE_JAR" > output-policy-current.json
python3 - <<'PY'
import json
current = json.load(open("output-policy-current.json"))
request = {
    "revision": current["revision"],
    "mode": "observe",
    "detector_version": current["detector_version"],  # explicitly use sensitive-text-v2 to opt in
    "categories": ["credential", "email", "phone"],
    "application_ids": [],
}
with open("output-policy-update.json", "w") as target:
    json.dump(request, target)
PY
curl --fail-with-body "$GOVWEAVE_ROOT/api/v1/policies/sensitive-output" \
  --cookie "$GOVWEAVE_COOKIE_JAR" \
  -H 'X-GovWeave-Request: console' -H 'Content-Type: application/json' \
  --request PUT --data-binary @output-policy-update.json
```

An empty, omitted or `null` application list selects all applications, including future ones. Non-empty scopes accept up to 64 known application IDs. Categories select one or more of `credential`, `email`, `phone`; the decision uses selected categories, while the detector remains version-pinned. Scope, categories and policy mode come from the operator, never from model output or tool arguments.

| Mode | Supported valid output | Unknown or unsupported output |
| --- | --- | --- |
| `disabled` | This policy does not enforce output | Existing model/tool behavior remains in force |
| `observe` | Returns text, including selected-category matches, and records evidence | Withheld on the protected path |
| `block` | Returns text if no selected-category match is observed; otherwise withholds it | Withheld on the protected path |
| `redact` | Replaces selected observed content and rechecks it before return; no match returns unchanged text | Withheld on the protected path |

Start with a scope appropriate to your application, inspect measured errors and actual observation evidence, then enable blocking where its false-positive/miss tradeoff is acceptable. Observe returns the original text. Explicitly select `mode: redact` to replace detected content before release.

## Return redacted output

Save `"mode": "redact"` as an administrator to enable transformation within the existing application and category scope. The snapshot pins `redaction_version: sensitive-redaction-v1`; other modes omit this field. The independent read-tool credential block still takes precedence and cannot be bypassed by redaction.

Transformation covers only selected findings actually recognized by the detector. Email and phone matches are replaced by the fixed `[REDACTED]` marker at their original byte spans; overlapping/adjacent spans are merged and other text stays unchanged. Any selected credential finding replaces the **entire output** with `[REDACTED]`: private-key detection may locate only a header, which cannot safely authorize partial masking. V2 formatting variants retain original-byte mapping.

The transformed text is checked again with the same detector generation. A remaining selected finding, unknown result, invalid span or output above 8192 bytes returns `502 content_output_unavailable` without text. Failed terminal audit still returns `503` without the transformed body. Streaming remains unsupported.

Completed model/tool transformation returns HTTP 200 with `X-GovWeave-Output-Action: redacted`. Audit `output_policy.result` is `redacted`; `state: observed` describes the original detection. Optional `redaction` evidence contains only version, scope (`matched_spans` or `full_output`), replaced segment count, and transformation/recheck microseconds. It contains no original text, spans or content hashes. Tools also return `governance.decision: redact`; the updated Python reference client validates completion evidence. Older strict clients may reject the new decision.

Standalone `POST /v1/content/evaluations` returns only a `policy.result: redact` recommendation; it performs no replacement and returns neither text nor redaction completion evidence. Product fact `runtime.sample.output_redacted_count` counts successful model/tool operations with completed evidence, excluding standalone evaluations, active tests and failed calls. Contact-only redaction that leaves unselected credentials retains the conservative legacy credential-release count.

Redaction does not improve detector recall or establish anonymization: missed and unselected categories can remain. Applications should inspect the completion indication before deciding how to display or reuse transformed text.

## Model and tool execution boundaries

An enabled, in-scope model-output policy rejects `stream: true` with `400 content_stream_unsupported` **before upstream I/O**. Streaming content protection is not implemented; this response prevents silently forwarding an unchecked stream under an active policy.

Protected non-streaming Chat Completions accept one complete `assistant` text choice with `finish_reason: stop`, or the explicitly declared single `read_resource` proposal described in [the knowledge Agent contract](knowledge-agent.md). Other tool calls, legacy `function_call`, mixed text/action messages, non-text content, incomplete responses, an envelope over 64 KiB or text over 8192 UTF-8 bytes are withheld with `502 content_output_unavailable`. Unsupported tool declarations return `400 content_tools_unsupported` before provider I/O. Selected sensitive tool arguments are blocked in both block and redact modes; they are never rewritten into a different action. A proposal does not authorize resource execution.

Successful protected responses use a canonical completion envelope built by the gateway: gateway request ID, configured model alias, local creation timestamp, the checked text and supported numeric usage. Unchecked provider extensions, reasoning fields, provider IDs and other provider-specific metadata are dropped. Disabled or out-of-scope traffic keeps the existing [model adapter behavior](model-gateway.md).

Read tools keep their independent `credentials-v1` check and existing `block`/`observe` mode. The new policy adds its assessment as `governance.output_policy`; either control may withhold the text. Enabling the new policy does not relax resource authorization or remove the legacy credential control. Integrations using the Python reference client should use the updated example, which validates this optional assessment before releasing text to its caller. See [read-tool integration](tool-governance.md).

Each admitted call pins its policy snapshot. Later edits affect subsequent calls. Before provider I/O, the gateway reserves audit capacity; protected output is released only after its terminal metadata decision is saved. Failure to save that decision returns `503 audit_unavailable` and withholds the text. A prior provider call may still have occurred.

## History, evidence and limits

| Interface | Purpose |
| --- | --- |
| `GET /api/v1/policies/sensitive-output` | Current snapshot |
| `PUT /api/v1/policies/sensitive-output` | Revision-checked update |
| `GET /api/v1/policies/sensitive-output/history` | Complete bounded history, newest first |
| `GET /api/v1/policies/sensitive-output/revisions/{revision}` | Exact immutable snapshot |
| `POST /v1/content/evaluations` | Application-authenticated standalone observations |
| `GET /api/v1/requests` | Administrator access to metadata decisions |

Management writes use the existing JSON, custom-header and origin checks. Stale writes return `409 revision_conflict`. Private `output-policies.json` stores at most 128 snapshots **including revision zero**, within 2 MiB. It is written atomically with private permissions. Capacity exhaustion returns `409 output_history_full` and preserves the current policy; history is never silently evicted. There is no delete/prune endpoint. A missing file means the disabled initial state, so include it in backups and do not delete it to change enforcement. Invalid state refuses startup.

Call records contain `output_policy`: fixed policy/detector versions, mode, selected and matched category/rule IDs, state, reason and check duration. They contain no input/output text, matched values, byte spans, content hashes, raw upstream errors or application/upstream credentials. The independent evaluation response can return byte spans to its authenticated caller, but those spans are not persisted in call records.

Product assessments retain the output-policy revision in their source snapshot. A policy update invalidates cached assessments; active tests also reject changed configuration rather than publishing a stale result. Older archives remain replayable without inventing output-policy evidence. Evidence and replay describe technical observations at their recorded time, not legal compliance or an approval to deploy.

## Measure and verify

Install the draft [sensitive-output technical-control pack](sensitive-output-governance.md) to evaluate configuration, actual model/tool execution and retained release evidence together. `make demo-output-governance` verifies eight controls across 11 report snapshots using local synthetic services, including replay after later policy changes. A current mode alone is insufficient: the pack requires current-revision execution evidence and preserves historical sample findings.

The authored [synthetic corpus](../tests/testdata/sensitive-validation-v1.json) and its [provenance](../tests/testdata/sensitive-v1-provenance.md) include positive candidates, normal lookalikes, context cases and known unsupported disclosures. Authoring is separated from detector implementation, but this remains an internal developer benchmark, not external validation or representative customer data.

```bash
make validate-sensitive
```

This runs both v1 and v2 against the original 80 cases and a new frozen 64-case set, producing four reports. The new set was frozen before implementing v2 but authored by the same development process; it is internal validation, not blind or externally independent evidence. See [v2 provenance and first comparison](../tests/testdata/sensitive-v2-provenance.md). For one combination use `go run ./cmd/sensitive-eval -detector sensitive-text-v2 -corpus tests/testdata/sensitive-validation-v2.json`.

The command writes a new private report under `dist/sensitive-validation/`. Quality counts each case once and reports each category separately. Unknown positives count as misses; unknown negatives do not become true negatives. Precision, recall, unknown counts and coverage are kept separate. Warmed local detector P50/P95/P99 exclude HTTP, provider/model time, queuing and audit I/O. These timings are not an end-to-end service latency guarantee.

Gateway tests verify standalone observations, application identity, scope/category behavior, output withholding, unknown/unsupported input, streaming rejection before I/O, immutable in-flight policy versions and audit failure. See [OpenAPI](../api/openapi.yaml) and the [content schema](../schemas/content.schema.json) for the wire contract.

Run `make demo-sensitive` to check v1 plain forms followed by v2 obfuscated forms in an isolated real-HTTP demonstration with a scripted local model. It checks standalone observations, all three output categories, observe release, redaction, no-match release, and streaming rejection before provider access. No account is needed. After `make build`, explicitly run `python3 scripts/demo-sensitive.py --kimi` to use `kimi-k2.6` at `https://api.moonshot.cn/v1`: the script reads a key without echo (or from `MOONSHOT_API_KEY`), sends at most three synthetic requests with 128 output tokens each and no retries, removes its temporary encrypted gateway state, and retains only a private metadata summary under `dist/sensitive-demo/`. Non-thinking mode follows the [official K2.6 parameter reference](https://platform.kimi.com/docs/guide/kimi-k2-6-quickstart). Unexpected model behavior is reported as inconclusive, not relabelled as a successful test. These few calls verify integration only.

After building, run `python3 tests/redaction-smoke.py` to verify the real Python reference client against contact masking, whole-output credential replacement, legacy block precedence, unknown withholding, audit privacy and cleanup. It uses only local synthetic services.

## Exact public-email permissions

The sensitive-output management policy accepts optional `public_emails`, an operator-declared list of at most 16 unique exact ASCII email addresses. It applies within `application_ids` (empty means all applications) to final model text, read-tool results and standalone evaluation recommendations. Omitted/null/empty clears the list on PUT. Historical snapshots and the admitted policy revision retain their own permissions; applications and model/tool text cannot declare permissions.

For example, `"public_emails": ["support@example.com"]` permits that exact literal finding while other emails remain subject to the selected action. Matching is case-sensitive and excludes normalized/obfuscated spellings, wildcard/domain grants, credentials, action arguments and incomplete scans. A mixed public/private result retains the public address and redacts the private one; a selected credential still replaces the whole output. The transformed result is rechecked with the same pinned permissions.

Raw detector output remains unchanged, including `state: observed`; an allowed public address is a disclosure permission, not a claim that the detector was wrong. Policy `matched_categories`/`matched_rules` describe actionable findings after permissions. Optional `public_email_exceptions` counts excepted findings in metadata; values are never written to call records. A public resource classification alone grants neither access nor a content exception. Administrators must list only addresses they intend to publish.

## Explicit v3: formatted email boundaries and single-layer Base64

Set `detector_version: sensitive-text-v3` in a new administrator policy revision to opt in. Existing policies and the frozen v1/v2 sources keep their behavior; omitting the field preserves the current version. The same version governs content evaluations, model responses and read-tool responses. Update copied Python reference clients before selecting v3; older clients reject unfamiliar evidence.

V3 recognizes an entire ASCII email inside paired inline backticks, `**` or `__`, with restricted punctuation/whitespace boundaries, producing `formatted_email_address` spans that exclude markup. This fixes a reproduced v2 case where a leading Markdown delimiter becomes part of the email candidate and defeats an exact public-email permission. It is a small format recognizer, not a general Markdown parser. Only the exact case-sensitive operator-listed address can be exempted. Other domains, transformed spellings, credentials, ambiguous markup and incomplete scans gain no permission. The historical live output was not retained, so reproduction alone cannot identify that answer's exact formatting.

V3 also scans standalone contiguous canonical Base64/Base64url tokens, padded or unpadded, with a minimum length of eight bytes. A token may contain up to 2,048 encoded bytes; at most 32 decoded UTF-8 text views are checked. Binary/control-containing payloads are not treated as text (tab/newline/carriage return are allowed). Decoding is exactly one layer and then uses the bounded plaintext/normalization and format rules. Findings use `base64_` prefixes and map to the **whole original encoded token**, so redaction removes that complete token. Encoded credentials still trigger full-output replacement. Decoded text is never returned or persisted, and even an encoded public address cannot use a public-email exception.

Oversized encoding-shaped tokens or exhausted decoded-view budgets return `unknown`, reason `encoding_limit`, with `truncated: true`; no partial release is allowed. The original 8,192-byte input and 32-finding caps still apply. Long ordinary opaque strings can consequently become unknown. Nested encodings, hexadecimal, split tokens, arbitrary transformations and general semantic privacy remain unsupported. One extra valid negative in each older validation set became unknown under the new encoding bound; this tradeoff is retained in the reports.

The [45-case authored corpus](../tests/testdata/sensitive-validation-v3.json), [corpus freeze](../tests/testdata/sensitive-v3-freeze.json) and [source freeze](../tests/testdata/sensitive-v3-source-freeze.json) record the protocol. Cases were written after the v2 live findings and before v3 implementation; the author could see them. This is not blind validation. One oversized-input case is excluded from quality denominators; the two encoding-budget unknowns remain in them.

| Detector on new corpus | Credential TP / FP / FN | Email TP / FP / FN | Phone TP / FP / FN | Known valid cases |
| --- | --- | --- | --- | --- |
| v2 | 0 / 0 / 2 | 12 / 0 / 15 | 0 / 0 / 4 | 44/44 |
| v3 | 2 / 0 / 0 | 23 / 0 / 4 | 4 / 0 / 0 | 42/44 |

Unknown positives count as misses; unknown negatives do not count as correct clean decisions. The four email misses include unsupported forms and the oversized encoded input. The observed v3 local-detector P95 was about 60.9 microseconds versus 15.4 for v2 on this corpus (4,500 timing calls each); this excludes HTTP, model inference, audit and policy work, and is not a production SLA. There were no observed false positives on this small authored set, which cannot establish general precision.

```bash
make validate-sensitive-v3
python3 scripts/accept-knowledge-agent.py --controls instructions-v2-reviewed \
  --sensitive-detector sensitive-text-v3
```

The acceptance corpus and grading remain unchanged; default acceptance still uses v2. Reports record `sensitive_detector_version`, detector sources and the resulting policy audit. See [Agent evaluation](knowledge-agent.md) for separately retained local/live outcomes.
