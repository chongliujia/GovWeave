# Retained risk evidence

**English** | [简体中文](zh-CN/risk-evidence.md)

GovWeave can retain application-scoped evidence for investigating an observed model call, controlled read-tool call or independent content evaluation. The **Risk evidence** page joins the call record, captured objects, policy snapshots and existing detector observations. A separate graph exposes the retained relationships. This provides inspectable evidence, not an automatic risk probability, legal determination or complete reconstruction of an Agent's task.

## Two evidence paths

Ordinary `calls.jsonl` records, diagnostics and trace responses remain metadata only. The explicitly authorized content vault extends the earlier no-body-storage boundary **only for this separate, opt-in store**. Capture starts disabled; enabling it does not enable a detector or change a policy decision.

| Path | What it retains | When it is available |
| --- | --- | --- |
| Product report `runtime_evidence` | Exact scoped audit records and request IDs behind numeric runtime facts; no bodies | New reports when audit is available, even with vault capture disabled |
| Evidence vault, `metadata` | Call metadata, object sizes and keyed fingerprints, available policy snapshots | Explicitly selected applications and subsequent admitted captures |
| Evidence vault, `full` | The same metadata plus eligible bounded UTF-8 bodies | Explicitly selected applications; object state determines whether text was actually retained |

Capture is independent of call authorization and the existing durable audit gates. A supplementary capture failure or full vault does not convert an admitted model call into a failure or weaken policy enforcement. It leaves the evidence unavailable. Absence is unknown, not evidence of safety. Captures require a matching committed terminal audit record; an evidence ID derivable from a request ID is not proof that a bundle exists.

## Configure capture deliberately

In **Risk evidence**, open the retention settings, choose `metadata` or `full`, explicitly select applications, and save. An empty application list never means all applications; enabled modes require at least one existing application. Future applications are not added automatically. The request freezes its capture settings after identity is rechecked. Later configuration changes affect later captures, not an already admitted capture's mode or expiry. Disabling capture does not delete existing evidence or prevent an administrator from accessing unexpired retained objects.

| Limit | Implemented value |
| --- | --- |
| Initial mode | `disabled` |
| Application scope | 1–64 explicit IDs when enabled; no wildcard |
| Retention | Default 30 days; allowed 1–365 days from capture time |
| Retained bytes per object | Default 64 KiB; configurable 4 KiB–1 MiB |
| Objects per capture | At most 4 |
| Observed SSE bytes per output object | At most 64 MiB; the frozen per-object retention cap still applies |
| SSE frame manifest per object | First 128 frames; total count and truncation are explicit |
| Policy snapshots per capture | At most 8, with 64 KiB of serialized snapshot content in total |
| Retained captures | At most 2,048; 256 MiB total sealed-file bytes |
| Sealed file | At most 6 MiB |
| Evidence list | Default 50, maximum 100 results; newest first, no pagination cursor |
| Access journal | At most 8 MiB; API exposes the latest requested 1–100 events from its 128-event memory window |
| Graph | At most 32 retained captures in the selected application and root trace |

Content above the configured per-object limit is omitted, not partially retained. Each summary and bundle records its frozen `max_content_bytes`; consult that value rather than today's configuration when interpreting a retained object. This is a retention limit, separate from gateway request/response admission limits. Capacity does not evict unexpired evidence. Full capture can retain personal data, confidential text and secrets included **inside a body**, including text that output protection withheld from the caller. HTTP authorization headers, cookies, arbitrary caller headers and configured provider credentials are not copied into the vault.

## Understand the four objects

| Object kind | Meaning |
| --- | --- |
| `request` | Accepted application request body before gateway transformations |
| `upstream_request` | Body prepared for the actual upstream attempt; for a model call this includes the provider model ID replacing the public alias |
| `upstream_output` | Bounded upstream body observed before output transformation or withholding; for SSE, complete validated frames |
| `released_output` | Body prepared for release, including canonicalization/redaction; for SSE, complete frames included in write attempts |

Not every stage is observed. An input block has no upstream output; a blocked output has no prepared successful response. Authenticated authorization denials can retain decision metadata without the ungranted request body. Invalid requests, malformed upstream responses and failures before a capture point do not promise full forensic content. `content.evaluate` has no upstream request or response. Older streamed output objects marked `streaming_not_captured` remain readable and are not reconstructed retroactively.

Inspect each object's `content_state`: `retained`, `metadata_only`, `omitted_size`, `unsupported_encoding`, `not_observed` or `streaming_not_captured`. A keyed, application-scoped fingerprint identifies observed bytes; equal fingerprints do not prove transmission between Agents, and they are not public SHA-256 checksums.

The bundle's `delivery_state` is `not_observed`, `withheld`, `release_prepared`, `write_completed`, `write_failed` or `stream_incomplete`. Protected output may be captured after its audit commit but before the write, so `release_prepared` is intentional. For a started stream, `write_completed` means the stream completed, `write_failed` identifies an actual write/flush failure, and `stream_incomplete` describes other unsuccessful endings such as early EOF or an upstream error. It does not claim that a downstream write failed. Even a completed gateway write does not prove that a remote client received, interpreted or used the answer.

## Streamed response evidence

Scoped SSE captures use the same configuration, evidence-detail and reveal APIs. A streamed output object adds optional `stream` metadata with `version: sse-evidence-v1`. It describes two separate stages:

| Object and `stream.scope` | Bytes represented |
| --- | --- |
| `upstream_output` / `validated_frames` | Concatenated complete SSE frames accepted by the gateway parser; `written_bytes` is always zero |
| `released_output` / `write_attempted_frames` | Concatenated complete frames included in downstream write attempts; `written_bytes` sums the byte counts reported by `Write` |

These are validated-frame observations, not a recording of all transport bytes. Malformed frames, provider error-frame contents and incomplete trailing bytes are excluded. If a later frame in one read batch is invalid, earlier valid frames in that batch can appear in upstream evidence even though the batch was rejected before a downstream write. A short or failed write can leave attempted frame bytes that were not reported as written; a successful `Write` does not prove a successful flush or client receipt.

The HMAC and object `bytes` cover every complete observed frame in that stage, up to the 64 MiB stream bound. In `full` mode, an eligible object's entire observed frame sequence is retained when it fits the frozen `max_content_bytes`, even if the stream ended with an error. Exceeding that cap drops the entire body, including any previously buffered prefix, and records `omitted_size`; counts, HMAC and bounded frame metadata remain. `metadata` mode keeps no body. Thus `content_state: retained` can describe an incomplete stream and is not a completion claim.

`stream.frames` contains the first 128 frame entries: one-based `sequence`, zero-based byte `offset` within that stage's concatenation, positive `bytes`, request-relative `elapsed_ms`, and `kind` (`data`, `done` or `other`). `frame_count` counts all observed frames; `frames_truncated` marks manifest overflow. The console shows this bounded timeline without automatically revealing text. These times are when the gateway observes or attempts frames and depend on read batching. They are not token-generation timing, provider timestamps or a trusted measure of model latency.

| `stream.end_state` | Interpretation |
| --- | --- |
| `completed` | A valid `[DONE]`, EOF, no pending bytes, and successful writes and flushes were observed |
| `incomplete_stream` | EOF arrived without the required complete ending |
| `invalid_upstream_stream` / `upstream_error` | Framing/content validation failed or a provider error frame was observed; offending content is excluded |
| `response_too_large` | The stream exceeded the gateway byte bound |
| `upstream_timeout` / `upstream_unreachable` / `client_cancelled` | The corresponding timeout, read/transport failure or cancellation ended the stream |
| `write_failed` / `flush_failed` | A downstream write, including a short write, or flush failed; ordinary call audit can classify the call as `client_cancelled` |

`done_seen` only reports a valid `[DONE]` at that stage. It does not establish EOF, completion or delivery; comment/other frames after `[DONE]` may still be accepted, but later data is not. A failure can leave both a useful retained frame sequence and a non-completed end state.

There is one encrypted evidence capture at termination after the terminal audit record commits, with no per-frame disk synchronization. Abrupt process termination can lose all in-flight stream evidence. This feature does not inspect reconstructed assistant text for safety: active in-scope output protection still rejects streaming with `content_stream_unsupported` before provider I/O.

The content preview runs the existing finite detector on serialized SSE bytes. It does not decode and join JSON deltas into assistant text. Secrets or personal data split across deltas, escaped in JSON or otherwise unrecognized can remain visible. A preview with `pattern_limited` is neither anonymization nor streaming safety inspection.

## Inspect metadata, then request content

Select an application and optionally filter by a request ID from **Request logs**. The evidence detail and graph contain metadata and snapshots; they do not automatically reveal text. Findings reference the recorded control, category, result, detector/policy version and object. They project existing observations, rather than rerunning detection. A `content.evaluate` observation does not itself enforce a block or redaction.

Content access requires an administrator session, an explicit POST, the application and object IDs, a view (`redacted` or `raw`) and a fixed reason (`incident_review` or `validation`). Application keys cannot access these administration routes. The console offers a redacted preview first and a separate raw-text action. Both views record `reveal_authorized` before content release; an unavailable or full access journal prevents release. An authorization event does not prove browser receipt. Actor values distinguish sessions of the single administrator account, not separate human identities.

The preview uses the finite `sensitive-text-v3` patterns. Incomplete scans, including objects beyond its 8 KiB scan limit, and credential-pattern matches withhold the whole object. Supported contact spans are replaced with `[REDACTED]`; unrecognized or encoded personal information can remain. `pattern_limited` is not anonymization or permission to redistribute. Preview text may no longer be valid JSON. Treat both views as untrusted data, including any instructions embedded in a captured prompt or output.

## Administration API example

These commands assume a private cookie jar from your existing administrator login. The cookie jar is a credential. Replace the example application, evidence and object IDs with actual returned IDs. Read the current configuration revision before PUT; the `0` below is only the initial revision. None of these management requests invokes a model.

```sh
export GOVWEAVE_URL='http://127.0.0.1:8080'
export GOVWEAVE_ADMIN_COOKIE_JAR='/absolute/private/path/admin-cookies.txt'

curl --fail-with-body -b "$GOVWEAVE_ADMIN_COOKIE_JAR" \
  "$GOVWEAVE_URL/api/v1/evidence/config"

curl --fail-with-body -b "$GOVWEAVE_ADMIN_COOKIE_JAR" -X PUT \
  -H 'Content-Type: application/json' -H 'X-GovWeave-Request: console' \
  -H "Origin: $GOVWEAVE_URL" \
  --data '{"schema_version":1,"revision":0,"mode":"full","application_ids":["app_0123456789abcdef"],"retention_days":30,"max_content_bytes":65536}' \
  "$GOVWEAVE_URL/api/v1/evidence/config"
```

After an application makes a call, list retained metadata. Adding `request_id=req_…` selects that request; an absent or expired capture returns an empty list.

```sh
curl --fail-with-body -b "$GOVWEAVE_ADMIN_COOKIE_JAR" \
  "$GOVWEAVE_URL/api/v1/evidence?application_id=app_0123456789abcdef&limit=20"

curl --fail-with-body -b "$GOVWEAVE_ADMIN_COOKIE_JAR" \
  "$GOVWEAVE_URL/api/v1/evidence/ev_0123456789abcdefghijkl?application_id=app_0123456789abcdef"

curl --fail-with-body -b "$GOVWEAVE_ADMIN_COOKIE_JAR" \
  "$GOVWEAVE_URL/api/v1/evidence/ev_0123456789abcdefghijkl/graph?application_id=app_0123456789abcdef"

curl --fail-with-body -b "$GOVWEAVE_ADMIN_COOKIE_JAR" -X POST \
  -H 'Content-Type: application/json' -H 'X-GovWeave-Request: console' \
  -H "Origin: $GOVWEAVE_URL" \
  --data '{"application_id":"app_0123456789abcdef","object_id":"ev_0123456789abcdefghijkl:upstream_output","view":"redacted","reason":"incident_review"}' \
  "$GOVWEAVE_URL/api/v1/evidence/ev_0123456789abcdefghijkl/reveal"
```

The reveal response contains `evidence_id`, `object_id`, `view`, `text` and `redaction_state`; this command prints that content to your terminal. Requesting `view: raw` is a separate privileged disclosure. `GET /api/v1/evidence/access?limit=20` reads access metadata. `POST /api/v1/evidence/purge` with `{}` removes only expired captures and returns `expired_records_removed`. GET filters reject repeated, unsupported or empty parameters; query strings are bounded to 512 bytes.

| Response | Interpretation |
| --- | --- |
| `400 invalid_evidence_request` | Invalid configuration, scope, query or reveal fields |
| `401` | Administrator session required |
| `404 evidence_not_found` | No retained capture in this application; another application's ID grants no access |
| `409 evidence_content_unavailable` | The requested object's text was not retained |
| `409 revision_conflict` | Refresh the current configuration revision before saving |
| `410 evidence_expired` | Retention ended; direct access denied even before physical purge |
| `503 evidence_unavailable` | Stored evidence or its access journal cannot be verified or written |
| `507 evidence_capacity` | A bounded store or access journal has no remaining capacity |

The exact contracts are in [OpenAPI](../api/openapi.yaml) and the [evidence schema](../schemas/evidence.schema.json).

## Graph and report boundaries

The graph links retained calls to objects, policy snapshots and findings. If the root has a trace ID, it includes at most 32 retained captures with that trace **inside the same application**. Parent, link and retry edges stay `caller_declared`, even when the target is visible. Missing targets remain `unresolved`; duplicate matching spans are `ambiguous`. There are no inferred edges based on content similarity or fingerprints, and no cross-application content correlation. `history_may_be_missing` stays true and `graph_complete` stays false. Check `result_truncated` and `unavailable_records`. The existing [Agent trace view](agent-tracing.md) remains a separate metadata view over its global 1,000-request index.

New product reports add optional `runtime_evidence` when audit is available. Its `records` are the exact product-scoped model/tool records selected from the **global latest 100 audit entries**, not 100 per application. Each numeric fact lists `source_request_ids` considered and `matched_request_ids` contributing to its value. A runtime `evidence_id` such as `audit-bytes-…` is a source stamp, not a vault `ev_…` identifier. The sample and references are saved with explicit report archives and can be inspected after the live audit window moves; this works with capture disabled. Historical reports without this field remain replayable. Archive availability, window size and partial observations still bound interpretation. See [product assessments](product-assessments.md) and [report snapshots](eu-transparency-reports.md).

## Cross-application task evidence

The console's **Task evidence across applications** view joins retained captures with recent audit metadata for one trace. Enter a trace ID and explicitly select 1–16 existing applications, then choose **Load task evidence**. The **Inspect this task across applications** action on an individual capture prefills its trace and that application only; add other applications deliberately. Querying does not enable capture, grant application access or reveal body content.

This administrator-only endpoint uses repeated, distinct `application_id` parameters:

```sh
curl --fail-with-body -b "$GOVWEAVE_ADMIN_COOKIE_JAR" \
  "$GOVWEAVE_URL/api/v1/evidence-traces/1234567890abcdef1234567890abcdef?application_id=app_0123456789abcdef&application_id=app_fedcba9876543210&limit=128"
```

`limit` defaults to 100 and accepts 1–128. The view first reads the newest `min(32, limit)` unexpired captures across the selected applications, then fills remaining call slots from recent audit metadata. The audit source considers at most 128 matching records in its **global latest-1,000 request index**. Captures can remain visible after leaving that audit window. Selection is global across the chosen scope, not a per-application quota or guarantee of complete history. Returned calls are ordered by record timestamp, using capture creation time when a record cannot be read. Query strings are limited to 2,048 bytes; unknown parameters, duplicate applications and repeated limits are rejected. Valid scopes with no visible calls return an empty `200` view.

| Call `evidence_state` | Meaning |
| --- | --- |
| `retained` | The capture was read and authenticated; individual objects may still have no retained body |
| `not_found` | A recent audit call has no matching unexpired capture in the observed index; the reason is unknown |
| `unavailable` | A matching indexed capture could not be read or verified, or became unavailable during the query |
| `not_loaded` | A recent audit call has an indexed capture beyond this view's capture-read budget |

`record_source` distinguishes `retained_evidence`, `recent_audit` and `evidence_index`. Index-only rows omit `record`; they do not fabricate an outcome. Findings and `summary.retained_findings` come **only from successfully read captures**, not every recent audit record. An empty finding array on another state is not a clean result; the console shows “—”. Open an available capture to inspect its policy versions, objects and audited content-review controls. Changing task scope clears the previous view and visible content; late responses cannot restore the old scope.

Calls act as graph nodes. Parent, join (`link`) and retry relationships resolve only against records returned in this view; duplicate spans stay `ambiguous`, missing targets stay `unresolved`. Relationships and Agent IDs remain caller declarations, including across applications. Neither a shared trace ID nor a resolved edge proves a handoff, transmitted data, root cause or task completion. No cross-application content fingerprint comparison is performed. The existing application-key `/v1/traces/{trace_id}` remains restricted to its authenticated application.

Check `result_truncated`, `audit_result_truncated`, `evidence_result_truncated`, `audit_window_saturated` and `audit_available`. The last flag describes audit admission capacity for new calls; existing observations remain queryable when it is false. `history_may_be_missing` is always true, `graph_complete` is false and `task_completion` is `not_determined`. Audit and vault are read separately: this is a live, non-atomic investigation view, not a retained report snapshot. It cannot reconstruct calls absent from both stores, extend expired retention or establish legal compliance. The single-capture `/api/v1/evidence/{id}/graph` keeps its original same-application scope.

## Task snapshots and report export

After loading a task view, choose **Save this task snapshot**. The server rebuilds the same bounded query and compares its digest with the displayed result. If calls, findings, evidence states or coverage flags have changed, saving returns `409 task_view_changed`; reload and review the new view before saving. The digest is an optimistic concurrency check, not authentication. Saving does not invoke a model, change capture settings or accept call records from the browser.

Use **Load saved snapshots** with the same trace and exact application set to find historical results. A subset or superset does not match. Snapshots persist across restart and remain readable after their calls leave the audit window or their original content expires. The console identifies historical results and uses application IDs instead of current application names. Capture availability describes the saved observation, not current access. Reload live task evidence for current observations; historical viewing does not reopen body content.

Each snapshot freezes the task view's selected applications, calls, finding references and detector/policy observation versions, declared edges, evidence states, source limits and incompleteness flags. It does **not** copy bodies, complete vault object manifests or complete policy documents. `created_at` is the snapshot save time; audit and vault observations are still collected separately. `created_by` identifies the administrator session, not an independently identified person. Empty views may be saved and remain insufficient evidence.

**Export snapshot JSON** downloads the complete versioned snapshot. Its exact bytes, including the final newline, match `summary.bytes`, `summary.sha256` and the download's `X-GovWeave-SHA256` header. **Export report Markdown (English)** generates a deterministic English report from that same saved snapshot, with call and finding tables, relation provenance and coverage limits. It cites the JSON checksum; that checksum does not cover the Markdown file. Neither export performs a new assessment or establishes legal compliance.

The administrator APIs share the explicit repeated `application_id` scope:

| Method and path | Behavior |
| --- | --- |
| `POST /api/v1/evidence-traces/{trace_id}/snapshots` | Protected JSON mutation with `{"expected_view_sha256":"…"}`; use the live GET's digest and the same `limit` (default 100, maximum 128); returns `201` |
| `GET /api/v1/evidence-traces/{trace_id}/snapshots` | List up to 256 summaries matching the exact trace/application set, newest first |
| `GET /api/v1/evidence-traces/{trace_id}/snapshots/{snapshot_id}` | Authenticate and read the saved metadata without querying live evidence |
| `GET /api/v1/evidence-traces/{trace_id}/snapshots/{snapshot_id}/export/json` | Download the complete JSON snapshot |
| `GET /api/v1/evidence-traces/{trace_id}/snapshots/{snapshot_id}/export/markdown` | Download the English Markdown report |

Only creation accepts `limit`; other filters are rejected. Application keys cannot use any of these routes. A mismatched valid scope or unknown ID returns `404 evidence_not_found`; invalid queries return `400`; unavailable or unsafe files return `503 evidence_unavailable`. Creation/read concurrency is limited to four operations (`429 task_snapshot_busy`). Successful repeated POSTs create separate snapshots. If a save response is lost, inspect the saved list before retrying; a timed-out response does not prove that saving failed. Scope changes discard late UI responses and remove old download links.

Snapshots are private **plaintext metadata**, stored as authenticated files in `task-evidence/`, with a purpose-derived HMAC key tied to `evidence.key`. Opening/exporting verifies the stored file; summary listing is an index rather than a fresh verification of every file. Changed content without the key, unsafe permissions and invalid saved records are rejected, including at startup. `authenticated_local` does not establish external attestation, trusted time or a complete authenticated inventory; deleting an entire snapshot before restart can still go undetected.

Capacity is independent of the body vault: at most 256 snapshots, 2 MiB per stored file and 64 MiB total. Reaching a limit returns `507 evidence_capacity` without evicting existing snapshots. There is no automatic expiry, rollover or snapshot deletion API in this version; monitor capacity and retain consistent backups. Vault purge does not delete task snapshots or exported copies. Metadata can still contain sensitive operational identifiers and relationships, so keep downloads and backups private.

## Storage, retention and recovery

The private data directory contains a separate 32-byte `evidence.key`, encrypted `evidence/ev_….sealed` bundles, `evidence/config.json` and metadata-only `evidence/access.jsonl`. Bundles use AES-256-GCM with a random nonce and evidence-ID-bound authenticated data. Fingerprints and access-event authentication derive separate HMAC keys. The configuration and access metadata are private files, not encrypted content bundles. `integrity: authenticated` describes local ciphertext authentication, not external certification, a trusted timestamp or proof that the observations are correct.

There is no external or write-once anchor and no authenticated inventory of every expected bundle. Deleting a whole bundle before restart can appear simply as missing evidence; removing a valid tail of the access journal is not independently disproved after restart. Authenticated ciphertext therefore does not establish a tamper-proof or complete forensic chain.

Back up the stopped instance's **entire private data directory**, including `evidence.key` together with `evidence/`, `task-evidence/` and the existing credential-vault files; protect the backup as sensitive data. A missing or wrong evidence key, invalid ciphertext, unsafe permissions, an invalid task snapshot or a damaged access journal can prevent startup. There is no implemented key rotation, remote KMS or automatic access-journal rollover. Restore a consistent verified backup rather than replacing a key while keeping its ciphertext or authenticated snapshots. See [deployment and recovery](deployment.md).

Expiry is enforced on reads. Expired files are purged at startup, during an applicable capture, or by the explicit purge operation; there is no continuous expiry worker. Purge records authorization before deleting files, and failures remain visible. Deletion does not erase copies in backups, storage snapshots or previously revealed output, and does not guarantee physical secure erasure. Ordinary call logs and explicitly archived metadata reports have their own retention boundaries and are not deleted by vault purge. See [ADR 0010](adr/0010-scoped-risk-evidence.md) for the storage decision.
