# ADR 0010: Explicitly scoped risk evidence

**English** | [简体中文](../zh-CN/adr/0010-scoped-risk-evidence.md)

Status: Accepted

## Decision

Support explicitly configured, application-scoped content evidence for investigation with a separate optional evidence vault. Operator configuration enables this feature; it does not establish a legal basis for collecting content. This extends the initial no-body-storage boundary only for that vault. Ordinary call records, diagnostics, trace views and report runtime references remain metadata only.

Start capture disabled. Require explicit existing application IDs for both metadata and full modes. Freeze capture configuration for an admitted request; retain bounded input, prepared upstream input, observed upstream output and prepared client output with available policy snapshots. Preserve gaps and delivery uncertainty. Use a separate AES-256-GCM key, private files, immutable authenticated bundles and bounded retention/capacity.

Treat this store as supplementary to existing durable call audit. Capture failures do not change an admitted inference result or bypass audit and policy gates. Do not advertise evidence before successful retention. Require an administrator session, explicit view/reason and a committed metadata access event before releasing raw or pattern-limited preview content. The preview is not anonymization.

Build individual capture graphs from retained metadata in the same application, bounded to 32 captures. Caller-declared trace relationships remain declarations; do not infer data flow or task completeness. Independently freeze the exact scoped latest-100 audit sample and per-fact request references in new product reports and their explicit archives, including when the content vault is disabled.

## Consequences

Operators can investigate the observed input, original output, prepared output and policy basis of a captured decision. Full capture can retain sensitive or blocked text and increases storage, access-control and backup responsibilities. Retention expiry denies access and permits bounded deletion; it does not erase external copies or guarantee physical secure erasure. The local key is not a remote KMS or external attestation. Without an external/write-once anchor or authenticated inventory, whole-bundle deletion and valid-tail journal truncation before restart can remain undetected; the store is not a complete tamper-proof forensic chain. Missing evidence and incomplete graphs remain unknown; no calibrated risk probability or legal conclusion is generated. See [Retained risk evidence](../risk-evidence.md) for the contracts and implemented limits.

## Extension: bounded SSE stage evidence

Streamed output may retain complete validated frames and downstream write-attempted frames as separate objects, with an optional `sse-evidence-v1` manifest. Preserve byte totals, application-scoped HMACs, ending state and only the first 128 frame observations. Full capture retains the entire observed stage within the frozen object cap or omits its body entirely; incomplete streams remain explicitly incomplete. Capture once after terminal audit, not once per frame, so abrupt process termination can lose in-flight evidence. Stream timing is gateway observation affected by batching, not token timing; write counts do not prove client receipt. This does not add streaming output protection or reconstruction-aware redaction.

## Extension: explicitly scoped task evidence

An administrator can select 1–16 applications for a separate metadata-only task view. Merge at most 32 authenticated capture reads with recent audit observations into at most 128 calls; preserve independent source limits and distinguish missing, unavailable and budget-excluded captures. Findings come only from successfully read captures. Resolve caller-declared parent, link and retry references only against returned calls; duplicate spans remain ambiguous. Application keys retain their own scope. The view is a live, non-atomic join, not a report archive or proof of data flow. Content access keeps its existing separate authorization and access-journal requirement.

## Extension: historical task snapshots

Explicitly archive the task view only when its server-recomputed digest matches the displayed view. Freeze metadata and coverage states, not bodies or complete vault policy/object documents. Require the exact selected application set for listing, reading and exporting. Persist private metadata with a purpose-derived local HMAC tied to the evidence key; bound count, bytes and concurrency without automatic eviction. Exports and historical reads use only authenticated saved metadata and do not re-read live calls or invoke models. Historical availability is not current availability; content expiry does not erase the metadata snapshot. JSON downloads carry a digest of their exact bytes, while deterministic Markdown reports cite that JSON digest. Local authentication and checksums do not establish completeness, trusted time, actual causality or legal compliance.
