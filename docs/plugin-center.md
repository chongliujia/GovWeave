# Plugin center

**English** | [简体中文](zh-CN/plugin-center.md)

Open **Management → Plugin center** after administrator sign-in. The console lists only installed rule packs and executable sensitive-text detector versions; it does not claim that uninstalled frameworks are available. The page is bilingual, works offline, and does not send detection content to an external service.

## Selection and configuration

- Use **Detectors & redaction** or **Frameworks & rule packs** to work on one category at a time. Changing tabs or language preserves both drafts. Tabs support arrow keys and Home/End.
- Detector cards compare version coverage; processing-mode cards explain their effects. The selection border represents your draft, while **Saved configuration** marks the stored version or mode. Only saving changes the live configuration.
- Find rule packs by name, ID or version and filter by framework type. Filtering does not unbind a selected version. Full metadata and fingerprints are under **Version details & fingerprint**.
- Search application lists and use **Select visible** / **Clear visible**. These buttons affect only matching applications; selections outside the filter remain intact. Counts include all selections, not just visible rows.
- The save bar shows unsaved changes, the intended scope and missing required fields. It stays within reach while editing. **Discard changes** restores that form without touching the other draft. Switching products or reloading asks before discarding unsaved changes.
- Public email exceptions, safety details, revision history and saved-product assessment are collapsed sections. Evaluation is unavailable until the product draft is saved or discarded.

## Select a framework / rule pack

1. Install a validated, data-only JSON rule pack under `<data_dir>/rule-packs/`, then restart GovWeave and reload the page. Follow the [rule-pack contract](compliance-engine.md); invalid packs fail startup. Preserve old versions required by historical reports. There is no web upload, remote installer or hot reload.
2. Choose an existing product, or select **New product** and supply its name, version and application scope.
3. Choose an exact installed pack version. The console shows its framework kind, review status, control count and SHA-256. “Reviewed” is the publisher's metadata declaration, not independently verified certification. Draft status remains visible.
4. Save, then use **Evaluate saved product** to assess the saved profile. Unsaved edits are not evaluated. Existing profile facts survive edits; new products start with no declared facts, so missing evidence remains unknown rather than becoming a pass.

Each product currently binds **one rule pack version**. Multiple products may use different packs, including the same applications. Changing a product's pack does not change runtime policies or existing archived reports. Selecting a framework is not a legal-compliance determination. This interface does not add or certify new ISO, NIST, EU or other regulatory mappings.

## Select a detector / redaction policy
For the opt-in EU / US starter catalog, evidence keys and isolated tests, see [EU / US compliance bundle](eu-us-compliance-bundle.md). These new draft mappings are data plugins; they do not add legal approval or enable enforcement.


The built-in `sensitive-text` plugin exposes three explicitly selectable versions:

| Version | Scope |
| --- | --- |
| `sensitive-text-v1` | Existing bounded credential, email and mainland China mobile patterns |
| `sensitive-text-v2` | Adds bounded full-width/zero-width and bracketed-email normalization |
| `sensitive-text-v3` | Adds paired email formatting and bounded single-layer Base64 detection |

Choose **Disabled**, **Observe**, **Block**, or **Redact and recheck**, select detection categories, and choose all applications (including future ones) or an explicit nonempty scope. Exact public email exceptions are optional and entered one per line; they do not exempt other controls. Save explicitly to activate changes. Merely selecting another version does nothing, and no automatic upgrade to the newest version occurs.

This is one shared sensitive-output policy with an application scope, not a separate detector policy per application. Save a new revision to disable protection or switch implementations. Policy history remains available; there is no destructive uninstall or history rewrite. Concurrent saves reject stale revisions: preserve your intended changes, reload current configuration, and reconcile before saving again.

Protection applies to supported non-streaming model responses and tool outputs. Protected streaming requests are rejected rather than silently bypassed. Incomplete or failed protected checks withhold output, including observe mode. Observe returns original content after a completed check. The standalone content-evaluation API returns observations/advice, not rewritten text. See [sensitive output](sensitive-output.md) for precise limits, exceptions and known false positives/negatives.

## Try before saving

Choose **Try before saving** beside the detector cards. Load a synthetic email, encoded-text or credential sample, or enter your own synthetic UTF-8 text. **Test current draft** uses the selected detector, mode, categories and exact public-email exceptions without saving them. It assumes the sample is in scope; it does not verify which applications are protected.

The result shows selected category/rule matches, applied exceptions, the action and any returned text. Redaction uses the runtime transformation and recheck; credential matches can replace the entire output. Blocked or incomplete/failed active checks do not return output. Disabled mode returns the sample without scanning. Changing the sample or draft invalidates the result immediately. **Clear sample and result** and logout remove the sample/result from the console; changing language preserves the sample without translating it.

The administrator-only `POST /api/v1/plugins/sensitive-output/preview` accepts `text`, `detector_version`, `mode`, `categories` and optional `public_emails`. It uses the console's same-origin/custom-header checks, strict JSON decoding, a 16 KiB JSON request cap and an 8192-byte decoded-text cap. It rejects policy revisions and application scope fields rather than implying a saved or routed evaluation. Responses are marked `preview_only: true` and `Cache-Control: no-store`; `output` is absent when withheld.

Samples are sent only to this GovWeave instance, with no model/upstream call. GovWeave does not persist the sample or response, change policy/history, or create request/evidence records for a preview. Infrastructure outside GovWeave may have its own logging policy; use synthetic data. This is a plain-text configuration aid, not compliance evidence, a complete detection guarantee, or a test of model envelopes, tool-argument protection and application routing.

## Rule pack details and control results

Under **Frameworks & rule packs**, expand **Rule pack coverage and sources** for the selected installed version. The panel reads its definition without installing or enabling anything: declared coverage, exclusions, source versions/check dates, publisher review metadata, effective dates, fingerprint and individual controls. Each control exposes its citation, severity, assessment method, basis, declared remediation and exact applicability/requirement expressions. Source links open only when clicked; content from packs is rendered as text, not HTML. Missing coverage, limitations or dates are explicitly marked as missing rather than filled in or treated as complete coverage.

Expand **Saved product assessment** and choose **Load latest assessment** to read the existing evaluation, or **Evaluate saved product** to refresh it. The panel shows product revision/version, pinned rule-pack version/fingerprint, engine version, evaluation/refresh times and the runtime sampling limit. Counts use all returned controls as the denominator and distinguish satisfied requirements, control gaps, unknown/review-needed results and not-applicable results; no certification score is inferred.

Filter by status, **Needs attention** or **Awaiting manual review**, or search IDs, titles, citations and evidence fact names. Expand a result to inspect its reason, missing/stale/expired/wrong-source/type evidence issues, recorded next actions and evidence references (IDs, source and observation/expiry times). Operator declarations are not independently verified evidence; manual requirements remain unknown pending the separate qualified-review process. The panel does not edit evidence or approve reviews.

These are assessment snapshots, not live conclusions. Editing or switching the product, changing its selected rule pack, reloading configuration or saving the detector policy hides previous results. Product ID/revision/version and rule-pack ID/version/fingerprint must match before a ready response can be displayed. Pending, failed and mismatched responses never reuse a previous success. A snapshot past its returned refresh deadline displays an explicit refresh warning; changes made elsewhere still require loading a fresh assessment. Late rule-pack responses cannot overwrite a newer selection. No new legal mappings or default rule-pack installations are added.

## Plugin implementation and APIs

- `GET /api/v1/plugins` is administrator-only. It returns `rule_packs` from the installed compliance engine and `detectors` from the actual sensitive detector registry, including versions, supported categories/modes and bounds.
- Product changes use the existing revision-checked `/api/v1/compliance/products` APIs. Assessment uses the saved product's `/evaluate` endpoint.
- Detector configuration uses `/api/v1/policies/sensitive-output`; `/history` returns immutable policy revisions. Existing authentication, origin checks, validation, persistence and runtime evidence apply unchanged.
- Rule packs are data plugins; detectors are trusted compiled Go implementations. Add and test a detector in `internal/sensitive/plugins.go`, rebuild and deploy explicitly. Catalog discovery, supported-version checks and runtime `Scan` dispatch share that registry. Frozen historical v1/v2 entry points remain unchanged. No arbitrary code uploads or dynamic `.so` loading are supported.
- The offline canary experiment in `internal/detection` remains separate; it is not advertised as a runtime redactor.

## Verification

With Go, Node, Playwright and Chrome available:

```sh
make build
make check
go test -race ./...
node tests/plugins-smoke.cjs
```

The browser test uses isolated data, two synthetic installed pack versions, two applications and a loopback model. It checks draft previews, redaction/recheck, incomplete-check withholding, safe text rendering, stale-result invalidation, preview isolation and logout cleanup. It also covers saved pack selection, fact preservation, actual scoped redaction, bilingual draft preservation, policy history, stale-write rejection, missing packs, load failure/retry, persistence after restart and responsive layouts. It does not contact cloud models or modify a running production instance. `GOVWEAVE_TEST_BINARY` and `GOVWEAVE_BROWSER_PATH` can select the test executable and browser.
