# Risk remediation and verification

**English** | [简体中文](zh-CN/remediation.md)

Remediations connect a product's failed or unknown technical control to recorded work, a fresh assessment and optional explicit model/tool retest evidence. They are available in **Plugin center → Frameworks & rule packs** and the [administration CLI](admin-cli.md). This first version tracks product assessment controls; it does not automatically turn every blocked request into an incident.

## Console workflow

1. Select a saved product and evaluate it. Expand a failed or unknown control and select **Track remediation**. The server retains a fresh assessment, then creates the record from that report's exact control. If the control now passes, creation is rejected. A report can remain in the archive if creating the record fails; reload records before retrying.
2. Open **Remediation and verification**. Supply a responsible person/team, optional target date and a brief note. These are operator declarations, not authenticated assignment, notifications or approval. Do not put credentials, prompts or response bodies in notes.
3. Apply the actual fix through the appropriate policy, product or application configuration. Save the remediation as **Ready for recheck**, with a note describing the change. This records work; it does not declare the control fixed.
4. If a model/tool retest is needed, explicitly start the configured test after marking the record ready. **Open model tests** opens the existing plan/run panel. Loading a remediation never starts a test. After completion, reload remediations and optionally select that run. The backend requires the same product, current configuration and plan revisions, and a start time after the ready event. Running, older, cross-product or expired runs are rejected. A failed/inconclusive run cannot verify a fix.
5. Select **Recheck evidence and verify**. This runs a fresh local assessment and retains its report; it makes no model/tool call. Only a `pass` on the original control, with a passing optional retest, produces **Verified at recorded snapshot**. `fail`, `unknown` and `not_applicable` return the record to **Remediation in progress**. Manual-review controls remain unknown; this feature does not approve them.

Rechecks retain the original rule-pack fingerprint and exact application set. Changing a product version or facts can be part of a fix, but replacing the pack or removing an application cannot close the original finding. Create a separate record for a different pack/scope. The same product/control/pack/application set has one record; reopen it instead of creating duplicates.

## Historical verification and current evidence

Progress has four states: `open`, `in_progress`, `ready_for_recheck`, `verified`. Ordinary updates accept only the first three; verified records must first return to `open`. Each successful write appends an event, including the note, owner and date at that time. Previous notes and verification references are never rewritten through the API.

The separate `verification_state` is computed when records are read:

| State | Meaning |
| --- | --- |
| `not_verified` | The current progress event is not a successful verification |
| `current` | Retained evidence still passes at read time and matches current source versions |
| `stale` | Product, gateway, policy, tool, test evidence, audit sample or evidence validity changed |
| `unavailable` | Referenced verification evidence cannot be validated |

A historical `verified` event stays in history when evidence changes. It must not be counted as a current success unless `verification_state` is `current`. Reload after changes; this is a point-in-time check, not continuous monitoring or a deployment gate. Revision matching is conservative: unrelated gateway edits or new audit traffic may also require rechecking. Attached operation tests expire after twice the plan interval; pre-deployment tests expire after 30 days. Rule facts may expire earlier.

**View original finding** and **View verification report** show the specific retained control and evidence references. Reports preserve their original evaluation time and can be replayed through the existing archive API. An optional retest references its immutable ID and digest; remediation files do not copy test prompts or responses. A passing retest covers its declared target and suite, not every application or risk. Technical verification is not legal certification.

## CLI and API

After logging in as described in the [CLI guide](admin-cli.md), use `gw` below as that guide's session-bound shell function. Replace all uppercase IDs and revision examples with actual returned values.

```bash
gw products list
gw reports create --product PRODUCT_ID
umask 077
cat > remediation-create.json <<'JSON'
{"report_id":"REPORT_ID","control_id":"CONTROL_ID","owner":"Platform team","due_date":"","note":"Investigate the failed control"}
JSON
gw remediations create --product PRODUCT_ID --file remediation-create.json
gw remediations list --product PRODUCT_ID
```

Update with a private file containing `revision`, `status`, `owner`, `due_date`, and `note`, then run:

```bash
gw remediations update --product PRODUCT_ID --id REMEDIATION_ID --file remediation-update.json
gw tests plans --product PRODUCT_ID
# This explicitly authorizes calls to the configured model or tool:
gw tests run --product PRODUCT_ID --plan PLAN_ID --phase operation
gw tests list --product PRODUCT_ID
gw tests show --id TEST_RUN_ID
gw remediations recheck --product PRODUCT_ID --id REMEDIATION_ID --revision 2 --test-run TEST_RUN_ID
gw remediations show --product PRODUCT_ID --id REMEDIATION_ID
```

Omit `--test-run` for a local recheck using only the assessment's saved evidence sources. Requirements for active-test evidence in a rule pack still apply. `tests run` only starts an existing plan; it does not wait for completion or retry failed calls. Configure plans in the model test panel or the existing test-plan API. Empty legacy plan IDs are supported by the API; the CLI expects a named plan.

The administrator endpoints are `GET/POST /api/v1/compliance/products/{id}/remediations`, `GET/PUT .../remediations/{remediation}` and `POST .../remediations/{remediation}/recheck`. Inputs and outputs are defined in [OpenAPI](../api/openapi.yaml) and [the remediation schema](../schemas/remediation.schema.json). Writes use the remediation's current event revision, independently of policy revisions. Administrator authentication, strict JSON, 16 KiB request bounds and origin/custom-header protection apply. Application keys cannot access these records. Conflicts and uncertain writes are not retried automatically.

## Persistence and verification

`remediations.json` is a private `0600` file, atomically saved with at most 128 records, 64 events per record and 2 MiB in total. Notes are limited to 2000 UTF-8 bytes, owner labels to 100 bytes. It is not encrypted or a tamper-proof audit service. There is no deletion/pruning endpoint or automatic retention eviction. Capacity errors preserve existing history. Each recheck consumes an ordinary report archive slot, subject to its existing 256-report/64 MiB limits; a report committed before a later record-write failure is retained.

Back up the file together with product configuration, `assessment-reports/`, `test-runs/`, test plans and the rest of the data directory while stopped. Startup validates event order, transitions and the referenced evidence; missing/corrupt history is not silently reset. Restoring only the remediation file without its referenced reports/tests is unsupported.

Go tests cover failure/unknown/not-applicable handling, scope and version binding, fresh explicit local model retests, concurrent updates, capacity, persistence failure, corruption, expiry, restart and API/CLI authorization. `node tests/plugins-smoke.cjs` additionally checks the actual browser lifecycle, safe text rendering, language switching, mobile layout, stale evidence, late responses, logout and restart. Fixtures use synthetic data and no external provider.
