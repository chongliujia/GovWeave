# EU / US AI compliance starter bundle

**English** | [简体中文](zh-CN/eu-us-compliance-bundle.md)

Bundle `eu-us-ai-starter/2026.11.13` is an explicit selection of eight existing-format JSON plugins, not a comprehensive legal catalog. Five new drafts add 25 controls (13 evidence-availability checks and 12 manual reviews). Existing versions are unchanged. The manifest is `examples/compliance-bundles/eu-us.json`; it is **not** itself a rule pack.

| Pack ID | Version | Purpose |
| --- | --- | --- |
| `eu-ai-act-chatbot-transparency` | 0.1.0 | Existing selected Article 50 interaction-notice controls |
| `eu-ai-act-high-risk-readiness` | 0.1.0 | Selected provider preparation records; not currently applicable legal-violation findings |
| `eu-ai-act-gpai` | 0.1.0 | Selected model-provider documentation, copyright and training-summary evidence |
| `eu-gdpr-ai` | 0.1.0 | Selected processing-accountability evidence and manual privacy review |
| `nist-ai-rmf-lifecycle` | 0.1.0 | Existing lifecycle test-evidence integration |
| `nist-genai-profile` | 0.1.0 | Selected voluntary AI 600-1 evidence requests |
| `us-ftc-ai-claims` | 0.1.0 | Claims substantiation support, not a standalone US AI statute |
| `sensitive-output-governance` | 1.1.0 | Internal runtime/detector technical evidence, not legal compliance |

## Selection and evidence

After installation and restart, select a pack in **Plugin center → Compliance frameworks and rule packs**. A product still pins one version: use separate product profiles for different packs, optionally bound to the same real application. Do not migrate existing products or automatically enable redaction. Install only versions you intend to assess; a draft is not qualified legal approval.

The new packs use `scope.euhr_in_scope`, `scope.eu_gpai_in_scope`, `scope.eu_gdpr_in_scope`, `scope.genai_in_scope` and `scope.us_ftc_claims_in_scope`, respectively, from `assessment` evidence. Each has an unconditional manual scope review. Missing scope stays unknown; false scope routes other controls out but cannot yield a scope approval. GPAI documentation has its own `scope.gpai_documentation_required`; GDPR uses `scope.gdpr_dpia_required` and `scope.gdpr_article22_relevant`. A documentation exception never switches off copyright or summary controls.

Exact evidence keys, types and sources are visible in the installed pack definition. Submit real references through the product API's `facts` map, preserving the current revision and other facts. Each fact carries `value`, `source`, `evidence_id`, `observed_at` and optionally `expires_at`. The console now edits evidence references in the product draft; it does not upload documents or approve reviews. See the [three-framework workflow](framework-workflows.md). Never copy affirmative synthetic test facts into a real product.

New automatic checks assess **evidence availability**, not document contents, test success or legal adequacy. A submitted document/assessment claim is not independently verified. Their 30-day freshness limit is a local assurance choice, not a legal deadline. Manual controls remain unknown even when their evidence value is true. Detector results cannot satisfy documentary or legal requirements automatically.

## Sources and coverage limits

Each JSON lists official source URLs, versions, checked dates, citations and exclusions. The new sources were checked on 2026-11-13; older immutable packs retain their original dates. GDPR uses the published regulation references and EDPB guidance; EUR-Lex's anti-bot response prevented a full automated text fetch, so no claim of exhaustive consolidated-text review is made. FTC's unavailable 2023 blog is not a source dependency; the pack uses its accessible substantiation policy and a labelled enforcement example instead.

The high-risk pack deliberately has no enforcement start date: it is a preparation checklist. The Commission's checked timeline distinguishes 2027-12-02 and 2028-08-02 high-risk milestones. Individual role, transition and exemption decisions remain manual. GPAI applicability likewise needs model-specific review; ordinary API use is not automatically model-provider status.

Not implemented here: full AI Act/GDPR coverage, US state AI/privacy rules, employment/credit/healthcare rules, UK-specific rules, licensed ISO/IEC 42001 mapping, formal approval or multi-pack products. This is a bounded first bundle, not “all mainstream AI laws.”

## Reproducible checks and installation

### Hosted-model isolated trial

The optional SiliconFlow trial makes billable API calls. Supply the key through the hidden prompt or `SILICONFLOW_API_KEY`, never in command-line arguments, source, or reports.

```sh
python3 tests/siliconflow-trial-test.py
python3 scripts/test-siliconflow-model.py --model Qwen/Qwen3.8-27B --output dist/siliconflow-trial.json
```

The script checks the account's exact model catalog and one benign inference, then starts a disposable GovWeave instance. It runs four synthetic probes in each of disabled, observe, redact and block modes with `sensitive-text-v3`, plus an operation-phase block run: at most 21 inference requests. It does not substitute models, start a local GPU model, or change the live instance. Provider credentials are encrypted in temporary gateway storage, which is deleted afterward; reports omit response text. Native active probes use provider-default reasoning, a 30-second per-case timeout and a 128-token output budget, not a guaranteed billing cap.

Coverage is limited to synthetic credentials, email, mainland-China mobile numbers and benign text, not EU/US phone coverage, detector recall or general model safety. Refusal, truncation or absent target categories must not be counted as successful protection. The eight rule packs are separately evaluated with no organizational evidence; missing materials and manual reviews remain unresolved. The technical output-governance report is separate and does not establish legal compliance.

### Rule-pack regression and installation

The 2026-11-13 isolated SiliconFlow `Qwen/Qwen3.8-27B` run is retained in `dist/siliconflow-qwen38-compliance-20261113.json`:

| Mode / phase | Pass | Fail | Unknown | Observation |
| --- | --- | --- | --- | --- |
| Disabled / pre-deployment | 0 | 4 | 0 | Expected inactive-protection negative control |
| Observe / pre-deployment | 0 | 3 | 1 | Three sensitive categories detected but released; benign exact-match unresolved |
| Redact / pre-deployment | 3 | 0 | 1 | All three sensitive probes redacted; benign exact-match unresolved |
| Block / pre-deployment | 3 | 0 | 1 | All three sensitive probes returned 403; benign exact-match unresolved |
| Block / operation | 2 | 0 | 2 | Credential/email blocked; phone request timed out at 30 seconds; benign exact-match unresolved |

All four policy-enabled benign probes returned 200, but their content digests differ from the expected literal. This does not identify the exact difference and must not be changed to pass. Totals: 8 pass, 7 fail, 5 unknown across 20 active probes. The negative controls are not block-mode regressions. The technical governance report has 7 pass, 1 fail (`OUTPUT-CURRENT-EVIDENCE`), and 2 unknown: active probes do not substitute for real business traffic samples. Eight empty-evidence pack evaluations leave 49 controls unknown, not a legal judgment about this model. Two benign preflight inferences were made: the first attempt stopped at test-plan timeout validation, before any active probes; the second used the corrected 30-second timeout. Temporary services and credential storage were removed, with no live-instance changes.

```sh
go test ./internal/compliance
make test-regional-compliance
python3 tests/compliance-smoke.py
```

`tests/regional-compliance-smoke.py --output dist/regional-results.json` creates an isolated local instance and performs 30 synthetic API evaluations over the five new packs. It verifies all eight manifest versions in the plugin API. Optional `--pack-directory /path/to/staged/rule-packs` validates a **complete staged catalog**, including retained old packs, using the actual service startup parser. An existing output file is not overwritten. No live credentials, real assessments or upstream models are used.

Expected all-evidence-available counts (pass / manual unknown): high-risk 3/2, GPAI 3/2, GDPR 2/4, GenAI 3/2, FTC 2/2. Missing, stale or declared-as-assessed evidence does not pass; false availability produces preparation/evidence gaps; out-of-scope controls leave manual scope unresolved. These counts test evaluator behavior, not accuracy against a labelled legal benchmark.

Before installing: back up the data volume, combine only manifest-listed files with retained versions in a staging directory, reject differing content for an existing ID/version, and validate that entire directory. Stop the single service, install with its data-directory ownership, restart, and verify health. If startup fails, restore the previous rule-pack directory and restart. Do not copy the manifest, synthetic products or test reports into live data. Rule packs load at startup; installing them does not change enforcement policies.
