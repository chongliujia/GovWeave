# Model and tool assessment for one product

**English** | [简体中文](zh-CN/application-assessments.md)

A product can now maintain one model test plan and one read-tool test plan. Their current lifecycle evidence enters the same product report, with independent run IDs, plan revisions and expiration times. The optional `application-output-governance@1.0.0` pack checks thirteen technical controls: eight runtime output controls, resource-grant coverage, two model lifecycle checks and two tool lifecycle checks.

## Configure the two plans

Install the combined pack and both suites, then restart:

```bash
mkdir -p data/rule-packs data/test-suites
cp examples/rule-packs/application-output-governance.json data/rule-packs/
cp examples/test-suites/sensitive-output-controls.json data/test-suites/
cp examples/test-suites/read-tool-output-controls.json data/test-suites/
```

Register [the product example](../examples/application-assessment-product.json) with your application ID. Configure an authorized model, the five dedicated synthetic tool resources, and the intended output policy as described in [model output assessment](output-control-assessments.md) and [read-tool assessment](tool-control-assessments.md). There is no automatic policy change or provider call during plan configuration.

Use the existing administrator session and mutation headers for these endpoints:

| Endpoint | Purpose |
| --- | --- |
| `GET /api/v1/compliance/products/{id}/test-plans` | List up to two plans, including any legacy default |
| `GET, PUT /api/v1/compliance/products/{id}/test-plans/model` | Named model plan, using the [model plan input](../examples/sensitive-output-test-plan.json) |
| `GET, PUT /api/v1/compliance/products/{id}/test-plans/read_tool` | Named tool plan, using the [tool plan input](../examples/read-tool-test-plan.json) |
| `POST /api/v1/compliance/products/{id}/test-runs` | Start the explicitly selected plan and phase |

The plan ID comes from the URL, not the save body. Each plan has its own optimistic `revision`; start at zero and use the returned revision for updates. `model` requires a model suite and model fields; `read_tool` requires `target_kind: read_tool`, a tool suite and tool fields. The server rejects duplicate target kinds, including conflicts with a legacy default plan, with `409 test_plan_target_conflict`.

Start four runs sequentially, waiting for each returned run ID to finish:

```json
{"plan_id":"model","phase":"pre_deployment"}
{"plan_id":"model","phase":"operation"}
{"plan_id":"read_tool","phase":"pre_deployment"}
{"plan_id":"read_tool","phase":"operation"}
```

Each line is a separate request body. Starting a run tests only that plan; it does not fan out to the other target. Run summaries and retained plans expose `plan_id`. History lists both plans, so clients should use this field when grouping results.

## Existing plans and scheduling

The singular `/test-plan` endpoint still reads and updates the original default plan. An absent or empty `plan_id` in a start request still selects only that default. It never guesses between named plans. If a product contains only named plans, a start request without `plan_id` returns 404 without provider I/O.

Existing files and old run hashes keep their original serialization: the default plan has no `plan_id` field. Keep an existing model default and add the named `read_tool` plan, or keep a tool default and add the named `model` plan. Do not create a second plan of the same target kind. No migration or deletion of historical evidence is required.

Each plan independently controls opt-in scheduling, next due time, last run and last error. The existing limits remain: two runs globally and one per product, including both plans. Due plans are considered oldest first; a plan waiting for its product's running test remains due for a later scheduler tick. A manual overlapping request receives `429 test_busy`. Editing the other plan alone does not cancel an in-flight test. Editing the running plan or shared configuration does.

## How the report combines evidence

| Evidence | Independent scope |
| --- | --- |
| `testing.output.pre_deployment.passed` / `testing.output.operation.passed` | Latest matching model run in each phase |
| `testing.tools.output.pre_deployment.passed` / `testing.tools.output.operation.passed` | Latest matching tool run in each phase |

Each target needs its complete category/benign suite; the tool suite also needs a denial check. A missing, running, interrupted, expired or inconclusive latest run cannot reuse an old success. A model-only plan edit invalidates model evidence while retaining current tool evidence, and vice versa. Product or shared gateway/request-policy/tool-store/output-policy changes invalidate both conservatively; even an unrelated tool-store edit changes the shared revision. Pre-deployment evidence lasts 30 days; operation evidence lasts twice that plan's interval.

Current product `/evaluation` results and saved `/reports` combine both plans. An individual test run still evaluates its own plan's facts, so the combined pack will show the other target's active controls as unknown in that run. Read the product report for the combined result. Runtime evidence remains separate: assessment requests do not increase production counters. The last-100-entry shared audit sample, retention limits and replay boundaries are unchanged.

Both plans can bind different applications already registered in the product, but one model and one tool plan do not establish coverage of every bound application or route. They test the selected targets independently, not a complete Agent trajectory. The pack is an internal technical policy draft, and `legal_compliance` remains `not_determined`.

## Local demonstration

```bash
make demo-application-assessment
```

The isolated demo uses 38 local calls, nine active runs and nine retained product reports. It shows 9 passes/4 unknowns before active tests, 11 passes/2 unknowns after only model tests, then all 13 passes after tool tests. A model plan edit preserves tool evidence; a missing challenge affects only the corresponding target/phase; a shared policy change invalidates both. All eighteen records replay without provider I/O. Results are saved under `dist/application-assessment-demo/<unique-run>/`. These synthetic checks verify control execution and evidence handling, not measured real-world risk coverage.
