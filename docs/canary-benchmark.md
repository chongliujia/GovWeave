# Offline canary quality and cost replay

**English** | [简体中文](zh-CN/canary-benchmark.md)

This tool measures the detection benefit and local function-call cost of four standalone stages on the same labelled synthetic corpus. It does not call a model, require an API key, change an instance, or install a response filter. It is a development replay, not evidence of a production realtime SLA.

## Run

From the source repository:

```bash
make benchmark-canary
```

To choose the corpus and measurement settings directly:

```bash
go run ./cmd/canary-bench \
  -corpus tests/testdata/canary-validation-v2.json \
  -output-dir dist/canary-benchmark \
  -repetitions 30 -warmup 2 -trials 2 \
  -workers 1,2 -seed 20261028 -timeout 60s
```

The command prints a newly created private report location. Existing reports are retained. The report follows [benchmark.schema.json](../schemas/benchmark.schema.json) and records the corpus identity and SHA-256, benchmark version, stage versions, settings, derived round seeds, executable SHA-256, Go version, OS/architecture, CPU count, GOMAXPROCS and selected build settings. With `go run`, the executable hash identifies that invocation's generated binary, not a reproducible source-build guarantee. Do not compare reports without checking their environment and workload.

Repetitions are 1–2000, warmup passes 0–20, and trials 1–5. Worker modes must be distinct choices from 1 and 2. Total reference, warmup and measured calls are bounded by 200000. A timeout before reference evaluation completes produces no report; an interruption during warmup or measurement can preserve `state: incomplete` and exits nonzero. Cancellation is cooperative between bounded detector calls, so an in-flight call can finish after the deadline. Do not interpret partial rounds as a completed comparison.

## What each stage means

| Stage | Experiment |
| --- | --- |
| `exact` | Literal matching, including common input eligibility and result metadata |
| `normalized` | Exact matching plus the documented lossy normalization |
| `single_layer` | The v2 detector's transformations and budgets, limited to one reversible layer |
| `two_layer` | The current v2 detector with its two-layer limit |

The single- and two-layer stages share the same v2 methods and budgets; their intended difference is depth. `single_layer` is **not** the historical v1 detector, whose methods and limits differ. Experimental stage versions are not registered production detector versions and cannot reinterpret saved active-assessment evidence. Historical v1/v2 quality comparison remains available through [Canary validation](canary-validation.md).

These are independent complete evaluations of each input, not an implemented routing cascade. A future policy that sends only selected requests to a slower stage needs its own test: a gate can discard the very cases the slower detector would catch. Stage outcomes are not assumed to improve monotonically.

## Quality accounting

Every stage scores each unique labelled case once. Repeated timing calls do not create more labelled examples or independent quality evidence. Both frozen sets of 48 and 72 cases have already been inspected and used in development; they are regression and ablation data, not fresh unseen validation.

The report retains per-case state/reason, group scores and transitions from the preceding stage: newly detected exposures, lost detections, added/resolved false positives, and cases that become unknown or become assessable. Read those case lists, not only the difference between total true-positive counts.

The scoring contract remains:

- Recall counts a labelled exposure that returns unknown as a miss.
- Unknown labelled negatives are not true negatives; decision coverage and unknown counts remain visible.
- Precision is undefined when no positives are detected.
- False-positive rate uses all labelled negatives and must be read together with decision coverage.
- Unknown exposed cases are included in both the false-negative count and the unknown breakdown. Do not sum those columns as disjoint populations.
- Inputs labelled `unevaluable` must remain unknown; a binary verdict increments `boundary_errors`.

The two corpora have different exposure prevalence and coverage. Their percentages are not comparable population estimates. New model output, risk families and application contexts still require separate validation and appropriate sampling.

## Timing boundary

Before measurement, the tool computes one untimed reference result for every case/stage and performs the requested warmup for each round. Case/stage pairs are shuffled each pass using recorded seeds. Worker-mode order alternates across trials. This reduces a fixed-order advantage but does not control CPU affinity, thermal/power state, background programs or operating-system scheduling.

Timing starts inside a worker immediately before `DetectStage` and stops when it returns. It includes eligibility checks, matching/decoding, result metadata, and scheduling or GC pauses occurring during that call. The two clock reads affect very fast stages; no timer-overhead subtraction is performed.

It excludes queue wait, corpus reading/parsing, reference quality scoring, post-call consistency checks and report encoding/writing. No network, HTTP routing, authentication, audit sync, model inference, streaming buffer or client delivery is timed. The repeated call's stage version, state and reason are checked against the reference outside the measured interval.

One and two worker modes are fixed-concurrency, closed-loop local workloads. They do not emulate an independent arrival rate, production queue buildup, burst traffic or saturation. Stage latency under two workers includes contention with other stages in the mixed workload. `harness_inclusive_calls_per_second` divides completed calls by measured batch wall time. That wall time includes dispatch, goroutine startup and consistency checking, and mixes all stages. It is harness throughput, not per-stage service capacity or model throughput. Warmup is excluded.

## Read the tail and slices

Latency fields use nanoseconds and include call count, unique-case count, mean, minimum, P50/P95/P99 and maximum. Quantiles use nearest rank: sorted index `ceil(p × n) - 1`. `p99_is_maximum` means the chosen rank is the maximum observation; this occurs with fewer than 100 calls. A P99 value can also numerically equal the maximum because of ties, which alone does not imply a small sample.

Per-round summaries identify incomplete work and variation between trials. Pooled worker-mode quantiles are computed from the pooled individual calls, not averages of round quantiles. Repeating one fixed case many times does not make it representative of other inputs or supply an independent population confidence interval.

The pooled report includes slices by group, label, category, input-size range, input eligibility, resulting state and unknown reason. Overall replay weights every corpus case equally, including fast ineligible inputs. Check long/noisy/encoded cases and eligible-input slices before describing a detector as fast. A small slice can have a P99 equal to its worst observed call. This report does not measure allocations per operation.

## Verification and use

Use the report to ask which stage adds useful detections, introduces false positives or unknowns, and consumes local tail latency. It does not choose production thresholds, certify privacy, establish a universal safe budget or prove that a live blocking policy is effective. A zero exit code means replay completed consistently, not zero mistakes or an acceptable SLA.

The [known-marker scope](canary-validation.md) and [active-assessment boundaries](active-assessments.md) still apply. The current marker detector runs in active testing; it has not become a business-response blocker. Structured evidence and replay remain deterministic code with no LLM or agent dependency.

For the version-pinned plugin interface and an actual fast/deep routing experiment on a separately frozen corpus, see [Detector plugins and routing](detector-routing.md). That replay measures complete pipeline cost through the registry, so it is not directly comparable with the raw-stage timings here.
