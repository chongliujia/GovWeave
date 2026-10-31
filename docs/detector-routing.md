# Detector plugins and offline routing validation

**English** | [简体中文](zh-CN/detector-routing.md)

This experiment gives compiled detectors a common observation format and compares three fixed ways to route known-marker checks. It runs offline on authored synthetic text. It does not install a business-response filter, call a model, or make a legal conclusion.

## Run the comparison

From the source repository, run:

```bash
make validate-routing
```

To select the frozen corpus and replay settings explicitly:

```bash
go run ./cmd/canary-bench -routing \
  -corpus tests/testdata/canary-validation-v3.json \
  -output-dir dist/canary-routing \
  -repetitions 30 -warmup 2 -trials 2 \
  -workers 1,2 -seed 20261028 -timeout 60s
```

The command creates a new private report and prints its location. Existing reports remain available. Check the report state before comparing results: an interrupted experiment is incomplete, and its completed work does not stand in for all requested cases or rounds. Cancellation is cooperative between bounded detector calls; it cannot preempt a plugin that ignores its context.

The observation contract is described by [detection.schema.json](../schemas/detection.schema.json); the comparison report uses [routing.schema.json](../schemas/routing.schema.json). The previous [standalone-stage benchmark](canary-benchmark.md) remains a separate experiment.

## Plugin contract and boundaries

The Go interface in `internal/detection` is:

```go
type Plugin interface {
    Descriptor() Descriptor
    Evaluate(context.Context, Input) (Finding, error)
}
```

A descriptor pins `id`, `version` and `risk_type`. `NewRegistry` snapshots descriptors and accepts at most 16 distinct ID/version registrations. Evaluation requests an exact ID/version pair; there is no implicit latest version. The registry is immutable after construction. Plugin implementations still have to keep their behavior stable, support concurrent calls, bound their own work and cooperate with cancellation.

These are trusted Go implementations registered explicitly when compiling the program. This is not dynamic `.so` loading, an uploaded-code sandbox or an implemented external model/classifier service. A future detector needs its own implementation and validation in addition to satisfying the interface.

Input carries ephemeral content bytes and optional known-marker context. The generic envelope accepts at most 8192 content bytes, requires valid UTF-8, and bounds known-marker context to 512 bytes. The known-marker adapter applies its own narrower marker eligibility rules. If several limits fail, the generic envelope can return a different first reason from a direct detector call. The registry checks size before copying or hashing oversized content, provides a private content copy to each invocation, validates the finding, and returns static operational errors without retaining a plugin's error text.

An observation records the detector identity, risk type, `observed` / `not_observed` / `unknown` state, machine-readable reason, bounded byte-span evidence, input byte count, elapsed time and an eligible content hash. It does not retain the original content or marker. `evaluated` says whether plugin code was entered; it can be true for a plugin error, cancellation after entry or an adapter result that remains unknown. Evidence points into the original content: encoded or transformed regions are not decoded-text offsets.

The supplied registry adapts the existing exact, normalized, one-layer and two-layer known-marker stages. Its current risk type is `known_marker_exposure`; a common interface does not turn those stages into general privacy, prompt-injection or AI compliance classifiers. The adapters preserve existing detector versions, active-test runners and historical replay semantics.

Regulatory rule packs describe how evidence supports particular technical checks and manual review. They are separate from detector implementations. This change does not publish the new `Observation` format into production `runtime.*` or `testing.*` facts; the existing evidence path remains the documented one in [active assessment](active-assessments.md).

## Register a compiled detector

This minimal repository-internal example implements the contract and pins its version at the call site. It only checks literal known-marker exposure and is not a production replacement for the supplied adapters.

```go
// Imports: bytes, context, and govweave/internal/detection.
type literalDemo struct{}

func (literalDemo) Descriptor() detection.Descriptor {
    return detection.Descriptor{
        ID: "example_literal", Version: "example-literal-v1",
        RiskType: "known_marker_exposure",
    }
}

func (literalDemo) Evaluate(ctx context.Context, in detection.Input) (detection.Finding, error) {
    if err := ctx.Err(); err != nil {
        return detection.Finding{}, err
    }
    if in.KnownMarker == "" {
        return detection.Finding{State: detection.Unknown, Reason: "marker_required"}, nil
    }
    at := bytes.Index(in.Content, []byte(in.KnownMarker))
    if at < 0 {
        return detection.Finding{State: detection.NotObserved, Reason: "literal_not_observed"}, nil
    }
    return detection.Finding{
        State: detection.Observed, Reason: "literal_observed",
        Evidence: []detection.Evidence{{Representation: "exact", StartByte: at,
            EndByte: at + len(in.KnownMarker), SpanScope: "raw_fragment"}},
    }, nil
}

func checkDemo(ctx context.Context, in detection.Input) (detection.Observation, error) {
    registry, err := detection.NewRegistry(literalDemo{})
    if err != nil {
        return detection.Observation{}, err
    }
    return registry.Evaluate(ctx, detection.Ref{
        ID: "example_literal", Version: "example-literal-v1",
    }, in)
}
```

An `observed` finding must include evidence spans in the original content; other states must not carry positive evidence. There is no probability field. An uncalibrated classifier score must not be presented as a probability. Regulatory packs remain declarative JSON, while future classifier or model adapters still require their own implementation.

## Frozen routing policies

`internal/detectionroute.FrozenManifest()` is the source of policy IDs, detector references, gate rules and versions. The experiment uses routing version `canary-routing-v1` and gate version `encoded-surface-hints-v1`.

| Policy | Execution |
| --- | --- |
| `deep_reference` | Request the pinned two-layer detector for every input. |
| `normalized_fallback_all` | Run normalized detection first. Return a fast observation if observed; preserve an unknown result. Otherwise request the two-layer detector. |
| `normalized_encoded_hint` | Use the same fast stage. After a fast negative, request two-layer detection only when a content hint matches. Otherwise return final `unknown` with reason `deep_stage_skipped`. |

The hint gate only sees response bytes. It receives no expected marker, labels, case IDs, categories, groups or reference decisions. Its fixed hints cover hexadecimal escapes, long ASCII encoding-character runs, sequences of decimal integers and named encoding labels. The exact patterns and precedence are retained in the source and manifest. A hint is a routing heuristic, not proof of leakage or a calibrated risk probability.

A gated skip retains the fast `not_observed` step but sets the final route to `fast_only_unknown`. It does not claim the two-layer scope was checked. `deep_evaluated` is true only when the deep plugin was actually entered; a registry request rejected by the envelope does not count as plugin execution. An early fast observation and a fast unknown also have no deep execution.

These policies are offline experiments. Before any future use on business traffic, routing needs validation under the intended workload and explicit decisions about unknowns, errors and latency limits.

## Labels and the deep reference answer different questions

Each policy is scored against the authored labels once per unique case. Repeated timing calls do not enlarge the quality sample. Unknown exposed cases count as misses; unknown normal cases are not true negatives. Read false-positive rate with unknown counts and decision coverage. A policy that skips many inputs may be fast while losing decision coverage.

The deep reference is a comparator, not ground truth. It can itself miss an exposed case, raise a false positive or return unknown. Read policy transitions separately from label-based quality:

- Losing a reference observation is not automatically a new true miss: the reference observation may have been a false positive.
- An added miss requires an exposed label that the reference observed and the candidate did not observe; a candidate unknown still counts as a miss.
- A candidate negative when the reference was unknown is not evidence that uncertainty was correctly resolved.
- An added false positive requires a normal label and a candidate observation that the reference did not make.

Per-case routes, reasons, steps and state transitions make these differences inspectable. Do not turn agreement with the reference into an accuracy claim or treat a smaller deep-call count as evidence of safety.

## Cost measurement

The timed unit is the complete policy call. Both the deep baseline and routed candidates use the same registry wrapper. Timing includes input checks, content hashing/copies, applicable fast detection, hint matching, applicable deep detection, observation validation and pipeline assembly. An independently computed reference used for quality comparison is excluded from that timed call.

The old standalone benchmark times `leakage.DetectStage` directly. Its values exclude the new registry and pipeline work, so its P99 should not be compared directly with routed-policy P99 as if the units were identical.

Reports distinguish policy calls, registry requests and actual plugin entries, including fast/deep counts. The per-policy `fast_requests` / `deep_requests` and `fast_evaluations` / `deep_evaluations` summarize unique quality cases. In measured rounds and loads, `pipeline_calls`, `registry_requests` and the fast/deep counters count only completed, consistent calls. Attempted failed, cancelled or inconsistent calls are retained separately in `discarded_calls`; unstarted work is not counted. Untimed quality and warmup calls are excluded from measured counters. A successful request can still produce an unknown observation. A completed quality pass does not make an interrupted timing experiment complete. Deep calls omitted by a candidate describe that candidate's execution plan; the offline comparison still executes reference and other policies to evaluate the plan. They are not calls saved by the complete evaluation program.

Single- and double-worker replays are closed-loop local workloads. The policy mix shares CPU, allocation and GC pressure. The measured wall-clock call includes scheduling and GC occurring during it, excludes queue wait, and does not subtract clock-read overhead. Warmup, reference quality calculation, corpus I/O and report writing are outside the measured unit. Any batch calls-per-second number includes harness work and mixes policies; it is not a model rate or deployed service capacity.

P50/P95/P99 are empirical nearest-rank quantiles over repeated calls. Small slices can select the maximum as P99; correlated repetitions of one fixed text do not establish a population confidence interval. Check per-route, eligible-input and input-size slices alongside the overall mixture. These measurements exclude gateway authentication, audit I/O, network, model generation and streaming, so they do not establish a production realtime SLA.

## Fresh-corpus procedure and evidence limits

The new [v3 corpus provenance](../tests/testdata/canary-v3-provenance.md) records 60 authored cases: 32 exposed, 22 not exposed and 6 unevaluable. Its frozen SHA-256 is `d0fd785f73105c898d3a8a4b47284a19465759ed1f55d525ab77468d0aa36c15`.

Another agent in the same project created and froze the new cases without inspecting detector implementations or earlier corpora/results. Detector and routing source hashes were separately frozen before the first v3 evaluation. The evaluation must retain the exact corpus and implementation identities and evaluate all frozen cases; results must not be used to remove or relabel awkward examples.

This is internal separation of duties with constructed labels, not an external blind review, a human labeling panel or real-model output validation. The original 48-case and 72-case sets remain development regression data. After the first v3 results have been inspected, subsequent algorithm tuning requires another untouched set for a fresh validation claim. Synthetic correctness, routing fidelity and local timing each provide different evidence; none alone establishes general AI compliance.

Per-case `steps[].elapsed_ns` values come from the initial quality traversal and are diagnostic observations. Use `rounds` and `loads` for warmed repeated-call latency distributions; the per-case values are not additional performance samples.

## First frozen v3 measurement

On the 60 authored cases (32 exposed, 22 not exposed, 6 ineligible), the first frozen experiment produced:

| Policy | Detected exposures | False positives | Unknown | Actual deep plugin entries |
| --- | --- | --- | --- | --- |
| Full-depth reference | 26/32 | 0/22 | 7 | 58 |
| Normalized, unconditional fallback | 26/32 | 0/22 | 7 | 44 |
| Normalized, encoded-surface gate | 26/32 | 0/22 | 16 | 35 |

These are unique-case counts, not repeated timing calls. Two oversized inputs are rejected before plugin entry, so full-depth requests (60) and actual entries (58) differ. The unconditional fallback preserved the reference outcomes on these cases. The selective gate had no added labelled misses on this corpus, but reduced labelled-input decision coverage from 98.15% to 81.48%; nine additional outcomes became unknown. Its measured P99 did not improve in this local run. Fewer deep entries alone do not demonstrate a useful latency/coverage tradeoff.

A separate authored unit case contains spaced ROT13 text that the full detector finds while the gate skips it. This demonstrates a real routing failure even though it did not appear as an added miss in this particular v3 corpus. The gate remains an experiment. The reference itself still misses six authored exposures; results are not comparable to older-corpus percentages as an improvement estimate.

The retained [pre-evaluation source record](../tests/testdata/canary-routing-v1-freeze.json) identifies detector, registry and routing files fixed before first measurement. Each report additionally identifies its executable and manifest. New implementations require new validation data after these outcomes have been inspected.
