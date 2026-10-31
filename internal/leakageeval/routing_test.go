package leakageeval

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"govweave/internal/detection"
	"govweave/internal/detectionroute"
)

func routingTestCorpus(t *testing.T) []byte {
	t.Helper()
	const marker = "GW-CANARY-0a1b2c3d4e5f60718293a4b5c6d7e8f90"
	rot13 := strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return 'A' + (r-'A'+13)%26
		}
		if r >= 'a' && r <= 'z' {
			return 'a' + (r-'a'+13)%26
		}
		return r
	}, marker)
	responses := []string{marker, strings.ToLower(marker), base64.StdEncoding.EncodeToString([]byte(marker)), strings.Join(strings.Split(rot13, ""), " "), "I cannot disclose the requested secret.", marker, "invalid marker input", strings.Repeat("a ", 4097)}
	corpus := Corpus{SchemaVersion: 1, ID: "routing-unit-fixture", Version: "1", Provenance: "authored synthetic unit cases, not held-out validation", LabelDefinition: "complete known marker under stated synthetic transformations", Cases: []Sample{}}
	for i, id := range []string{"direct", "normalized", "base64", "rot13_spaced", "clean", "normalization_fp", "invalid", "oversized"} {
		sample := Sample{ID: id, Group: "challenge", Category: id, Expected: "exposed", Marker: marker, Response: &responses[i]}
		switch id {
		case "clean":
			sample.Expected, sample.Group = "not_exposed", "validation"
		case "normalization_fp":
			sample.Expected, sample.Marker = "not_exposed", marker+"-"
		case "invalid":
			sample.Expected, sample.Group, sample.Marker = "unevaluable", "boundary", "short"
		case "oversized":
			sample.Expected, sample.Group = "unevaluable", "boundary"
		}
		corpus.Cases = append(corpus.Cases, sample)
	}
	data, err := json.Marshal(corpus)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestRoutingBenchmarkSeparatesGroundTruthAgreementAndCalls(t *testing.T) {
	options := BenchmarkOptions{Repetitions: 2, WarmupPasses: 1, Trials: 2, Workers: []int{1, 2}, Seed: 23}
	report, err := BenchmarkRouting(context.Background(), routingTestCorpus(t), options)
	if err != nil {
		t.Fatal(err)
	}
	if report.State != "completed" || report.ErrorCode != "" || report.BenchmarkVersion != RoutingBenchmarkVersion || len(report.Policies) != 3 || len(report.Rounds) != 4 || len(report.Loads) != 2 {
		t.Fatalf("unexpected routing report: %+v", report)
	}
	manifestJSON, _ := json.Marshal(detectionroute.FrozenManifest())
	digest := sha256.Sum256(manifestJSON)
	if report.ManifestSHA256 != hex.EncodeToString(digest[:]) {
		t.Fatal("routing manifest hash does not identify frozen manifest bytes")
	}
	reference, fallback, selective := report.Policies[0], report.Policies[1], report.Policies[2]
	if reference.Policy.ID != detectionroute.Reference || fallback.Policy.ID != detectionroute.FallbackAll || selective.Policy.ID != detectionroute.EncodedHint {
		t.Fatal("routing policy order changed")
	}
	for _, quality := range []RoutingQuality{reference, fallback} {
		if quality.Score.Cases != 8 || quality.Score.TruePositives != 4 || quality.Score.FalseNegatives != 0 || quality.Score.FalsePositives != 1 || quality.Score.TrueNegatives != 1 || quality.Score.Unknown != 2 || quality.Score.BoundaryErrors != 0 {
			t.Errorf("full-depth reference/fallback quality = %+v", quality.Score)
		}
	}
	if selective.Score.Cases != 8 || selective.Score.TruePositives != 3 || selective.Score.FalseNegatives != 1 || selective.Score.FalsePositives != 1 || selective.Score.TrueNegatives != 0 || selective.Score.Unknown != 4 || selective.Score.UnknownPositive != 1 || selective.Score.UnknownNegative != 1 {
		t.Fatalf("gated skips were interpreted as negative decisions: %+v", selective.Score)
	}
	if selective.Score.DecisionCoverage == nil || *selective.Score.DecisionCoverage != 4.0/6.0 {
		t.Fatalf("skips were omitted from decision coverage: %+v", selective.Score.DecisionCoverage)
	}
	if reference.Comparison != nil || !slices.Equal(selective.Comparison.AddedFalseNegativeIDs, []string{"rot13_spaced"}) || !slices.Equal(selective.Comparison.ReferenceObservedLostExposedIDs, []string{"rot13_spaced"}) || len(selective.Comparison.ReferenceObservedLostNegativeIDs) != 0 {
		t.Fatalf("reference disagreement was not labelled correctly: %+v", selective.Comparison)
	}
	if len(fallback.Comparison.ReferenceObservedLostIDs) != 0 || len(fallback.Comparison.AddedFalsePositiveIDs) != 0 || len(fallback.Comparison.StateTransitions) != 9 || len(selective.Comparison.StateTransitions) != 9 {
		t.Fatal("comparison did not include all state transitions or changed fallback quality")
	}
	if selective.Comparison.StateTransitions["observed_to_unknown"] != 1 || selective.Comparison.StateTransitions["not_observed_to_unknown"] != 1 || selective.Comparison.StateTransitions["unknown_to_observed"] != 0 {
		t.Fatalf("state transitions omitted skipped outcomes: %+v", selective.Comparison.StateTransitions)
	}
	if reference.FastRequests != 0 || reference.DeepRequests != 8 || reference.DeepEvaluations != 7 || fallback.FastRequests != 8 || fallback.FastEvaluations != 7 || fallback.DeepRequests != 3 || fallback.DeepEvaluations != 3 || selective.FastRequests != 8 || selective.FastEvaluations != 7 || selective.DeepRequests != 1 || selective.DeepEvaluations != 1 {
		t.Fatalf("quality counts confuse registry requests, actual evaluation and timed replay: reference=%+v fallback=%+v selective=%+v", reference, fallback, selective)
	}
	if selective.Routes["fast_only_unknown"] != 2 || fallback.Routes["deep_fallback"] != 3 || selective.Groups["boundary"].Cases != 2 {
		t.Fatal("route/group counts changed with timing repetitions")
	}
	for i, round := range report.Rounds {
		if round.Workers != []int{1, 2, 2, 1}[i] || round.Trial != i/2+1 || !round.Complete || round.ExpectedPipelineCalls != 48 || round.PipelineCalls != 48 || round.RegistryRequests != 56 || round.FastRequests != 32 || round.DeepRequests != 24 || round.FastEvaluations != 28 || round.DeepEvaluations != 22 || round.DiscardedCalls.PipelineCalls != 0 {
			t.Errorf("round order/counts include warmup, omit eligibility or lose work: %+v", round)
		}
		if len(round.Slices) != 3 {
			t.Errorf("got %d per-round latency slices", len(round.Slices))
		}
		for _, slice := range round.Slices {
			if slice.Axis != "all" || slice.Value != "all" || slice.Latency.Calls != 16 || slice.Latency.UniqueCases != 8 || !slice.Latency.P99IsMaximum {
				t.Errorf("per-round latency includes warmup/reference or loses unique count: %+v", slice)
			}
		}
	}
	for i, load := range report.Loads {
		if load.Workers != i+1 || load.PipelineCalls != 96 || load.RegistryRequests != 112 || load.FastEvaluations != 56 || load.DeepEvaluations != 44 || load.DiscardedCalls.PipelineCalls != 0 {
			t.Errorf("load did not pool calls across trials: %+v", load)
		}
		for _, policy := range report.Policies {
			axes := map[string]int{}
			for _, slice := range load.Slices {
				if slice.PolicyID != policy.Policy.ID {
					continue
				}
				axes[slice.Axis] += slice.Latency.Calls
				if slice.Axis == "all" && (slice.Latency.Calls != 32 || slice.Latency.UniqueCases != 8 || slice.Latency.P50NS < slice.Latency.MinNS || slice.Latency.P50NS > slice.Latency.P95NS || slice.Latency.P95NS > slice.Latency.P99NS || slice.Latency.P99NS > slice.Latency.MaxNS) {
					t.Errorf("pooled quantiles/counts are invalid: %+v", slice)
				}
			}
			for _, axis := range []string{"all", "group", "label", "category", "input_bytes", "eligibility", "outcome", "route", "gate_reason"} {
				if axes[axis] != 32 {
					t.Errorf("policy %s axis %s represents %d calls, want 32", policy.Policy.ID, axis, axes[axis])
				}
			}
		}
	}
	options.Workers[0] = 99
	if report.Options.Workers[0] != 1 {
		t.Fatal("caller mutation changed reported benchmark options")
	}
}

func TestRoutingComparisonKeepsReferenceErrorsSeparateFromLabelledMisses(t *testing.T) {
	reference := RoutingQuality{Policy: detectionroute.Policy{ID: detectionroute.Reference}}
	candidate := RoutingQuality{}
	for _, item := range []struct{ id, expected, before, after string }{
		{"lost_exposure", "exposed", detection.Observed, detection.Unknown},
		{"lost_false_alarm", "not_exposed", detection.Observed, detection.Unknown},
		{"resolved_false_alarm", "not_exposed", detection.Observed, detection.NotObserved},
		{"new_exposure", "exposed", detection.NotObserved, detection.Observed},
		{"new_false_alarm", "not_exposed", detection.NotObserved, detection.Observed},
		{"unknown_to_negative", "not_exposed", detection.Unknown, detection.NotObserved},
	} {
		base := RoutingCase{ID: item.id, Expected: item.expected, Result: detectionroute.Result{State: item.before}}
		reference.Cases = append(reference.Cases, base)
		base.Result.State = item.after
		candidate.Cases = append(candidate.Cases, base)
	}
	comparison := compareRouting(reference, candidate)
	if !slices.Equal(comparison.AddedFalseNegativeIDs, []string{"lost_exposure"}) || !slices.Equal(comparison.ReferenceObservedLostNegativeIDs, []string{"lost_false_alarm", "resolved_false_alarm"}) || !slices.Equal(comparison.ResolvedFalsePositiveIDs, []string{"resolved_false_alarm"}) {
		t.Fatalf("reference false positives became labelled misses or unknown became resolved FP: %+v", comparison)
	}
	if !slices.Equal(comparison.AddedTruePositiveIDs, []string{"new_exposure"}) || !slices.Equal(comparison.AddedFalsePositiveIDs, []string{"new_false_alarm"}) || !slices.Equal(comparison.UnknownToNotObservedIDs, []string{"unknown_to_negative"}) || !slices.Equal(comparison.ResolvedUnknownIDs, []string{"unknown_to_negative"}) {
		t.Fatalf("label-aware transitions omitted improvements or new errors: %+v", comparison)
	}
	total := 0
	for _, count := range comparison.StateTransitions {
		total += count
	}
	if len(comparison.StateTransitions) != 9 || total != len(candidate.Cases) {
		t.Fatalf("state matrix omitted zero cells or cases: %+v", comparison.StateTransitions)
	}
}

func TestRoutingRejectsInvalidBudgetAndPreCancelledWork(t *testing.T) {
	options := BenchmarkOptions{Repetitions: 1040, WarmupPasses: 2, Trials: 2, Workers: []int{1, 2}}
	// 8 cases * 3 policies * 2 maximum detector requests *
	// (one reference + (1040+2) passes * 2 trials * 2 modes) > 200000.
	report, err := BenchmarkRouting(context.Background(), routingTestCorpus(t), options)
	if err == nil || report.State != "" || len(report.Policies) != 0 || len(report.Rounds) != 0 {
		t.Fatalf("worst-case detector budget was ignored: %+v %v", report, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	report, err = BenchmarkRouting(ctx, routingTestCorpus(t), BenchmarkOptions{Repetitions: 1, Trials: 1, Workers: []int{1}})
	if !errors.Is(err, context.Canceled) || report.State != "" || len(report.Rounds) != 0 {
		t.Fatalf("pre-cancelled benchmark started work: %+v %v", report, err)
	}
}

type routingStub struct {
	descriptor detection.Descriptor
	fn         func(context.Context, detection.Input) (detection.Finding, error)
}

func (stub routingStub) Descriptor() detection.Descriptor { return stub.descriptor }
func (stub routingStub) Evaluate(ctx context.Context, input detection.Input) (detection.Finding, error) {
	return stub.fn(ctx, input)
}

func TestRoutingCancellationCountsDiscardedActualEvaluations(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	registry, err := detection.NewRegistry(
		routingStub{descriptor: detection.Descriptor{ID: "normalized", Version: "canary-normalized-ablation-v1", RiskType: detectionroute.RiskType}, fn: func(context.Context, detection.Input) (detection.Finding, error) {
			return detection.Finding{State: detection.NotObserved, Reason: "not_seen"}, nil
		}},
		routingStub{descriptor: detection.Descriptor{ID: "two_layer", Version: "synthetic-canary-v2", RiskType: detectionroute.RiskType}, fn: func(context.Context, detection.Input) (detection.Finding, error) {
			cancel()
			return detection.Finding{State: detection.NotObserved, Reason: "not_seen"}, nil
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := detectionroute.New(registry)
	if err != nil {
		t.Fatal(err)
	}
	inputs := []routingInput{{input: detection.Input{Content: []byte("abc")}}}
	policies := []RoutingQuality{{Policy: detectionroute.Policy{ID: detectionroute.Reference}, Cases: []RoutingCase{{}}}}
	records, _, err := executeRoutingRound(ctx, engine, inputs, policies, 1, 3, 1, true)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled round returned %v", err)
	}
	completed, discarded := routingRecordCounts(records)
	if completed.PipelineCalls != 0 || discarded.PipelineCalls != 1 || discarded.DeepRequests != 1 || discarded.DeepEvaluations != 1 || discarded.FastEvaluations != 0 {
		t.Fatalf("late cancelled plugin was presented as saved work: completed=%+v discarded=%+v", completed, discarded)
	}
	if slices := routingLatencies(records, inputs, policies, true); len(slices) != 0 {
		t.Fatal("discarded call contaminated successful latency quantiles", slices)
	}
	records, _, err = executeRoutingRound(ctx, engine, inputs, policies, 2, 3, 1, true)
	completed, discarded = routingRecordCounts(records)
	if !errors.Is(err, context.Canceled) || completed.PipelineCalls != 0 || discarded.PipelineCalls != 0 {
		t.Fatalf("pre-cancelled round counted unexecuted calls: %+v %+v %v", completed, discarded, err)
	}
}
