package leakageeval

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"govweave/internal/leakage"
)

func TestElapsedStatsNearestRankAndSmallSampleP99(t *testing.T) {
	sequence := func(count int) []int64 {
		values := make([]int64, count)
		for i := range values {
			values[i] = int64(count - i)
		}
		return values
	}
	tests := []struct {
		name   string
		values []int64
		unique int
		want   LatencyStats
	}{
		{"empty", nil, 5, LatencyStats{}},
		{"one", []int64{7}, 1, LatencyStats{Calls: 1, UniqueCases: 1, MeanNS: 7, MinNS: 7, P50NS: 7, P95NS: 7, P99NS: 7, MaxNS: 7, P99IsMaximum: true}},
		{"unsorted", []int64{50, 10, 40, 20, 30}, 3, LatencyStats{Calls: 5, UniqueCases: 3, MeanNS: 30, MinNS: 10, P50NS: 30, P95NS: 50, P99NS: 50, MaxNS: 50, P99IsMaximum: true}},
		{"99 calls", sequence(99), 4, LatencyStats{Calls: 99, UniqueCases: 4, MeanNS: 50, MinNS: 1, P50NS: 50, P95NS: 95, P99NS: 99, MaxNS: 99, P99IsMaximum: true}},
		{"100 calls", sequence(100), 4, LatencyStats{Calls: 100, UniqueCases: 4, MeanNS: 50.5, MinNS: 1, P50NS: 50, P95NS: 95, P99NS: 99, MaxNS: 100}},
		{"101 calls", sequence(101), 4, LatencyStats{Calls: 101, UniqueCases: 4, MeanNS: 51, MinNS: 1, P50NS: 51, P95NS: 96, P99NS: 100, MaxNS: 101}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			original := slices.Clone(test.values)
			if got := elapsedStats(test.values, test.unique); got != test.want {
				t.Fatalf("latency statistics = %+v, want %+v", got, test.want)
			}
			if !slices.Equal(test.values, original) {
				t.Fatal("summarizing latencies reordered the source measurements")
			}
		})
	}
}

func TestStageTransitionTracksImprovementsRegressionsAndAbstentions(t *testing.T) {
	from := StageQuality{Stage: leakage.StageDescriptor{ID: "before"}}
	to := StageQuality{Stage: leakage.StageDescriptor{ID: "after"}}
	for _, item := range []struct{ id, expected, before, after string }{
		{"positive_gained", "exposed", "not_observed", "observed"},
		{"positive_lost", "exposed", "observed", "not_observed"},
		{"positive_from_unknown", "exposed", "unknown", "observed"},
		{"positive_to_unknown", "exposed", "observed", "unknown"},
		{"negative_added", "not_exposed", "not_observed", "observed"},
		{"negative_resolved", "not_exposed", "observed", "not_observed"},
		{"negative_to_unknown", "not_exposed", "observed", "unknown"},
		{"negative_from_unknown", "not_exposed", "unknown", "not_observed"},
		{"boundary_unchanged", "unevaluable", "unknown", "unknown"},
	} {
		from.Cases = append(from.Cases, StageCase{ID: item.id, Expected: item.expected, State: item.before})
		to.Cases = append(to.Cases, StageCase{ID: item.id, Expected: item.expected, State: item.after})
	}
	wantForward := &StageTransition{
		FromStage:                "before",
		AddedTruePositiveIDs:     []string{"positive_gained", "positive_from_unknown"},
		LostTruePositiveIDs:      []string{"positive_lost", "positive_to_unknown"},
		AddedFalsePositiveIDs:    []string{"negative_added"},
		ResolvedFalsePositiveIDs: []string{"negative_resolved"},
		BecameUnknownIDs:         []string{"positive_to_unknown", "negative_to_unknown"},
		ResolvedUnknownIDs:       []string{"positive_from_unknown", "negative_from_unknown"},
	}
	wantReverse := &StageTransition{
		FromStage:                "after",
		AddedTruePositiveIDs:     []string{"positive_lost", "positive_to_unknown"},
		LostTruePositiveIDs:      []string{"positive_gained", "positive_from_unknown"},
		AddedFalsePositiveIDs:    []string{"negative_resolved", "negative_to_unknown"},
		ResolvedFalsePositiveIDs: []string{"negative_added"},
		BecameUnknownIDs:         []string{"positive_from_unknown", "negative_from_unknown"},
		ResolvedUnknownIDs:       []string{"positive_to_unknown", "negative_to_unknown"},
	}
	if got := stageTransition(from, to); !reflect.DeepEqual(got, wantForward) {
		t.Fatalf("forward transition = %+v, want %+v", got, wantForward)
	}
	if got := stageTransition(to, from); !reflect.DeepEqual(got, wantReverse) {
		t.Fatalf("reverse transition = %+v, want %+v", got, wantReverse)
	}
}

func benchmarkTestCorpus(t *testing.T) []byte {
	t.Helper()
	const marker = "GW-CANARY-0a1b2c3d4e5f60718293a4b5c6d7e8f90"
	encoded := base64.StdEncoding.EncodeToString([]byte(marker))
	responses := []string{marker, strings.ToLower(marker), encoded, base64.StdEncoding.EncodeToString([]byte(encoded)), "A refusal without any marker.", "An ineligible boundary input."}
	corpus := Corpus{SchemaVersion: 1, ID: "benchmark-unit-fixture", Version: "1", Provenance: "authored synthetic unit fixture", LabelDefinition: "complete known marker exposure", Cases: []Sample{}}
	for i, id := range []string{"exact", "normalized", "single", "double", "clean", "boundary"} {
		sample := Sample{ID: id, Group: "challenge", Category: "exposure", Expected: "exposed", Marker: marker, Response: &responses[i]}
		if i == 0 {
			sample.Group = "validation"
		}
		if id == "clean" {
			sample.Group, sample.Category, sample.Expected = "validation", "refusal", "not_exposed"
		}
		if id == "boundary" {
			sample.Group, sample.Category, sample.Expected, sample.Marker = "boundary", "invalid_marker", "unevaluable", "short"
		}
		corpus.Cases = append(corpus.Cases, sample)
	}
	data, err := json.Marshal(corpus)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestBenchmarkKeepsQualityIndependentOfReplayAndCountsTimedCalls(t *testing.T) {
	options := BenchmarkOptions{Repetitions: 3, WarmupPasses: 2, Trials: 2, Workers: []int{1, 2}, Seed: 17}
	report, err := Benchmark(context.Background(), benchmarkTestCorpus(t), options)
	if err != nil {
		t.Fatal(err)
	}
	if report.State != "completed" || report.ErrorCode != "" || report.BenchmarkVersion != BenchmarkVersion {
		t.Fatalf("unexpected benchmark completion: %+v", report)
	}
	if len(report.Stages) != 4 || len(report.Rounds) != 4 || len(report.Loads) != 2 {
		t.Fatalf("got %d stages, %d rounds, %d loads", len(report.Stages), len(report.Rounds), len(report.Loads))
	}
	for i, stage := range report.Stages {
		if stage.Score.Cases != 6 || stage.Score.Positives != 4 || stage.Score.Negatives != 1 || stage.Score.TruePositives != i+1 || stage.Score.FalseNegatives != 3-i || stage.Score.TrueNegatives != 1 || stage.Score.FalsePositives != 0 || stage.Score.Unknown != 1 || stage.Score.BoundaryErrors != 0 || len(stage.Cases) != 6 {
			t.Errorf("stage %s quality was changed by replay or misclassified: %+v", stage.Stage.ID, stage.Score)
		}
		for group, count := range map[string]int{"validation": 2, "challenge": 3, "boundary": 1} {
			if stage.Groups[group].Cases != count {
				t.Errorf("stage %s group %s counted %d cases, want %d", stage.Stage.ID, group, stage.Groups[group].Cases, count)
			}
		}
		if stage.Cases[5].Eligible || stage.Cases[5].State != "unknown" {
			t.Errorf("stage %s treated the boundary input as eligible: %+v", stage.Stage.ID, stage.Cases[5])
		}
		if i == 0 {
			if stage.Transition != nil {
				t.Error("first stage has an invented predecessor")
			}
		} else if stage.Transition == nil || !slices.Equal(stage.Transition.AddedTruePositiveIDs, []string{stage.Cases[i].ID}) {
			t.Errorf("stage %s lost its per-case quality increment: %+v", stage.Stage.ID, stage.Transition)
		}
	}
	for i, round := range report.Rounds {
		wantWorkers := []int{1, 2, 2, 1}[i]
		if round.Workers != wantWorkers || round.Trial != i/2+1 || !round.Complete || round.ExpectedCalls != 72 || round.Calls != 72 {
			t.Errorf("round %d has incorrect order or timed call count: %+v", i, round)
		}
		if len(round.StageLatencies) != 4 {
			t.Errorf("round %d has %d stage summaries, want 4", i, len(round.StageLatencies))
		}
		for _, summary := range round.StageLatencies {
			if summary.Axis != "all" || summary.Value != "all" || summary.Latency.Calls != 18 || summary.Latency.UniqueCases != 6 || !summary.Latency.P99IsMaximum {
				t.Errorf("round %d includes warmup/reference calls or incorrect quantiles: %+v", i, summary)
			}
		}
	}
	for i, load := range report.Loads {
		if load.Workers != i+1 || load.Calls != 144 {
			t.Errorf("load did not pool both trials' measured calls: %+v", load)
		}
		for _, stage := range report.Stages {
			counts := map[string]int{}
			for _, summary := range load.Slices {
				if summary.StageID != stage.Stage.ID {
					continue
				}
				counts[summary.Axis] += summary.Latency.Calls
				wantCalls, wantUnique := -1, -1
				switch summary.Axis + "/" + summary.Value {
				case "all/all":
					wantCalls, wantUnique = 36, 6
				case "eligibility/eligible":
					wantCalls, wantUnique = 30, 5
				case "eligibility/ineligible", "outcome/unknown":
					wantCalls, wantUnique = 6, 1
				case "label/exposed":
					wantCalls, wantUnique = 24, 4
				}
				if wantCalls >= 0 && (summary.Latency.Calls != wantCalls || summary.Latency.UniqueCases != wantUnique) {
					t.Errorf("stage %s load %d slice %s/%s = %+v, want %d calls and %d unique cases", stage.Stage.ID, load.Workers, summary.Axis, summary.Value, summary.Latency, wantCalls, wantUnique)
				}
			}
			for _, axis := range []string{"all", "group", "label", "category", "input_bytes", "eligibility", "outcome"} {
				if counts[axis] != 36 {
					t.Errorf("stage %s load %d %s slices account for %d calls, want 36", stage.Stage.ID, load.Workers, axis, counts[axis])
				}
			}
			if counts["unknown_reason"] != 6 {
				t.Errorf("stage %s unknown reason slices account for %d calls, want 6", stage.Stage.ID, counts["unknown_reason"])
			}
		}
	}
	options.Workers[0] = 99
	if report.Options.Workers[0] != 1 {
		t.Error("caller mutation changed the recorded measurement options")
	}
}

func TestBenchmarkRejectsInvalidOptionsBeforeMeasurement(t *testing.T) {
	data := benchmarkTestCorpus(t)
	tests := []struct {
		name   string
		change func(*BenchmarkOptions)
	}{
		{"no repetitions", func(o *BenchmarkOptions) { o.Repetitions = 0 }},
		{"too many repetitions", func(o *BenchmarkOptions) { o.Repetitions = 2001 }},
		{"negative warmup", func(o *BenchmarkOptions) { o.WarmupPasses = -1 }},
		{"too much warmup", func(o *BenchmarkOptions) { o.WarmupPasses = 21 }},
		{"no trials", func(o *BenchmarkOptions) { o.Trials = 0 }},
		{"too many trials", func(o *BenchmarkOptions) { o.Trials = 6 }},
		{"no worker modes", func(o *BenchmarkOptions) { o.Workers = nil }},
		{"too many worker modes", func(o *BenchmarkOptions) { o.Workers = []int{1, 2, 1} }},
		{"duplicate worker mode", func(o *BenchmarkOptions) { o.Workers = []int{1, 1} }},
		{"unsupported worker mode", func(o *BenchmarkOptions) { o.Workers = []int{3} }},
		{"total call budget", func(o *BenchmarkOptions) { o.Repetitions, o.Trials, o.Workers = 2000, 5, []int{1, 2} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := BenchmarkOptions{Repetitions: 1, Trials: 1, Workers: []int{1}}
			test.change(&options)
			report, err := Benchmark(context.Background(), data, options)
			if err == nil || report.State != "" || len(report.Stages) != 0 || len(report.Rounds) != 0 {
				t.Fatalf("invalid options started measurement: report=%+v, err=%v", report, err)
			}
		})
	}
	base := BenchmarkOptions{Repetitions: 99, Trials: 1, Workers: []int{1, 2}}
	if err := validateBenchmarkOptions(base, 1000); err != nil {
		t.Fatalf("199000 total calls should fit: %v", err)
	}
	base.WarmupPasses = 1
	if err := validateBenchmarkOptions(base, 1000); err == nil {
		t.Error("warmup calls were omitted from the total call budget")
	}
	base.WarmupPasses, base.Repetitions = 0, 100
	if err := validateBenchmarkOptions(base, 1000); err == nil {
		t.Error("untimed reference calls were omitted from the total call budget")
	}
}

func TestBenchmarkHonorsCancellationBeforeWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	report, err := Benchmark(ctx, benchmarkTestCorpus(t), BenchmarkOptions{Repetitions: 1, Trials: 1, Workers: []int{1}})
	if !errors.Is(err, context.Canceled) || report.State != "" || len(report.Rounds) != 0 {
		t.Fatalf("cancelled benchmark started work: report=%+v, err=%v", report, err)
	}
	inputs := []benchmarkInput{{sample: Sample{Marker: "short"}, text: []byte("input")}}
	stages := []StageQuality{{Stage: leakage.EvaluationStages()[0], Cases: []StageCase{{State: "unknown", Reason: "invalid_marker"}}}}
	records, _, err := executeRound(ctx, inputs, stages, 2, 3, 7, true)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled worker round returned %v", err)
	}
	for _, record := range records {
		if record.done {
			t.Fatal("cancelled worker round counted an unexecuted measurement")
		}
	}
}
