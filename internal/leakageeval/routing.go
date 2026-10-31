package leakageeval

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/rand"
	"reflect"
	"slices"
	"sort"
	"sync"
	"time"

	"govweave/internal/detection"
	"govweave/internal/detectionroute"
	"govweave/internal/leakage"
)

const RoutingBenchmarkVersion = "canary-routing-cost-quality-v1"

type RoutingCase struct {
	ID            string                `json:"id"`
	Group         string                `json:"group"`
	Category      string                `json:"category"`
	Expected      string                `json:"expected"`
	ResponseBytes int                   `json:"response_bytes"`
	Eligible      bool                  `json:"eligible"`
	Result        detectionroute.Result `json:"result"`
}

type RoutingComparison struct {
	ReferencePolicy                  string         `json:"reference_policy"`
	StateTransitions                 map[string]int `json:"state_transitions"`
	ReferenceObservedLostIDs         []string       `json:"reference_observed_lost_ids"`
	ReferenceObservedLostExposedIDs  []string       `json:"reference_observed_lost_exposed_ids"`
	ReferenceObservedLostNegativeIDs []string       `json:"reference_observed_lost_negative_ids"`
	AddedFalseNegativeIDs            []string       `json:"added_false_negative_ids"`
	AddedFalsePositiveIDs            []string       `json:"added_false_positive_ids"`
	AddedTruePositiveIDs             []string       `json:"added_true_positive_ids"`
	ResolvedFalsePositiveIDs         []string       `json:"resolved_false_positive_ids"`
	BecameUnknownIDs                 []string       `json:"became_unknown_ids"`
	ResolvedUnknownIDs               []string       `json:"resolved_unknown_ids"`
	UnknownToNotObservedIDs          []string       `json:"unknown_to_not_observed_ids"`
}

type RoutingQuality struct {
	Policy          detectionroute.Policy `json:"policy"`
	Score           Score                 `json:"score"`
	Groups          map[string]Score      `json:"groups"`
	Cases           []RoutingCase         `json:"cases"`
	Comparison      *RoutingComparison    `json:"comparison,omitempty"`
	FastRequests    int                   `json:"fast_requests"`
	DeepRequests    int                   `json:"deep_requests"`
	FastEvaluations int                   `json:"fast_evaluations"`
	DeepEvaluations int                   `json:"deep_evaluations"`
	Routes          map[string]int        `json:"routes"`
}

// RoutingCounts accounts only for completed, consistent measured calls. Failed
// or cancelled calls are separately counted in DiscardedCalls. Untimed quality
// and warmup invocations are excluded from both sets of measured counts.
type RoutingCounts struct {
	PipelineCalls    int `json:"pipeline_calls"`
	RegistryRequests int `json:"registry_requests"`
	FastRequests     int `json:"fast_requests"`
	DeepRequests     int `json:"deep_requests"`
	FastEvaluations  int `json:"fast_evaluations"`
	DeepEvaluations  int `json:"deep_evaluations"`
}

type RoutingLatencySlice struct {
	PolicyID string       `json:"policy_id"`
	Axis     string       `json:"axis"`
	Value    string       `json:"value"`
	Latency  LatencyStats `json:"latency"`
}

type RoutingRound struct {
	Trial                 int   `json:"trial"`
	Workers               int   `json:"workers"`
	Seed                  int64 `json:"seed"`
	ExpectedPipelineCalls int   `json:"expected_pipeline_calls"`
	RoutingCounts
	DiscardedCalls RoutingCounts         `json:"discarded_calls"`
	BatchElapsedNS int64                 `json:"batch_elapsed_ns"`
	Complete       bool                  `json:"complete"`
	Slices         []RoutingLatencySlice `json:"slices"`
}

type RoutingLoad struct {
	Workers int `json:"workers"`
	RoutingCounts
	DiscardedCalls            RoutingCounts         `json:"discarded_calls"`
	BatchElapsedNS            int64                 `json:"batch_elapsed_ns"`
	HarnessPipelinesPerSecond float64               `json:"harness_inclusive_pipelines_per_second"`
	Slices                    []RoutingLatencySlice `json:"slices"`
}

type RoutingReport struct {
	SchemaVersion    int                     `json:"schema_version"`
	BenchmarkVersion string                  `json:"benchmark_version"`
	ExecutableSHA256 string                  `json:"executable_sha256,omitempty"`
	State            string                  `json:"state"`
	ErrorCode        string                  `json:"error_code,omitempty"`
	MeasuredAt       string                  `json:"measured_at"`
	CorpusID         string                  `json:"corpus_id"`
	CorpusVersion    string                  `json:"corpus_version"`
	CorpusSHA256     string                  `json:"corpus_sha256"`
	Provenance       string                  `json:"provenance"`
	Manifest         detectionroute.Manifest `json:"manifest"`
	ManifestSHA256   string                  `json:"manifest_sha256"`
	Options          BenchmarkOptions        `json:"options"`
	Environment      BenchmarkEnvironment    `json:"environment"`
	Policies         []RoutingQuality        `json:"policies"`
	Rounds           []RoutingRound          `json:"rounds"`
	Loads            []RoutingLoad           `json:"loads"`
	Limitations      []string                `json:"limitations"`
}

type routingInput struct {
	sample   Sample
	input    detection.Input
	eligible bool
}

type routingPair struct{ sample, policy int }
type routingRecord struct {
	sample, policy int
	elapsed        int64
	attempted      bool
	done           bool
	counts         RoutingCounts
}

func routingCounts(result detectionroute.Result) RoutingCounts {
	counts := RoutingCounts{PipelineCalls: 1, RegistryRequests: len(result.Steps)}
	for _, step := range result.Steps {
		switch step.Detector.ID {
		case "normalized":
			counts.FastRequests++
			if step.Evaluated {
				counts.FastEvaluations++
			}
		case "two_layer":
			counts.DeepRequests++
			if step.Evaluated {
				counts.DeepEvaluations++
			}
		}
	}
	return counts
}

func (counts *RoutingCounts) add(other RoutingCounts) {
	counts.PipelineCalls += other.PipelineCalls
	counts.RegistryRequests += other.RegistryRequests
	counts.FastRequests += other.FastRequests
	counts.DeepRequests += other.DeepRequests
	counts.FastEvaluations += other.FastEvaluations
	counts.DeepEvaluations += other.DeepEvaluations
}

func compareRouting(reference, candidate RoutingQuality) *RoutingComparison {
	comparison := &RoutingComparison{ReferencePolicy: reference.Policy.ID, StateTransitions: map[string]int{}, ReferenceObservedLostIDs: []string{}, ReferenceObservedLostExposedIDs: []string{}, ReferenceObservedLostNegativeIDs: []string{}, AddedFalseNegativeIDs: []string{}, AddedFalsePositiveIDs: []string{}, AddedTruePositiveIDs: []string{}, ResolvedFalsePositiveIDs: []string{}, BecameUnknownIDs: []string{}, ResolvedUnknownIDs: []string{}, UnknownToNotObservedIDs: []string{}}
	for _, before := range []string{detection.Observed, detection.NotObserved, detection.Unknown} {
		for _, after := range []string{detection.Observed, detection.NotObserved, detection.Unknown} {
			comparison.StateTransitions[before+"_to_"+after] = 0
		}
	}
	for i, item := range candidate.Cases {
		before, after := reference.Cases[i].Result.State, item.Result.State
		comparison.StateTransitions[before+"_to_"+after]++
		if before == detection.Observed && after != detection.Observed {
			comparison.ReferenceObservedLostIDs = append(comparison.ReferenceObservedLostIDs, item.ID)
			if item.Expected == "exposed" {
				comparison.ReferenceObservedLostExposedIDs = append(comparison.ReferenceObservedLostExposedIDs, item.ID)
				comparison.AddedFalseNegativeIDs = append(comparison.AddedFalseNegativeIDs, item.ID)
			} else if item.Expected == "not_exposed" {
				comparison.ReferenceObservedLostNegativeIDs = append(comparison.ReferenceObservedLostNegativeIDs, item.ID)
			}
		}
		if before != detection.Observed && after == detection.Observed {
			if item.Expected == "exposed" {
				comparison.AddedTruePositiveIDs = append(comparison.AddedTruePositiveIDs, item.ID)
			} else if item.Expected == "not_exposed" {
				comparison.AddedFalsePositiveIDs = append(comparison.AddedFalsePositiveIDs, item.ID)
			}
		}
		if before == detection.Observed && after == detection.NotObserved && item.Expected == "not_exposed" {
			comparison.ResolvedFalsePositiveIDs = append(comparison.ResolvedFalsePositiveIDs, item.ID)
		}
		if before != detection.Unknown && after == detection.Unknown {
			comparison.BecameUnknownIDs = append(comparison.BecameUnknownIDs, item.ID)
		}
		if before == detection.Unknown && after != detection.Unknown {
			comparison.ResolvedUnknownIDs = append(comparison.ResolvedUnknownIDs, item.ID)
		}
		if before == detection.Unknown && after == detection.NotObserved {
			comparison.UnknownToNotObservedIDs = append(comparison.UnknownToNotObservedIDs, item.ID)
		}
	}
	return comparison
}

func equalRoutingResult(left, right detectionroute.Result) bool {
	left.Steps, right.Steps = slices.Clone(left.Steps), slices.Clone(right.Steps)
	for i := range left.Steps {
		left.Steps[i].ElapsedNS = 0
	}
	for i := range right.Steps {
		right.Steps[i].ElapsedNS = 0
	}
	return reflect.DeepEqual(left, right)
}

func routingLatencies(records []routingRecord, inputs []routingInput, policies []RoutingQuality, allSlices bool) []RoutingLatencySlice {
	type key struct {
		policy      int
		axis, value string
	}
	type aggregate struct {
		values []int64
		cases  map[int]bool
	}
	groups := map[key]*aggregate{}
	add := func(k key, record routingRecord) {
		group := groups[k]
		if group == nil {
			group = &aggregate{cases: map[int]bool{}}
			groups[k] = group
		}
		group.values = append(group.values, record.elapsed)
		group.cases[record.sample] = true
	}
	for _, record := range records {
		if !record.done {
			continue
		}
		add(key{record.policy, "all", "all"}, record)
		if !allSlices {
			continue
		}
		input, outcome := inputs[record.sample], policies[record.policy].Cases[record.sample].Result
		eligibility := "ineligible"
		if input.eligible {
			eligibility = "eligible"
		}
		for _, slice := range [][2]string{{"group", input.sample.Group}, {"label", input.sample.Expected}, {"category", input.sample.Category}, {"input_bytes", sizeBucket(len(input.input.Content))}, {"eligibility", eligibility}, {"outcome", outcome.State}, {"route", outcome.Route}, {"gate_reason", outcome.GateReason}} {
			add(key{record.policy, slice[0], slice[1]}, record)
		}
		if outcome.State == detection.Unknown {
			add(key{record.policy, "unknown_reason", outcome.Reason}, record)
		}
	}
	keys := make([]key, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.policy != b.policy {
			return a.policy < b.policy
		}
		if a.axis != b.axis {
			return a.axis < b.axis
		}
		return a.value < b.value
	})
	result := []RoutingLatencySlice{}
	for _, k := range keys {
		group := groups[k]
		result = append(result, RoutingLatencySlice{PolicyID: policies[k.policy].Policy.ID, Axis: k.axis, Value: k.value, Latency: elapsedStats(group.values, len(group.cases))})
	}
	return result
}

func routingRecordCounts(records []routingRecord) (completed, discarded RoutingCounts) {
	for _, record := range records {
		if record.done {
			completed.add(record.counts)
		} else if record.attempted {
			discarded.add(record.counts)
		}
	}
	return completed, discarded
}

func executeRoutingRound(parent context.Context, engine *detectionroute.Engine, inputs []routingInput, policies []RoutingQuality, workers, repetitions int, seed int64, timed bool) ([]routingRecord, int64, error) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	pairs := make([]routingPair, 0, len(inputs)*len(policies))
	for sample := range inputs {
		for policy := range policies {
			pairs = append(pairs, routingPair{sample, policy})
		}
	}
	records := make([]routingRecord, len(pairs)*repetitions)
	type work struct {
		pair  routingPair
		index int
	}
	jobs := make(chan work, workers)
	var wait sync.WaitGroup
	var once sync.Once
	var executionErr error
	started := time.Now()
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for job := range jobs {
				if ctx.Err() != nil {
					return
				}
				input, policy := inputs[job.pair.sample], policies[job.pair.policy]
				var result detectionroute.Result
				var err error
				var elapsed int64
				if timed {
					start := time.Now()
					result, err = engine.Run(ctx, policy.Policy.ID, input.input)
					elapsed = time.Since(start).Nanoseconds()
				} else {
					result, err = engine.Run(ctx, policy.Policy.ID, input.input)
				}
				record := routingRecord{sample: job.pair.sample, policy: job.pair.policy, elapsed: elapsed, attempted: true, counts: routingCounts(result)}
				if err != nil || !equalRoutingResult(result, policy.Cases[job.pair.sample].Result) {
					records[job.index] = record
					once.Do(func() {
						if err != nil {
							executionErr = err
						} else {
							executionErr = errors.New("routing result changed during repeated measurement")
						}
						cancel()
					})
					return
				}
				record.done = true
				records[job.index] = record
			}
		}()
	}
	random := rand.New(rand.NewSource(seed))
	index := 0
dispatch:
	for pass := 0; pass < repetitions; pass++ {
		random.Shuffle(len(pairs), func(i, j int) { pairs[i], pairs[j] = pairs[j], pairs[i] })
		for _, pair := range pairs {
			select {
			case <-ctx.Done():
				break dispatch
			case jobs <- work{pair, index}:
				index++
			}
		}
	}
	close(jobs)
	wait.Wait()
	elapsed := time.Since(started).Nanoseconds()
	if executionErr != nil {
		return records, elapsed, executionErr
	}
	if err := ctx.Err(); err != nil {
		return records, elapsed, err
	}
	return records, elapsed, nil
}

func BenchmarkRouting(ctx context.Context, data []byte, options BenchmarkOptions) (RoutingReport, error) {
	corpus, err := decodeCorpus(data)
	if err != nil {
		return RoutingReport{}, err
	}
	manifest := detectionroute.FrozenManifest()
	// Every pipeline may request two detectors. This deliberately conservative
	// budget also includes reference scoring and all untimed warmup calls.
	if err := validateBenchmarkOptions(options, len(corpus.Cases)*len(manifest.Policies)*2); err != nil {
		return RoutingReport{}, err
	}
	if err := ctx.Err(); err != nil {
		return RoutingReport{}, err
	}
	registry, err := detection.CanaryRegistry()
	if err != nil {
		return RoutingReport{}, err
	}
	engine, err := detectionroute.New(registry)
	if err != nil {
		return RoutingReport{}, err
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return RoutingReport{}, err
	}
	manifestDigest, corpusDigest := sha256.Sum256(manifestJSON), sha256.Sum256(data)
	options.Workers = slices.Clone(options.Workers)
	report := RoutingReport{SchemaVersion: 1, BenchmarkVersion: RoutingBenchmarkVersion, State: "completed", MeasuredAt: time.Now().UTC().Format(time.RFC3339Nano), CorpusID: corpus.ID, CorpusVersion: corpus.Version, CorpusSHA256: hex.EncodeToString(corpusDigest[:]), Provenance: corpus.Provenance, Manifest: manifest, ManifestSHA256: hex.EncodeToString(manifestDigest[:]), Options: options, Environment: benchmarkEnvironment(), Policies: []RoutingQuality{}, Rounds: []RoutingRound{}, Loads: []RoutingLoad{}, Limitations: []string{
		"Frozen offline routing experiments for known synthetic marker exposure only; no semantic classifier, model call, business-response blocker or legal conclusion.",
		"Authored labels score quality once per case/policy. Full-depth reference agreement is separately reported and is not ground truth; losing a reference false positive is not an added labelled false negative.",
		"A gated skip returns unknown/deep_stage_skipped, never a full-depth negative. Read unknown-positive/negative counts and decision coverage together with false-positive rate and recall.",
		"Pipeline timing starts inside a worker before Run and stops on return; it includes registry checks, hashing/copying, fast/gate/deep work and evidence validation, with timer overhead, scheduling and GC. Queue wait, I/O, quality scoring and post-call consistency checks are excluded.",
		"Untimed quality and per-round warmup precede timed shuffled replay. Mode order alternates per trial. CPU affinity, background load and power state are uncontrolled; repeated fixed cases are correlated and do not increase quality sample size.",
		"Pooled nearest-rank empirical quantiles combine successful individual calls, not round quantiles. Small slices can have P99 equal to the maximum. No population confidence interval or production realtime SLA is inferred.",
		"Fixed one/two-worker closed-loop replay mixes policies. Batch throughput includes dispatch/startup/consistency checks; it is harness throughput, not model throughput or independent-arrival service capacity.",
		"Measured counts exclude untimed quality/warmup and distinguish registry requests from actual plugin evaluations. Failed/cancelled measured attempts are separately discarded and excluded from latency quantiles; incomplete reports must not be interpreted as invocation savings.",
		"Context cancellation is cooperative between bounded detector calls. Overall times equally weight this corpus, including fast ineligible inputs; inspect eligibility, size, category, label, route and unknown-reason slices.",
	}}
	inputs := make([]routingInput, len(corpus.Cases))
	for i, sample := range corpus.Cases {
		content := []byte(*sample.Response)
		inputs[i] = routingInput{sample: sample, input: detection.Input{Content: content, KnownMarker: sample.Marker}, eligible: leakage.InputProblem(sample.Marker, content) == ""}
	}
	for _, policy := range manifest.Policies {
		quality := RoutingQuality{Policy: policy, Groups: map[string]Score{}, Cases: []RoutingCase{}, Routes: map[string]int{}}
		for _, input := range inputs {
			if err := ctx.Err(); err != nil {
				return RoutingReport{}, err
			}
			result, err := engine.Run(ctx, policy.ID, input.input)
			if err != nil {
				return RoutingReport{}, err
			}
			counts := routingCounts(result)
			quality.FastRequests += counts.FastRequests
			quality.DeepRequests += counts.DeepRequests
			quality.FastEvaluations += counts.FastEvaluations
			quality.DeepEvaluations += counts.DeepEvaluations
			quality.Routes[result.Route]++
			quality.Score.add(input.sample.Expected, result.State)
			group := quality.Groups[input.sample.Group]
			group.add(input.sample.Expected, result.State)
			quality.Groups[input.sample.Group] = group
			quality.Cases = append(quality.Cases, RoutingCase{ID: input.sample.ID, Group: input.sample.Group, Category: input.sample.Category, Expected: input.sample.Expected, ResponseBytes: len(input.input.Content), Eligible: input.eligible, Result: result})
		}
		if policy.ID != detectionroute.Reference {
			quality.Comparison = compareRouting(report.Policies[0], quality)
		}
		report.Policies = append(report.Policies, quality)
	}
	allRecords := map[int][]routingRecord{}
	wallTimes := map[int]int64{}
rounds:
	for trial := 0; trial < options.Trials; trial++ {
		modes := slices.Clone(options.Workers)
		if trial%2 == 1 {
			slices.Reverse(modes)
		}
		for _, workers := range modes {
			seed := options.Seed + int64(trial)*1009 + int64(workers)*97
			if options.WarmupPasses > 0 {
				if _, _, err = executeRoutingRound(ctx, engine, inputs, report.Policies, workers, options.WarmupPasses, seed-1, false); err != nil {
					break rounds
				}
			}
			var records []routingRecord
			var elapsed int64
			records, elapsed, err = executeRoutingRound(ctx, engine, inputs, report.Policies, workers, options.Repetitions, seed, true)
			completed, discarded := routingRecordCounts(records)
			expected := len(inputs) * len(manifest.Policies) * options.Repetitions
			report.Rounds = append(report.Rounds, RoutingRound{Trial: trial + 1, Workers: workers, Seed: seed, ExpectedPipelineCalls: expected, RoutingCounts: completed, DiscardedCalls: discarded, BatchElapsedNS: elapsed, Complete: err == nil && completed.PipelineCalls == expected, Slices: routingLatencies(records, inputs, report.Policies, false)})
			allRecords[workers] = append(allRecords[workers], records...)
			wallTimes[workers] += elapsed
			if err != nil {
				break rounds
			}
		}
	}
	for _, workers := range options.Workers {
		records := allRecords[workers]
		if len(records) == 0 {
			continue
		}
		completed, discarded := routingRecordCounts(records)
		wall := wallTimes[workers]
		rate := 0.0
		if wall > 0 {
			rate = float64(completed.PipelineCalls) * 1e9 / float64(wall)
		}
		report.Loads = append(report.Loads, RoutingLoad{Workers: workers, RoutingCounts: completed, DiscardedCalls: discarded, BatchElapsedNS: wall, HarnessPipelinesPerSecond: rate, Slices: routingLatencies(records, inputs, report.Policies, true)})
	}
	if err != nil {
		report.State, report.ErrorCode = "incomplete", "routing_benchmark_cancelled_or_inconsistent"
	}
	return report, err
}
