package leakageeval

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/rand"
	"runtime"
	"runtime/debug"
	"slices"
	"sort"
	"sync"
	"time"

	"govweave/internal/leakage"
)

const BenchmarkVersion = "canary-cost-quality-v1"
const maxBenchmarkCalls = 200000

type BenchmarkOptions struct {
	Repetitions  int   `json:"repetitions_per_case_per_round"`
	WarmupPasses int   `json:"warmup_passes_per_round"`
	Trials       int   `json:"trials"`
	Workers      []int `json:"workers"`
	Seed         int64 `json:"seed"`
}

func DefaultBenchmarkOptions() BenchmarkOptions {
	return BenchmarkOptions{Repetitions: 30, WarmupPasses: 2, Trials: 2, Workers: []int{1, 2}, Seed: 20261028}
}

type BenchmarkEnvironment struct {
	GoVersion     string            `json:"go_version"`
	GOOS          string            `json:"goos"`
	GOARCH        string            `json:"goarch"`
	LogicalCPUs   int               `json:"logical_cpus"`
	GOMAXPROCS    int               `json:"gomaxprocs"`
	BuildSettings map[string]string `json:"build_settings"`
}

type StageCase struct {
	ID            string `json:"id"`
	Group         string `json:"group"`
	Category      string `json:"category"`
	Expected      string `json:"expected"`
	ResponseBytes int    `json:"response_bytes"`
	Eligible      bool   `json:"eligible"`
	State         string `json:"state"`
	Reason        string `json:"reason"`
}

type StageTransition struct {
	FromStage                string   `json:"from_stage"`
	AddedTruePositiveIDs     []string `json:"added_true_positive_ids"`
	LostTruePositiveIDs      []string `json:"lost_true_positive_ids"`
	AddedFalsePositiveIDs    []string `json:"added_false_positive_ids"`
	ResolvedFalsePositiveIDs []string `json:"resolved_false_positive_ids"`
	BecameUnknownIDs         []string `json:"became_unknown_ids"`
	ResolvedUnknownIDs       []string `json:"resolved_unknown_ids"`
}

type StageQuality struct {
	Stage      leakage.StageDescriptor `json:"stage"`
	Score      Score                   `json:"score"`
	Groups     map[string]Score        `json:"groups"`
	Cases      []StageCase             `json:"cases"`
	Transition *StageTransition        `json:"transition,omitempty"`
}

type LatencyStats struct {
	Calls        int     `json:"calls"`
	UniqueCases  int     `json:"unique_cases"`
	MeanNS       float64 `json:"mean_ns"`
	MinNS        int64   `json:"min_ns"`
	P50NS        int64   `json:"p50_ns"`
	P95NS        int64   `json:"p95_ns"`
	P99NS        int64   `json:"p99_ns"`
	MaxNS        int64   `json:"max_ns"`
	P99IsMaximum bool    `json:"p99_is_maximum"`
}

type LatencySlice struct {
	StageID string       `json:"stage_id"`
	Axis    string       `json:"axis"`
	Value   string       `json:"value"`
	Latency LatencyStats `json:"latency"`
}

type BenchmarkRound struct {
	Trial          int            `json:"trial"`
	Workers        int            `json:"workers"`
	Seed           int64          `json:"seed"`
	ExpectedCalls  int            `json:"expected_calls"`
	Calls          int            `json:"calls"`
	BatchElapsedNS int64          `json:"batch_elapsed_ns"`
	Complete       bool           `json:"complete"`
	StageLatencies []LatencySlice `json:"stage_latencies"`
}

type BenchmarkLoad struct {
	Workers               int            `json:"workers"`
	Calls                 int            `json:"calls"`
	BatchElapsedNS        int64          `json:"batch_elapsed_ns"`
	HarnessCallsPerSecond float64        `json:"harness_inclusive_calls_per_second"`
	Slices                []LatencySlice `json:"slices"`
}

type BenchmarkReport struct {
	SchemaVersion    int                  `json:"schema_version"`
	BenchmarkVersion string               `json:"benchmark_version"`
	ExecutableSHA256 string               `json:"executable_sha256,omitempty"`
	State            string               `json:"state"`
	ErrorCode        string               `json:"error_code,omitempty"`
	MeasuredAt       string               `json:"measured_at"`
	CorpusID         string               `json:"corpus_id"`
	CorpusVersion    string               `json:"corpus_version"`
	CorpusSHA256     string               `json:"corpus_sha256"`
	Provenance       string               `json:"provenance"`
	Options          BenchmarkOptions     `json:"options"`
	Environment      BenchmarkEnvironment `json:"environment"`
	Stages           []StageQuality       `json:"stages"`
	Rounds           []BenchmarkRound     `json:"rounds"`
	Loads            []BenchmarkLoad      `json:"loads"`
	Limitations      []string             `json:"limitations"`
}

type benchmarkInput struct {
	sample   Sample
	text     []byte
	eligible bool
}
type benchmarkPair struct{ sample, stage int }
type timedRecord struct {
	sample, stage int
	elapsed       int64
	done          bool
}

func benchmarkEnvironment() BenchmarkEnvironment {
	env := BenchmarkEnvironment{GoVersion: runtime.Version(), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, LogicalCPUs: runtime.NumCPU(), GOMAXPROCS: runtime.GOMAXPROCS(0), BuildSettings: map[string]string{}}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if slices.Contains([]string{"vcs.revision", "vcs.modified", "GOOS", "GOARCH", "CGO_ENABLED", "GOAMD64", "GOARM64", "-race"}, setting.Key) {
				env.BuildSettings[setting.Key] = setting.Value
			}
		}
	}
	return env
}

func validateBenchmarkOptions(options BenchmarkOptions, pairs int) error {
	if options.Repetitions < 1 || options.Repetitions > 2000 || options.WarmupPasses < 0 || options.WarmupPasses > 20 || options.Trials < 1 || options.Trials > 5 || len(options.Workers) < 1 || len(options.Workers) > 2 {
		return errors.New("invalid benchmark repetitions, warmup, trials or worker modes")
	}
	seen := map[int]bool{}
	for _, workers := range options.Workers {
		if (workers != 1 && workers != 2) || seen[workers] {
			return errors.New("benchmark workers must be distinct modes selected from 1 and 2")
		}
		seen[workers] = true
	}
	if int64(pairs)+int64(pairs)*int64(options.Repetitions+options.WarmupPasses)*int64(options.Trials)*int64(len(options.Workers)) > maxBenchmarkCalls {
		return errors.New("benchmark exceeds the 200000-call budget including warmup and reference calls")
	}
	return nil
}

func stageTransition(from, to StageQuality) *StageTransition {
	delta := &StageTransition{FromStage: from.Stage.ID, AddedTruePositiveIDs: []string{}, LostTruePositiveIDs: []string{}, AddedFalsePositiveIDs: []string{}, ResolvedFalsePositiveIDs: []string{}, BecameUnknownIDs: []string{}, ResolvedUnknownIDs: []string{}}
	for i, current := range to.Cases {
		old := from.Cases[i]
		if current.Expected == "exposed" {
			if old.State != "observed" && current.State == "observed" {
				delta.AddedTruePositiveIDs = append(delta.AddedTruePositiveIDs, current.ID)
			}
			if old.State == "observed" && current.State != "observed" {
				delta.LostTruePositiveIDs = append(delta.LostTruePositiveIDs, current.ID)
			}
		}
		if current.Expected == "not_exposed" {
			if old.State != "observed" && current.State == "observed" {
				delta.AddedFalsePositiveIDs = append(delta.AddedFalsePositiveIDs, current.ID)
			}
			if old.State == "observed" && current.State == "not_observed" {
				delta.ResolvedFalsePositiveIDs = append(delta.ResolvedFalsePositiveIDs, current.ID)
			}
		}
		if old.State != "unknown" && current.State == "unknown" {
			delta.BecameUnknownIDs = append(delta.BecameUnknownIDs, current.ID)
		}
		if old.State == "unknown" && current.State != "unknown" {
			delta.ResolvedUnknownIDs = append(delta.ResolvedUnknownIDs, current.ID)
		}
	}
	return delta
}

func elapsedStats(values []int64, unique int) LatencyStats {
	if len(values) == 0 {
		return LatencyStats{}
	}
	data := slices.Clone(values)
	slices.Sort(data)
	var total float64
	for _, value := range data {
		total += float64(value)
	}
	quantile := func(p int) int64 { return data[(p*len(data)+99)/100-1] }
	return LatencyStats{Calls: len(data), UniqueCases: unique, MeanNS: total / float64(len(data)), MinNS: data[0], P50NS: quantile(50), P95NS: quantile(95), P99NS: quantile(99), MaxNS: data[len(data)-1], P99IsMaximum: (99*len(data)+99)/100 == len(data)}
}

func sizeBucket(size int) string {
	switch {
	case size < 256:
		return "0-255"
	case size < 1024:
		return "256-1023"
	case size < 4096:
		return "1024-4095"
	case size <= 8192:
		return "4096-8192"
	default:
		return "over-8192"
	}
}

func summarizeLatencies(records []timedRecord, inputs []benchmarkInput, stages []StageQuality, allSlices bool) []LatencySlice {
	type key struct {
		stage       int
		axis, value string
	}
	type aggregate struct {
		values []int64
		cases  map[int]bool
	}
	groups := map[key]*aggregate{}
	add := func(k key, record timedRecord) {
		a := groups[k]
		if a == nil {
			a = &aggregate{cases: map[int]bool{}}
			groups[k] = a
		}
		a.values = append(a.values, record.elapsed)
		a.cases[record.sample] = true
	}
	for _, record := range records {
		if !record.done {
			continue
		}
		add(key{record.stage, "all", "all"}, record)
		if !allSlices {
			continue
		}
		item := inputs[record.sample]
		outcome := stages[record.stage].Cases[record.sample]
		eligibility := "ineligible"
		if item.eligible {
			eligibility = "eligible"
		}
		for _, slice := range [][2]string{{"group", item.sample.Group}, {"label", item.sample.Expected}, {"category", item.sample.Category}, {"input_bytes", sizeBucket(len(item.text))}, {"eligibility", eligibility}, {"outcome", outcome.State}} {
			add(key{record.stage, slice[0], slice[1]}, record)
		}
		if outcome.State == "unknown" {
			add(key{record.stage, "unknown_reason", outcome.Reason}, record)
		}
	}
	keys := make([]key, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.stage != b.stage {
			return a.stage < b.stage
		}
		if a.axis != b.axis {
			return a.axis < b.axis
		}
		return a.value < b.value
	})
	result := []LatencySlice{}
	for _, k := range keys {
		a := groups[k]
		result = append(result, LatencySlice{StageID: stages[k.stage].Stage.ID, Axis: k.axis, Value: k.value, Latency: elapsedStats(a.values, len(a.cases))})
	}
	return result
}

// executeRound measures only the call made inside a worker, not queue wait.
// Batch wall time also includes driver dispatch, goroutine startup and checks.
func executeRound(parent context.Context, inputs []benchmarkInput, stages []StageQuality, workers, repetitions int, seed int64, timed bool) ([]timedRecord, int64, error) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	pairs := make([]benchmarkPair, 0, len(inputs)*len(stages))
	for sample := range inputs {
		for stage := range stages {
			pairs = append(pairs, benchmarkPair{sample, stage})
		}
	}
	records := make([]timedRecord, len(pairs)*repetitions)
	type work struct {
		pair  benchmarkPair
		index int
	}
	jobs := make(chan work, workers)
	var wg sync.WaitGroup
	var once sync.Once
	var executionErr error
	start := time.Now()
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				if ctx.Err() != nil {
					return
				}
				input := inputs[job.pair.sample]
				stage := stages[job.pair.stage]
				var result leakage.Result
				var err error
				var elapsed int64
				if timed {
					started := time.Now()
					result, err = leakage.DetectStage(stage.Stage.ID, input.sample.Marker, input.text)
					elapsed = time.Since(started).Nanoseconds()
				} else {
					result, err = leakage.DetectStage(stage.Stage.ID, input.sample.Marker, input.text)
				}
				reference := stage.Cases[job.pair.sample]
				if err != nil || result.Version != stage.Stage.Version || result.State != reference.State || result.Reason != reference.Reason {
					once.Do(func() { executionErr = errors.New("stage result changed during repeated measurement"); cancel() })
					return
				}
				records[job.index] = timedRecord{sample: job.pair.sample, stage: job.pair.stage, elapsed: elapsed, done: true}
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
	wg.Wait()
	elapsed := time.Since(start).Nanoseconds()
	if executionErr != nil {
		return records, elapsed, executionErr
	}
	if ctx.Err() != nil {
		return records, elapsed, ctx.Err()
	}
	return records, elapsed, nil
}

func Benchmark(ctx context.Context, data []byte, options BenchmarkOptions) (BenchmarkReport, error) {
	corpus, err := decodeCorpus(data)
	if err != nil {
		return BenchmarkReport{}, err
	}
	descriptors := leakage.EvaluationStages()
	if err := validateBenchmarkOptions(options, len(corpus.Cases)*len(descriptors)); err != nil {
		return BenchmarkReport{}, err
	}
	if err := ctx.Err(); err != nil {
		return BenchmarkReport{}, err
	}
	options.Workers = slices.Clone(options.Workers)
	digest := sha256.Sum256(data)
	report := BenchmarkReport{SchemaVersion: 1, BenchmarkVersion: BenchmarkVersion, State: "completed", MeasuredAt: time.Now().UTC().Format(time.RFC3339Nano), CorpusID: corpus.ID, CorpusVersion: corpus.Version, CorpusSHA256: hex.EncodeToString(digest[:]), Provenance: corpus.Provenance, Options: options, Environment: benchmarkEnvironment(), Stages: []StageQuality{}, Rounds: []BenchmarkRound{}, Loads: []BenchmarkLoad{}, Limitations: []string{
		"Local warm function-call replay, not a gateway, model, streaming, network or production realtime SLA measurement.",
		"Timing starts inside a worker immediately before DetectStage and stops on return. Input eligibility, detector work and result metadata are included; queue wait, parsing, corpus I/O, quality scoring and report serialization are excluded. Clock-read overhead is not subtracted; scheduling and GC during the call are included.",
		"Quality counts each authored case once. Repeated timings do not create new independent quality observations; both corpora have already been used in development.",
		"Warmup and one untimed reference call per case/stage precede measurement. Sample/stage pairs are shuffled each pass with recorded seeds; worker-mode order alternates by trial. CPU affinity, background load and power state are uncontrolled.",
		"Nearest-rank empirical quantiles use ceil(p*n)-1. P99 can equal the maximum on a small slice; no population confidence interval is implied. Pooled quantiles combine calls, not averages of per-round quantiles.",
		"Batch calls/sec includes driver dispatch, worker startup and post-call consistency checks. It mixes all stages, is closed-loop, excludes warmup and cannot be interpreted as model throughput or service capacity.",
		"Stages are standalone evaluations, not a validated production cascade. Single/two-layer share v2 transforms and budgets and differ only in depth; no monotonic quality or routing guarantee is assumed.",
		"Overall timings weight this corpus equally per case, including fast ineligible inputs. Read eligible, label, size, category, outcome and unknown-reason slices before extrapolating.",
	}}
	inputs := make([]benchmarkInput, len(corpus.Cases))
	for i, sample := range corpus.Cases {
		text := []byte(*sample.Response)
		inputs[i] = benchmarkInput{sample: sample, text: text, eligible: leakage.InputProblem(sample.Marker, text) == ""}
	}
	for _, descriptor := range descriptors {
		stage := StageQuality{Stage: descriptor, Groups: map[string]Score{}, Cases: []StageCase{}}
		for _, input := range inputs {
			if err := ctx.Err(); err != nil {
				return BenchmarkReport{}, err
			}
			result, err := leakage.DetectStage(descriptor.ID, input.sample.Marker, input.text)
			if err != nil {
				return BenchmarkReport{}, err
			}
			stage.Score.add(input.sample.Expected, result.State)
			group := stage.Groups[input.sample.Group]
			group.add(input.sample.Expected, result.State)
			stage.Groups[input.sample.Group] = group
			stage.Cases = append(stage.Cases, StageCase{input.sample.ID, input.sample.Group, input.sample.Category, input.sample.Expected, len(input.text), input.eligible, result.State, result.Reason})
		}
		if len(report.Stages) > 0 {
			stage.Transition = stageTransition(report.Stages[len(report.Stages)-1], stage)
		}
		report.Stages = append(report.Stages, stage)
	}
	allRecords := map[int][]timedRecord{}
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
				if _, _, err = executeRound(ctx, inputs, report.Stages, workers, options.WarmupPasses, seed-1, false); err != nil {
					break rounds
				}
			}
			var records []timedRecord
			var elapsed int64
			records, elapsed, err = executeRound(ctx, inputs, report.Stages, workers, options.Repetitions, seed, true)
			completed := []timedRecord{}
			for _, record := range records {
				if record.done {
					completed = append(completed, record)
				}
			}
			expected := len(inputs) * len(descriptors) * options.Repetitions
			report.Rounds = append(report.Rounds, BenchmarkRound{trial + 1, workers, seed, expected, len(completed), elapsed, err == nil && len(completed) == expected, summarizeLatencies(completed, inputs, report.Stages, false)})
			allRecords[workers] = append(allRecords[workers], completed...)
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
		wall := wallTimes[workers]
		rate := 0.0
		if wall > 0 {
			rate = float64(len(records)) * 1e9 / float64(wall)
		}
		report.Loads = append(report.Loads, BenchmarkLoad{workers, len(records), wall, rate, summarizeLatencies(records, inputs, report.Stages, true)})
	}
	if err != nil {
		report.State, report.ErrorCode = "incomplete", "benchmark_cancelled_or_inconsistent"
	}
	return report, err
}
