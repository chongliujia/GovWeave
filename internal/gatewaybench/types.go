// Package gatewaybench runs isolated, synthetic HTTP load experiments. It is
// development tooling and is not linked into the production gateway command.
package gatewaybench

import (
	"errors"
	"math"
	"math/rand"
	"slices"
)

type Options struct {
	Requests    int      `json:"requests_per_cell"`
	Warmup      int      `json:"warmup_per_cell"`
	Rounds      int      `json:"rounds"`
	Concurrency []int    `json:"concurrency"`
	Sizes       []int    `json:"output_text_bytes"`
	Protocols   []string `json:"protocols"`
	DelayMS     int      `json:"provider_delay_ms"`
	GoMaxProcs  int      `json:"gateway_gomaxprocs"`
	Seed        int64    `json:"seed"`
	Profile     string   `json:"profile,omitempty"`
}

func (o Options) Validate() error {
	if o.Profile != "" && (!slices.Contains([]string{"cpu", "contention", "trace", "allocs"}, o.Profile) || len(o.Concurrency)*len(o.Sizes)*len(o.Protocols)*o.Rounds*4 > 8) {
		return errors.New("diagnostic profiling requires cpu, contention, trace or allocs and at most 8 cells")
	}
	if o.Requests < 1 || o.Requests > 512 || o.Warmup < 1 || o.Warmup > 64 || o.Rounds < 1 || o.Rounds > 5 || o.DelayMS < 0 || o.DelayMS > 100 || o.GoMaxProcs < 1 || o.GoMaxProcs > 128 || len(o.Concurrency) == 0 || len(o.Concurrency) > 64 || len(o.Sizes) == 0 || len(o.Sizes) > 64 || len(o.Protocols) == 0 || len(o.Protocols) > 2 || len(o.Concurrency)*len(o.Sizes)*len(o.Protocols)*o.Rounds*4 > 256 {
		return errors.New("invalid or excessive benchmark matrix")
	}
	for i, n := range o.Concurrency {
		if n < 1 || n > 128 || slices.Contains(o.Concurrency[:i], n) {
			return errors.New("concurrency must contain distinct values from 1 to 128")
		}
	}
	for i, n := range o.Sizes {
		if n < 128 || n > 32768 || slices.Contains(o.Sizes[:i], n) {
			return errors.New("output sizes must contain distinct values from 128 to 32768")
		}
	}
	for i, p := range o.Protocols {
		if !slices.Contains([]string{"json", "sse"}, p) || slices.Contains(o.Protocols[:i], p) {
			return errors.New("protocols must be distinct json or sse values")
		}
	}
	return nil
}

type Cell struct {
	Round       int    `json:"round"`
	Concurrency int    `json:"concurrency"`
	OutputBytes int    `json:"output_text_bytes"`
	Protocol    string `json:"protocol"`
	Mode        string `json:"mode"`
}

func Plan(o Options) []Cell {
	rng := rand.New(rand.NewSource(o.Seed))
	result := []Cell{}
	for round := 1; round <= o.Rounds; round++ {
		blocks := []Cell{}
		for _, protocol := range o.Protocols {
			for _, size := range o.Sizes {
				for _, concurrency := range o.Concurrency {
					blocks = append(blocks, Cell{round, concurrency, size, protocol, ""})
				}
			}
		}
		rng.Shuffle(len(blocks), func(i, j int) { blocks[i], blocks[j] = blocks[j], blocks[i] })
		for _, block := range blocks {
			modes := []string{"direct", "disabled", "metadata", "full"}
			rng.Shuffle(len(modes), func(i, j int) { modes[i], modes[j] = modes[j], modes[i] })
			for _, mode := range modes {
				cell := block
				cell.Mode = mode
				result = append(result, cell)
			}
		}
	}
	return result
}

type Sample struct {
	Index       int     `json:"index"`
	Status      int     `json:"http_status"`
	ElapsedMS   float64 `json:"elapsed_ms"`
	FirstBodyMS float64 `json:"first_body_byte_ms"`
	Bytes       int     `json:"response_bytes"`
	Error       string  `json:"error,omitempty"`
}

type Distribution struct {
	Count    int     `json:"count"`
	MinMS    float64 `json:"min_ms"`
	MeanMS   float64 `json:"mean_ms"`
	P50MS    float64 `json:"p50_ms"`
	P95MS    float64 `json:"p95_ms"`
	P99MS    float64 `json:"p99_ms"`
	MaxMS    float64 `json:"max_ms"`
	P99IsMax bool    `json:"p99_is_max_rank"`
}

func distribution(values []float64) *Distribution {
	if len(values) == 0 {
		return nil
	}
	v := slices.Clone(values)
	slices.Sort(v)
	sum := 0.0
	for _, n := range v {
		sum += n
	}
	q := func(p float64) float64 { return v[int(math.Ceil(p*float64(len(v))))-1] }
	return &Distribution{len(v), v[0], sum / float64(len(v)), q(.5), q(.95), q(.99), v[len(v)-1], int(math.Ceil(.99*float64(len(v)))) == len(v)}
}

type Verification struct {
	ExpectedCalls      int   `json:"expected_calls_including_warmup"`
	StartedAuditCalls  int   `json:"started_audit_calls"`
	FinishedAuditCalls int   `json:"finished_audit_calls"`
	SuccessfulAudits   int   `json:"successful_audits"`
	EvidenceFiles      int   `json:"evidence_files"`
	VerifiedCaptures   int   `json:"verified_captures"`
	AuditBytes         int64 `json:"audit_file_bytes"`
	EvidenceBytes      int64 `json:"sealed_evidence_bytes"`
	Passed             bool  `json:"passed"`
}

type Result struct {
	Cell
	Profiles             []ProfileArtifact `json:"profiles,omitempty"`
	Samples              []Sample          `json:"samples"`
	Succeeded            int               `json:"succeeded"`
	Failed               int               `json:"failed"`
	Errors               map[string]int    `json:"errors"`
	WarmupFailed         int               `json:"warmup_failed"`
	ElapsedMS            float64           `json:"client_batch_elapsed_ms"`
	SucceededPerSec      float64           `json:"client_successes_per_second"`
	AllLatency           *Distribution     `json:"all_attempt_latency"`
	SuccessLatency       *Distribution     `json:"success_latency"`
	FirstBodyLatency     *Distribution     `json:"success_first_body_latency"`
	ProviderCalls        int64             `json:"provider_calls_including_warmup"`
	ProviderInvalid      int64             `json:"provider_invalid_requests"`
	ProviderCountMatches bool              `json:"provider_count_matches"`
	Resources            *ResourceWindow   `json:"gateway_resources"`
	Verification         *Verification     `json:"durability_verification"`
	DrainMS              float64           `json:"gateway_drain_ms"`
	DurableWindowMS      float64           `json:"client_start_to_drained_ack_ms"`
	DurablePerSec        float64           `json:"verified_successes_per_durable_second"`
}

type Comparison struct {
	GatewayIndex int      `json:"gateway_result_index"`
	DirectIndex  int      `json:"direct_result_index"`
	Comparable   bool     `json:"comparable"`
	P50DeltaMS   *float64 `json:"completion_p50_difference_ms"`
	P95DeltaMS   *float64 `json:"completion_p95_difference_ms"`
	P99DeltaMS   *float64 `json:"completion_p99_difference_ms"`
	FirstP95MS   *float64 `json:"first_body_p95_difference_ms"`
}

func comparable(r Result) bool {
	return len(r.Samples) > 0 && r.SuccessLatency != nil && r.FirstBodyLatency != nil && r.Failed == 0 && r.WarmupFailed == 0 && r.ProviderInvalid == 0 && r.ProviderCountMatches &&
		(r.Mode == "direct" || r.Resources != nil && r.Verification != nil && r.Verification.Passed)
}

func comparisons(results []Result) []Comparison {
	answer := []Comparison{}
	for i, r := range results {
		if r.Mode == "direct" {
			continue
		}
		for j, direct := range results {
			if direct.Mode != "direct" || direct.Round != r.Round || direct.Concurrency != r.Concurrency || direct.OutputBytes != r.OutputBytes || direct.Protocol != r.Protocol {
				continue
			}
			c := Comparison{GatewayIndex: i, DirectIndex: j, Comparable: comparable(r) && comparable(direct) && len(r.Profiles) == 0}
			if c.Comparable {
				delta := func(a, b float64) *float64 { v := a - b; return &v }
				c.P50DeltaMS, c.P95DeltaMS, c.P99DeltaMS = delta(r.SuccessLatency.P50MS, direct.SuccessLatency.P50MS), delta(r.SuccessLatency.P95MS, direct.SuccessLatency.P95MS), delta(r.SuccessLatency.P99MS, direct.SuccessLatency.P99MS)
				c.FirstP95MS = delta(r.FirstBodyLatency.P95MS, direct.FirstBodyLatency.P95MS)
			}
			answer = append(answer, c)
			break
		}
	}
	return answer
}
