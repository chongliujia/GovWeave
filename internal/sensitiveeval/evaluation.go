// Package sensitiveeval measures authored category labels independently of the
// detector. Text is supplied only to Detect; labels never control detection.
package sensitiveeval

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/rand"
	"regexp"
	"slices"
	"sort"
	"time"
	"unicode/utf8"

	"govweave/internal/config"
	"govweave/internal/sensitive"
)

const MaxCorpusBytes = 1 << 20
const MaxCalls = 100000

var categories = []string{"credential", "email", "phone"}
var identifier = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,99}$`)

type Sample struct {
	ID                 string   `json:"id"`
	Text               *string  `json:"text"`
	ExpectedCategories []string `json:"expected_categories"`
	Invalid            bool     `json:"invalid"`
	Group              string   `json:"group"`
	Notes              string   `json:"notes"`
}

type Corpus struct {
	SchemaVersion int      `json:"schema_version"`
	ID            string   `json:"id"`
	Description   string   `json:"description"`
	Cases         []Sample `json:"cases"`
}

type Options struct {
	DetectorVersion string `json:"detector_version,omitempty"`
	Repetitions     int    `json:"repetitions"`
	Warmups         int    `json:"warmups"`
	Seed            int64  `json:"seed"`
}

type Score struct {
	Cases             int      `json:"cases"`
	Positives         int      `json:"positives"`
	Negatives         int      `json:"negatives"`
	TruePositives     int      `json:"true_positives"`
	FalsePositives    int      `json:"false_positives"`
	FalseNegatives    int      `json:"false_negatives"`
	TrueNegatives     int      `json:"true_negatives"`
	Unknown           int      `json:"unknown"`
	UnknownPositive   int      `json:"unknown_positive"`
	UnknownNegative   int      `json:"unknown_negative"`
	Precision         *float64 `json:"precision"`
	Recall            *float64 `json:"recall"`
	FalsePositiveRate *float64 `json:"false_positive_rate"`
	DecisionCoverage  *float64 `json:"decision_coverage"`
	FalseNegativeIDs  []string `json:"false_negative_ids"`
	FalsePositiveIDs  []string `json:"false_positive_ids"`
	UnknownIDs        []string `json:"unknown_ids"`
}

type CaseResult struct {
	ID                 string   `json:"id"`
	Group              string   `json:"group"`
	Invalid            bool     `json:"invalid"`
	ExpectedCategories []string `json:"expected_categories"`
	DetectedCategories []string `json:"detected_categories"`
	State              string   `json:"state"`
	Reason             string   `json:"reason"`
	InputBytes         int      `json:"input_bytes"`
	Truncated          bool     `json:"truncated"`
}

type Timing struct {
	Scope          string `json:"scope"`
	Workers        int    `json:"workers"`
	CompletedCalls int    `json:"completed_calls"`
	ExpectedCalls  int    `json:"expected_calls"`
	P50NS          *int64 `json:"p50_ns"`
	P95NS          *int64 `json:"p95_ns"`
	P99NS          *int64 `json:"p99_ns"`
}

type Report struct {
	SchemaVersion    int              `json:"schema_version"`
	State            string           `json:"state"`
	ErrorCode        string           `json:"error_code,omitempty"`
	MeasuredAt       string           `json:"measured_at"`
	CorpusID         string           `json:"corpus_id"`
	CorpusSHA256     string           `json:"corpus_sha256"`
	DetectorVersion  string           `json:"detector_version"`
	Options          Options          `json:"options"`
	ExpectedCases    int              `json:"expected_cases"`
	ScoredValidCases int              `json:"scored_valid_cases"`
	InvalidCases     int              `json:"invalid_cases"`
	BoundaryErrors   int              `json:"boundary_errors"`
	Categories       map[string]Score `json:"categories"`
	Cases            []CaseResult     `json:"cases"`
	TotalCalls       int              `json:"total_calls"`
	Timing           Timing           `json:"timing"`
	Limitations      []string         `json:"limitations"`
}

func Decode(data []byte) (Corpus, error) {
	var corpus Corpus
	if len(data) > MaxCorpusBytes || !utf8.Valid(data) || config.DecodeStrict(bytes.NewReader(data), &corpus) != nil ||
		corpus.SchemaVersion != 1 || !identifier.MatchString(corpus.ID) || len(corpus.Description) > 2000 || len(corpus.Cases) < 1 || len(corpus.Cases) > 256 {
		return Corpus{}, errors.New("invalid or oversized sensitive corpus")
	}
	ids := map[string]bool{}
	for _, sample := range corpus.Cases {
		if !identifier.MatchString(sample.ID) || ids[sample.ID] || !identifier.MatchString(sample.Group) ||
			sample.Text == nil || !utf8.ValidString(*sample.Text) || len(*sample.Text) > 32768 || len(sample.Notes) > 2000 ||
			sample.ExpectedCategories == nil || len(sample.ExpectedCategories) > len(categories) {
			return Corpus{}, errors.New("invalid sensitive corpus case")
		}
		ids[sample.ID] = true
		seen := map[string]bool{}
		for _, category := range sample.ExpectedCategories {
			if !slices.Contains(categories, category) || seen[category] {
				return Corpus{}, errors.New("invalid or duplicate category label")
			}
			seen[category] = true
		}
		if sample.Invalid != (len(*sample.Text) > sensitive.MaxBytes) || (sample.Invalid && len(sample.ExpectedCategories) != 0) {
			return Corpus{}, errors.New("invalid input eligibility label")
		}
	}
	return corpus, nil
}

func fraction(numerator, denominator int) *float64 {
	if denominator == 0 {
		return nil
	}
	value := float64(numerator) / float64(denominator)
	return &value
}

func (s *Score) add(id string, positive bool, state string) {
	s.Cases++
	if state == "unknown" {
		s.Unknown++
		s.UnknownIDs = append(s.UnknownIDs, id)
	}
	if positive {
		s.Positives++
		if state == "observed" {
			s.TruePositives++
		} else {
			s.FalseNegatives++
			s.FalseNegativeIDs = append(s.FalseNegativeIDs, id)
		}
		if state == "unknown" {
			s.UnknownPositive++
		}
	} else {
		s.Negatives++
		switch state {
		case "observed":
			s.FalsePositives++
			s.FalsePositiveIDs = append(s.FalsePositiveIDs, id)
		case "not_observed":
			s.TrueNegatives++
		default:
			s.UnknownNegative++
		}
	}
	s.Precision = fraction(s.TruePositives, s.TruePositives+s.FalsePositives)
	s.Recall = fraction(s.TruePositives, s.Positives)
	s.FalsePositiveRate = fraction(s.FalsePositives, s.Negatives)
	s.DecisionCoverage = fraction(s.Cases-s.Unknown, s.Cases)
}

func percentile(values []int64, percent int) *int64 {
	if len(values) == 0 {
		return nil
	}
	value := values[(len(values)*percent+99)/100-1]
	return &value
}

func detectedCategories(result sensitive.Result) []string {
	found := []string{}
	for _, category := range categories {
		for _, finding := range result.Findings {
			if finding.Category == category {
				found = append(found, category)
				break
			}
		}
	}
	return found
}

func validResult(result sensitive.Result, input []byte, version string) bool {
	if result.DetectorVersion != version || !slices.Contains([]string{"observed", "not_observed", "unknown"}, result.State) ||
		!identifier.MatchString(result.Reason) || result.InputBytes != len(input) || len(result.Findings) > sensitive.MaxFindings {
		return false
	}
	if (result.State == "observed" && len(result.Findings) == 0) || (result.State == "not_observed" && len(result.Findings) != 0) {
		return false
	}
	for _, finding := range result.Findings {
		if !slices.Contains(categories, finding.Category) || !identifier.MatchString(finding.RuleID) ||
			finding.StartByte < 0 || finding.EndByte <= finding.StartByte || finding.EndByte > len(input) {
			return false
		}
	}
	return true
}

// Evaluate scores each unique case once, then separately measures warmed,
// shuffled single-worker calls. A partial report is retained on cancellation.
func Evaluate(ctx context.Context, data []byte, options Options) (Report, error) {
	version := options.DetectorVersion
	if version == "" {
		version = sensitive.Version
	}
	return evaluate(ctx, data, options, func(input []byte) sensitive.Result { return sensitive.Scan(input, version) })
}

func evaluate(ctx context.Context, data []byte, options Options, detect func([]byte) sensitive.Result) (Report, error) {
	version := options.DetectorVersion
	if version == "" {
		version = sensitive.Version
	}
	if !sensitive.Supports(version) {
		return Report{}, errors.New("unsupported detector version")
	}
	corpus, err := Decode(data)
	if err != nil {
		return Report{}, err
	}
	if ctx == nil || options.Repetitions < 1 || options.Repetitions > 1000 || options.Warmups < 0 || options.Warmups > 10 ||
		len(corpus.Cases)*(1+options.Warmups+options.Repetitions) > MaxCalls {
		return Report{}, errors.New("invalid measurement options or call budget")
	}
	digest := sha256.Sum256(data)
	report := Report{
		SchemaVersion: 1, State: "incomplete", MeasuredAt: time.Now().UTC().Format(time.RFC3339Nano),
		CorpusID: corpus.ID, CorpusSHA256: hex.EncodeToString(digest[:]), DetectorVersion: version,
		Options: options, ExpectedCases: len(corpus.Cases), Categories: map[string]Score{}, Cases: []CaseResult{},
		Timing: Timing{Scope: "local detector calls only; excludes HTTP, network, provider/model calls, audit synchronization and policy evaluation; includes invalid cases in corpus proportions", Workers: 1, ExpectedCalls: len(corpus.Cases) * options.Repetitions},
		Limitations: []string{
			"Authored synthetic development baseline; not external validation, production accuracy or a legal conclusion.",
			"Category-presence scoring, not span accuracy; finding-limit unknowns receive no partial detection credit.",
			"Unsupported positive forms remain labelled positive and contribute false negatives.",
			"Unknown positives count as false negatives; unknown negatives never count as true negatives. Invalid input cases are excluded from category denominators.",
			"Repeated timing calls do not increase quality sample size. Percentiles use nearest-rank and vary by machine and load.",
		},
	}
	for _, category := range categories {
		report.Categories[category] = Score{FalseNegativeIDs: []string{}, FalsePositiveIDs: []string{}, UnknownIDs: []string{}}
	}
	inputs := make([][]byte, len(corpus.Cases))
	order := make([]int, len(inputs))
	for i, sample := range corpus.Cases {
		inputs[i], order[i] = []byte(*sample.Text), i
	}
	cancelled := func() bool {
		if ctx.Err() != nil {
			report.ErrorCode = "measurement_cancelled"
			return true
		}
		return false
	}
	for i, sample := range corpus.Cases {
		if cancelled() {
			return report, ctx.Err()
		}
		result := detect(inputs[i])
		report.TotalCalls++
		if !validResult(result, inputs[i], version) {
			report.ErrorCode = "invalid_detector_result"
			return report, errors.New("invalid detector result")
		}
		found := detectedCategories(result)
		report.Cases = append(report.Cases, CaseResult{ID: sample.ID, Group: sample.Group, Invalid: sample.Invalid,
			ExpectedCategories: slices.Clone(sample.ExpectedCategories), DetectedCategories: found,
			State: result.State, Reason: result.Reason, InputBytes: len(inputs[i]), Truncated: result.Truncated})
		if sample.Invalid {
			report.InvalidCases++
			if result.State != "unknown" {
				report.BoundaryErrors++
			}
			continue
		}
		report.ScoredValidCases++
		for _, category := range categories {
			state := result.State
			if state != "unknown" {
				state = "not_observed"
				if slices.Contains(found, category) {
					state = "observed"
				}
			}
			score := report.Categories[category]
			score.add(sample.ID, slices.Contains(sample.ExpectedCategories, category), state)
			report.Categories[category] = score
		}
	}
	rng := rand.New(rand.NewSource(options.Seed))
	latencies := make([]int64, 0, report.Timing.ExpectedCalls)
	finishTiming := func() {
		sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
		report.Timing.P50NS = percentile(latencies, 50)
		report.Timing.P95NS = percentile(latencies, 95)
		report.Timing.P99NS = percentile(latencies, 99)
	}
	for repetition := -options.Warmups; repetition < options.Repetitions; repetition++ {
		rng.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
		for _, i := range order {
			if cancelled() {
				finishTiming()
				return report, ctx.Err()
			}
			start := time.Now()
			result := detect(inputs[i])
			elapsed := time.Since(start).Nanoseconds()
			report.TotalCalls++
			if !validResult(result, inputs[i], version) || result.State != report.Cases[i].State || result.Reason != report.Cases[i].Reason ||
				result.Truncated != report.Cases[i].Truncated || !slices.Equal(detectedCategories(result), report.Cases[i].DetectedCategories) {
				report.ErrorCode = "inconsistent_detector_result"
				finishTiming()
				return report, errors.New("detector results changed during repeated calls")
			}
			if repetition >= 0 {
				latencies = append(latencies, elapsed)
				report.Timing.CompletedCalls++
			}
		}
	}
	finishTiming()
	if cancelled() {
		return report, ctx.Err()
	}
	report.State = "complete"
	return report, nil
}
