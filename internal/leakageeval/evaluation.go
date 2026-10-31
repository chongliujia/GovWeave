// Package leakageeval scores frozen labelled fixtures. Expected labels are
// consumed here only; the detector receives solely a marker and response bytes.
package leakageeval

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"time"

	"govweave/internal/config"
	"govweave/internal/leakage"
)

const MaxCorpusBytes = 1 << 20
const BaselineVersion = "literal-exact-v1"

type Sample struct {
	ID       string  `json:"id"`
	Group    string  `json:"group"`
	Category string  `json:"category"`
	Expected string  `json:"expected"`
	Marker   string  `json:"marker"`
	Response *string `json:"response"`
}

type Corpus struct {
	SchemaVersion   int      `json:"schema_version"`
	ID              string   `json:"id"`
	Version         string   `json:"version"`
	Provenance      string   `json:"provenance"`
	LabelDefinition string   `json:"label_definition"`
	Cases           []Sample `json:"cases"`
}

type Score struct {
	Cases             int      `json:"cases"`
	Positives         int      `json:"labelled_exposed"`
	Negatives         int      `json:"labelled_not_exposed"`
	TruePositives     int      `json:"true_positives"`
	FalsePositives    int      `json:"false_positives"`
	FalseNegatives    int      `json:"false_negatives"`
	TrueNegatives     int      `json:"true_negatives"`
	Unknown           int      `json:"unknown"`
	UnknownPositive   int      `json:"unknown_exposed"`
	UnknownNegative   int      `json:"unknown_not_exposed"`
	BoundaryErrors    int      `json:"boundary_errors"`
	Precision         *float64 `json:"precision"`
	Recall            *float64 `json:"recall"`
	FalsePositiveRate *float64 `json:"false_positive_rate"`
	DecisionCoverage  *float64 `json:"decision_coverage"`
}

type Comparison struct {
	Detector         Score  `json:"detector"`
	LiteralBaseline  Score  `json:"literal_baseline"`
	PreviousDetector *Score `json:"previous_detector,omitempty"`
}

type CaseResult struct {
	ID               string          `json:"id"`
	Group            string          `json:"group"`
	Category         string          `json:"category"`
	Expected         string          `json:"expected"`
	ResponseSHA256   string          `json:"response_sha256"`
	Detector         leakage.Result  `json:"detector"`
	LiteralBaseline  leakage.Result  `json:"literal_baseline"`
	PreviousDetector *leakage.Result `json:"previous_detector,omitempty"`
}

type Report struct {
	SchemaVersion           int                   `json:"schema_version"`
	MeasuredAt              string                `json:"measured_at"`
	CorpusID                string                `json:"corpus_id"`
	CorpusVersion           string                `json:"corpus_version"`
	CorpusSHA256            string                `json:"corpus_sha256"`
	Provenance              string                `json:"provenance"`
	DetectorVersion         string                `json:"detector_version"`
	BaselineVersion         string                `json:"baseline_version"`
	PreviousDetectorVersion string                `json:"previous_detector_version,omitempty"`
	Aggregate               Comparison            `json:"aggregate"`
	Groups                  map[string]Comparison `json:"groups"`
	Cases                   []CaseResult          `json:"cases"`
	FalseNegativeIDs        []string              `json:"false_negative_ids"`
	FalsePositiveIDs        []string              `json:"false_positive_ids"`
	UnknownIDs              []string              `json:"unknown_ids"`
	Limitations             []string              `json:"limitations"`
}

func fraction(numerator, denominator int) *float64 {
	if denominator == 0 {
		return nil
	}
	value := float64(numerator) / float64(denominator)
	return &value
}

func (s *Score) add(expected, state string) {
	s.Cases++
	if state == "unknown" {
		s.Unknown++
	}
	switch expected {
	case "exposed":
		s.Positives++
		if state == "observed" {
			s.TruePositives++
		} else {
			s.FalseNegatives++
		}
		if state == "unknown" {
			s.UnknownPositive++
		}
	case "not_exposed":
		s.Negatives++
		if state == "observed" {
			s.FalsePositives++
		} else if state == "not_observed" {
			s.TrueNegatives++
		} else {
			s.UnknownNegative++
		}
	case "unevaluable":
		if state != "unknown" {
			s.BoundaryErrors++
		}
	}
	s.Precision = fraction(s.TruePositives, s.TruePositives+s.FalsePositives)
	s.Recall = fraction(s.TruePositives, s.Positives)
	s.FalsePositiveRate = fraction(s.FalsePositives, s.Negatives)
	s.DecisionCoverage = fraction(s.Positives+s.Negatives-s.UnknownPositive-s.UnknownNegative, s.Positives+s.Negatives)
}

func baseline(marker string, text []byte) leakage.Result {
	result := leakage.Result{Version: BaselineVersion, State: "unknown", InputBytes: len(text), Matches: []leakage.Match{}}
	if problem := leakage.InputProblem(marker, text); problem != "" {
		result.Reason = problem
		return result
	}
	result.MarkerSHA256 = leakage.MarkerDigest(marker)
	result.ScannedBytes = len(text)
	if at := bytes.Index(text, []byte(marker)); at >= 0 {
		result.State, result.Reason = "observed", "full_marker_observed"
		result.Matches = []leakage.Match{{Representation: "exact", StartByte: at, EndByte: at + len(marker), SpanScope: "raw_fragment"}}
	} else {
		result.State, result.Reason = "not_observed", "full_marker_not_observed"
	}
	return result
}

func decodeCorpus(data []byte) (Corpus, error) {
	var corpus Corpus
	if len(data) > MaxCorpusBytes || config.DecodeStrict(bytes.NewReader(data), &corpus) != nil || corpus.SchemaVersion != 1 || len(corpus.ID) < 1 || len(corpus.ID) > 100 || len(corpus.Version) < 1 || len(corpus.Version) > 100 || len(corpus.Provenance) < 1 || len(corpus.Provenance) > 2000 || len(corpus.LabelDefinition) < 1 || len(corpus.LabelDefinition) > 2000 || len(corpus.Cases) < 1 || len(corpus.Cases) > 256 {
		return Corpus{}, errors.New("invalid or oversized labelled corpus")
	}
	seen := map[string]bool{}
	for _, sample := range corpus.Cases {
		if sample.ID == "" || len(sample.ID) > 100 || seen[sample.ID] || sample.Category == "" || len(sample.Category) > 100 || !slices.Contains([]string{"validation", "challenge", "boundary"}, sample.Group) || !slices.Contains([]string{"exposed", "not_exposed", "unevaluable"}, sample.Expected) || len(sample.Marker) > 512 || sample.Response == nil || len(*sample.Response) > 32768 {
			return Corpus{}, errors.New("invalid or duplicate labelled case")
		}
		seen[sample.ID] = true
	}
	return corpus, nil
}

func Evaluate(data []byte) (Report, error) {
	return EvaluateVersion(data, leakage.Version)
}

func EvaluateVersion(data []byte, version string) (Report, error) {
	if !leakage.SupportedVersion(version) {
		return Report{}, errors.New("unsupported canary detector version")
	}
	corpus, err := decodeCorpus(data)
	if err != nil {
		return Report{}, err
	}
	digest := sha256.Sum256(data)
	report := Report{SchemaVersion: 1, MeasuredAt: time.Now().UTC().Format(time.RFC3339Nano), CorpusID: corpus.ID, CorpusVersion: corpus.Version, CorpusSHA256: hex.EncodeToString(digest[:]), Provenance: corpus.Provenance, DetectorVersion: leakage.Version, BaselineVersion: BaselineVersion, Groups: map[string]Comparison{}, Cases: []CaseResult{}, FalseNegativeIDs: []string{}, FalsePositiveIDs: []string{}, UnknownIDs: []string{}, Limitations: []string{
		"Authored synthetic examples from the same development process, not independent third-party or blind validation; no real-model effectiveness claim.",
		"All challenge cases are included in aggregate metrics. Group names are coverage labels, not randomized train/test partitions.",
		"Recall counts an unknown positive as a miss. False-positive rate must be read together with decision coverage and unknown counts.",
		"Precision is undefined (null) when there are no detected positives. No population confidence interval is inferred from curated examples.",
		"The detector checks full known markers only, with documented normalization and single-layer decoding. Partial, semantic and other encoded leakage remain outside its reliable coverage.",
	}}
	report.DetectorVersion = version
	if version == leakage.Version {
		report.PreviousDetectorVersion = leakage.VersionV1
		report.Aggregate.PreviousDetector = &Score{}
	}
	report.Limitations[len(report.Limitations)-1] = "The detector checks complete known markers under the selected version's bounded transformations. Other, partial or semantic disclosures remain outside reliable coverage. Previous detector metrics, when present, use the identical corpus."
	for _, sample := range corpus.Cases {
		text := []byte(*sample.Response)
		result, _ := leakage.DetectVersion(version, sample.Marker, text)
		literal := baseline(sample.Marker, text)
		var previous *leakage.Result
		if report.PreviousDetectorVersion != "" {
			value, _ := leakage.DetectVersion(report.PreviousDetectorVersion, sample.Marker, text)
			previous = &value
			report.Aggregate.PreviousDetector.add(sample.Expected, value.State)
		}
		report.Aggregate.Detector.add(sample.Expected, result.State)
		report.Aggregate.LiteralBaseline.add(sample.Expected, literal.State)
		group := report.Groups[sample.Group]
		if previous != nil {
			if group.PreviousDetector == nil {
				group.PreviousDetector = &Score{}
			}
			group.PreviousDetector.add(sample.Expected, previous.State)
		}
		group.Detector.add(sample.Expected, result.State)
		group.LiteralBaseline.add(sample.Expected, literal.State)
		report.Groups[sample.Group] = group
		responseHash := sha256.Sum256(text)
		report.Cases = append(report.Cases, CaseResult{ID: sample.ID, Group: sample.Group, Category: sample.Category, Expected: sample.Expected, ResponseSHA256: hex.EncodeToString(responseHash[:]), Detector: result, LiteralBaseline: literal, PreviousDetector: previous})
		if sample.Expected == "exposed" && result.State != "observed" {
			report.FalseNegativeIDs = append(report.FalseNegativeIDs, sample.ID)
		}
		if sample.Expected == "not_exposed" && result.State == "observed" {
			report.FalsePositiveIDs = append(report.FalsePositiveIDs, sample.ID)
		}
		if result.State == "unknown" {
			report.UnknownIDs = append(report.UnknownIDs, sample.ID)
		}
	}
	return report, nil
}
