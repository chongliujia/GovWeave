package sensitiveeval

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"govweave/internal/sensitive"
)

func sample(id, text string, categories ...string) Sample {
	if categories == nil {
		categories = []string{}
	}
	return Sample{ID: id, Text: &text, ExpectedCategories: categories, Group: "test", Notes: "unit fixture"}
}

func encoded(t *testing.T, samples ...Sample) []byte {
	t.Helper()
	data, err := json.Marshal(Corpus{SchemaVersion: 1, ID: "test", Description: "unit fixture", Cases: samples})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestUnknownAccountingDoesNotBecomeNegativeEvidence(t *testing.T) {
	s := Score{}
	s.add("found", true, "observed")
	s.add("unknown-positive", true, "unknown")
	s.add("missed", true, "not_observed")
	s.add("false-positive", false, "observed")
	s.add("negative", false, "not_observed")
	s.add("unknown-negative", false, "unknown")
	if s.Cases != 6 || s.TruePositives != 1 || s.FalsePositives != 1 || s.FalseNegatives != 2 || s.TrueNegatives != 1 ||
		s.Unknown != 2 || s.UnknownPositive != 1 || s.UnknownNegative != 1 {
		t.Fatalf("unknown cases were incorrectly scored: %+v", s)
	}
	if *s.Precision != .5 || *s.Recall != 1.0/3 || *s.DecisionCoverage != 4.0/6 || *s.FalsePositiveRate != 1.0/3 {
		t.Fatal("incorrect metric denominators")
	}
	var negatives Score
	negatives.add("only-negative", false, "not_observed")
	if negatives.Precision != nil || negatives.Recall != nil {
		t.Fatal("undefined ratio reported as zero")
	}
}

func TestCategoryScoringCountsQualityOnceAndOmitsRawText(t *testing.T) {
	first := sample("positive", "PRIVATE-SYNTHETIC-INPUT", "credential")
	second := sample("negative", "A CLEAN UNIT FIXTURE")
	invalid := sample("oversized", strings.Repeat("x", sensitive.MaxBytes+1))
	invalid.Invalid = true
	calls := 0
	detector := func(data []byte) sensitive.Result {
		calls++
		result := sensitive.Result{DetectorVersion: sensitive.Version, State: "not_observed", Reason: "patterns_not_observed", InputBytes: len(data), Findings: []sensitive.Finding{}}
		if string(data) == *first.Text {
			result.State, result.Reason = "observed", "patterns_observed"
			result.Findings = []sensitive.Finding{{Category: "credential", RuleID: "api_key", StartByte: 0, EndByte: 3}}
		}
		if len(data) > sensitive.MaxBytes {
			result.State, result.Reason = "unknown", "input_limit"
		}
		return result
	}
	report, err := evaluate(context.Background(), encoded(t, first, second, invalid), Options{Repetitions: 3, Warmups: 2}, detector)
	if err != nil {
		t.Fatal(err)
	}
	if report.State != "complete" || report.ScoredValidCases != 2 || report.InvalidCases != 1 || report.BoundaryErrors != 0 ||
		report.TotalCalls != 18 || calls != 18 || report.Timing.CompletedCalls != 9 || report.Timing.P99NS == nil {
		t.Fatal("quality and repeated timing mixed", report.TotalCalls, calls)
	}
	if report.Categories["credential"].TruePositives != 1 || report.Categories["credential"].Cases != 2 || report.Categories["email"].TrueNegatives != 2 {
		t.Fatal("incorrect category presence scoring")
	}
	data, _ := json.Marshal(report)
	for _, private := range []string{*first.Text, *second.Text, first.Notes} {
		if strings.Contains(string(data), private) {
			t.Fatal("raw sample text or notes retained in report")
		}
	}
}

func TestPartialFindingUnknownNeverGetsPartialQualityCredit(t *testing.T) {
	f := sample("partial", "email-and-credential-fixture", "credential", "email")
	detector := func(data []byte) sensitive.Result {
		return sensitive.Result{DetectorVersion: sensitive.Version, State: "unknown", Reason: "finding_limit", InputBytes: len(data), Truncated: true,
			Findings: []sensitive.Finding{{Category: "email", RuleID: "email_address", StartByte: 0, EndByte: 5}}}
	}
	report, err := evaluate(context.Background(), encoded(t, f), Options{Repetitions: 1}, detector)
	if err != nil {
		t.Fatal(err)
	}
	if report.Categories["email"].FalseNegatives != 1 || report.Categories["email"].TruePositives != 0 ||
		report.Categories["credential"].UnknownPositive != 1 || report.Categories["phone"].UnknownNegative != 1 ||
		report.Categories["phone"].TrueNegatives != 0 {
		t.Fatal("partial or unknown output overclaimed detection coverage")
	}
}

func TestBoundsAndCorpusEligibilityAreEnforced(t *testing.T) {
	invalid := sample("invalid", strings.Repeat("x", sensitive.MaxBytes+1))
	cases := [][]byte{
		encoded(t, invalid),
		encoded(t, sample("duplicate", ""), sample("duplicate", "")),
		encoded(t, sample("bad-category", "", "unknown")),
		encoded(t, sample("duplicate-category", "", "email", "email")),
		append(encoded(t, sample("valid", "")), []byte("{}")...),
		[]byte(strings.Repeat(" ", MaxCorpusBytes+1)),
	}
	for _, data := range cases {
		if _, err := Decode(data); err == nil {
			t.Fatal("invalid corpus accepted")
		}
	}
	data := encoded(t, sample("valid", "clean"))
	for _, options := range []Options{{Repetitions: 0}, {Repetitions: 1001}, {Repetitions: 1, Warmups: 11}, {Repetitions: 1, Warmups: -1}} {
		if _, err := Evaluate(context.Background(), data, options); err == nil {
			t.Fatal("unbounded options accepted")
		}
	}
	many := make([]Sample, 256)
	for i := range many {
		id := "case-" + string(rune('a'+i/26)) + string(rune('a'+i%26))
		many[i] = sample(id, "clean")
	}
	if _, err := Evaluate(context.Background(), encoded(t, many...), Options{Repetitions: 400}); err == nil {
		t.Fatal("aggregate call budget ignored")
	}
}

func TestCancellationKeepsClearlyIncompleteReport(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	report, err := Evaluate(ctx, encoded(t, sample("cancelled", "clean")), Options{Repetitions: 1})
	if err == nil || report.State != "incomplete" || report.ErrorCode != "measurement_cancelled" || report.TotalCalls != 0 || len(report.Cases) != 0 {
		t.Fatal("cancelled quality run presented a complete report")
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	detector := func(data []byte) sensitive.Result {
		calls++
		if calls == 3 {
			cancel()
		}
		return sensitive.Result{DetectorVersion: sensitive.Version, State: "not_observed", Reason: "patterns_not_observed", InputBytes: len(data), Findings: []sensitive.Finding{}}
	}
	report, err = evaluate(ctx, encoded(t, sample("cancelled", "clean")), Options{Repetitions: 5}, detector)
	if err == nil || report.State != "incomplete" || report.TotalCalls != 3 || report.Timing.CompletedCalls != 2 || report.Timing.P99NS == nil {
		t.Fatal("partial timing progress lost or overclaimed")
	}
}

func TestRepeatedDetectorDriftMarksReportIncomplete(t *testing.T) {
	calls := 0
	detector := func(data []byte) sensitive.Result {
		calls++
		result := sensitive.Result{DetectorVersion: sensitive.Version, State: "not_observed", Reason: "patterns_not_observed", InputBytes: len(data)}
		if calls > 1 {
			result.State, result.Reason = "unknown", "finding_limit"
		}
		return result
	}
	report, err := evaluate(context.Background(), encoded(t, sample("drift", "clean")), Options{Repetitions: 3}, detector)
	if err == nil || report.State != "incomplete" || report.ErrorCode != "inconsistent_detector_result" || report.TotalCalls != 2 || report.Timing.CompletedCalls != 0 {
		t.Fatal("detector drift silently included in latency evidence")
	}
}

func TestPercentilesAndFrozenCorpusIdentity(t *testing.T) {
	values := make([]int64, 100)
	for i := range values {
		values[i] = int64(i + 1)
	}
	if *percentile(values, 50) != 50 || *percentile(values, 95) != 95 || *percentile(values, 99) != 99 || percentile(nil, 99) != nil {
		t.Fatal("incorrect nearest-rank percentile")
	}
	data, err := os.ReadFile("../../tests/testdata/sensitive-validation-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != "f1f5cdd4cb2dcc782cb9b1479b2884ed4f5c55728f98a100eedf972c95963b71" {
		t.Fatal("frozen baseline changed")
	}
	corpus, err := Decode(data)
	if err != nil || len(corpus.Cases) != 80 {
		t.Fatal("frozen baseline is invalid", err)
	}
}

func TestExplicitDetectorVersionIsRecordedAndChangesOnlySelectedGeneration(t *testing.T) {
	data := encoded(t, sample("obfuscated", "separate [at] example [dot] net", "email"))
	for _, version := range []string{sensitive.Version, sensitive.Version2} {
		report, err := Evaluate(context.Background(), data, Options{DetectorVersion: version, Repetitions: 1})
		if err != nil || report.DetectorVersion != version {
			t.Fatal("wrong measured generation", err)
		}
		want := 0
		if version == sensitive.Version2 {
			want = 1
		}
		if report.Categories["email"].TruePositives != want {
			t.Fatal("generation ignored")
		}
	}
	if report, err := Evaluate(context.Background(), data, Options{DetectorVersion: "unknown", Repetitions: 1}); err == nil || report.SchemaVersion != 0 {
		t.Fatal("unknown generation measured")
	}
	frozen, err := os.ReadFile("../../tests/testdata/sensitive-validation-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(frozen)
	if hex.EncodeToString(sum[:]) != "a81027500c2793291288b514a7f0357fc4ebcd17a070f34b451c55c4003c3a48" {
		t.Fatal("new frozen corpus changed")
	}
}
