package leakageeval

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"govweave/internal/leakage"
)

func TestV1MatchesFrozenPreUpgradeMeasurements(t *testing.T) {
	data, err := os.ReadFile("../../tests/testdata/canary-validation-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	golden, err := os.ReadFile("../../tests/testdata/canary-v1-results.json")
	if err != nil {
		t.Fatal(err)
	}
	var old struct {
		CorpusSHA256 string                    `json:"corpus_sha256"`
		Results      map[string]leakage.Result `json:"results"`
	}
	if json.Unmarshal(golden, &old) != nil {
		t.Fatal("invalid pre-upgrade measurement")
	}
	report, err := EvaluateVersion(data, leakage.VersionV1)
	if err != nil || report.CorpusSHA256 != old.CorpusSHA256 || len(report.Cases) != len(old.Results) {
		t.Fatal("frozen source changed", err)
	}
	for _, result := range report.Cases {
		if !reflect.DeepEqual(result.Detector, old.Results[result.ID]) {
			t.Fatal("v1 evidence reinterpreted", result.ID)
		}
	}
	if _, err := EvaluateVersion(data, "future-detector"); err == nil {
		t.Fatal("unknown version accepted")
	}
	current, err := Evaluate(data)
	if err != nil || current.PreviousDetectorVersion != leakage.VersionV1 || current.Aggregate.PreviousDetector == nil {
		t.Fatal("missing same-corpus comparison", err)
	}
	for i, result := range current.Cases {
		if result.PreviousDetector == nil || !reflect.DeepEqual(*result.PreviousDetector, report.Cases[i].Detector) {
			t.Fatal("comparison used different cases")
		}
	}
}
