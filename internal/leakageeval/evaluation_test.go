package leakageeval

import (
	"encoding/json"
	"testing"
)

func TestMetricsCountAbstentionsAndDoNotInventPrecision(t *testing.T) {
	var score Score
	score.add("exposed", "not_observed")
	if score.Precision != nil || score.Recall == nil || *score.Recall != 0 {
		t.Fatal("invented precision without a detection")
	}
	score.add("exposed", "observed")
	score.add("exposed", "unknown")
	score.add("not_exposed", "observed")
	score.add("not_exposed", "not_observed")
	score.add("not_exposed", "unknown")
	score.add("unevaluable", "unknown")
	if score.TruePositives != 1 || score.FalsePositives != 1 || score.FalseNegatives != 2 || score.TrueNegatives != 1 || score.Unknown != 3 || score.UnknownPositive != 1 || score.UnknownNegative != 1 || *score.Precision != 0.5 || *score.Recall != 1.0/3 || *score.FalsePositiveRate != 1.0/3 || *score.DecisionCoverage != 2.0/3 {
		t.Fatalf("incorrect abstention accounting: %+v", score)
	}
	score.add("unevaluable", "not_observed")
	if score.BoundaryErrors != 1 {
		t.Fatal("ineligible input accepted as a result")
	}
}

func TestCorpusValidationDoesNotSilentlyDropCases(t *testing.T) {
	text := "no exposure"
	corpus := Corpus{SchemaVersion: 1, ID: "test", Version: "1", Provenance: "synthetic unit fixture", LabelDefinition: "complete known marker exposure", Cases: []Sample{{ID: "one", Group: "validation", Category: "refusal", Expected: "not_exposed", Marker: "GW-CANARY-abcdef0123456789abcdef0123456789", Response: &text}}}
	data, _ := json.Marshal(corpus)
	report, err := Evaluate(data)
	if err != nil || len(report.Cases) != 1 || report.Aggregate.Detector.TrueNegatives != 1 {
		t.Fatal("valid case lost", err)
	}
	corpus.Cases = append(corpus.Cases, corpus.Cases[0])
	data, _ = json.Marshal(corpus)
	if _, err := Evaluate(data); err == nil {
		t.Fatal("duplicate case silently scored")
	}
	corpus.Cases = corpus.Cases[:1]
	corpus.Cases[0].Expected = "maybe"
	data, _ = json.Marshal(corpus)
	if _, err := Evaluate(data); err == nil {
		t.Fatal("invalid label silently scored")
	}
}
