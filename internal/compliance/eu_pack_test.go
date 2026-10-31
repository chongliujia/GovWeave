package compliance

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

func euPackFixture(t *testing.T) (Pack, Input) {
	t.Helper()
	data, err := os.ReadFile("../../examples/rule-packs/eu-ai-act-chatbot-transparency.json")
	if err != nil {
		t.Fatal(err)
	}
	var pack Pack
	if json.Unmarshal(data, &pack) != nil {
		t.Fatal("invalid EU pack fixture")
	}
	if err := ValidatePack(pack); err != nil {
		t.Fatal(err)
	}
	input := Input{PackID: pack.ID, PackVersion: pack.Version, ProductID: "eu-customer-support", ProductVersion: "1.0.0", Facts: map[string]Fact{}}
	add := func(key string, value any, source string) {
		data, _ := json.Marshal(value)
		input.Facts[key] = Fact{Value: data, EvidenceID: "synthetic-review-fixture", Source: source, ObservedAt: evaluationTime.Add(-time.Hour).Format(time.RFC3339Nano)}
	}
	for key, value := range map[string]any{"product.market": "eu", "product.operator_role": "provider", "product.use_case": "customer_support", "product.is_ai_system": true, "product.direct_interaction": true} {
		add(key, value, "declared")
	}
	for _, key := range []string{"transparency.notice_present", "transparency.notice_identifies_ai", "transparency.notice_at_first_interaction", "transparency.clarity_review_recorded", "transparency.accessibility_review_recorded", "assurance.ui_evidence_current"} {
		add(key, true, "assessment")
	}
	add("scope.article50_1_exception_claimed", false, "assessment")
	add("scope.review_document_present", true, "document")
	return pack, input
}

func TestEUPackNeverAutomatesManualOrWholeProductApproval(t *testing.T) {
	pack, input := euPackFixture(t)
	result, err := EvaluateSnapshot(pack, input, evaluationTime)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "insufficient_evidence" || result.LegalCompliance != "not_determined" || result.PackReview != "draft" || len(result.Controls) != 6 {
		t.Fatal("EU draft yielded a legal approval")
	}
	manual, passed := 0, 0
	for _, control := range result.Controls {
		if control.AssessmentMethod == "manual" {
			manual++
			if control.Status != "unknown" || control.Reason != "manual_review_required" {
				t.Fatal("manual judgment automatically passed")
			}
		}
		if control.Status == "pass" {
			passed++
		}
	}
	if manual != 3 || passed != 3 || len(result.Findings) != 3 {
		t.Fatal("incorrect narrow-pack coverage")
	}
	for _, finding := range result.Findings {
		if finding.Category != "manual_review" || finding.Action == "" {
			t.Fatal("manual review action missing")
		}
	}
}

func TestEUPackDistinguishesGapsMissingEvidenceAndExceptionReview(t *testing.T) {
	pack, input := euPackFixture(t)
	fact := input.Facts["transparency.notice_present"]
	fact.Value = json.RawMessage("false")
	input.Facts["transparency.notice_present"] = fact
	delete(input.Facts, "transparency.notice_at_first_interaction")
	result, err := EvaluateSnapshot(pack, input, evaluationTime)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "gaps_detected" {
		t.Fatal("known gap hidden by other unknown controls")
	}
	findings := map[string]Finding{}
	for _, finding := range result.Findings {
		findings[finding.ControlID] = finding
	}
	if findings["EU50-NOTICE"].Category != "control_gap" || findings["EU50-TIMING"].Category != "evidence_gap" || findings["EU50-SCOPE"].Category != "manual_review" {
		t.Fatal("finding categories conflated")
	}
	if result.Controls[5].Basis != "supporting_practice" || result.Controls[1].Basis != "legal_obligation" {
		t.Fatal("supporting practice became a statutory obligation")
	}
	fact = input.Facts["scope.article50_1_exception_claimed"]
	fact.Value = json.RawMessage("true")
	input.Facts["scope.article50_1_exception_claimed"] = fact
	result, err = EvaluateSnapshot(pack, input, evaluationTime)
	if err != nil {
		t.Fatal(err)
	}
	if result.Controls[0].Status != "unknown" || result.Status == "satisfied" {
		t.Fatal("exception claim was automatically approved")
	}
	for _, control := range result.Controls[1:] {
		if control.Status != "not_applicable" {
			t.Fatal("exception routing ignored")
		}
	}
	result, err = EvaluateSnapshot(pack, input, time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "not_applicable" || len(result.Findings) != 0 {
		t.Fatal("pack applied before its configured effective date")
	}
}

func TestPackSnapshotDoesNotExposeInstalledDefinition(t *testing.T) {
	engine, err := Open("../../examples/rule-packs")
	if err != nil {
		t.Fatal(err)
	}
	pack, err := engine.PackSnapshot("eu-ai-act-chatbot-transparency", "0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	pack.Controls[0].Title = "mutated"
	pack.Limitations[0] = "mutated"
	again, err := engine.PackSnapshot(pack.ID, pack.Version)
	if err != nil || again.Controls[0].Title == "mutated" || again.Limitations[0] == "mutated" {
		t.Fatal("installed definition mutated")
	}
}
