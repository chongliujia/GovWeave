package compliance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var regionalPackCounts = map[string][2]int{
	"iso-42001-readiness":           {4, 2},
	"eu-ai-act-high-risk-readiness": {3, 2},
	"eu-ai-act-gpai":                {3, 2},
	"eu-gdpr-ai":                    {2, 4},
	"nist-genai-profile":            {3, 2},
	"us-ftc-ai-claims":              {2, 2},
}

func regionalFixture(t *testing.T, id string) (Pack, Input) {
	t.Helper()
	engine, err := Open("../../examples/rule-packs")
	if err != nil {
		t.Fatal(err)
	}
	pack, err := engine.PackSnapshot(id, "0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	input := Input{PackID: id, PackVersion: pack.Version, ProductID: "synthetic-regional", ProductVersion: "1.0.0", Facts: map[string]Fact{}}
	var fill func(Expression)
	fill = func(expression Expression) {
		if expression.Fact != "" {
			input.Facts[expression.Fact] = Fact{Value: json.RawMessage("true"), EvidenceID: "synthetic-not-a-real-assessment", Source: expression.Source, ObservedAt: evaluationTime.Add(-time.Hour).Format(time.RFC3339)}
		}
		for _, child := range expression.All {
			fill(child)
		}
	}
	for _, control := range pack.Controls {
		fill(control.Requirement)
		if control.AppliesWhen != nil {
			fill(*control.AppliesWhen)
		}
	}
	return pack, input
}

func TestRegionalPackEvidenceBoundaries(t *testing.T) {
	for id, expected := range regionalPackCounts {
		t.Run(id, func(t *testing.T) {
			for _, scenario := range []string{"missing", "available", "false", "stale", "expired", "future", "declared", "wrong-type", "outside-scope"} {
				t.Run(scenario, func(t *testing.T) {
					pack, input := regionalFixture(t, id)
					if pack.Controls[0].AssessmentMethod != "manual" || pack.Controls[0].AppliesWhen != nil {
						t.Fatal("scope review must be unconditional and manual")
					}
					if scenario == "missing" {
						input.Facts = map[string]Fact{}
					}
					for _, control := range pack.Controls {
						if control.Remediation == "" || control.Basis == "" {
							t.Fatal("control must explain basis and remediation")
						}
						if control.AssessmentMethod != "evidence" {
							continue
						}
						if control.Basis != "supporting_practice" || control.Requirement.MaxAgeSeconds != 2592000 {
							t.Fatal("evidence availability is bounded supporting practice")
						}
						entry, exists := input.Facts[control.Requirement.Fact]
						if !exists {
							continue
						}
						switch scenario {
						case "false":
							entry.Value = json.RawMessage("false")
						case "stale":
							entry.ObservedAt = evaluationTime.Add(-31 * 24 * time.Hour).Format(time.RFC3339)
						case "expired":
							entry.ExpiresAt = evaluationTime.Format(time.RFC3339)
						case "future":
							entry.ObservedAt = evaluationTime.Add(time.Hour).Format(time.RFC3339)
						case "declared":
							entry.Source = "declared"
						case "wrong-type":
							entry.Value = json.RawMessage(`"true"`)
						}
						input.Facts[control.Requirement.Fact] = entry
					}
					if scenario == "outside-scope" {
						for key, entry := range input.Facts {
							if len(key) > 6 && key[:6] == "scope." {
								entry.Value = json.RawMessage("false")
								input.Facts[key] = entry
							}
						}
					}
					result, err := EvaluateSnapshot(pack, input, evaluationTime)
					if err != nil {
						t.Fatal(err)
					}
					if !result.EvaluationOnly || result.LegalCompliance != "not_determined" || result.PackReview != "draft" {
						t.Fatal("draft became a legal conclusion")
					}
					counts := map[string]int{}
					for _, control := range result.Controls {
						counts[control.Status]++
						if control.AssessmentMethod == "manual" && control.Status != "unknown" && control.Status != "not_applicable" {
							t.Fatal("manual review passed automatically")
						}
					}
					wantStatus := "insufficient_evidence"
					switch scenario {
					case "available":
						if counts["pass"] != expected[0] || counts["unknown"] != expected[1] {
							t.Fatalf("unexpected coverage: %v", counts)
						}
					case "false":
						wantStatus = "gaps_detected"
						if counts["fail"] != expected[0] || counts["unknown"] != expected[1] {
							t.Fatalf("known gaps lost: %v", counts)
						}
					case "outside-scope":
						if counts["unknown"] != 1 || counts["not_applicable"] != expected[0]+expected[1]-1 {
							t.Fatalf("scope bypass: %v", counts)
						}
					default:
						if counts["unknown"] != expected[0]+expected[1] {
							t.Fatalf("untrusted evidence accepted: %v", counts)
						}
					}
					if result.Status != wantStatus {
						t.Fatalf("unexpected status: %s", result.Status)
					}
				})
			}
		})
	}
}

func TestRegionalConditionalScope(t *testing.T) {
	for _, spec := range []struct{ pack, fact, control string }{
		{"eu-ai-act-gpai", "scope.gpai_documentation_required", "GPAI-DOCS"},
		{"eu-gdpr-ai", "scope.gdpr_dpia_required", "GDPR-DPIA"},
		{"eu-gdpr-ai", "scope.gdpr_article22_relevant", "GDPR-ADM"},
	} {
		for _, supplied := range []bool{false, true} {
			pack, input := regionalFixture(t, spec.pack)
			if supplied {
				entry := input.Facts[spec.fact]
				entry.Value = json.RawMessage("false")
				input.Facts[spec.fact] = entry
			} else {
				delete(input.Facts, spec.fact)
			}
			result, err := EvaluateSnapshot(pack, input, evaluationTime)
			if err != nil {
				t.Fatal(err)
			}
			for _, control := range result.Controls {
				if control.ID == spec.control && ((supplied && control.Status != "not_applicable") || (!supplied && control.Status != "unknown")) {
					t.Fatalf("conditional routing %s: %+v", spec.fact, control)
				}
				if spec.pack == "eu-ai-act-gpai" && control.ID == "GPAI-COPYRIGHT" && control.Status != "pass" {
					t.Fatal("documentation exception incorrectly disabled copyright evidence")
				}
			}
		}
	}
}

func TestEUUSBundlePinsInstalledDefinitions(t *testing.T) {
	var bundle struct {
		Packs []struct{ File, ID, Version string }
	}
	data, err := os.ReadFile("../../examples/compliance-bundles/eu-us.json")
	if err != nil || json.Unmarshal(data, &bundle) != nil || len(bundle.Packs) != 8 {
		t.Fatal("invalid bundle", err)
	}
	directory := t.TempDir()
	for _, entry := range bundle.Packs {
		if filepath.Base(entry.File) != entry.File {
			t.Fatal("bundle path escapes pack directory")
		}
		data, err := os.ReadFile(filepath.Join("../../examples/rule-packs", entry.File))
		if err != nil {
			t.Fatal(err)
		}
		var pack Pack
		if json.Unmarshal(data, &pack) != nil || pack.ID != entry.ID || pack.Version != entry.Version {
			t.Fatal("unpinned pack")
		}
		if err := os.WriteFile(filepath.Join(directory, entry.File), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	engine, err := Open(directory)
	if err != nil || len(engine.Catalog()) != len(bundle.Packs) {
		t.Fatal("bundle cannot be installed", err)
	}
}
