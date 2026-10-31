package governance

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"govweave/internal/gateway"
)

func outputAdapterFixture() (sources, Product) {
	s, p := adapterFixture()
	s.outputPolicy = gateway.OutputPolicySnapshot{SchemaVersion: 1, ID: "sensitive-output", OutputPolicyInput: gateway.OutputPolicyInput{DetectorVersion: "sensitive-text-v1", Revision: 7, Mode: "observe", Categories: []string{"email"}, ApplicationIDs: []string{"app-a"}}}
	return s, p
}

func TestOutputFactsScopedCoverageAndUnknownApplications(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		change     func(*sources, *Product)
	}{
		{"scoped known application", "true", func(*sources, *Product) {}},
		{"all application scope", "true", func(s *sources, _ *Product) { s.outputPolicy.ApplicationIDs = nil }},
		{"disabled policy", "false", func(s *sources, _ *Product) { s.outputPolicy.Mode = "disabled" }},
		{"outside scope", "false", func(s *sources, _ *Product) { s.outputPolicy.ApplicationIDs = []string{"other"} }},
		{"partial scope", "false", func(s *sources, p *Product) {
			s.resources.Applications = append(s.resources.Applications, gateway.Application{ID: "app-b"})
			p.ApplicationIDs = append(p.ApplicationIDs, "app-b")
		}},
		{"unknown application", "", func(s *sources, _ *Product) { s.resources.Applications = nil }},
		{"unknown additional application", "", func(_ *sources, p *Product) { p.ApplicationIDs = append(p.ApplicationIDs, "missing") }},
		{"no applications", "false", func(_ *sources, p *Product) { p.ApplicationIDs = nil }},
		{"revoked application configuration remains covered", "true", func(s *sources, _ *Product) { s.resources.Applications[0].Revoked = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, p := outputAdapterFixture()
			tc.change(&s, &p)
			facts := s.input(p, time.Now()).Facts
			fact, exists := facts["runtime.output_policy_covers_product"]
			if exists != (tc.want != "") || string(fact.Value) != tc.want {
				t.Fatalf("coverage %s (present %v), want %s", fact.Value, exists, tc.want)
			}
			if tc.name == "revoked application configuration remains covered" && string(facts["runtime.applications_active"].Value) != "false" {
				t.Fatal("output configuration coverage erased independent application revocation")
			}
		})
	}
}

func TestOutputFactsFilterRuntimeSamplesAndPreserveLegacyCredentialCounts(t *testing.T) {
	s, p := outputAdapterFixture()
	record := func(operation, outcome, code, result string) gateway.CallRecord {
		return gateway.CallRecord{ApplicationID: "app-a", Operation: operation, Phase: "finished", Outcome: outcome, ErrorCode: code,
			OutputPolicy: &gateway.OutputAssessment{Result: result}}
	}
	piiOnly := record("tools.invoke", "completed", "", "observe")
	piiOnly.ToolGovernance = &gateway.ToolGovernance{Decision: "observe", Content: gateway.ToolContent{State: "not_observed"}, OutputPolicy: piiOnly.OutputPolicy}
	credentials := record("tools.invoke", "completed", "", "observe")
	credentials.ToolGovernance = &gateway.ToolGovernance{Decision: "observe", Content: gateway.ToolContent{State: "observed"}, OutputPolicy: credentials.OutputPolicy}
	legacy := gateway.CallRecord{ApplicationID: "app-a", Operation: "tools.invoke", Phase: "finished", Outcome: "completed", ToolGovernance: &gateway.ToolGovernance{Decision: "observe", Content: gateway.ToolContent{State: "observed"}}}
	instructionOnly := gateway.CallRecord{ApplicationID: "app-a", Operation: "tools.invoke", Phase: "finished", Outcome: "completed", ToolGovernance: &gateway.ToolGovernance{Decision: "observe", Content: gateway.ToolContent{State: "not_observed"}, InstructionPolicy: &gateway.InstructionAssessment{Decision: "observe"}}}
	instructionOnly.ToolGovernance.InstructionPolicy.State = "observed"
	instructionOnly.ToolGovernance.InstructionPolicy.RuleIDs = []string{"answer_manipulation"}
	instructionOnly.ToolGovernance.InstructionPolicy.Mode = "observe"
	instructionOnly.ToolGovernance.InstructionPolicy.Version = "tool-instructions-v2"
	started := record("chat.completions", "incomplete", "content_output_blocked", "error")
	started.Phase = "started"
	otherApp := record("chat.completions", "completed", "content_output_blocked", "observe")
	otherApp.ApplicationID = "app-other"
	noAssessment := record("chat.completions", "blocked", "content_output_blocked", "block")
	noAssessment.OutputPolicy = nil
	s.audit.Records = []gateway.CallRecord{
		record("chat.completions", "blocked", "content_output_blocked", "block"),
		record("tools.invoke", "blocked", "content_output_blocked", "block"),
		record("chat.completions", "completed", "", "observe"),
		piiOnly, credentials, legacy, instructionOnly,
		record("chat.completions", "failed", "content_output_unavailable", "error"),
		record("tools.invoke", "failed", "content_output_unavailable", "error"),
		record("tools.invoke", "failed", "audit_unavailable", "observe"),
		record("chat.completions", "completed", "", "disabled"),
		record("content.evaluate", "completed", "content_output_blocked", "observe"),
		record("content.evaluate", "failed", "", "error"),
		record("assessment.chat.completions", "completed", "content_output_blocked", "observe"),
		record("assessment.chat.completions", "failed", "", "error"),
		started, otherApp, noAssessment,
	}
	wants := map[string]string{"output_block_count": "2", "output_observed_release_count": "3", "output_unknown_count": "2"}
	for _, missingApp := range []bool{false, true} {
		if missingApp {
			s.resources.Applications = nil
		}
		facts := s.input(p, time.Now()).Facts
		for name, want := range wants {
			fact := facts["runtime.sample."+name]
			if string(fact.Value) != want || fact.EvidenceID != "audit-bytes-100" || fact.Source != "runtime" {
				t.Fatalf("incorrect output sample %s: %+v", name, fact)
			}
		}
		if string(facts["runtime.tools.sample.observed_release_count"].Value) != "2" {
			t.Fatal("PII-only observation inflated the independent credential release sample")
		}
	}
	s.audit.Available = false
	facts := s.input(p, time.Now()).Facts
	for name := range wants {
		if _, exists := facts["runtime.sample."+name]; exists {
			t.Fatal("unavailable audit emitted authoritative output sample", name)
		}
	}
	if string(facts["runtime.output_policy_revision"].Value) != "7" {
		t.Fatal("audit failure removed independent configuration evidence")
	}
	s.audit.Available, s.audit.Records = true, nil
	facts = s.input(p, time.Now()).Facts
	for name := range wants {
		if string(facts["runtime.sample."+name].Value) != "0" {
			t.Fatal("available empty sample must yield zero", name)
		}
	}
}

func TestOutputFactsExposeVersionedMetadataOnly(t *testing.T) {
	s, p := outputAdapterFixture()
	s.audit.Records = []gateway.CallRecord{{ApplicationID: "app-a", Operation: "chat.completions", Phase: "finished", Outcome: "completed", OutputPolicy: &gateway.OutputAssessment{
		Result: "observe", Reason: "private-sentinel-reason", MatchedCategories: []string{"email"}, MatchedRules: []string{"private-sentinel-rule"},
	}}}
	now := time.Now().UTC()
	input := s.input(p, now)
	count := 0
	for name, fact := range input.Facts {
		if !strings.HasPrefix(name, "runtime.output_") && !strings.HasPrefix(name, "runtime.sample.output_") {
			continue
		}
		count++
		if fact.Source != "runtime" || fact.ObservedAt != now.Format(time.RFC3339Nano) {
			t.Fatal("output evidence provenance missing", name)
		}
		if strings.HasPrefix(name, "runtime.output_") && fact.EvidenceID != "gw-3-output-7" {
			t.Fatal("output configuration evidence lacks its source version", name)
		}
	}
	if count != 14 || string(input.Facts["runtime.output_policy_mode"].Value) != `"observe"` {
		t.Fatal("missing output configuration or sample facts")
	}
	encoded, _ := json.Marshal(input)
	for _, private := range []string{"private-sentinel", "app-a", "matched_categories", "matched_rules", "start_byte", "end_byte"} {
		if strings.Contains(string(encoded), private) {
			t.Fatal("per-call details or scoped identifiers escaped into product facts", private)
		}
	}
}

func TestOutputRedactedFactsDistinguishPerformedWorkAndUnselectedCredentialRelease(t *testing.T) {
	s, p := outputAdapterFixture()
	record := func(scope, operation, outcome string) gateway.CallRecord {
		assessment := &gateway.OutputAssessment{Mode: "redact", Result: "redacted", Redaction: &gateway.RedactionEvidence{Version: "sensitive-redaction-v1", Scope: scope, Replacements: 1}}
		return gateway.CallRecord{ApplicationID: "app-a", Operation: operation, Phase: "finished", Outcome: outcome, OutputPolicy: assessment,
			ToolGovernance: &gateway.ToolGovernance{Decision: "redact", Content: gateway.ToolContent{State: "observed"}, OutputPolicy: assessment}}
	}
	s.audit.Records = []gateway.CallRecord{record("full_output", "tools.invoke", "completed"), record("matched_spans", "tools.invoke", "completed"), record("matched_spans", "chat.completions", "completed"), record("matched_spans", "tools.invoke", "failed"), record("matched_spans", "content.evaluate", "completed"), record("matched_spans", "assessment.chat.completions", "completed")}
	recommendation := record("matched_spans", "chat.completions", "completed")
	recommendation.OutputPolicy.Result = "redact"
	recommendation.OutputPolicy.Redaction = nil
	s.audit.Records = append(s.audit.Records, recommendation)
	facts := s.input(p, time.Now()).Facts
	if string(facts["runtime.sample.output_redacted_count"].Value) != "3" || string(facts["runtime.sample.output_observed_release_count"].Value) != "0" {
		t.Fatal("redaction recommendations, failed calls or standalone evaluations counted as releases")
	}
	if string(facts["runtime.tools.sample.observed_release_count"].Value) != "1" {
		t.Fatal("partial selected-category redaction hid unselected legacy credential release")
	}
	s.audit.Available = false
	if _, exists := s.input(p, time.Now()).Facts["runtime.sample.output_redacted_count"]; exists {
		t.Fatal("unavailable audit manufactured redaction evidence")
	}
}
