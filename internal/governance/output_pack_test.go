package governance

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"govweave/internal/compliance"
	"govweave/internal/gateway"
)

func protectedOutputFixture() (sources, Product) {
	s, p := outputAdapterFixture()
	s.outputPolicy.Mode = "block"
	s.outputPolicy.Categories = []string{"credential", "email", "phone"}
	p.PackID, p.PackVersion = "sensitive-output-governance", "1.0.0"
	s.audit.Records = []gateway.CallRecord{{ApplicationID: "app-a", Operation: "chat.completions", Phase: "finished", Outcome: "blocked", ErrorCode: "content_output_blocked", UpstreamAttempted: true,
		OutputPolicy: &gateway.OutputAssessment{ID: "sensitive-output", Revision: 7, DetectorVersion: "sensitive-text-v1", Mode: "block", Result: "block", State: "observed", Categories: []string{"credential", "email", "phone"}}}}
	return s, p
}

func TestSensitiveOutputPackUsesConfigurationAndExecutionEvidence(t *testing.T) {
	e, err := compliance.Open("../../examples/rule-packs")
	if err != nil {
		t.Fatal(err)
	}
	pack, err := e.PackSnapshot("sensitive-output-governance", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		change  func(*sources, *Product)
		failed  []string
		unknown []string
	}{
		{"blocked output", func(*sources, *Product) {}, nil, nil},
		{"inspected tool output", func(s *sources, _ *Product) { s.audit.Records[0].Operation = "tools.invoke" }, nil, nil},
		{"redacted output", func(s *sources, _ *Product) {
			s.outputPolicy.Mode = "redact"
			r := &s.audit.Records[0]
			r.Outcome, r.ErrorCode, r.OutputPolicy.Mode, r.OutputPolicy.Result = "completed", "", "redact", "redacted"
			r.OutputPolicy.Redaction = &gateway.RedactionEvidence{Version: "sensitive-redaction-v1", Scope: "matched_spans", Replacements: 1}
		}, nil, nil},
		{"empty sample", func(s *sources, _ *Product) { s.audit.Records = nil }, []string{"CURRENT-EVIDENCE"}, nil},
		{"disabled", func(s *sources, _ *Product) { s.outputPolicy.Mode = "disabled"; s.audit.Records = nil }, []string{"PROTECTIVE-MODE", "SCOPE-COVERAGE", "CURRENT-EVIDENCE"}, nil},
		{"observe releases", func(s *sources, _ *Product) {
			s.outputPolicy.Mode = "observe"
			r := &s.audit.Records[0]
			r.Outcome, r.ErrorCode, r.OutputPolicy.Mode, r.OutputPolicy.Result = "completed", "", "observe", "observe"
		}, []string{"PROTECTIVE-MODE", "SAMPLE-RELEASES"}, nil},
		{"partial categories", func(s *sources, _ *Product) { s.outputPolicy.Categories = []string{"email"} }, []string{"CATEGORY-COVERAGE"}, nil},
		{"partial application scope", func(s *sources, p *Product) {
			s.resources.Applications = append(s.resources.Applications, gateway.Application{ID: "app-b"})
			p.ApplicationIDs = append(p.ApplicationIDs, "app-b")
		}, []string{"SCOPE-COVERAGE"}, nil},
		{"revoked application", func(s *sources, _ *Product) { s.resources.Applications[0].Revoked = true }, []string{"APPLICATIONS-ACTIVE"}, nil},
		{"missing application", func(s *sources, _ *Product) { s.resources.Applications = nil }, nil, []string{"APPLICATIONS-ACTIVE", "SCOPE-COVERAGE"}},
		{"unavailable audit", func(s *sources, _ *Product) { s.audit.Available = false }, []string{"AUDIT-AVAILABLE"}, []string{"CURRENT-EVIDENCE", "SAMPLE-RELEASES", "SAMPLE-COMPLETENESS"}},
		{"old revision cannot validate current policy", func(s *sources, _ *Product) { s.outputPolicy.Revision++ }, []string{"CURRENT-EVIDENCE"}, nil},
		{"other detector cannot validate current policy", func(s *sources, _ *Product) { s.outputPolicy.DetectorVersion = "sensitive-text-v2" }, []string{"CURRENT-EVIDENCE"}, nil},
		{"standalone evaluation excluded", func(s *sources, _ *Product) { s.audit.Records[0].Operation = "content.evaluate" }, []string{"CURRENT-EVIDENCE"}, nil},
		{"active assessment excluded", func(s *sources, _ *Product) { s.audit.Records[0].Operation = "assessment.chat.completions" }, []string{"CURRENT-EVIDENCE"}, nil},
		{"unrelated application excluded", func(s *sources, _ *Product) { s.audit.Records[0].ApplicationID = "other" }, []string{"CURRENT-EVIDENCE"}, nil},
		{"no upstream execution", func(s *sources, _ *Product) { s.audit.Records[0].UpstreamAttempted = false }, []string{"CURRENT-EVIDENCE"}, nil},
		{"unknown check", func(s *sources, _ *Product) {
			r := &s.audit.Records[0]
			r.Outcome, r.OutputPolicy.Result, r.OutputPolicy.State = "failed", "error", "unknown"
		}, []string{"CURRENT-EVIDENCE", "SAMPLE-COMPLETENESS"}, nil},
		{"recovered incomplete call", func(s *sources, _ *Product) {
			r := &s.audit.Records[0]
			r.Phase, r.Outcome = "started", "incomplete"
		}, []string{"CURRENT-EVIDENCE", "SAMPLE-COMPLETENESS"}, nil},
		{"legacy release retained", func(s *sources, _ *Product) {
			s.audit.Records = append(s.audit.Records, gateway.CallRecord{ApplicationID: "app-a", Operation: "tools.invoke", Phase: "finished", Outcome: "completed", UpstreamAttempted: true})
		}, []string{"SAMPLE-RELEASES"}, nil},
		{"past partial-category release retained", func(s *sources, _ *Product) {
			a := *s.audit.Records[0].OutputPolicy
			a.Revision, a.Result, a.State, a.Categories = 6, "allow", "not_observed", []string{"email"}
			s.audit.Records = append(s.audit.Records, gateway.CallRecord{ApplicationID: "app-a", Operation: "chat.completions", Phase: "finished", Outcome: "completed", UpstreamAttempted: true, OutputPolicy: &a})
		}, []string{"SAMPLE-RELEASES"}, nil},
		{"earlier observe release survives restoration", func(s *sources, _ *Product) {
			a := *s.audit.Records[0].OutputPolicy
			a.Revision, a.Mode, a.Result = 6, "observe", "observe"
			s.audit.Records = append(s.audit.Records, gateway.CallRecord{ApplicationID: "app-a", Operation: "chat.completions", Phase: "finished", Outcome: "completed", UpstreamAttempted: true, OutputPolicy: &a})
		}, []string{"SAMPLE-RELEASES"}, nil},
		{"redaction recommendation is not completed work", func(s *sources, _ *Product) {
			s.audit.Records[0].Outcome, s.audit.Records[0].OutputPolicy.Result = "completed", "redact"
		}, []string{"CURRENT-EVIDENCE", "SAMPLE-RELEASES"}, nil},
		{"redaction completion evidence missing", func(s *sources, _ *Product) {
			s.audit.Records[0].Outcome, s.audit.Records[0].OutputPolicy.Result = "completed", "redacted"
		}, []string{"CURRENT-EVIDENCE", "SAMPLE-RELEASES"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, p := protectedOutputFixture()
			tc.change(&s, &p)
			now := time.Now()
			evaluation, err := compliance.EvaluateSnapshot(pack, s.input(p, now), now)
			if err != nil {
				t.Fatal(err)
			}
			want := map[string]string{}
			for _, id := range tc.failed {
				want["OUTPUT-"+id] = "fail"
			}
			for _, id := range tc.unknown {
				want["OUTPUT-"+id] = "unknown"
			}
			got := map[string]string{}
			for _, c := range evaluation.Controls {
				if c.Status != "pass" {
					got[c.ID] = c.Status
				}
			}
			if len(evaluation.Controls) != 8 || !reflect.DeepEqual(got, want) {
				t.Fatalf("findings %v, want %v", got, want)
			}
			if !evaluation.EvaluationOnly || evaluation.LegalCompliance != "not_determined" || evaluation.PackReview != "draft" {
				t.Fatal("technical check became a legal conclusion")
			}
		})
	}
}

func TestOutputFactsLeaveRoomForMaximumProductAndActiveTestEvidence(t *testing.T) {
	s, p := protectedOutputFixture()
	p.Facts = map[string]compliance.Fact{}
	now := time.Now()
	fact := compliance.Fact{Value: json.RawMessage("true"), EvidenceID: "synthetic", Source: "declared", ObservedAt: now.UTC().Format(time.RFC3339Nano)}
	for i := 0; i < 112; i++ {
		p.Facts[fmt.Sprintf("profile.fact_%d", i)] = fact
	}
	in := s.input(p, now)
	for _, name := range []string{"test_set_documented", "canary.exposure_observed", "pre_deployment.passed", "operation.passed", "output.pre_deployment.passed", "output.operation.passed"} {
		fact.Source = "assessment"
		in.Facts["testing."+name] = fact
	}
	if len(in.Facts) != 159 {
		t.Fatalf("unexpected evidence budget: %d", len(in.Facts))
	}
	if err := compliance.ValidateInput(in); err != nil {
		t.Fatal(err)
	}
}

func TestSensitiveOutputPackRefreshesInBackgroundAfterActualCalls(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"Synthetic contact: test@example.com"},"finish_reason":"stop"}]}`))
	}))
	defer provider.Close()
	f := setup(t)
	_, err := f.gateway.Store.SaveConnection(f.connection.ID, gateway.ConnectionInput{Revision: f.connection.Revision, Name: "Synthetic output", BaseURL: provider.URL + "/v1", Model: "local", Alias: "assistant", Enabled: true, AllowInsecureHTTP: true, TimeoutSeconds: 1})
	if err != nil {
		t.Fatal(err)
	}
	policy := func(mode string) uint64 {
		in := f.gateway.OutputPolicies.Snapshot().OutputPolicyInput
		in.Mode = mode
		saved, err := f.gateway.OutputPolicies.Save(in, f.gateway.Store.Snapshot())
		if err != nil {
			t.Fatal(err)
		}
		f.gateway.NotifyChange()
		return saved.Revision
	}
	revision := policy("block")
	in := f.input()
	in.PackID = "sensitive-output-governance"
	product, err := f.service.Save("", in)
	if err != nil {
		t.Fatal(err)
	}
	waitFor := func(rev uint64, failures ...string) Report {
		want := map[string]string{}
		for _, id := range failures {
			want["OUTPUT-"+id] = "fail"
		}
		// await reads the worker's cache directly: no Latest, Refresh,
		// report capture or HTTP evaluation request can repair it for us.
		return await(t, f.service, product.ID, func(r Report) bool {
			if r.State != "ready" || r.Snapshot.OutputPolicyRevision != rev {
				return false
			}
			got := map[string]string{}
			for _, c := range r.Evaluation.Controls {
				if c.Status != "pass" {
					got[c.ID] = c.Status
				}
			}
			return reflect.DeepEqual(got, want)
		})
	}
	invoke := func(status int) {
		req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"assistant","messages":[{"role":"user","content":"Return a synthetic contact."}],"stream":false}`))
		req.Header.Set("Authorization", "Bearer "+f.key)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.gateway.Chat(w, req)
		if w.Code != status {
			t.Fatalf("gateway returned %d, want %d", w.Code, status)
		}
	}
	waitFor(revision, "CURRENT-EVIDENCE")
	invoke(403)
	waitFor(revision)
	revision = policy("observe")
	waitFor(revision, "PROTECTIVE-MODE", "CURRENT-EVIDENCE")
	invoke(200)
	waitFor(revision, "PROTECTIVE-MODE", "SAMPLE-RELEASES")
	revision = policy("block")
	waitFor(revision, "CURRENT-EVIDENCE", "SAMPLE-RELEASES")
	invoke(403)
	waitFor(revision, "SAMPLE-RELEASES")
}
