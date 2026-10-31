package governance

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"govweave/internal/gateway"
)

func TestRuntimeEvidenceReferencesExactlyMatchRuntimeCounters(t *testing.T) {
	product := Product{ProductInput: ProductInput{ApplicationIDs: []string{"app-a"}}}
	output := func(result, state string) *gateway.OutputAssessment {
		return &gateway.OutputAssessment{ID: "sensitive-output", Revision: 7, DetectorVersion: "sensitive-text-v1", Result: result, State: state, Categories: []string{"credential", "email", "phone"}}
	}
	redacted := output("redacted", "observed")
	redacted.Redaction = &gateway.RedactionEvidence{Scope: "matched_spans", Replacements: 1}
	records := []gateway.CallRecord{
		{Operation: "chat.completions", Outcome: "completed"},
		{Operation: "chat.completions", Outcome: "blocked", ErrorCode: "policy_blocked"},
		{Operation: "chat.completions", Outcome: "completed", ContentPolicy: &gateway.PolicyAssessment{Result: "observe"}, OutputPolicy: output("observe", "observed")},
		{Operation: "chat.completions", Outcome: "blocked", ErrorCode: "content_output_blocked", OutputPolicy: output("block", "observed")},
		{Operation: "chat.completions", Outcome: "completed", OutputPolicy: redacted},
		{Operation: "chat.completions", Outcome: "failed", OutputPolicy: output("error", "unknown")},
		{Operation: "tools.invoke", Outcome: "completed", ToolGovernance: &gateway.ToolGovernance{Decision: "observe", Content: gateway.ToolContent{State: "observed"}}, OutputPolicy: output("allow", "not_observed")},
		{Operation: "tools.invoke", Outcome: "blocked", ErrorCode: "tool_not_allowed"},
		{Operation: "tools.invoke", Outcome: "failed"},
		{Operation: "tools.invoke", Outcome: "completed", ToolGovernance: &gateway.ToolGovernance{Decision: "redact", Content: gateway.ToolContent{State: "observed"}, OutputPolicy: redacted}, OutputPolicy: redacted},
		{Operation: "tools.invoke", Outcome: "cancelled"},
		{Operation: "tools.invoke", Outcome: "blocked", ErrorCode: "tool_output_blocked", ToolGovernance: &gateway.ToolGovernance{Decision: "block", Content: gateway.ToolContent{State: "observed"}}},
		{Operation: "chat.completions", Outcome: "incomplete", Phase: "started"},
		{Operation: "tools.invoke", Outcome: "incomplete", Phase: "started"},
		{Operation: "chat.completions", Outcome: "in_progress", Phase: "started"},
		{Operation: "assessment.chat.completions", Outcome: "completed"},
		{Operation: "chat.completions", Outcome: "completed", ApplicationID: "other-app"},
	}
	for i := range records {
		records[i].RequestID = fmt.Sprintf("req_%022d", i)
		if records[i].ApplicationID == "" {
			records[i].ApplicationID = "app-a"
		}
		if records[i].Phase == "" {
			records[i].Phase = "finished"
		}
		records[i].UpstreamAttempted = records[i].ErrorCode != "tool_not_allowed" && records[i].ErrorCode != "policy_blocked"
	}
	source := sources{audit: gateway.AuditView{Available: true, Bytes: 5000, Records: records}, outputPolicy: gateway.OutputPolicySnapshot{OutputPolicyInput: gateway.OutputPolicyInput{Revision: 7, DetectorVersion: "sensitive-text-v1"}}}
	input := source.input(product, time.Now())
	evidence := runtimeEvidence(product, input, source)
	if len(evidence.Records) != 15 || evidence.GlobalSampleSize != 17 || !evidence.HistoryMayBeMissing {
		t.Fatal("scope or sample boundary lost")
	}
	for _, fact := range evidence.Facts {
		if fact.Value != len(fact.MatchedRequestIDs) {
			t.Fatalf("counter %s=%d has %d matching records", fact.Fact, fact.Value, len(fact.MatchedRequestIDs))
		}
		var value int
		if json.Unmarshal(input.Facts[fact.Fact].Value, &value) != nil || value != fact.Value {
			t.Fatal("fact value differs")
		}
		for _, id := range fact.SourceRequestIDs {
			if id == records[15].RequestID || id == records[16].RequestID {
				t.Fatal("assessment or another app entered evidence")
			}
		}
	}
	cloned := cloneRuntimeEvidence(evidence)
	cloned.Records[2].ContentPolicy.Result = "changed"
	cloned.Facts[0].MatchedRequestIDs = append(cloned.Facts[0].MatchedRequestIDs, "changed")
	if evidence.Records[2].ContentPolicy.Result != "observe" || reflect.DeepEqual(evidence, cloned) {
		t.Fatal("evidence shares mutable state")
	}
}

func TestArchivedRuntimeEvidenceSurvivesLiveAuditWindowAndRejectsFalseReferences(t *testing.T) {
	f := setup(t)
	f.service.Close()
	product, err := f.service.Save("", f.input())
	if err != nil {
		t.Fatal(err)
	}
	id := "req_0000000000000000000001"
	if err := f.gateway.Audit.Finish(gateway.CallRecord{SchemaVersion: 1, RequestID: id, ApplicationID: f.app.ID, Operation: "chat.completions", Outcome: "blocked", ErrorCode: "policy_blocked", HTTPStatus: 403, ContentPolicy: &gateway.PolicyAssessment{ID: "credential-egress", Result: "block", MatchedRules: []string{"api_key"}}}); err != nil {
		t.Fatal(err)
	}
	archive, err := f.service.Archive(product.ID)
	if err != nil {
		t.Fatal(err)
	}
	if e := archive.Snapshot.Report.RuntimeEvidence; e == nil || len(e.Records) != 1 || e.Records[0].RequestID != id {
		t.Fatal("actual runtime records not archived")
	}
	for i := 2; i <= 1003; i++ {
		if err := f.gateway.Audit.Finish(gateway.CallRecord{SchemaVersion: 1, RequestID: fmt.Sprintf("req_%022d", i), ApplicationID: f.app.ID, Operation: "chat.completions", Outcome: "completed", HTTPStatus: 200}); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range f.gateway.Audit.View(1000, f.app.ID).Records {
		if r.RequestID == id {
			t.Fatal("test did not evict old sample")
		}
	}
	saved, err := f.service.Archives.Get(archive.Summary.ID)
	if err != nil || saved.Snapshot.Report.RuntimeEvidence.Records[0].RequestID != id {
		t.Fatal("historical evidence lost", err)
	}
	if result, err := f.service.Archives.Replay(archive.Summary.ID); err != nil || !result.Matches {
		t.Fatal("snapshot replay failed", err)
	}
	bad := saved.Snapshot
	bad.Report.RuntimeEvidence.Records[0].ApplicationID = "another-application"
	if validateSnapshot(bad) == nil {
		t.Fatal("cross-application record accepted in report evidence")
	}
	legacy := archive.Snapshot
	legacy.Report.RuntimeEvidence = nil
	if validateSnapshot(legacy) != nil {
		t.Fatal("legacy report compatibility lost")
	}
}
