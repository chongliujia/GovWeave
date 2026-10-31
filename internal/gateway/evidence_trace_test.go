package gateway

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func evidenceTraceFixture(t *testing.T) (*Engine, string, EvidenceConfig) {
	t.Helper()
	s, dir, c := evidenceFixture(t, "full")
	c.ApplicationIDs = []string{evidenceTestApp, evidenceOtherApp}
	var err error
	c, err = s.SaveConfig(c, Snapshot{Applications: []Application{{ID: evidenceTestApp}, {ID: evidenceOtherApp}}}, "test_admin")
	if err != nil {
		t.Fatal(err)
	}
	a, err := OpenAudit(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	return &Engine{Evidence: s, Audit: a}, dir, c
}

func TestEvidenceTraceJoinsExplicitScopeWithoutContentOrCausalityClaims(t *testing.T) {
	g, dir, config := evidenceTraceFixture(t)
	trace := strings.Repeat("a", 32)
	a := evidenceTestRecord(t, evidenceTestApp)
	a.Trace = &TraceContext{Version: traceVersion, TraceID: trace, SpanID: strings.Repeat("1", 16), AgentID: strings.Repeat("a", 16)}
	b := evidenceTestRecord(t, evidenceOtherApp)
	b.Trace = &TraceContext{Version: traceVersion, TraceID: trace, SpanID: strings.Repeat("2", 16), ParentSpanID: a.Trace.SpanID}
	b.OutputPolicy = &OutputAssessment{Revision: 3, DetectorVersion: "sensitive-text-v1", Result: "block", State: "observed", MatchedCategories: []string{"email"}}
	missing := evidenceTestRecord(t, evidenceTestApp)
	missing.Trace = &TraceContext{Version: traceVersion, TraceID: trace, SpanID: strings.Repeat("3", 16), RetryOfSpanID: b.Trace.SpanID, Links: []string{a.Trace.SpanID}}
	foreign := evidenceTestRecord(t, "app_0123456789ABCDEF")
	foreign.Trace = &TraceContext{Version: traceVersion, TraceID: trace, SpanID: strings.Repeat("4", 16)}
	for _, r := range []CallRecord{a, b} {
		if _, err := g.Evidence.Capture(r, evidenceTestPayload(config)); err != nil {
			t.Fatal(err)
		}
	}
	g.Audit.recent = []CallRecord{a, b, missing, foreign}
	view, err := g.EvidenceTraceView(trace, []string{evidenceTestApp}, 128)
	if err != nil || len(view.Calls) != 2 || view.Summary.Retained != 1 || view.Summary.NotFound != 1 {
		t.Fatal("single application view changed", err, view.Summary)
	}
	for _, edge := range view.Edges {
		if edge.Relation == "retry_of" && (edge.Resolution != "unresolved" || edge.TargetRequestID != "") {
			t.Fatal("unselected application resolved a reference")
		}
	}
	data, _ := json.Marshal(view)
	for _, forbidden := range []string{b.RequestID, evidenceOtherApp, foreign.RequestID, foreign.ApplicationID} {
		if strings.Contains(string(data), forbidden) {
			t.Fatal("single application view exposed another application")
		}
	}
	view, err = g.EvidenceTraceView(trace, []string{evidenceOtherApp, evidenceTestApp}, 128)
	if err != nil || view.Scope != "selected_applications" || len(view.Calls) != 3 || view.Summary.Retained != 2 || view.Summary.RetainedFindings != 1 || view.TaskCompletion != "not_determined" || !view.HistoryMayBeMissing || view.GraphComplete {
		t.Fatal("combined evidence missing or overclaims coverage", err, view.Summary)
	}
	if len(view.Edges) != 3 {
		t.Fatal("declared parent/join/retry references missing")
	}
	for _, edge := range view.Edges {
		if edge.Provenance != "caller_declared" || edge.Resolution != "observed" || edge.TargetRequestID == "" {
			t.Fatal("declared edge source or resolution changed")
		}
	}
	data, _ = json.Marshal(view)
	for _, forbidden := range []string{"Synthetic secret input phrase", "hidden-person@private.example", foreign.RequestID, foreign.ApplicationID, "confirmed_leak"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatal("task view leaked content or invented causal proof")
		}
	}
	for i := range view.Calls {
		if view.Calls[i].RequestID == b.RequestID {
			view.Calls[i].Record.Trace.ParentSpanID = strings.Repeat("f", 16)
			view.Calls[i].Findings[0].Category = "changed"
		}
	}
	again, _ := g.EvidenceTraceView(trace, []string{evidenceTestApp, evidenceOtherApp}, 128)
	if len(again.Edges) != 3 || again.Summary.RetainedFindings != 1 {
		t.Fatal("returned view aliases retained state")
	}
	for _, row := range again.Calls {
		if row.RequestID == b.RequestID && (row.Record.Trace.ParentSpanID != a.Trace.SpanID || row.Findings[0].Category != "email") {
			t.Fatal("returned record or findings mutated the stored capture")
		}
	}
	// Audit admission failure must not hide already retained observations.
	g.Audit.failed = true
	degraded, err := g.EvidenceTraceView(trace, []string{evidenceTestApp, evidenceOtherApp}, 128)
	if err != nil || degraded.AuditAvailable || len(degraded.Calls) != 3 || degraded.Summary.Retained != 2 {
		t.Fatal("audit admission failure discarded existing task evidence", err)
	}
	g.Audit.failed = false
	// A retained task remains inspectable after the recent audit window moves.
	g.Audit.recent = nil
	reopened, err := OpenEvidence(dir)
	if err != nil {
		t.Fatal(err)
	}
	g.Evidence = reopened
	old, err := g.EvidenceTraceView(trace, []string{evidenceTestApp, evidenceOtherApp}, 128)
	if err != nil || len(old.Calls) != 2 || old.Summary.Retained != 2 {
		t.Fatal("retained history depended on recent audit", err)
	}
	if err := os.Remove(filepath.Join(dir, "evidence", EvidenceID(b.RequestID)+".sealed")); err != nil {
		t.Fatal(err)
	}
	broken, err := g.EvidenceTraceView(trace, []string{evidenceTestApp, evidenceOtherApp}, 128)
	if err != nil || broken.Summary.Unavailable != 1 {
		t.Fatal("unreadable capture was hidden", err)
	}
	for _, row := range broken.Calls {
		if row.RequestID == b.RequestID && (row.Record != nil || row.RecordSource != "evidence_index" || len(row.Findings) != 0) {
			t.Fatal("unreadable capture fabricated a record or findings")
		}
	}
}

func TestEvidenceTraceBoundsMissingLoadedAndAmbiguousStates(t *testing.T) {
	g, _, config := evidenceTraceFixture(t)
	trace := strings.Repeat("b", 32)
	var records []CallRecord
	for i := 0; i < 33; i++ {
		r := evidenceTestRecord(t, evidenceTestApp)
		r.Trace = &TraceContext{Version: traceVersion, TraceID: trace, SpanID: strings.Repeat("1", 16)}
		if _, err := g.Evidence.Capture(r, evidenceTestPayload(config)); err != nil {
			t.Fatal(err)
		}
		records = append(records, r)
	}
	for i := 0; i < 100; i++ {
		r := evidenceTestRecord(t, evidenceOtherApp)
		r.Trace = &TraceContext{Version: traceVersion, TraceID: trace, SpanID: fmt.Sprintf("%016x", i+2), ParentSpanID: strings.Repeat("1", 16)}
		records = append(records, r)
	}
	g.Audit.recent = records
	view, err := g.EvidenceTraceView(trace, []string{evidenceTestApp, evidenceOtherApp}, 128)
	if err != nil || len(view.Calls) != 128 || view.Summary.Retained != 32 || !view.EvidenceResultTruncated || !view.AuditResultTruncated || !view.ResultTruncated {
		t.Fatal("independent source/union limits missing", err, view.Summary)
	}
	for _, edge := range view.Edges {
		if edge.Resolution != "ambiguous" || edge.TargetRequestID != "" {
			t.Fatal("duplicate visible span IDs resolved to an arbitrary call")
		}
	}
	g.Audit.recent = records[:33]
	view, err = g.EvidenceTraceView(trace, []string{evidenceTestApp}, 128)
	if err != nil || view.Summary.NotLoaded != 1 || view.Summary.NotFound != 0 {
		t.Fatal("capture outside read budget mislabeled missing", err, view.Summary)
	}
	small, err := g.EvidenceTraceView(trace, []string{evidenceTestApp}, 1)
	if err != nil || len(small.Calls) != 1 || small.EvidenceLimit != 1 || !small.ResultTruncated {
		t.Fatal("caller call bound ignored", err)
	}
	g.Evidence.now = func() time.Time { return time.Now().Add(400 * 24 * time.Hour) }
	expired, err := g.EvidenceTraceView(trace, []string{evidenceTestApp}, 128)
	if err != nil || expired.Summary.Retained != 0 || expired.Summary.NotFound != 33 {
		t.Fatal("task view revived expired content", err, expired.Summary)
	}
	for _, input := range []struct {
		trace string
		ids   []string
		limit int
	}{{trace, nil, 128}, {trace, []string{evidenceTestApp, evidenceTestApp}, 128}, {trace, []string{"*"}, 128}, {"bad", []string{evidenceTestApp}, 128}, {trace, []string{evidenceTestApp}, 0}, {trace, []string{evidenceTestApp}, 129}} {
		if _, err := g.EvidenceTraceView(input.trace, input.ids, input.limit); err != ErrEvidenceInvalid {
			t.Fatal("invalid/implicit scope accepted", err)
		}
	}
}
