package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEvidenceGraphKeepsScopeProvenanceAndMissingHistory(t *testing.T) {
	s, dir, c := evidenceFixture(t, "full")
	c.ApplicationIDs = []string{evidenceTestApp, evidenceOtherApp}
	var err error
	c, err = s.SaveConfig(c, Snapshot{Applications: []Application{{ID: evidenceTestApp}, {ID: evidenceOtherApp}}}, "test_admin")
	if err != nil {
		t.Fatal(err)
	}
	trace := "1234567890abcdef1234567890abcdef"
	first := evidenceTestRecord(t, evidenceTestApp)
	first.Trace = &TraceContext{Version: traceVersion, TraceID: trace, SpanID: "1111111111111111"}
	second := evidenceTestRecord(t, evidenceTestApp)
	second.Trace = &TraceContext{Version: traceVersion, TraceID: trace, SpanID: "2222222222222222", ParentSpanID: first.Trace.SpanID, Links: []string{"3333333333333333"}}
	second.OutputPolicy = &OutputAssessment{Revision: 3, DetectorVersion: "sensitive-text-v1", Result: "block", State: "observed", MatchedCategories: []string{"email"}}
	other := evidenceTestRecord(t, evidenceOtherApp)
	other.Trace = &TraceContext{Version: traceVersion, TraceID: trace, SpanID: "3333333333333333"}
	for _, r := range []CallRecord{first, second, other} {
		if _, err := s.Capture(r, evidenceTestPayload(c)); err != nil {
			t.Fatal(err)
		}
	}
	graph, err := s.Graph(EvidenceID(second.RequestID), evidenceTestApp)
	if err != nil {
		t.Fatal(err)
	}
	if graph.GraphComplete || !graph.HistoryMayBeMissing || graph.Scope != "same_application" {
		t.Fatal("graph claimed complete history")
	}
	parent, unresolved, finding := false, false, false
	for _, edge := range graph.Edges {
		if edge.Relation == "parent" {
			parent = edge.Provenance == "caller_declared" && edge.Resolution == "observed"
		}
		if edge.Relation == "link" {
			unresolved = edge.Provenance == "caller_declared" && edge.Resolution == "unresolved"
		}
	}
	for _, node := range graph.Nodes {
		finding = finding || node.Type == "finding" && strings.Contains(node.Label, "email")
	}
	if !parent || !unresolved || !finding {
		t.Fatal("typed risk/provenance relationships missing")
	}
	data, _ := json.Marshal(graph)
	for _, hidden := range []string{EvidenceID(other.RequestID), evidenceOtherApp, "hidden-person@private.example", "Synthetic secret input phrase", "confirmed_leak"} {
		if strings.Contains(string(data), hidden) {
			t.Fatal("graph exposed content, foreign identity or invented causal finding")
		}
	}
	if err := os.Remove(filepath.Join(dir, "evidence", EvidenceID(first.RequestID)+".sealed")); err != nil {
		t.Fatal(err)
	}
	missing, err := s.Graph(EvidenceID(second.RequestID), evidenceTestApp)
	if err != nil || missing.UnavailableRecords != 1 || missing.GraphComplete {
		t.Fatal("missing retained reference was hidden", err)
	}
}

func TestEvidenceGraphBoundedWithoutInventingFingerprintLineage(t *testing.T) {
	s, dir, c := evidenceFixture(t, "metadata")
	var root string
	for i := 0; i < 35; i++ {
		r := evidenceTestRecord(t, evidenceTestApp)
		r.Trace = &TraceContext{Version: traceVersion, TraceID: "abcdef1234567890abcdef1234567890", SpanID: "1111111111111111"}
		if i == 0 {
			root = EvidenceID(r.RequestID)
		}
		if _, err := s.Capture(r, evidenceTestPayload(c)); err != nil {
			t.Fatal(err)
		}
	}
	g, err := s.Graph(root, evidenceTestApp)
	if err != nil || !g.ResultTruncated || g.GraphComplete {
		t.Fatal("bounded graph overclaims coverage", err)
	}
	count := 0
	for _, node := range g.Nodes {
		if node.Type == "call" {
			count++
		}
	}
	if count != 32 {
		t.Fatal("graph record bound not applied", count)
	}
	for _, edge := range g.Edges {
		if edge.Relation == "derived_from" || edge.Relation == "parent" {
			t.Fatal("identical content or repeated spans invented lineage")
		}
	}
	related, err := s.ListTrace(evidenceTestApp, "abcdef1234567890abcdef1234567890", 33)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range related[:2] {
		if err := os.Remove(filepath.Join(dir, "evidence", item.ID+".sealed")); err != nil {
			t.Fatal(err)
		}
	}
	partial, err := s.Graph(root, evidenceTestApp)
	if err != nil || !partial.ResultTruncated || partial.UnavailableRecords != 2 {
		t.Fatal("unreadable candidates hid truncation", err)
	}
}
