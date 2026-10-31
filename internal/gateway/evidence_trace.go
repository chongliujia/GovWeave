package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"slices"
	"sort"
	"time"
)

const maxEvidenceTraceCaptures = 32

// A task view joins two bounded observation sources. It does not infer data
// transmission, task success, or a permission from a caller-declared trace ID.
type EvidenceTraceCall struct {
	RequestID     string            `json:"request_id"`
	ApplicationID string            `json:"application_id"`
	RecordSource  string            `json:"record_source"`
	Record        *CallRecord       `json:"record,omitempty"`
	EvidenceID    string            `json:"evidence_id,omitempty"`
	EvidenceState string            `json:"evidence_state"`
	Findings      []EvidenceFinding `json:"findings"`
}

type EvidenceTraceEdge struct {
	SourceRequestID string `json:"source_request_id"`
	TargetRequestID string `json:"target_request_id,omitempty"`
	TargetSpanID    string `json:"target_span_id"`
	Relation        string `json:"relation"`
	Provenance      string `json:"provenance"`
	Resolution      string `json:"resolution"`
}

type EvidenceTraceSummary struct {
	Calls            int `json:"calls"`
	Retained         int `json:"retained"`
	NotFound         int `json:"not_found"`
	Unavailable      int `json:"unavailable"`
	NotLoaded        int `json:"not_loaded"`
	RetainedFindings int `json:"retained_findings"`
}

type EvidenceTraceView struct {
	ViewSHA256              string               `json:"view_sha256,omitempty"`
	SchemaVersion           int                  `json:"schema_version"`
	TraceID                 string               `json:"trace_id"`
	ApplicationIDs          []string             `json:"application_ids"`
	Scope                   string               `json:"scope"`
	Coverage                string               `json:"coverage"`
	FindingCoverage         string               `json:"finding_coverage"`
	TaskCompletion          string               `json:"task_completion"`
	HistoryMayBeMissing     bool                 `json:"history_may_be_missing"`
	GraphComplete           bool                 `json:"graph_complete"`
	ResultTruncated         bool                 `json:"result_truncated"`
	AuditAvailable          bool                 `json:"audit_available"`
	AuditWindowSaturated    bool                 `json:"audit_window_saturated"`
	AuditResultTruncated    bool                 `json:"audit_result_truncated"`
	EvidenceResultTruncated bool                 `json:"evidence_result_truncated"`
	CallLimit               int                  `json:"call_limit"`
	EvidenceLimit           int                  `json:"evidence_limit"`
	Summary                 EvidenceTraceSummary `json:"summary"`
	Calls                   []EvidenceTraceCall  `json:"calls"`
	Edges                   []EvidenceTraceEdge  `json:"edges"`
}

func validEvidenceTraceScope(traceID string, ids []string, limit int) bool {
	if !traceHex(traceID, 32) || len(ids) < 1 || len(ids) > 16 || limit < 1 || limit > maxTraceRecords {
		return false
	}
	for i, id := range ids {
		if !evidenceApplicationID.MatchString(id) || slices.Contains(ids[:i], id) {
			return false
		}
	}
	return true
}

// Snapshot only index metadata for the selected trace/applications. The whole
// vault index is bounded by MaxEvidenceRecords; ciphertext reads are separately
// limited. Expired captures never enter this inventory or extend retention.
func (s *EvidenceStore) traceCandidates(traceID string, ids []string) []EvidenceSummary {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := []EvidenceSummary{}
	now := s.now()
	for _, entry := range s.entries {
		v := entry.summary
		expires, _ := time.Parse(time.RFC3339Nano, v.ExpiresAt)
		if v.TraceID == traceID && slices.Contains(ids, v.ApplicationID) && now.Before(expires) {
			result = append(result, v)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		first, _ := time.Parse(time.RFC3339Nano, result[i].CreatedAt)
		second, _ := time.Parse(time.RFC3339Nano, result[j].CreatedAt)
		if !first.Equal(second) {
			return first.After(second)
		}
		return result[i].RequestID > result[j].RequestID
	})
	return result
}

// EvidenceTraceView is administrator-only at the HTTP boundary. Applications
// continue to use their own authenticated /v1/traces scope. This is a live,
// non-atomic view across audit and vault snapshots, never a report archive.
func (g *Engine) EvidenceTraceView(traceID string, ids []string, limit int) (EvidenceTraceView, error) {
	if !validEvidenceTraceScope(traceID, ids, limit) {
		return EvidenceTraceView{}, ErrEvidenceInvalid
	}
	if g.Evidence == nil || g.Audit == nil {
		return EvidenceTraceView{}, ErrEvidenceUnavailable
	}
	ids = slices.Clone(ids)
	slices.Sort(ids)
	audit, _ := g.Audit.TraceView(traceID, ids, maxTraceRecords)
	candidates := g.Evidence.traceCandidates(traceID, ids)
	v := EvidenceTraceView{SchemaVersion: 1, TraceID: traceID, ApplicationIDs: ids, Scope: "selected_applications",
		Coverage: "retained_evidence_and_recent_audit", FindingCoverage: "retained_evidence_only", TaskCompletion: "not_determined",
		HistoryMayBeMissing: true, GraphComplete: false, AuditAvailable: audit.AuditAvailable,
		AuditWindowSaturated: audit.WindowSaturated, AuditResultTruncated: audit.ResultTruncated,
		CallLimit: limit, EvidenceLimit: min(limit, maxEvidenceTraceCaptures), Calls: []EvidenceTraceCall{}, Edges: []EvidenceTraceEdge{}}
	v.EvidenceResultTruncated = len(candidates) > v.EvidenceLimit
	v.ResultTruncated = v.EvidenceResultTruncated || v.AuditResultTruncated
	byRequest := map[string]int{}
	known := map[string]EvidenceSummary{}
	observed := map[string]CallRecord{}
	times := map[string]time.Time{}
	for _, r := range audit.Records {
		observed[r.RequestID] = r
	}
	for _, c := range candidates {
		known[c.RequestID] = c
	}
	// Prioritize the bounded retained-capture selection, then fill remaining
	// call slots with the latest audit records. Selection is global across the
	// explicit scope, not a per-application completeness guarantee.
	for _, c := range candidates[:min(len(candidates), v.EvidenceLimit)] {
		row := EvidenceTraceCall{RequestID: c.RequestID, ApplicationID: c.ApplicationID, EvidenceID: c.ID,
			EvidenceState: "unavailable", RecordSource: "evidence_index", Findings: []EvidenceFinding{}}
		if r, ok := observed[c.RequestID]; ok && r.ApplicationID == c.ApplicationID {
			row.Record, row.RecordSource = &r, "recent_audit"
		}
		if bundle, err := g.Evidence.Get(c.ID, c.ApplicationID); err == nil && bundle.TraceID == traceID {
			r := bundle.Record
			row.Record, row.RecordSource, row.EvidenceState = &r, "retained_evidence", "retained"
			row.Findings = EvidenceFindings(bundle)
		}
		times[c.RequestID], _ = time.Parse(time.RFC3339Nano, c.CreatedAt)
		byRequest[row.RequestID] = len(v.Calls)
		v.Calls = append(v.Calls, row)
	}
	for i := len(audit.Records) - 1; i >= 0; i-- {
		r := audit.Records[i]
		if _, found := byRequest[r.RequestID]; found {
			continue
		}
		if len(v.Calls) == limit {
			v.ResultTruncated = true
			break
		}
		row := EvidenceTraceCall{RequestID: r.RequestID, ApplicationID: r.ApplicationID, Record: &r,
			RecordSource: "recent_audit", EvidenceState: "not_found", Findings: []EvidenceFinding{}}
		if c, found := known[r.RequestID]; found && c.ApplicationID == r.ApplicationID {
			row.EvidenceID, row.EvidenceState = c.ID, "not_loaded"
		}
		byRequest[row.RequestID] = len(v.Calls)
		v.Calls = append(v.Calls, row)
	}
	for _, row := range v.Calls {
		if row.Record != nil {
			times[row.RequestID], _ = time.Parse(time.RFC3339Nano, row.Record.Timestamp)
		}
	}
	sort.Slice(v.Calls, func(i, j int) bool {
		left, right := v.Calls[i].RequestID, v.Calls[j].RequestID
		if !times[left].Equal(times[right]) {
			return times[left].Before(times[right])
		}
		return left < right
	})
	v.summarize()
	v.ViewSHA256 = evidenceTraceDigest(v)
	return v, nil
}

// The digest covers the canonical Go JSON view with its digest field omitted.
// It is an optimistic concurrency check, not an authenticity claim.
func evidenceTraceDigest(v EvidenceTraceView) string {
	v.ViewSHA256 = ""
	data, _ := json.Marshal(v)
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func (v *EvidenceTraceView) summarize() {
	spans := map[string][]string{}
	for _, row := range v.Calls {
		v.Summary.Calls++
		switch row.EvidenceState {
		case "retained":
			v.Summary.Retained++
		case "not_found":
			v.Summary.NotFound++
		case "unavailable":
			v.Summary.Unavailable++
		case "not_loaded":
			v.Summary.NotLoaded++
		}
		v.Summary.RetainedFindings += len(row.Findings)
		if row.Record != nil && row.Record.Trace != nil {
			span := row.Record.Trace.SpanID
			spans[span] = append(spans[span], row.RequestID)
		}
	}
	for _, row := range v.Calls {
		if row.Record == nil || row.Record.Trace == nil {
			continue
		}
		t := row.Record.Trace
		edge := func(target, relation string) {
			if target == "" {
				return
			}
			e := EvidenceTraceEdge{SourceRequestID: row.RequestID, TargetSpanID: target, Relation: relation, Provenance: "caller_declared", Resolution: "unresolved"}
			if matches := spans[target]; len(matches) == 1 {
				e.TargetRequestID, e.Resolution = matches[0], "observed"
			} else if len(matches) > 1 {
				e.Resolution = "ambiguous"
			}
			v.Edges = append(v.Edges, e)
		}
		edge(t.ParentSpanID, "parent")
		for _, target := range t.Links {
			edge(target, "link")
		}
		edge(t.RetryOfSpanID, "retry_of")
	}
}

// The server must wrap this handler with administrator session authorization.
func (g *Engine) GetAdminEvidenceTrace(w http.ResponseWriter, r *http.Request) {
	traceID, ids, limit, ok := ParseEvidenceTraceQuery(r)
	if !ok {
		failure(w, 400, "invalid_trace_query", "")
		return
	}
	apps := g.Store.Snapshot().Applications
	for _, id := range ids {
		if !slices.ContainsFunc(apps, func(app Application) bool { return app.ID == id }) {
			failure(w, 400, "invalid_trace_query", "")
			return
		}
	}
	view, err := g.EvidenceTraceView(traceID, ids, limit)
	if err != nil {
		failure(w, 503, "evidence_unavailable", "")
		return
	}
	respond(w, 200, view)
}

func ParseEvidenceTraceQuery(r *http.Request) (string, []string, int, bool) {
	traceID, ids, limit, ok := traceQuery(r, true)
	return traceID, ids, limit, ok && validEvidenceTraceScope(traceID, ids, limit)
}
