package gateway

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

const traceVersion = "agent-trace-v1"
const maxTraceRecords = 128

// TraceContext contains explicit, bounded correlation metadata. ApplicationID
// on CallRecord is the authenticated identity; AgentID and all relationships
// are caller declarations, never grants or proof of causality.
type TraceContext struct {
	Version       string   `json:"version"`
	TraceID       string   `json:"trace_id"`
	SpanID        string   `json:"span_id"`
	ParentSpanID  string   `json:"parent_span_id,omitempty"`
	AgentID       string   `json:"agent_id,omitempty"`
	Links         []string `json:"links,omitempty"`
	RetryOfSpanID string   `json:"retry_of_span_id,omitempty"`
}

func traceHex(value string, length int) bool {
	if len(value) != length || value == strings.Repeat("0", length) {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func validTrace(t *TraceContext) bool {
	if t == nil {
		return true
	}
	if t.Version != traceVersion || !traceHex(t.TraceID, 32) || !traceHex(t.SpanID, 16) || len(t.Links) > 4 {
		return false
	}
	for _, id := range []string{t.ParentSpanID, t.AgentID, t.RetryOfSpanID} {
		if id != "" && !traceHex(id, 16) {
			return false
		}
	}
	for i, id := range t.Links {
		if !traceHex(id, 16) || slices.Contains(t.Links[:i], id) {
			return false
		}
	}
	return true
}

var traceHeaders = []string{"X-GovWeave-Trace-ID", "X-GovWeave-Parent-Span-ID", "X-GovWeave-Agent-ID", "X-GovWeave-Link-Span-IDs", "X-GovWeave-Retry-Of"}

func traceContextError(err error) (int, string) {
	if err.Error() == "trace_unavailable" {
		return 503, "trace_unavailable"
	}
	return 400, "invalid_trace_context"
}

func captureTrace(w http.ResponseWriter, r *http.Request, record *CallRecord) error {
	values := make([]string, len(traceHeaders))
	present := false
	for i, name := range traceHeaders {
		all := r.Header.Values(name)
		if len(all) > 1 || len(all) == 1 && (all[0] == "" || len(all[0]) > 67) {
			return errors.New("invalid_trace_context")
		}
		if len(all) == 1 {
			values[i], present = all[0], true
		}
	}
	// A caller cannot choose the gateway's span identifier.
	if len(r.Header.Values("X-GovWeave-Span-ID")) != 0 {
		return errors.New("invalid_trace_context")
	}
	if !present {
		return nil
	}
	t := &TraceContext{Version: traceVersion, TraceID: values[0], ParentSpanID: values[1], AgentID: values[2], RetryOfSpanID: values[4]}
	if values[3] != "" {
		t.Links = strings.Split(values[3], ",")
	}
	// Validate before allocating a span or retaining any caller metadata.
	t.SpanID = "0000000000000001"
	if !validTrace(t) {
		return errors.New("invalid_trace_context")
	}
	var span [8]byte
	if _, err := rand.Read(span[:]); err != nil {
		return errors.New("trace_unavailable")
	}
	t.SpanID = hex.EncodeToString(span[:])
	if !traceHex(t.SpanID, 16) {
		return errors.New("trace_unavailable")
	}
	record.Trace = t
	w.Header().Set("X-GovWeave-Trace-ID", t.TraceID)
	w.Header().Set("X-GovWeave-Span-ID", t.SpanID)
	return nil
}

// Re-authentication after body reads may revoke the initial identity. Never
// retain its context on a record that no longer belongs to that application.
func rebindTrace(w http.ResponseWriter, record *CallRecord, initialApplicationID string) {
	if record.ApplicationID == "" || record.ApplicationID != initialApplicationID {
		record.Trace = nil
		w.Header().Del("X-GovWeave-Trace-ID")
		w.Header().Del("X-GovWeave-Span-ID")
	}
}

type TraceEdge struct {
	SourceSpanID string `json:"source_span_id"`
	TargetSpanID string `json:"target_span_id"`
	Relation     string `json:"relation"`
	Resolution   string `json:"resolution"`
}

type TraceSummary struct {
	Records              int `json:"records"`
	Completed            int `json:"completed"`
	Blocked              int `json:"blocked"`
	Failed               int `json:"failed"`
	InProgress           int `json:"in_progress"`
	Incomplete           int `json:"incomplete"`
	Redacted             int `json:"redacted"`
	UnknownDetection     int `json:"unknown_detection"`
	UnresolvedReferences int `json:"unresolved_references"`
	AmbiguousReferences  int `json:"ambiguous_references"`
}

type TraceRiskEvent struct {
	RequestID string `json:"request_id"`
	SpanID    string `json:"span_id"`
	Control   string `json:"control"`
	Result    string `json:"result"`
	Reason    string `json:"reason"`
}

type TraceView struct {
	SchemaVersion         int              `json:"schema_version"`
	TraceID               string           `json:"trace_id"`
	ApplicationIDs        []string         `json:"application_ids"`
	Coverage              string           `json:"coverage"`
	TaskCompletion        string           `json:"task_completion"`
	RelationshipSource    string           `json:"relationship_source"`
	HistoryMayBeTruncated bool             `json:"history_may_be_truncated"`
	WindowSaturated       bool             `json:"window_saturated"`
	ResultTruncated       bool             `json:"result_truncated"`
	AuditAvailable        bool             `json:"audit_available"`
	Records               []CallRecord     `json:"records"`
	Edges                 []TraceEdge      `json:"edges"`
	RiskEvents            []TraceRiskEvent `json:"risk_events"`
	Summary               TraceSummary     `json:"summary"`
}

// TraceView selects from the same global bounded index as the ordinary audit
// view. It never traverses caller edges or consults invisible applications.
func (a *Audit) TraceView(traceID string, applicationIDs []string, limit int) (TraceView, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if limit < 1 || limit > maxTraceRecords {
		limit = 100
	}
	v := TraceView{SchemaVersion: 1, TraceID: traceID, ApplicationIDs: slices.Clone(applicationIDs), Coverage: "gateway_calls_only",
		TaskCompletion: "not_determined", RelationshipSource: "caller_declared", HistoryMayBeTruncated: true,
		WindowSaturated: len(a.recent) == recentRequestLimit, AuditAvailable: !a.failed && a.size+a.reserved+2*maxAuditEventBytes <= AuditMaxBytes,
		Records: []CallRecord{}, Edges: []TraceEdge{}, RiskEvents: []TraceRiskEvent{}}
	for i := len(a.recent) - 1; i >= 0; i-- {
		r := a.recent[i]
		if r.Trace == nil || r.Trace.TraceID != traceID || !slices.Contains(applicationIDs, r.ApplicationID) {
			continue
		}
		if len(v.Records) == limit {
			v.ResultTruncated = true
			break
		}
		v.Records = append(v.Records, cloneCallRecord(r))
	}
	slices.Reverse(v.Records)
	v.summarize()
	return v, len(v.Records) != 0
}

func (v *TraceView) summarize() {
	spans := map[string]int{}
	for _, r := range v.Records {
		spans[r.Trace.SpanID]++
	}
	edge := func(source, target, relation string) {
		if target == "" {
			return
		}
		resolution := "unresolved"
		switch spans[target] {
		case 0:
			v.Summary.UnresolvedReferences++
		case 1:
			resolution = "observed"
		default:
			resolution = "ambiguous"
			v.Summary.AmbiguousReferences++
		}
		v.Edges = append(v.Edges, TraceEdge{source, target, relation, resolution})
	}
	for _, r := range v.Records {
		t := r.Trace
		v.Summary.Records++
		switch r.Outcome {
		case "completed":
			v.Summary.Completed++
		case "blocked":
			v.Summary.Blocked++
		case "failed", "cancelled", "rejected":
			v.Summary.Failed++
		case "in_progress":
			v.Summary.InProgress++
		case "incomplete":
			v.Summary.Incomplete++
		}
		add := func(control, result, reason string) {
			v.RiskEvents = append(v.RiskEvents, TraceRiskEvent{r.RequestID, t.SpanID, control, result, reason})
		}
		unknown := false
		if r.ErrorCode == "tool_not_allowed" || r.ErrorCode == "model_not_allowed" {
			add("authorization", "denied", r.ErrorCode)
		}
		if p := r.ContentPolicy; p != nil && (len(p.MatchedRules) > 0 || p.Result == "error") {
			add("credential_egress", p.Result, "credential_policy_result")
			unknown = p.Result == "error"
		}
		if p := r.OutputPolicy; p != nil {
			if p.Result == "redacted" && r.Outcome == "completed" {
				v.Summary.Redacted++
			}
			if len(p.MatchedCategories) > 0 || p.State == "unknown" {
				add("sensitive_output", p.Result, p.Reason)
			}
			unknown = unknown || p.State == "unknown"
		}
		if g := r.ToolGovernance; g != nil {
			if len(g.Content.RuleIDs) > 0 {
				add("tool_credentials", g.Decision, "credential_patterns_observed")
			}
			if p := g.InstructionPolicy; p != nil {
				if len(p.RuleIDs) > 0 || p.State == "unknown" {
					add("tool_instruction", p.Decision, p.State)
				}
				unknown = unknown || p.State == "unknown"
			}
		}
		if unknown {
			v.Summary.UnknownDetection++
		}
		edge(t.SpanID, t.ParentSpanID, "parent")
		for _, target := range t.Links {
			edge(t.SpanID, target, "link")
		}
		edge(t.SpanID, t.RetryOfSpanID, "retry_of")
	}
}

func traceQuery(r *http.Request, admin bool) (string, []string, int, bool) {
	traceID := r.PathValue("trace_id")
	if !traceHex(traceID, 32) || len(r.URL.RawQuery) > 2048 {
		return "", nil, 0, false
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return "", nil, 0, false
	}
	for key := range query {
		if key != "limit" && !(admin && key == "application_id") {
			return "", nil, 0, false
		}
	}
	limit := 100
	if raw, present := query["limit"]; present {
		if len(raw) != 1 || len(raw[0]) == 0 || len(raw[0]) > 3 {
			return "", nil, 0, false
		}
		var err error
		limit, err = strconv.Atoi(raw[0])
		if err != nil || limit < 1 || limit > maxTraceRecords {
			return "", nil, 0, false
		}
	}
	ids := query["application_id"]
	if admin {
		if len(ids) < 1 || len(ids) > 16 {
			return "", nil, 0, false
		}
		for i, id := range ids {
			if len(id) > 100 || id == "" || slices.Contains(ids[:i], id) {
				return "", nil, 0, false
			}
		}
	}
	return traceID, ids, limit, true
}

func (g *Engine) GetTrace(w http.ResponseWriter, r *http.Request) {
	if len(r.Header.Values("Authorization")) != 1 {
		failure(w, 401, "invalid_api_key", "")
		return
	}
	app, _, err := g.Store.Authenticate(r.Header.Get("Authorization"))
	if err != nil {
		failure(w, 401, "invalid_api_key", "")
		return
	}
	traceID, _, limit, ok := traceQuery(r, false)
	if !ok {
		failure(w, 400, "invalid_trace_query", "")
		return
	}
	view, found := g.Audit.TraceView(traceID, []string{app.ID}, limit)
	current, _, err := g.Store.Authenticate(r.Header.Get("Authorization"))
	if err != nil || current.ID != app.ID {
		failure(w, 401, "invalid_api_key", "")
		return
	}
	if !found {
		failure(w, 404, "trace_not_found", "")
		return
	}
	respond(w, 200, view)
}

// GetAdminTrace requires the server's administrator middleware. It deliberately
// has no implicit all-applications mode.
func (g *Engine) GetAdminTrace(w http.ResponseWriter, r *http.Request) {
	traceID, ids, limit, ok := traceQuery(r, true)
	if !ok {
		failure(w, 400, "invalid_trace_query", "")
		return
	}
	apps := g.Store.Snapshot().Applications
	for _, id := range ids {
		if !slices.ContainsFunc(apps, func(a Application) bool { return a.ID == id }) {
			failure(w, 400, "invalid_trace_query", "")
			return
		}
	}
	view, found := g.Audit.TraceView(traceID, ids, limit)
	if !found {
		failure(w, 404, "trace_not_found", "")
		return
	}
	respond(w, 200, view)
}
