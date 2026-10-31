package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

const tracingTestID = "1234567890abcdef1234567890abcdef"

var tracingTestHeaders = []string{
	"X-GovWeave-Trace-ID", "X-GovWeave-Parent-Span-ID", "X-GovWeave-Agent-ID",
	"X-GovWeave-Retry-Of", "X-GovWeave-Link-Span-IDs",
}

func tracingFixture(t *testing.T, calls *atomic.Int32) toolFixture {
	t.Helper()
	f := newToolFixture(t, func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		for _, header := range tracingTestHeaders {
			if len(r.Header.Values(header)) != 0 {
				t.Errorf("caller trace header forwarded upstream: %s", header)
			}
		}
		if r.URL.Path == "/v1/chat/completions" {
			return toolResponse(200, completion), nil
		}
		return toolResponse(200, `{"text":"synthetic benign answer"}`), nil
	})
	connection, err := f.g.Store.SaveConnection("", connectionInput("https://model.example/v1"))
	if err != nil {
		t.Fatal(err)
	}
	app, _, err := f.g.Store.SaveApplication(f.app.ID, ApplicationInput{Revision: f.app.Revision, Name: f.app.Name, AllowedConnections: []string{connection.ID}})
	if err != nil {
		t.Fatal(err)
	}
	f.app = app
	return f
}

func tracingRequest(path, key string, body io.Reader, headers http.Header) *http.Request {
	r := httptest.NewRequest(http.MethodPost, path, body)
	r.Header.Set("Authorization", "Bearer "+key)
	r.Header.Set("Content-Type", "application/json")
	for name, values := range headers {
		for _, value := range values {
			r.Header.Add(name, value)
		}
	}
	if strings.Contains(path, "/tools/") {
		r.SetPathValue("alias", "support")
	}
	return r
}

func tracingInvoke(g *Engine, path, key, body string, headers http.Header) *httptest.ResponseRecorder {
	r := tracingRequest(path, key, strings.NewReader(body), headers)
	w := httptest.NewRecorder()
	switch path {
	case "/v1/chat/completions":
		g.Chat(w, r)
	case "/v1/tools/support/invoke":
		g.ToolInvoke(w, r)
	case "/v1/content/evaluations":
		g.EvaluateContent(w, r)
	}
	return w
}

func tracingQuery(g *Engine, key, traceID, query string, admin bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/v1/traces/"+traceID+query, nil)
	r.SetPathValue("trace_id", traceID)
	r.Header.Set("Authorization", "Bearer "+key)
	w := httptest.NewRecorder()
	if admin {
		g.GetAdminTrace(w, r)
	} else {
		g.GetTrace(w, r)
	}
	return w
}

func tracingDecode(t *testing.T, w *httptest.ResponseRecorder) TraceView {
	t.Helper()
	var view TraceView
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &view) != nil {
		t.Fatalf("trace query failed: %d %s", w.Code, w.Body.String())
	}
	if view.Coverage != "gateway_calls_only" || view.TaskCompletion != "not_determined" || !view.HistoryMayBeTruncated {
		t.Fatal("bounded gateway evidence was presented as a complete task", w.Body.String())
	}
	return view
}

func TestTracingCapturesThreeCallPathsWithoutForwardingHeaders(t *testing.T) {
	var calls atomic.Int32
	f := tracingFixture(t, &calls)
	headers := http.Header{
		"X-GovWeave-Trace-ID":       {tracingTestID},
		"X-GovWeave-Agent-ID":       {"1111111111111111"},
		"X-GovWeave-Parent-Span-ID": {"2222222222222222"},
		"X-GovWeave-Retry-Of":       {"3333333333333333"},
		"X-GovWeave-Link-Span-IDs":  {"4444444444444444,5555555555555555"},
	}
	seen := map[string]bool{}
	for _, tc := range []struct{ path, body string }{
		{"/v1/chat/completions", chatBody("internal-assistant", false)},
		{"/v1/tools/support/invoke", `{"resource_id":"permitted-private-id"}`},
		{"/v1/content/evaluations", `{"text":"synthetic benign text"}`},
	} {
		w := tracingInvoke(f.g, tc.path, f.key, tc.body, headers)
		if w.Code != 200 {
			t.Fatalf("call failed: %s %d %s", tc.path, w.Code, w.Body.String())
		}
		record := waitRecord(t, f.g, w.Header().Get("X-Request-ID"))
		trace := record.Trace
		if trace == nil || trace.Version == "" || trace.TraceID != tracingTestID || len(trace.SpanID) != 16 || trace.SpanID == strings.Repeat("0", 16) || seen[trace.SpanID] {
			t.Fatal("missing or reused gateway trace span", record)
		}
		seen[trace.SpanID] = true
		if trace.ParentSpanID != "2222222222222222" || trace.AgentID != "1111111111111111" || trace.RetryOfSpanID != "3333333333333333" || len(trace.Links) != 2 {
			t.Fatal("declared relationship was not preserved", trace)
		}
		if w.Header().Get("X-GovWeave-Trace-ID") != trace.TraceID || w.Header().Get("X-GovWeave-Span-ID") != trace.SpanID {
			t.Fatal("response correlation disagrees with audit")
		}
		legacy := tracingInvoke(f.g, tc.path, f.key, tc.body, nil)
		if legacy.Code != 200 || legacy.Header().Get("X-GovWeave-Trace-ID") != "" || legacy.Header().Get("X-GovWeave-Span-ID") != "" || waitRecord(t, f.g, legacy.Header().Get("X-Request-ID")).Trace != nil {
			t.Fatal("legacy request unexpectedly enrolled in tracing")
		}
	}
	if calls.Load() != 4 {
		t.Fatal("content evaluation invoked provider or extra calls occurred", calls.Load())
	}
	view := tracingDecode(t, tracingQuery(f.g, f.key, tracingTestID, "", false))
	if len(view.Records) != 3 || len(view.Edges) != 12 {
		t.Fatal("model/tool/content trace did not preserve the selected calls")
	}
	for _, edge := range view.Edges {
		if edge.Resolution != "unresolved" {
			t.Fatal("unobserved caller dependency represented as observed", edge)
		}
	}
}

func TestTracingRejectsMalformedAndDuplicateContextBeforeProviderIO(t *testing.T) {
	var calls atomic.Int32
	f := tracingFixture(t, &calls)
	invalid := []http.Header{
		{"X-GovWeave-Trace-ID": {strings.Repeat("0", 32)}},
		{"X-GovWeave-Trace-ID": {strings.ToUpper(tracingTestID)}},
		{"X-GovWeave-Trace-ID": {"private-invalid-trace-must-not-be-retained"}},
		{"X-GovWeave-Trace-ID": {strings.Repeat("a", 4096)}},
		{"X-GovWeave-Trace-ID": {" " + tracingTestID}},
		{"X-GovWeave-Trace-ID": {""}},
		{"X-GovWeave-Trace-ID": {tracingTestID, tracingTestID}},
		{"X-GovWeave-Span-ID": {"1111111111111111"}},
		{"X-GovWeave-Trace-ID": {tracingTestID}, "X-GovWeave-Span-ID": {"1111111111111111"}},
		{"X-GovWeave-Agent-ID": {"1111111111111111"}},
		{"X-GovWeave-Trace-ID": {tracingTestID}, "X-GovWeave-Parent-Span-ID": {"bad-parent"}},
		{"X-GovWeave-Trace-ID": {tracingTestID}, "X-GovWeave-Agent-ID": {strings.Repeat("a", 17)}},
		{"X-GovWeave-Trace-ID": {tracingTestID}, "X-GovWeave-Retry-Of": {strings.Repeat("0", 16)}},
		{"X-GovWeave-Trace-ID": {tracingTestID}, "X-GovWeave-Link-Span-IDs": {"1111111111111111,1111111111111111"}},
		{"X-GovWeave-Trace-ID": {tracingTestID}, "X-GovWeave-Link-Span-IDs": {"1111111111111111,2222222222222222,3333333333333333,4444444444444444,5555555555555555"}},
		{"X-GovWeave-Trace-ID": {tracingTestID}, "X-GovWeave-Link-Span-IDs": {"1111111111111111,"}},
		{"X-GovWeave-Trace-ID": {tracingTestID}, "X-GovWeave-Parent-Span-ID": {"1111111111111111", "1111111111111111"}},
		{"X-GovWeave-Trace-ID": {tracingTestID}, "X-GovWeave-Link-Span-IDs": {"1111111111111111", "2222222222222222"}},
	}
	for i, headers := range invalid {
		for _, tc := range []struct{ path, body string }{
			{"/v1/chat/completions", chatBody("internal-assistant", false)},
			{"/v1/tools/support/invoke", `{"resource_id":"permitted-private-id"}`},
			{"/v1/content/evaluations", `{"text":"benign"}`},
		} {
			w := tracingInvoke(f.g, tc.path, f.key, tc.body, headers)
			if w.Code != 400 || !strings.Contains(w.Body.String(), `"invalid_trace_context"`) {
				t.Fatalf("bad context %d accepted on %s: %d %s", i, tc.path, w.Code, w.Body.String())
			}
			if waitRecord(t, f.g, w.Header().Get("X-Request-ID")).Trace != nil {
				t.Fatal("invalid caller trace was retained")
			}
		}
	}
	if calls.Load() != 0 {
		t.Fatal("malformed trace sent upstream", calls.Load())
	}
	data, err := os.ReadFile(filepath.Join(f.dir, "calls.jsonl"))
	if err != nil || bytes.Contains(data, []byte("private-invalid-trace")) || bytes.Contains(data, []byte("bad-parent")) {
		t.Fatal("invalid raw context leaked into audit")
	}
}

func TestTracingAuthenticationPrecedesCallerContext(t *testing.T) {
	var calls atomic.Int32
	f := tracingFixture(t, &calls)
	for _, path := range []string{"/v1/chat/completions", "/v1/tools/support/invoke", "/v1/content/evaluations"} {
		for _, traceID := range []string{tracingTestID, "invalid-private-trace"} {
			w := tracingInvoke(f.g, path, "invalid-key", `{}`, http.Header{"X-GovWeave-Trace-ID": {traceID}})
			if w.Code != 401 || !strings.Contains(w.Body.String(), `"invalid_api_key"`) || w.Header().Get("X-GovWeave-Trace-ID") != "" || w.Header().Get("X-GovWeave-Span-ID") != "" {
				t.Fatal("unauthenticated caller established a trace", path, w.Code, w.Header())
			}
			record := waitRecord(t, f.g, w.Header().Get("X-Request-ID"))
			if record.Trace != nil || record.ApplicationID != "" {
				t.Fatal("unauthenticated metadata retained as attributable trace evidence")
			}
		}
	}
	if calls.Load() != 0 {
		t.Fatal("unauthenticated trace invoked upstream")
	}
	if w := tracingQuery(f.g, "invalid-key", tracingTestID, "?limit=broken", false); w.Code != 401 {
		t.Fatal("trace query validated parameters before authenticating caller", w.Code)
	}
}

func TestTracingApplicationIsolationAndExplicitAdminJoin(t *testing.T) {
	var calls atomic.Int32
	f := tracingFixture(t, &calls)
	other, otherKey, err := f.g.Store.SaveApplication("", ApplicationInput{Name: "second-agent", AllowedConnections: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	_, outsiderKey, err := f.g.Store.SaveApplication("", ApplicationInput{Name: "unrelated-agent", AllowedConnections: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	headers := http.Header{"X-GovWeave-Trace-ID": {tracingTestID}}
	root := tracingInvoke(f.g, "/v1/content/evaluations", f.key, `{"text":"benign"}`, headers)
	parent := root.Header().Get("X-GovWeave-Span-ID")
	headers.Set("X-GovWeave-Parent-Span-ID", parent)
	child := tracingInvoke(f.g, "/v1/content/evaluations", otherKey, `{"text":"benign"}`, headers)
	if root.Code != 200 || child.Code != 200 {
		t.Fatal("agent calls failed")
	}
	private := tracingDecode(t, tracingQuery(f.g, otherKey, tracingTestID, "", false))
	if len(private.Records) != 1 || private.Records[0].ApplicationID != other.ID || len(private.Edges) != 1 || private.Edges[0].Resolution != "unresolved" {
		t.Fatal("application query crossed another application's namespace", private)
	}
	query := "?application_id=" + f.app.ID + "&application_id=" + other.ID
	shared := tracingDecode(t, tracingQuery(f.g, "", tracingTestID, query, true))
	if len(shared.Records) != 2 || len(shared.Edges) != 1 || shared.Edges[0].Resolution != "observed" || shared.Edges[0].SourceSpanID != child.Header().Get("X-GovWeave-Span-ID") || shared.Edges[0].TargetSpanID != parent {
		t.Fatal("explicitly selected administrator view did not resolve dependency", shared)
	}
	for _, traceID := range []string{tracingTestID, strings.Repeat("f", 32)} {
		w := tracingQuery(f.g, outsiderKey, traceID, "", false)
		if w.Code != 404 || !strings.Contains(w.Body.String(), `"trace_not_found"`) {
			t.Fatal("query exposed another application's trace existence", w.Code, w.Body.String())
		}
	}
	for _, tc := range []struct {
		query string
		admin bool
	}{
		{"?application_id=" + f.app.ID, false}, {"?limit=129", false}, {"?limit=0", false}, {"?limit=1&limit=2", false}, {"?unexpected=true", false},
		{"", true}, {"?application_id=" + f.app.ID + "&application_id=" + f.app.ID, true},
	} {
		if w := tracingQuery(f.g, f.key, tracingTestID, tc.query, tc.admin); w.Code != 400 {
			t.Fatalf("invalid trace query accepted: %s %t %d", tc.query, tc.admin, w.Code)
		}
	}
	if _, _, err := f.g.Store.ChangeKey(other.ID, other.Revision, true); err != nil {
		t.Fatal(err)
	}
	if w := tracingQuery(f.g, otherKey, tracingTestID, "", false); w.Code != 401 {
		t.Fatal("revoked application could query trace", w.Code)
	}
}

func TestTracingParallelBranchesFanInAndRetryRemainDistinct(t *testing.T) {
	var calls atomic.Int32
	f := tracingFixture(t, &calls)
	root := tracingInvoke(f.g, "/v1/content/evaluations", f.key, `{"text":"root"}`, http.Header{"X-GovWeave-Trace-ID": {tracingTestID}})
	rootSpan := root.Header().Get("X-GovWeave-Span-ID")
	const branches = 8
	spans := make(chan string, branches)
	var workers sync.WaitGroup
	for i := 0; i < branches; i++ {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			w := tracingInvoke(f.g, "/v1/content/evaluations", f.key, `{"text":"parallel"}`, http.Header{
				"X-GovWeave-Trace-ID": {tracingTestID}, "X-GovWeave-Parent-Span-ID": {rootSpan}, "X-GovWeave-Agent-ID": {fmt.Sprintf("%016x", i+1)},
			})
			if w.Code != 200 {
				t.Errorf("parallel call failed: %d %s", w.Code, w.Body.String())
			}
			spans <- w.Header().Get("X-GovWeave-Span-ID")
		}(i)
	}
	workers.Wait()
	close(spans)
	children := []string{}
	seen := map[string]bool{rootSpan: true}
	for span := range spans {
		if span == "" || seen[span] {
			t.Fatal("parallel requests reused or omitted a span")
		}
		seen[span] = true
		children = append(children, span)
	}
	headers := http.Header{"X-GovWeave-Trace-ID": {tracingTestID}, "X-GovWeave-Parent-Span-ID": {rootSpan}, "X-GovWeave-Link-Span-IDs": {children[0] + "," + children[1]}, "X-GovWeave-Retry-Of": {children[2]}}
	for i := 0; i < 2; i++ {
		w := tracingInvoke(f.g, "/v1/content/evaluations", f.key, `{"text":"fan-in"}`, headers)
		span := w.Header().Get("X-GovWeave-Span-ID")
		if w.Code != 200 || seen[span] {
			t.Fatal("repeat declaration deduplicated or reused gateway span")
		}
		seen[span] = true
	}
	view := tracingDecode(t, tracingQuery(f.g, f.key, tracingTestID, "", false))
	if len(view.Records) != branches+3 {
		t.Fatal("parallel trace lost a gateway call", len(view.Records))
	}
	relations := map[string]int{}
	for _, edge := range view.Edges {
		if edge.Resolution != "observed" {
			t.Fatal("visible declared dependency did not resolve", edge)
		}
		relations[edge.Relation]++
	}
	if relations["parent"] != branches+2 || relations["link"] != 4 || relations["retry_of"] != 2 {
		t.Fatal("fan-in/retry declarations conflated", relations)
	}
}

func TestTracingSecondAuthenticationClearsIdentityOnEveryCallPath(t *testing.T) {
	for _, path := range []string{"/v1/chat/completions", "/v1/tools/support/invoke", "/v1/content/evaluations"} {
		t.Run(path, func(t *testing.T) {
			var calls atomic.Int32
			f := tracingFixture(t, &calls)
			body := `{"text":"benign"}`
			if strings.Contains(path, "chat") {
				body = chatBody("internal-assistant", false)
			}
			if strings.Contains(path, "tools") {
				body = `{"resource_id":"permitted-private-id"}`
			}
			r := tracingRequest(path, f.key, &toolReadHook{Reader: strings.NewReader(body), hook: func() {
				if _, _, err := f.g.Store.ChangeKey(f.app.ID, f.app.Revision, false); err != nil {
					t.Fatal(err)
				}
			}}, http.Header{"X-GovWeave-Trace-ID": {tracingTestID}})
			w := httptest.NewRecorder()
			switch path {
			case "/v1/chat/completions":
				f.g.Chat(w, r)
			case "/v1/tools/support/invoke":
				f.g.ToolInvoke(w, r)
			case "/v1/content/evaluations":
				f.g.EvaluateContent(w, r)
			}
			if w.Code != 401 || calls.Load() != 0 || w.Header().Get("X-GovWeave-Trace-ID") != "" || w.Header().Get("X-GovWeave-Span-ID") != "" {
				t.Fatal("body-read rotation retained trace authority or reached provider", w.Code, w.Header())
			}
			record := waitRecord(t, f.g, w.Header().Get("X-Request-ID"))
			if record.Trace != nil || record.ApplicationID != "" {
				t.Fatal("invalidated identity retained trace ownership", record)
			}
		})
	}
}

func TestTracingCannotBypassAuthorizationOrAuditFailure(t *testing.T) {
	var calls atomic.Int32
	f := tracingFixture(t, &calls)
	headers := http.Header{"X-GovWeave-Trace-ID": {tracingTestID}}
	w := tracingInvoke(f.g, "/v1/tools/support/invoke", f.key, `{"resource_id":"forbidden-private-id"}`, headers)
	if w.Code != 403 || calls.Load() != 0 {
		t.Fatal("trace context granted resource access")
	}
	denied := waitRecord(t, f.g, w.Header().Get("X-Request-ID"))
	if denied.Trace == nil || denied.ErrorCode != "tool_not_allowed" || denied.UpstreamAttempted {
		t.Fatal("denied call did not retain attributable gateway evidence")
	}
	f.g.Audit.mu.Lock()
	f.g.Audit.failed = true
	f.g.Audit.mu.Unlock()
	w = tracingInvoke(f.g, "/v1/tools/support/invoke", f.key, `{"resource_id":"permitted-private-id"}`, headers)
	if w.Code != 503 || calls.Load() != 0 {
		t.Fatal("trace path bypassed audit admission")
	}
	var terminal toolFixture
	terminal = newToolFixture(t, func(*http.Request) (*http.Response, error) {
		terminal.g.Audit.mu.Lock()
		terminal.g.Audit.failed = true
		terminal.g.Audit.mu.Unlock()
		return toolResponse(200, `{"text":"must-never-be-released"}`), nil
	})
	w = tracingInvoke(terminal.g, "/v1/tools/support/invoke", terminal.key, `{"resource_id":"permitted-private-id"}`, headers)
	if w.Code != 503 || strings.Contains(w.Body.String(), "must-never-be-released") {
		t.Fatal("terminal trace audit failure released tool body")
	}
}

func TestTracingWindowRecoveryCloningAndAmbiguousDependencies(t *testing.T) {
	var calls atomic.Int32
	f := tracingFixture(t, &calls)
	w := tracingInvoke(f.g, "/v1/content/evaluations", f.key, `{"text":"benign"}`, http.Header{"X-GovWeave-Trace-ID": {tracingTestID}, "X-GovWeave-Link-Span-IDs": {"1111111111111111"}})
	base := waitRecord(t, f.g, w.Header().Get("X-Request-ID"))
	if base.Trace == nil {
		t.Fatal("missing trace")
	}
	base.Trace.Links[0] = "2222222222222222"
	if waitRecord(t, f.g, base.RequestID).Trace.Links[0] != "1111111111111111" {
		t.Fatal("audit view aliased trace links")
	}
	view, ok := f.g.Audit.TraceView(tracingTestID, []string{f.app.ID}, 100)
	if !ok || len(view.Records) != 1 {
		t.Fatal("trace record missing")
	}
	view.Records[0].Trace.Links[0] = "3333333333333333"
	view, _ = f.g.Audit.TraceView(tracingTestID, []string{f.app.ID}, 100)
	if view.Records[0].Trace.Links[0] != "1111111111111111" {
		t.Fatal("trace view aliased retained links")
	}

	dir := t.TempDir()
	var log bytes.Buffer
	for i := 0; i <= recentRequestLimit; i++ {
		record := cloneCallRecord(base)
		record.SchemaVersion, record.RequestID, record.Phase = 1, fmt.Sprintf("req_%022d", i), "finished"
		record.Trace.Links = nil
		record.Trace.SpanID = fmt.Sprintf("%016x", i+1)
		if i == 0 {
			record.Trace.TraceID = strings.Repeat("e", 32)
		}
		if i == recentRequestLimit {
			record.Phase, record.Outcome = "started", "in_progress"
			record.Trace.ParentSpanID = "0000000000000001"
		}
		encoded, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		log.Write(encoded)
		log.WriteByte('\n')
	}
	if err := os.WriteFile(filepath.Join(dir, "calls.jsonl"), log.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	audit, err := OpenAudit(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer audit.Close()
	view, ok = audit.TraceView(tracingTestID, []string{f.app.ID}, 128)
	if !ok || !view.WindowSaturated || !view.ResultTruncated || len(view.Records) != 128 || !view.HistoryMayBeTruncated {
		t.Fatal("bounded trace history not reported", view)
	}
	foundIncomplete, foundUnresolved := false, false
	for _, record := range view.Records {
		foundIncomplete = foundIncomplete || record.Outcome == "incomplete"
	}
	for _, edge := range view.Edges {
		foundUnresolved = foundUnresolved || edge.Resolution == "unresolved"
	}
	if !foundIncomplete || !foundUnresolved {
		t.Fatal("restart/window loss presented as complete evidence")
	}
	if _, ok := audit.TraceView(strings.Repeat("e", 32), []string{f.app.ID}, 128); ok {
		t.Fatal("evicted trace unexpectedly present in bounded window")
	}

	// Corrupt or colliding declared references cannot make the graph recurse or
	// silently choose one of several equally named gateway spans.
	audit.mu.Lock()
	first := cloneCallRecord(base)
	first.Trace.SpanID = "1111111111111111"
	first.Trace.ParentSpanID = "2222222222222222"
	first.Trace.Links = nil
	second := cloneCallRecord(first)
	second.RequestID = "req_duplicate_span"
	second.Trace.ParentSpanID = ""
	third := cloneCallRecord(base)
	third.Trace.SpanID = "2222222222222222"
	third.Trace.ParentSpanID = "1111111111111111"
	third.Trace.Links = nil
	audit.recent = []CallRecord{first, second, third}
	audit.mu.Unlock()
	view, _ = audit.TraceView(tracingTestID, []string{f.app.ID}, 100)
	ambiguous := 0
	for _, edge := range view.Edges {
		if edge.Resolution == "ambiguous" {
			ambiguous++
		}
	}
	if len(view.Records) != 3 || ambiguous == 0 {
		t.Fatal("ambiguous/cyclic caller references not bounded and distinguished", view)
	}
}

func TestTracingMaximumContextFitsDurableAuditReservation(t *testing.T) {
	var calls atomic.Int32
	f := tracingFixture(t, &calls)
	headers := http.Header{"X-GovWeave-Trace-ID": {tracingTestID}, "X-GovWeave-Parent-Span-ID": {"1111111111111111"}, "X-GovWeave-Agent-ID": {"2222222222222222"}, "X-GovWeave-Retry-Of": {"3333333333333333"}, "X-GovWeave-Link-Span-IDs": {"4444444444444444,5555555555555555,6666666666666666,7777777777777777"}}
	w := tracingInvoke(f.g, "/v1/tools/support/invoke", f.key, `{"resource_id":"permitted-private-id"}`, headers)
	if w.Code != 200 {
		t.Fatal("maximal trace rejected", w.Code)
	}
	record := waitRecord(t, f.g, w.Header().Get("X-Request-ID"))
	if record.Trace == nil || len(record.Trace.Links) != 4 {
		t.Fatal("maximum trace not retained")
	}
	rules := []string{"private_key", "api_key", "email_address", "cn_mobile_phone", "normalized_private_key", "normalized_api_key", "normalized_email_address", "normalized_cn_mobile_phone", "formatted_email_address"}
	for _, rule := range append([]string{}, rules...) {
		rules = append(rules, "base64_"+rule)
	}
	policy := &OutputAssessment{ID: "sensitive-output", Revision: 127, DetectorVersion: "sensitive-text-v3", Mode: "redact", Result: "redacted", State: "observed", Reason: "patterns_observed", Categories: []string{"credential", "email", "phone"}, MatchedCategories: []string{"credential", "email", "phone"}, MatchedRules: rules, CheckDurationUS: 9999999999, PublicEmailExceptions: 32,
		Redaction: &RedactionEvidence{Version: "sensitive-redaction-v1", Scope: "full_output", Replacements: 1, CheckDurationUS: 9999999999}}
	record.OutputPolicy, record.ToolGovernance.OutputPolicy = policy, policy
	record.ToolGovernance.Content = ToolContent{State: "observed", RuleIDs: []string{"private_key", "api_key"}}
	record.ToolGovernance.OutputMode, record.ToolGovernance.Decision = "observe", "redact"
	record.ToolGovernance.Reasons = []string{"resource_grant_allowed", "content_redacted"}
	// Use the actual representation for the longest instruction review fields.
	encodedInstruction := `{"version":"tool-instructions-v2","mode":"observe","state":"observed","rule_ids":["task_override","authority_spoof","role_delimiter","answer_manipulation"],"duration_us":9999999999,"decision":"allow","review":{"version":"exact-instruction-review-v1","state":"matched","exempted_rule_ids":["task_override","authority_spoof","role_delimiter","answer_manipulation"]}}`
	if err := json.Unmarshal([]byte(encodedInstruction), &record.ToolGovernance.InstructionPolicy); err != nil {
		t.Fatal(err)
	}
	record.Timestamp, record.StartedAt = "2026-10-29T14:00:00.123456789Z", "2026-10-29T14:00:00.123456789Z"
	encoded, err := json.Marshal(record)
	if err != nil || len(encoded)+1 > int(maxAuditEventBytes) {
		t.Fatalf("maximal trace plus output/instruction evidence exceeds reserved audit bytes: %d > %d", len(encoded)+1, maxAuditEventBytes)
	}
	audit, err := OpenAudit(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer audit.Close()
	if err := audit.Begin(record); err != nil {
		t.Fatal("trace admission exceeds reservation", err)
	}
	if err := audit.Finish(record); err != nil {
		t.Fatal("trace terminal evidence exceeds reservation", err)
	}
}

func TestTracingRejectsInvalidDurableContext(t *testing.T) {
	var calls atomic.Int32
	f := tracingFixture(t, &calls)
	w := tracingInvoke(f.g, "/v1/content/evaluations", f.key, `{"text":"benign"}`, http.Header{"X-GovWeave-Trace-ID": {tracingTestID}})
	base := waitRecord(t, f.g, w.Header().Get("X-Request-ID"))
	for name, corrupt := range map[string]func(*CallRecord){
		"missing_application": func(r *CallRecord) { r.ApplicationID = "" },
		"unknown_version":     func(r *CallRecord) { r.Trace.Version = "unknown-future-version" },
		"invalid_trace":       func(r *CallRecord) { r.Trace.TraceID = strings.Repeat("0", 32) },
		"invalid_span":        func(r *CallRecord) { r.Trace.SpanID = "caller-text" },
		"duplicate_links": func(r *CallRecord) {
			r.Trace.Links = []string{"1111111111111111", "1111111111111111"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			record := cloneCallRecord(base)
			corrupt(&record)
			dir := t.TempDir()
			data, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "calls.jsonl"), append(data, '\n'), 0600); err != nil {
				t.Fatal(err)
			}
			if audit, err := OpenAudit(dir); err == nil {
				audit.Close()
				t.Fatal("restart accepted corrupt or unattributed trace context")
			}
			audit, err := OpenAudit(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer audit.Close()
			if err := audit.Begin(record); err == nil {
				t.Fatal("audit accepted invalid trace evidence")
			}
		})
	}
}
