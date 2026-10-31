package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"govweave/internal/sensitive"
)

func enableOutput(t *testing.T, g *Engine, mode string, categories, apps []string) OutputPolicySnapshot {
	t.Helper()
	p, err := g.OutputPolicies.Save(OutputPolicyInput{Revision: g.OutputPolicies.Snapshot().Revision, Mode: mode, Categories: categories, ApplicationIDs: apps}, g.Store.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func evaluateText(g *Engine, key, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/v1/content/evaluations", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+key)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	g.EvaluateContent(w, r)
	return w
}

func TestContentEvaluationReportsEvidenceWithoutRawContent(t *testing.T) {
	f := newToolFixture(t, func(*http.Request) (*http.Response, error) {
		t.Fatal("standalone evaluation used upstream")
		return nil, nil
	})
	secret := "sk-" + strings.Repeat("z", 30)
	text := "Contact: synthetic@example.com 手机：13800138000 " + secret
	body, _ := json.Marshal(map[string]string{"text": text})
	enableOutput(t, f.g, "block", []string{"credential", "email", "phone"}, nil)
	w := evaluateText(f.g, f.key, string(body))
	var result struct {
		Detection sensitive.Result `json:"detection"`
		Policy    OutputAssessment `json:"policy"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Policy.Result != "block" || len(result.Policy.MatchedCategories) != 3 || result.Detection.State != "observed" {
		t.Fatal("wrong explicit evaluation", w.Code, w.Body.String())
	}
	for _, finding := range result.Detection.Findings {
		if finding.StartByte < 0 || finding.EndByte > len(text) || finding.EndByte <= finding.StartByte {
			t.Fatal("invalid byte evidence")
		}
	}
	record := waitRecord(t, f.g, w.Header().Get("X-Request-ID"))
	if record.UpstreamAttempted || record.Operation != "content.evaluate" || record.OutputPolicy.Revision != 1 {
		t.Fatal("wrong inspection audit")
	}
	audit, _ := os.ReadFile(filepath.Join(f.dir, "calls.jsonl"))
	for _, value := range []string{secret, "synthetic@example.com", "13800138000", "start_byte", "end_byte"} {
		if strings.Contains(string(audit), value) {
			t.Fatal("raw content/offsets persisted")
		}
		if value != "start_byte" && value != "end_byte" && strings.Contains(w.Body.String(), value) {
			t.Fatal("text echoed")
		}
	}
	// Detection and policy selection remain distinct.
	enableOutput(t, f.g, "observe", []string{"phone"}, nil)
	w = evaluateText(f.g, f.key, `{"text":"synthetic@example.com"}`)
	if json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Detection.State != "observed" || result.Policy.Result != "allow" {
		t.Fatal("unselected category enforced")
	}
	if evaluateText(f.g, "invalid", `{"text":"hello"}`).Code != 401 {
		t.Fatal("unauthenticated inspection")
	}
	for _, bad := range []string{`{"text":"one","text":"two"}`, `{"text":null}`, `{"text":"hello","application_id":"forged"}`, `{"text":"hello"} {}`} {
		if evaluateText(f.g, f.key, bad).Code != 400 {
			t.Fatal("invalid evaluation input accepted")
		}
	}
	body, _ = json.Marshal(map[string]string{"text": strings.Repeat("x", 8193)})
	if evaluateText(f.g, f.key, string(body)).Code != 413 {
		t.Fatal("text limit ignored")
	}
	if evaluateText(f.g, f.key, strings.Repeat(" ", maxToolEnvelopeBytes+1)).Code != 413 {
		t.Fatal("envelope limit ignored")
	}
	f.g.Audit.mu.Lock()
	f.g.Audit.failed = true
	f.g.Audit.mu.Unlock()
	if evaluateText(f.g, f.key, `{"text":"hello"}`).Code != 503 {
		t.Fatal("audit unavailable allowed inspection")
	}
}

func completionText(text, finish string) string {
	data, _ := json.Marshal(map[string]any{"id": "provider-private-id", "model": "provider-private-model", "choices": []any{map[string]any{"finish_reason": finish, "message": map[string]string{"role": "assistant", "content": text}}}})
	return string(data)
}

func TestModelOutputProtectionAndUnsupportedStreaming(t *testing.T) {
	for _, content := range []string{"synthetic@example.com", "手机号：13800138000", "sk-" + strings.Repeat("q", 30)} {
		t.Run(content[:3], func(t *testing.T) {
			var calls atomic.Int32
			f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, completionText(content, "stop"))
			})
			enableOutput(t, f.engine, "block", []string{"credential", "email", "phone"}, nil)
			w := f.call(f.key, chatBody("internal-assistant", false))
			if w.Code != 403 || strings.Contains(w.Body.String(), content) {
				t.Fatal("model output escaped", w.Code)
			}
			record := waitRecord(t, f.engine, w.Header().Get("X-Request-ID"))
			if record.OutputPolicy.Result != "block" || !record.UpstreamAttempted || record.Outcome != "blocked" {
				t.Fatal("block evidence missing")
			}
			if f.call(f.key, chatBody("internal-assistant", true)).Code != 400 || calls.Load() != 1 {
				t.Fatal("stream bypass or upstream sent")
			}
			enableOutput(t, f.engine, "observe", []string{"credential", "email", "phone"}, nil)
			w = f.call(f.key, chatBody("internal-assistant", false))
			if w.Code != 200 || !strings.Contains(w.Body.String(), content) || strings.Contains(w.Body.String(), "provider-private") {
				t.Fatal("observe/canonical projection failed", w.Code)
			}
			if waitRecord(t, f.engine, w.Header().Get("X-Request-ID")).OutputPolicy.Result != "observe" {
				t.Fatal("observe metadata missing")
			}
		})
	}
}

func TestProtectedModelProjectionDropsUncheckedChannels(t *testing.T) {
	content := `{"id":"synthetic@example.com","model":"13800138000","private_extension":"secret-extension","choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"ordinary answer","reasoning_content":"private-chain"},"extra":"private-choice"}],"usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3,"extra":"private-usage"}}`
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, content)
	})
	enableOutput(t, f.engine, "block", []string{"credential", "email", "phone"}, nil)
	w := f.call(f.key, chatBody("internal-assistant", false))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "ordinary answer") {
		t.Fatal("clean protected answer failed", w.Code)
	}
	for _, value := range []string{"synthetic@example.com", "13800138000", "secret-extension", "private-chain", "private-choice", "private-usage"} {
		if strings.Contains(w.Body.String(), value) {
			t.Fatal("unchecked provider field escaped")
		}
	}
}

func TestProtectedModelUnknownOutputIsWithheldInObserve(t *testing.T) {
	for _, body := range []string{
		completionText("partial answer", "length"), completionText(strings.Repeat("x", 8193), "stop"),
		completionText(strings.Repeat("synthetic@example.com ", 40), "stop"),
		`{"choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","content":null,"tool_calls":[{"function":{"arguments":"private-tool-args"}}]}}]}`,
		`{"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"ok","tool_calls":[{}]}}]}`,
	} {
		f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, body)
		})
		enableOutput(t, f.engine, "observe", []string{"email"}, nil)
		w := f.call(f.key, chatBody("internal-assistant", false))
		if w.Code != 502 || strings.Contains(w.Body.String(), "private-tool-args") {
			t.Fatal("unknown output released", w.Code)
		}
		if waitRecord(t, f.engine, w.Header().Get("X-Request-ID")).OutputPolicy.Result != "error" {
			t.Fatal("unknown treated as clean")
		}
	}
}

func TestProtectedCallPinsPolicyAndFailsClosedBeforeRelease(t *testing.T) {
	var f fixture
	f = newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		enableOutput(t, f.engine, "observe", []string{"email"}, nil)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, completionText("synthetic@example.com", "stop"))
	})
	enableOutput(t, f.engine, "block", []string{"email"}, nil)
	w := f.call(f.key, chatBody("internal-assistant", false))
	if w.Code != 403 || waitRecord(t, f.engine, w.Header().Get("X-Request-ID")).OutputPolicy.Revision != 1 {
		t.Fatal("in-flight policy changed")
	}
	var broken fixture
	broken = newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		broken.engine.Audit.mu.Lock()
		broken.engine.Audit.failed = true
		broken.engine.Audit.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, completionText("private-benign-answer", "stop"))
	})
	enableOutput(t, broken.engine, "block", []string{"email"}, nil)
	w = broken.call(broken.key, chatBody("internal-assistant", false))
	if w.Code != 503 || strings.Contains(w.Body.String(), "private-benign-answer") {
		t.Fatal("terminal audit failure released model text")
	}
}

func TestToolSharesOutputPolicyWithoutWeakeningCredentialGuard(t *testing.T) {
	content := "synthetic@example.com"
	f := newToolFixture(t, func(*http.Request) (*http.Response, error) {
		data, _ := json.Marshal(map[string]string{"text": content})
		return toolResponse(200, string(data)), nil
	})
	enableOutput(t, f.g, "block", []string{"email"}, nil)
	w := f.call(f.key, "support", `{"resource_id":"permitted-private-id"}`)
	if w.Code != 403 || strings.Contains(w.Body.String(), content) {
		t.Fatal("tool email escaped")
	}
	record := waitRecord(t, f.g, w.Header().Get("X-Request-ID"))
	if record.ToolGovernance.OutputPolicy.Result != "block" || record.OutputPolicy.Result != "block" {
		t.Fatal("tool evidence missing")
	}
	enableOutput(t, f.g, "observe", []string{"email"}, nil)
	w = f.call(f.key, "support", `{"resource_id":"permitted-private-id"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), content) {
		t.Fatal("tool observe failed")
	}
	content = "sk-" + strings.Repeat("q", 30)
	w = f.call(f.key, "support", `{"resource_id":"permitted-private-id"}`)
	if w.Code != 403 || !strings.Contains(w.Body.String(), "tool_output_blocked") {
		t.Fatal("new policy weakened legacy credential block")
	}
	content = strings.Repeat("synthetic@example.com ", 40)
	if f.call(f.key, "support", `{"resource_id":"permitted-private-id"}`).Code != 502 {
		t.Fatal("unknown tool output released")
	}
}

func TestInspectionRechecksKeyAndCancellation(t *testing.T) {
	f := newToolFixture(t, func(*http.Request) (*http.Response, error) { t.Fatal("unexpected upstream"); return nil, nil })
	r := httptest.NewRequest("POST", "/v1/content/evaluations", &toolReadHook{Reader: strings.NewReader(`{"text":"hello"}`), hook: func() {
		if _, _, err := f.g.Store.ChangeKey(f.app.ID, f.app.Revision, false); err != nil {
			t.Fatal(err)
		}
	}})
	r.Header.Set("Authorization", "Bearer "+f.key)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.g.EvaluateContent(w, r)
	if w.Code != 401 {
		t.Fatal("rotated key admitted")
	}
	fresh := newToolFixture(t, func(*http.Request) (*http.Response, error) {
		t.Fatal("cancelled inspection used upstream")
		return nil, nil
	})
	enableOutput(t, fresh.g, "block", []string{"email"}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r = httptest.NewRequest("POST", "/v1/content/evaluations", strings.NewReader(`{"text":"synthetic@example.com"}`)).WithContext(ctx)
	r.Header.Set("Authorization", "Bearer "+fresh.key)
	r.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	fresh.g.EvaluateContent(w, r)
	if w.Code != 499 || !strings.Contains(w.Body.String(), "client_cancelled") || strings.Contains(w.Body.String(), `"detection"`) {
		t.Fatal("cancelled inspection returned an assessment", w.Code, w.Body.String())
	}
	record := waitRecord(t, fresh.g, w.Header().Get("X-Request-ID"))
	if record.Outcome != "cancelled" || record.ErrorCode != "client_cancelled" || record.UpstreamAttempted || record.OutputPolicy != nil {
		t.Fatal("cancelled inspection has incorrect audit metadata")
	}
	if len(fresh.g.slots) != 0 {
		t.Fatal("cancelled inspection leaked a concurrency slot")
	}
}

func TestOutputPolicyScopePreservesUnprotectedModelResponses(t *testing.T) {
	body := completionText("synthetic@example.com", "stop")
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, body)
	})
	assertUnprotected := func() {
		t.Helper()
		w := f.call(f.key, chatBody("internal-assistant", false))
		if w.Code != 200 || w.Body.String() != body || w.Header().Get("X-GovWeave-Output-Policy-Revision") != "" {
			t.Fatal("unprotected application response changed", w.Code)
		}
		if waitRecord(t, f.engine, w.Header().Get("X-Request-ID")).OutputPolicy != nil {
			t.Fatal("unprotected response claimed output assessment")
		}
	}
	// Protection starts disabled. Enabling it for another application must not
	// silently enroll this application's existing integrations.
	assertUnprotected()
	app, key, err := f.engine.Store.SaveApplication("", ApplicationInput{Name: "protected-app", AllowedConnections: []string{f.connection.ID}})
	if err != nil {
		t.Fatal(err)
	}
	enableOutput(t, f.engine, "block", []string{"email"}, []string{app.ID})
	assertUnprotected()
	w := f.call(key, chatBody("internal-assistant", false))
	if w.Code != 403 || strings.Contains(w.Body.String(), "synthetic@example.com") {
		t.Fatal("scoped application escaped protection", w.Code)
	}
	record := waitRecord(t, f.engine, w.Header().Get("X-Request-ID"))
	if record.ApplicationID != app.ID || record.OutputPolicy == nil || record.OutputPolicy.Result != "block" {
		t.Fatal("scoped application assessment missing")
	}
}

func TestProtectedToolRejectsMalformedEscapedUnicode(t *testing.T) {
	for _, mode := range []string{"observe", "block"} {
		t.Run(mode, func(t *testing.T) {
			body := `{"text":"\ud800"}`
			f := newToolFixture(t, func(*http.Request) (*http.Response, error) {
				return toolResponse(200, body), nil
			})
			enableOutput(t, f.g, mode, []string{"email"}, nil)
			for _, invalid := range []string{`{"text":"\ud800"}`, `{"text":"\udc00"}`} {
				body = invalid
				w := f.call(f.key, "support", `{"resource_id":"permitted-private-id"}`)
				if w.Code != 502 || !strings.Contains(w.Body.String(), "content_output_unavailable") || strings.Contains(w.Body.String(), `"text"`) {
					t.Fatal("malformed Unicode released as assessed tool text", w.Code)
				}
				record := waitRecord(t, f.g, w.Header().Get("X-Request-ID"))
				if record.OutputPolicy == nil || record.OutputPolicy.Result != "error" || record.OutputPolicy.State != "unknown" {
					t.Fatal("malformed Unicode treated as clean")
				}
			}
			body = `{"text":"\ud83d\ude00"}`
			if w := f.call(f.key, "support", `{"resource_id":"permitted-private-id"}`); w.Code != 200 || !strings.Contains(w.Body.String(), "😀") {
				t.Fatal("valid surrogate pair rejected", w.Code)
			}
		})
	}
}
