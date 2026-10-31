package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type toolRoundTripper func(*http.Request) (*http.Response, error)

func (f toolRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type toolFixture struct {
	g     *Engine
	app   Application
	key   string
	dir   string
	tool  Tool
	input ToolInput
}

func newToolFixture(t *testing.T, transport toolRoundTripper) toolFixture {
	t.Helper()
	dir := t.TempDir()
	g, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.Close() })
	g.client = &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	app, key, err := g.Store.SaveApplication("", ApplicationInput{Name: "tool-only", AllowedConnections: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	credential := "upstream-tool-private"
	input := ToolInput{Name: "Read guide", Alias: "support", Endpoint: "https://tool.example/read", APIKey: &credential,
		Enabled: true, TimeoutSeconds: 1, OutputMode: "block", Resources: []ToolResource{
			{ID: "permitted-private-id", Sensitivity: "internal", AllowedApplications: []string{app.ID}},
			{ID: "forbidden-private-id", Sensitivity: "restricted", AllowedApplications: []string{}},
		}}
	tool, err := g.Tools.Save("", input)
	if err != nil {
		t.Fatal(err)
	}
	return toolFixture{g: g, app: app, key: key, dir: dir, tool: tool, input: input}
}

func toolResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
}

func (f toolFixture) call(key, alias, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/v1/tools/"+alias+"/invoke", strings.NewReader(body))
	r.SetPathValue("alias", alias)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+key)
	r.Header.Set("Cookie", "private-cookie")
	r.Header.Set("X-User-ID", "private-user")
	r.Header.Set("Idempotency-Key", "private-idempotency")
	w := httptest.NewRecorder()
	f.g.ToolInvoke(w, r)
	return w
}

func TestToolInvokeControlsExecutionAndOutput(t *testing.T) {
	calls := 0
	output := "a private benign answer"
	f := newToolFixture(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != "https://tool.example/read" || r.Method != "POST" || r.GetBody != nil || r.Header.Get("Authorization") != "Bearer upstream-tool-private" {
			t.Error("incorrect routing, credential or replay configuration")
		}
		for _, name := range []string{"Cookie", "X-User-ID", "Idempotency-Key"} {
			if r.Header.Get(name) != "" {
				t.Error("forwarded caller header", name)
			}
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != `{"resource_id":"permitted-private-id"}` {
			t.Error("unexpected tool arguments")
		}
		data, _ := json.Marshal(map[string]string{"text": output})
		response := toolResponse(200, string(data))
		response.Header.Set("Set-Cookie", "provider-private-cookie")
		return response, nil
	})
	w := f.call(f.key, "support", `{"resource_id":"permitted-private-id"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), output) || w.Header().Get("Set-Cookie") != "" {
		t.Fatal("authorized tool read failed", w.Code)
	}
	record := waitRecord(t, f.g, w.Header().Get("X-Request-ID"))
	if record.ToolGovernance.Decision != "allow" || record.ToolGovernance.Content.State != "not_observed" || record.ToolGovernance.SnapshotSHA256 != f.tool.SnapshotSHA256 || record.Operation != "tools.invoke" || record.FirstByteMS == nil {
		t.Fatalf("incorrect decision metadata: %+v", record)
	}
	for _, tc := range []struct {
		key, alias, body string
		status           int
	}{
		{f.key, "support", `{"resource_id":"forbidden-private-id"}`, 403},
		{f.key, "support", `{"resource_id":"unknown-private-id"}`, 403},
		{f.key, "missing", `{"resource_id":"permitted-private-id"}`, 403},
		{"invalid", "support", `{"resource_id":"permitted-private-id"}`, 401},
		{f.key, "support", `{"resource_id":"permitted-private-id","application_id":"spoofed"}`, 400},
	} {
		if w := f.call(tc.key, tc.alias, tc.body); w.Code != tc.status {
			t.Fatalf("got %d, want %d", w.Code, tc.status)
		}
	}
	if calls != 1 {
		t.Fatal("unauthorized call reached tool")
	}
	output = "sk-" + strings.Repeat("A", 30)
	w = f.call(f.key, "support", `{"resource_id":"permitted-private-id"}`)
	if w.Code != 403 || strings.Contains(w.Body.String(), output) || calls != 2 {
		t.Fatal("credential output was not withheld")
	}
	record = waitRecord(t, f.g, w.Header().Get("X-Request-ID"))
	if record.ToolGovernance.Content.State != "observed" || record.ToolGovernance.Content.RuleIDs[0] != "api_key" || !record.UpstreamAttempted || record.Outcome != "blocked" {
		t.Fatal("missing output-block evidence")
	}
	data, err := os.ReadFile(filepath.Join(f.dir, "calls.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{f.key, output, "a private benign answer", "upstream-tool-private", "tool.example", "private-id", "private-cookie", "private-user", "spoofed"} {
		if strings.Contains(string(data), secret) {
			t.Fatal("sensitive value in audit")
		}
	}
	// A tool-only identity must not accidentally gain model access.
	if _, err := f.g.Store.Resolve("Bearer "+f.key, "anything"); !errors.Is(err, ErrDenied) {
		t.Fatal("tool-only identity gained model access")
	}
	if _, err := OpenStore(f.dir); err != nil {
		t.Fatal("tool-only identity failed restart", err)
	}
}

func TestToolInvalidArgumentsNeverExecute(t *testing.T) {
	f := newToolFixture(t, func(*http.Request) (*http.Response, error) { t.Fatal("invalid request executed"); return nil, nil })
	for _, body := range []string{`null`, `{}`, `{"resource_id":null}`, `{"resource_id":1}`, `{"resource_id":"../read"}`, `{"Resource_id":"permitted-private-id"}`, `{"resource_id":"permitted-private-id","resource_id":"forbidden-private-id"}`, `{"resource_id":"permitted-private-id"} {}`, `{"resource_id":"` + string([]byte{0xff}) + `"}`} {
		if w := f.call(f.key, "support", body); w.Code != 400 {
			t.Fatal("invalid argument accepted", w.Code)
		}
	}
	if w := f.call(f.key, "support", strings.Repeat(" ", maxToolRequestBytes+1)); w.Code != 413 {
		t.Fatal("request bound not enforced")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{"resource_id":"permitted-private-id"}`)).WithContext(ctx)
	r.SetPathValue("alias", "support")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+f.key)
	w := httptest.NewRecorder()
	f.g.ToolInvoke(w, r)
	if w.Code != 499 {
		t.Fatal("cancelled request admitted")
	}
}

func TestToolUnknownOutputFailsClosedEvenInObserve(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"missing", `{}`, 200}, {"null", `{"text":null}`, 200}, {"array", `{"text":[]}`, 200},
		{"extra", `{"text":"private-response","extra":1}`, 200},
		{"duplicate", `{"text":"first","text":"second"}`, 200},
		{"trailing", `{"text":"private-response"} {}`, 200},
		{"invalid utf8", `{"text":"` + string([]byte{0xff}) + `"}`, 200},
		{"oversize text", `{"text":"` + strings.Repeat("a", maxToolTextBytes+1) + `"}`, 200},
		{"oversize envelope", strings.Repeat(" ", maxToolEnvelopeBytes+1), 200},
		{"provider error", `{"text":"private-response"}`, 500},
		{"redirect", `{"text":"private-response"}`, 307},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			f := newToolFixture(t, func(*http.Request) (*http.Response, error) { calls++; return toolResponse(tc.status, tc.body), nil })
			f.input.Revision, f.input.OutputMode = f.tool.Revision, "observe"
			if _, err := f.g.Tools.Save(f.tool.ID, f.input); err != nil {
				t.Fatal(err)
			}
			w := f.call(f.key, "support", `{"resource_id":"permitted-private-id"}`)
			if w.Code != 502 || strings.Contains(w.Body.String(), "private-response") || calls != 1 {
				t.Fatal("invalid output escaped", w.Code)
			}
			record := waitRecord(t, f.g, w.Header().Get("X-Request-ID"))
			if record.ToolGovernance.Content.State != "unknown" || record.ToolGovernance.Decision != "block" {
				t.Fatal("unknown treated as clean")
			}
		})
	}
}

func TestToolObserveAndImmutableInFlightSnapshot(t *testing.T) {
	secret := "-----BEGIN PRIVATE KEY-----"
	var f toolFixture
	var started CallRecord
	f = newToolFixture(t, func(*http.Request) (*http.Response, error) {
		started = f.g.Audit.View(1, "").Records[0]
		f.input.Revision, f.input.OutputMode = f.g.Tools.Snapshot().Revision, "observe"
		if _, err := f.g.Tools.Save(f.tool.ID, f.input); err != nil {
			t.Fatal(err)
		}
		return toolResponse(200, `{"text":"`+secret+`"}`), nil
	})
	w := f.call(f.key, "support", `{"resource_id":"permitted-private-id"}`)
	if w.Code != 403 {
		t.Fatal("configuration edit changed admitted output policy")
	}
	record := waitRecord(t, f.g, w.Header().Get("X-Request-ID"))
	if record.ToolGovernance.ToolRevision != f.tool.Revision || started.ToolGovernance.Content.State != "unknown" || started.ToolGovernance.Decision != "pending" {
		t.Fatal("immutable call or audit snapshot changed")
	}
	w = f.call(f.key, "support", `{"resource_id":"permitted-private-id"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), secret) {
		t.Fatal("observe failed to release with evidence")
	}
	record = waitRecord(t, f.g, w.Header().Get("X-Request-ID"))
	if record.ToolGovernance.Decision != "observe" || record.ToolGovernance.Content.State != "observed" {
		t.Fatal("missing observe evidence")
	}
	// Audit consumers cannot mutate retained metadata.
	record.ToolGovernance.Content.RuleIDs[0] = "changed"
	if f.g.Audit.View(1, "").Records[0].ToolGovernance.Content.RuleIDs[0] != "private_key" {
		t.Fatal("audit view aliases storage")
	}
}

func TestToolAuditAndCapacityFailClosed(t *testing.T) {
	for _, phase := range []string{"before_admission", "before_release", "capacity"} {
		t.Run(phase, func(t *testing.T) {
			calls := 0
			var f toolFixture
			f = newToolFixture(t, func(*http.Request) (*http.Response, error) {
				calls++
				f.g.Audit.mu.Lock()
				f.g.Audit.failed = true
				f.g.Audit.mu.Unlock()
				return toolResponse(200, `{"text":"private-response"}`), nil
			})
			want, wantCalls := 503, 0
			if phase == "before_admission" {
				f.g.Audit.mu.Lock()
				f.g.Audit.failed = true
				f.g.Audit.mu.Unlock()
			}
			if phase == "before_release" {
				wantCalls = 1
			}
			if phase == "capacity" {
				want = 429
				for i := 0; i < cap(f.g.slots); i++ {
					f.g.slots <- struct{}{}
				}
			}
			w := f.call(f.key, "support", `{"resource_id":"permitted-private-id"}`)
			if w.Code != want || calls != wantCalls || strings.Contains(w.Body.String(), "private-response") {
				t.Fatal("fail-closed boundary failed", w.Code, calls)
			}
		})
	}
}

type toolReadHook struct {
	io.Reader
	hook func()
}

func (r *toolReadHook) Read(p []byte) (int, error) {
	if r.hook != nil {
		hook := r.hook
		r.hook = nil
		hook()
	}
	return r.Reader.Read(p)
}

func TestToolRechecksKeyAfterReadingArguments(t *testing.T) {
	f := newToolFixture(t, func(*http.Request) (*http.Response, error) { t.Fatal("rotated key executed tool"); return nil, nil })
	r := httptest.NewRequest("POST", "/", &toolReadHook{Reader: strings.NewReader(`{"resource_id":"permitted-private-id"}`), hook: func() {
		if _, _, err := f.g.Store.ChangeKey(f.app.ID, f.app.Revision, false); err != nil {
			t.Fatal(err)
		}
	}})
	r.SetPathValue("alias", "support")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+f.key)
	w := httptest.NewRecorder()
	f.g.ToolInvoke(w, r)
	if w.Code != 401 {
		t.Fatal("key not rechecked after body read")
	}
}

func TestToolTimeoutAndErrorSanitization(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		f := newToolFixture(t, func(r *http.Request) (*http.Response, error) {
			if timeout {
				<-r.Context().Done()
				return nil, r.Context().Err()
			}
			return nil, errors.New("upstream-tool-private private-response")
		})
		w := f.call(f.key, "support", `{"resource_id":"permitted-private-id"}`)
		want := 502
		if timeout {
			want = 504
		}
		if w.Code != want || strings.Contains(w.Body.String(), "private-response") || strings.Contains(w.Body.String(), "upstream-tool-private") {
			t.Fatal("unsafe error handling", w.Code)
		}
	}
}

func TestToolConfigurationRequiresOriginalVaultWithoutGatewayState(t *testing.T) {
	dir := t.TempDir()
	g, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	credential := "private-tool-credential"
	_, err = g.Tools.Save("", ToolInput{Name: "Read", Alias: "read", Endpoint: "https://tool.example/read", APIKey: &credential,
		Enabled: true, TimeoutSeconds: 1, OutputMode: "block", Resources: []ToolResource{{ID: "guide", Sensitivity: "public", AllowedApplications: []string{}}}})
	if err != nil {
		t.Fatal(err)
	}
	g.Close()
	if _, err := os.Stat(filepath.Join(dir, "gateway.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("fixture unexpectedly has gateway state")
	}
	if err := os.Remove(filepath.Join(dir, "gateway.key")); err != nil {
		t.Fatal(err)
	}
	if reopened, err := Open(dir); err == nil {
		reopened.Close()
		t.Fatal("missing vault key accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "gateway.key")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("replacement key was generated over missing original")
	}
}
