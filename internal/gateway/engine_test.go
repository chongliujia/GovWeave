package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const completion = `{"id":"chat_test","object":"chat.completion","created":1,"model":"provider-model","choices":[{"index":0,"message":{"role":"assistant","content":"private-answer"},"finish_reason":"stop"}]}`
const event = "data: {\"id\":\"chat_test\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"provider-model\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"private-answer\"},\"finish_reason\":null}]}\n\n"
const done = "data: [DONE]\n\n"

type fixture struct {
	engine     *Engine
	connection Connection
	app        Application
	key, dir   string
}

func newFixture(t *testing.T, handler http.HandlerFunc) fixture {
	t.Helper()
	upstream := httptest.NewServer(handler)
	t.Cleanup(upstream.Close)
	dir := t.TempDir()
	g, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.Close() })
	c, err := g.Store.SaveConnection("", connectionInput(upstream.URL+"/v1"))
	if err != nil {
		t.Fatal(err)
	}
	a, key, err := g.Store.SaveApplication("", ApplicationInput{Name: "test-app", AllowedConnections: []string{c.ID}})
	if err != nil {
		t.Fatal(err)
	}
	return fixture{g, c, a, key, dir}
}

func chatBody(alias string, stream bool) string {
	return fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"private-prompt"}],"stream":%t,"temperature":0.2}`, alias, stream)
}
func chatRequest(ctx context.Context, url, key string, streaming bool) *http.Request {
	r, _ := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(chatBody("internal-assistant", streaming)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+key)
	return r
}
func (f fixture) call(key, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+key)
	r.Header.Set("Cookie", "private-cookie")
	r.Header.Set("X-Api-Key", "private-header")
	r.Header.Set("OpenAI-Organization", "private-org")
	r.Header.Set("Idempotency-Key", "private-idempotency")
	w := httptest.NewRecorder()
	f.engine.Chat(w, r)
	return w
}
func waitRecord(t *testing.T, g *Engine, id string) CallRecord {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, record := range g.Audit.View(100, "").Records {
			if record.RequestID == id && record.Phase == "finished" {
				return record
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("terminal call record missing")
	return CallRecord{}
}

func TestChatForwardingAuthorizationAndPrivacy(t *testing.T) {
	var calls atomic.Int32
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer provider-credential-private" {
			t.Error("wrong upstream routing or credentials")
		}
		for _, name := range []string{"Cookie", "X-Api-Key", "OpenAI-Organization", "Idempotency-Key"} {
			if r.Header.Get(name) != "" {
				t.Errorf("forwarded private header %s", name)
			}
		}
		var input map[string]any
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			t.Error(err)
		}
		if input["model"] != "provider-model" || input["temperature"] != 0.2 {
			t.Error("model rewrite or parameter passthrough failed")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "private-cookie")
		io.WriteString(w, completion)
	})
	w := f.call(f.key, chatBody("internal-assistant", false))
	if w.Code != 200 || w.Body.String() != completion || w.Header().Get("Set-Cookie") != "" {
		t.Fatal("invalid normal response", w.Code)
	}
	record := waitRecord(t, f.engine, w.Header().Get("X-Request-ID"))
	if record.Outcome != "completed" || record.ApplicationID != f.app.ID || record.FirstByteMS == nil || !record.UpstreamAttempted {
		t.Fatalf("incorrect record %+v", record)
	}
	for _, tc := range []struct {
		key, alias string
		status     int
	}{{"invalid-key", "internal-assistant", 401}, {f.key, "not-authorized", 403}, {"gw_admin_abcdef", "internal-assistant", 401}} {
		if got := f.call(tc.key, chatBody(tc.alias, false)); got.Code != tc.status {
			t.Fatalf("got %d want %d", got.Code, tc.status)
		}
	}
	if _, _, err := f.engine.Store.ChangeKey(f.app.ID, f.app.Revision, true); err != nil {
		t.Fatal(err)
	}
	if f.call(f.key, chatBody("internal-assistant", false)).Code != 401 || calls.Load() != 1 {
		t.Fatal("unauthorized request reached provider")
	}
	data, err := os.ReadFile(filepath.Join(f.dir, "calls.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"private-prompt", "private-answer", "provider-credential-private", f.key, "private-header", "not-authorized"} {
		if strings.Contains(string(data), secret) {
			t.Fatal("sensitive input in call records")
		}
	}
}

func TestAdmissionAndInvalidInputNeverReachProvider(t *testing.T) {
	var calls atomic.Int32
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1) })
	for _, tc := range []struct {
		body   string
		status int
	}{{`null`, 400}, {`{"model":"internal-assistant","messages":[]}`, 400}, {`{"model":"internal-assistant","messages":[null]}`, 400}, {`{"model":"internal-assistant","messages":[{}],"stream":null}`, 400}, {strings.Repeat("x", MaxRequestBytes+1), 413}} {
		if w := f.call(f.key, tc.body); w.Code != tc.status {
			t.Fatalf("got %d want %d", w.Code, tc.status)
		}
	}
	for i := 0; i < cap(f.engine.slots); i++ {
		f.engine.slots <- struct{}{}
	}
	if f.call(f.key, chatBody("internal-assistant", false)).Code != 429 {
		t.Fatal("concurrency limit ignored")
	}
	for i := 0; i < cap(f.engine.slots); i++ {
		<-f.engine.slots
	}
	f.engine.Audit.mu.Lock()
	f.engine.Audit.failed = true
	f.engine.Audit.mu.Unlock()
	if f.call(f.key, chatBody("internal-assistant", false)).Code != 503 || calls.Load() != 0 {
		t.Fatal("audit failure did not block inference")
	}
}

func TestErrorsAndRedirectsAreSanitizedWithoutRetries(t *testing.T) {
	var redirected atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
	defer target.Close()
	for _, tc := range []struct {
		name              string
		status            int
		contentType, body string
		want              int
	}{
		{"provider error", 500, "application/json", `{"error":"provider-credential-private private-prompt"}`, 502},
		{"rate limit", 429, "application/json", `{"error":"private-prompt"}`, 429},
		{"redirect", 307, "text/plain", "private-prompt", 502},
		{"invalid json", 200, "application/json", "private-prompt", 502},
		{"invalid choices", 200, "application/json", `{"choices":"private-prompt"}`, 502},
		{"null choices", 200, "application/json", `{"choices":null}`, 502},
		{"error in success", 200, "application/json", `{"choices":[],"error":"private-prompt"}`, 502},
		{"large response", 200, "application/json", strings.Repeat("x", maxResponseBytes+1), 502},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", tc.contentType)
				w.Header().Set("Location", target.URL)
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			})
			w := f.call(f.key, chatBody("internal-assistant", false))
			if w.Code != tc.want || strings.Contains(w.Body.String(), "private-prompt") || strings.Contains(w.Body.String(), "provider-credential-private") || calls.Load() != 1 {
				t.Fatal("unsafe upstream error handling", w.Code)
			}
		})
	}
	if redirected.Load() != 0 {
		t.Fatal("redirect followed")
	}
}

func TestTimeoutCancelsUpstream(t *testing.T) {
	cancelled := make(chan struct{})
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
		close(cancelled)
	})
	in := connectionInput(f.connection.BaseURL)
	in.Revision = f.connection.Revision
	in.TimeoutSeconds = 1
	if _, err := f.engine.Store.SaveConnection(f.connection.ID, in); err != nil {
		t.Fatal(err)
	}
	w := f.call(f.key, chatBody("internal-assistant", false))
	if w.Code != 504 {
		t.Fatal("expected timeout", w.Code)
	}
	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream not cancelled")
	}
	record := waitRecord(t, f.engine, w.Header().Get("X-Request-ID"))
	if record.ErrorCode != "upstream_timeout" || record.Outcome != "failed" {
		t.Fatal("incorrect timeout record")
	}
}

func TestStreamingFlushesBeforeCompletion(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, event)
		w.(http.Flusher).Flush()
		select {
		case <-release:
			io.WriteString(w, done)
		case <-r.Context().Done():
		}
	})
	gateway := httptest.NewServer(http.HandlerFunc(f.engine.Chat))
	defer gateway.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	response, err := http.DefaultClient.Do(chatRequest(ctx, gateway.URL, f.key, true))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	first, err := bufio.NewReader(response.Body).ReadString('\n')
	if err != nil || first != strings.Split(event, "\n")[0]+"\n" {
		t.Fatal("stream buffered until completion", err)
	}
	cancel()
	record := waitRecord(t, f.engine, response.Header.Get("X-Request-ID"))
	if record.Outcome != "cancelled" || record.FirstByteMS == nil {
		t.Fatalf("incorrect cancellation record %+v", record)
	}
}

func TestStreamsCompleteOrAbortHonestly(t *testing.T) {
	for _, tc := range []struct {
		name, body, outcome, code string
		complete                  bool
	}{
		{"complete", event + done, "completed", "", true},
		{"early EOF", event, "failed", "incomplete_stream", false},
		{"provider error", event + "data: {\"error\":\"provider-credential-private\"}\n\n", "failed", "upstream_error", false},
		{"invalid frame", event + "data: broken\n\n", "failed", "invalid_upstream_stream", false},
		{"oversized event", "data: " + strings.Repeat("x", (1<<20)+1), "failed", "invalid_upstream_stream", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				io.WriteString(w, tc.body)
			})
			gateway := httptest.NewServer(http.HandlerFunc(f.engine.Chat))
			defer gateway.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			response, err := http.DefaultClient.Do(chatRequest(ctx, gateway.URL, f.key, true))
			id := ""
			var data []byte
			if response != nil {
				id = response.Header.Get("X-Request-ID")
				data, err = io.ReadAll(response.Body)
				response.Body.Close()
			}
			if tc.complete {
				if err != nil || string(data) != tc.body {
					t.Fatal("stream bytes changed", err)
				}
			} else if err == nil {
				t.Fatal("broken stream reported complete")
			}
			if strings.Contains(string(data), "provider-credential-private") {
				t.Fatal("upstream error leaked")
			}
			if id == "" {
				records := f.engine.Audit.View(10, "").Records
				if len(records) != 1 {
					t.Fatal("missing failed record")
				}
				id = records[0].RequestID
			}
			record := waitRecord(t, f.engine, id)
			if record.Outcome != tc.outcome || record.ErrorCode != tc.code {
				t.Fatalf("incorrect stream outcome %+v", record)
			}
		})
	}
}

func TestModelsAndProbe(t *testing.T) {
	var calls atomic.Int32
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "GET" || r.URL.Path != "/v1/models" {
			t.Error("probe sent inference")
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":[{"id":"provider-model"}]}`)
	})
	r := httptest.NewRequest("GET", "/v1/models", nil)
	r.Header.Set("Authorization", "Bearer "+f.key)
	w := httptest.NewRecorder()
	f.engine.Models(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "internal-assistant") || strings.Contains(w.Body.String(), "provider-model") || calls.Load() != 0 {
		t.Fatal("model list leaked upstream information or made network request")
	}
	result, err := f.engine.Probe(context.Background(), f.connection.ID)
	if err != nil || !result.OK || !result.ModelFound || calls.Load() != 1 {
		t.Fatal("connection probe failed", err)
	}
}

func TestProbeFailureRecordsActualManagementStatus(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) { t.Error("cancelled probe reached upstream") })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := f.engine.Probe(ctx, f.connection.ID)
	if err != nil || result.OK {
		t.Fatal("expected a failed probe result")
	}
	record := waitRecord(t, f.engine, result.RequestID)
	if record.HTTPStatus != 200 || record.Outcome != "failed" {
		t.Fatal("probe result and recorded HTTP status differ")
	}
}

func TestSSEAcrossSingleByteChunks(t *testing.T) {
	observer := streamObserver{}
	input := strings.ReplaceAll(event+done, "\n", "\r\n")
	output := ""
	for _, b := range []byte(input) {
		if err := observer.observe([]byte{b}); err != nil {
			t.Fatal(err)
		}
		output += string(observer.take())
	}
	if output != input || !observer.Done {
		t.Fatal("fragmented CRLF stream changed")
	}
}
