package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func testPolicies(t *testing.T) (*PolicyStore, Snapshot) {
	t.Helper()
	resources := Snapshot{Applications: []Application{{ID: "app-a"}, {ID: "app-b"}}, Connections: []Connection{{ID: "model-a"}, {ID: "model-b"}}}
	p, err := OpenPolicies(t.TempDir(), resources)
	if err != nil {
		t.Fatal(err)
	}
	return p, resources
}

func TestCredentialRulesAndDecodedStrings(t *testing.T) {
	p, resources := testPolicies(t)
	in := p.Snapshot().PolicyInput
	in.Mode = "block"
	if _, err := p.Save(in, resources); err != nil {
		t.Fatal(err)
	}
	apiKey := "sk-" + strings.Repeat("synthetic", 5)
	privateKey := "-----BEGIN OPENSSH PRIVATE KEY-----"
	for _, tc := range []struct {
		name, body string
		rules      []string
	}{
		{"ordinary text", `{"messages":[{"content":"Explain API keys and public key encryption."}]}`, []string{}},
		{"short placeholder", `{"content":"sk-example"}`, []string{}},
		{"public key", `{"content":"-----BEGIN PUBLIC KEY-----"}`, []string{}},
		{"API key", fmt.Sprintf(`{"content":%q}`, apiKey), []string{"api_key"}},
		{"decoded escape", fmt.Sprintf(`{"content":"\u0073%s"}`, apiKey[1:]), []string{"api_key"}},
		{"duplicate keys", fmt.Sprintf(`{"content":%q,"content":"hello"}`, apiKey), []string{"api_key"}},
		{"extension object key", fmt.Sprintf(`{%q:0}`, apiKey), []string{"api_key"}},
		{"tool argument", fmt.Sprintf(`{"messages":[{"tool_calls":[{"function":{"arguments":%q}}]}]}`, `{"secret":"`+apiKey+`"}`), []string{"api_key"}},
		{"private key marker", fmt.Sprintf(`{"content":%q}`, privateKey), []string{"private_key"}},
		{"both deterministic", fmt.Sprintf(`{"a":%q,"b":%q}`, apiKey, privateKey), []string{"private_key", "api_key"}},
		{"key ending hyphen", fmt.Sprintf(`{"content":%q}`, "gw_app_"+strings.Repeat("x", 42)+"-"), []string{"api_key"}},
		{"deep nested values", strings.Repeat("[", 500) + fmt.Sprintf("%q", privateKey) + strings.Repeat("]", 500), []string{"private_key"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := p.Evaluate([]byte(tc.body), "app-a", "model-a")
			if err != nil || !reflect.DeepEqual(result.MatchedRules, tc.rules) {
				t.Fatalf("incorrect matches: %+v, %v", result, err)
			}
			want := "allow"
			if len(tc.rules) > 0 {
				want = "block"
			}
			if result.Result != want || result.Revision != 1 || result.RulesetVersion != credentialRuleset || result.CheckDurationUS < 0 {
				t.Fatalf("incorrect assessment: %+v", result)
			}
			serialized, _ := json.Marshal(result)
			if bytes.Contains(serialized, []byte(apiKey)) || bytes.Contains(serialized, []byte(privateKey)) {
				t.Fatal("matched text leaked")
			}
		})
	}
	in = p.Snapshot().PolicyInput
	in.Rules = []string{"private_key"}
	if _, err := p.Save(in, resources); err != nil {
		t.Fatal(err)
	}
	result, err := p.Evaluate([]byte(fmt.Sprintf(`{"content":%q}`, apiKey)), "app-a", "model-a")
	if err != nil || result.Result != "allow" {
		t.Fatal("disabled detector still matched")
	}
}

func TestPolicyScopesPersistenceAndFailedUpdates(t *testing.T) {
	p, resources := testPolicies(t)
	body := []byte(`{"content":"-----BEGIN PRIVATE KEY-----"}`)
	r, _ := p.Evaluate(body, "app-a", "model-a")
	if r.Result != "disabled" || r.Revision != 0 {
		t.Fatal("unsafe default")
	}
	input := p.Snapshot().PolicyInput
	input.Mode = "observe"
	input.ApplicationIDs = []string{"app-a"}
	input.ConnectionIDs = []string{"model-a"}
	saved, err := p.Save(input, resources)
	if err != nil {
		t.Fatal(err)
	}
	// Caller-owned slices must never mutate the active policy.
	input.ApplicationIDs[0] = "app-b"
	saved.Rules[0] = "api_key"
	for _, tc := range []struct{ app, model, result string }{{"app-a", "model-a", "observe"}, {"app-b", "model-a", "not_applicable"}, {"app-a", "model-b", "not_applicable"}} {
		result, err := p.Evaluate(body, tc.app, tc.model)
		if err != nil || result.Result != tc.result {
			t.Fatalf("scope failed: %+v", result)
		}
	}
	if _, err := p.Save(input, resources); !errors.Is(err, ErrConflict) {
		t.Fatal("stale write accepted")
	}
	for _, change := range []func(*PolicyInput){func(in *PolicyInput) { in.Mode = "invalid" }, func(in *PolicyInput) { in.ApplicationIDs = []string{"unknown"} }, func(in *PolicyInput) { in.ConnectionIDs = []string{"model-a", "model-a"} }, func(in *PolicyInput) { in.Rules = []string{"unknown"} }, func(in *PolicyInput) { in.Rules = nil }} {
		in := p.Snapshot().PolicyInput
		change(&in)
		if _, err := p.Save(in, resources); err == nil {
			t.Fatal("invalid policy accepted")
		}
	}
	reopened, err := OpenPolicies(filepath.Dir(p.path), resources)
	if err != nil || !reflect.DeepEqual(reopened.Snapshot(), p.Snapshot()) {
		t.Fatal("policy did not persist", err)
	}
	info, _ := os.Stat(p.path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("policy is not private")
	}
	before := p.Snapshot()
	path := p.path
	p.path = filepath.Join(t.TempDir(), "missing", "policies.json")
	in := p.Snapshot().PolicyInput
	in.Mode = "block"
	if _, err := p.Save(in, resources); !errors.Is(err, ErrPersistence) || !reflect.DeepEqual(before, p.Snapshot()) {
		t.Fatal("failed write changed policy")
	}
	p.path = path
	for _, data := range []string{`{`, `null`, `{"schema_version":2}`, strings.Replace(string(mustPolicyJSON(t, before)), credentialRuleset, "unknown-ruleset", 1)} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenPolicies(filepath.Dir(path), resources); err == nil {
			t.Fatal("invalid persisted policy silently accepted")
		}
	}
}
func mustPolicyJSON(t *testing.T, p PolicySnapshot) []byte {
	t.Helper()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCredentialPolicyPreventsEgressAndKeepsStreaming(t *testing.T) {
	var calls atomic.Int32
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var body struct {
			Stream bool `json:"stream"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if body.Stream {
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, event+done)
		} else {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, completion)
		}
	})
	secret := "sk-" + strings.Repeat("testfixture", 4)
	for _, mode := range []string{"disabled", "observe", "block"} {
		input := f.engine.Policies.Snapshot().PolicyInput
		input.Mode = mode
		saved, err := f.engine.Policies.Save(input, f.engine.Store.Snapshot())
		if err != nil {
			t.Fatal(err)
		}
		for _, stream := range []bool{false, true} {
			before := calls.Load()
			body := strings.Replace(chatBody("internal-assistant", stream), "private-prompt", secret, 1)
			w := f.call(f.key, body)
			record := waitRecord(t, f.engine, w.Header().Get("X-Request-ID"))
			if record.ContentPolicy == nil || record.ContentPolicy.Revision != saved.Revision || record.Decision != "allow" {
				t.Fatal("missing policy attribution")
			}
			if mode == "block" {
				if w.Code != 403 || calls.Load() != before || record.UpstreamAttempted || record.Outcome != "blocked" || record.ErrorCode != "policy_blocked" {
					t.Fatal("blocked request reached upstream")
				}
			} else if w.Code != 200 || calls.Load() != before+1 || !record.UpstreamAttempted {
				t.Fatal("observation or disabled mode blocked a request")
			}
		}
	}
	if w := f.call(f.key, chatBody("internal-assistant", true)); w.Code != 200 || !strings.HasSuffix(w.Body.String(), done) {
		t.Fatal("clean SSE broken")
	}
	log, err := os.ReadFile(filepath.Join(f.dir, "calls.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(log, []byte(secret)) || bytes.Contains(log, []byte("private-prompt")) || bytes.Contains(log, []byte("private-answer")) {
		t.Fatal("request content leaked into audit")
	}
	for _, line := range bytes.Split(bytes.TrimSpace(log), []byte("\n")) {
		if len(line)+1 > int(maxAuditEventBytes) {
			t.Fatal("policy audit exceeds reservation")
		}
	}
	f.engine.Audit.mu.Lock()
	f.engine.Audit.failed = true
	f.engine.Audit.mu.Unlock()
	before := calls.Load()
	if w := f.call(f.key, strings.Replace(chatBody("internal-assistant", false), "private-prompt", secret, 1)); w.Code != 503 || calls.Load() != before {
		t.Fatal("policy hit bypassed audit availability")
	}
}

func TestConcurrentPolicySnapshots(t *testing.T) {
	p, resources := testPolicies(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				result, err := p.Evaluate([]byte(`{"text":"-----BEGIN PRIVATE KEY-----"}`), "app-a", "model-a")
				if err != nil || (result.Revision == 0 && result.Result != "disabled") || (result.Revision > 0 && result.Result != result.Mode) {
					t.Error("inconsistent policy snapshot")
				}
				snapshot, lookupErr := p.Revision(result.Revision)
				if lookupErr != nil || snapshot.Mode != result.Mode || snapshot.RulesetVersion != result.RulesetVersion {
					t.Error("concurrent assessment cannot be traced to its retained snapshot")
				}
			}
		}()
	}
	for i := 0; i < 10; i++ {
		in := p.Snapshot().PolicyInput
		in.Mode = "observe"
		if i%2 == 1 {
			in.Mode = "block"
		}
		if _, err := p.Save(in, resources); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
	if history := p.History(100, nil); history.Total != 11 || history.Snapshots[0].Revision != 10 || history.Snapshots[10].Revision != 0 {
		t.Fatal("concurrent evaluations changed policy history")
	}
}

func BenchmarkCredentialPolicy(b *testing.B) {
	p := &PolicyStore{state: PolicySnapshot{ID: credentialPolicyID, RulesetVersion: credentialRuleset, PolicyInput: PolicyInput{Mode: "observe", Rules: []string{"private_key", "api_key"}}}}
	for _, size := range []int{4096, MaxRequestBytes - 100} {
		body := []byte(`{"messages":[{"role":"user","content":"` + strings.Repeat("a", size) + `"}]}`)
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(body)))
			for i := 0; i < b.N; i++ {
				if _, err := p.Evaluate(body, "a", "c"); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
