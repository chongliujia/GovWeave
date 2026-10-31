package gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

const readDeclaration = `[{"type":"function","function":{"name":"read_resource","parameters":{"type":"object","properties":{"resource_id":{"type":"string"}},"required":["resource_id"],"additionalProperties":false}}}]`

func readProposal(arguments string) string {
	b, _ := json.Marshal(map[string]any{"private": "unchecked-provider-extension", "choices": []any{map[string]any{"finish_reason": "tool_calls", "message": map[string]any{"role": "assistant", "content": nil, "reasoning_content": "unchecked-reasoning", "tool_calls": []any{map[string]any{"id": "unchecked-provider-id", "type": "function", "function": map[string]string{"name": "read_resource", "arguments": arguments}}}}}}})
	return string(b)
}

func readRequest(tools string) string {
	return `{"model":"internal-assistant","messages":[{"role":"user","content":"read a resource"}],"tools":` + tools + `}`
}

func TestProtectedReadProposalCanonicalAndAudited(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, readProposal(`{"resource_id":"public-guide"}`))
	})
	enableOutput(t, f.engine, "redact", []string{"credential", "email", "phone"}, nil)
	w := f.call(f.key, readRequest(readDeclaration))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "call_"+w.Header().Get("X-Request-ID")) || !strings.Contains(w.Body.String(), "public-guide") {
		t.Fatal("valid proposal withheld", w.Code)
	}
	if strings.Contains(w.Body.String(), "unchecked") {
		t.Fatal("unchecked provider metadata escaped")
	}
	record := waitRecord(t, f.engine, w.Header().Get("X-Request-ID"))
	if record.OutputPolicy.ToolCallVersion != readToolCallVersion || record.OutputPolicy.Result != "allow" || record.Outcome != "completed" {
		t.Fatal("proposal evidence missing")
	}
	// An undeclared tool response cannot enable the capability on its own.
	if f.call(f.key, chatBody("internal-assistant", false)).Code != 502 {
		t.Fatal("unsolicited tool proposal released")
	}
}

func TestProtectedReadProposalBlocksSensitiveArgumentsWithoutRewriting(t *testing.T) {
	secret := "sk-" + strings.Repeat("q", 35)
	for _, mode := range []string{"block", "redact", "observe"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, readProposal(`{"resource_id":"\u0073k-`+strings.Repeat("q", 35)+`"}`))
			})
			enableOutput(t, f.engine, mode, []string{"credential"}, nil)
			w := f.call(f.key, readRequest(readDeclaration))
			record := waitRecord(t, f.engine, w.Header().Get("X-Request-ID"))
			if mode == "observe" {
				if w.Code != 200 || !strings.Contains(w.Body.String(), secret) {
					t.Fatal("observe changed arguments")
				}
				return
			}
			if w.Code != 403 || strings.Contains(w.Body.String(), secret) || record.OutputPolicy.Result != "block" || record.OutputPolicy.Redaction != nil {
				t.Fatal("action arguments were released or rewritten")
			}
			if mode == "redact" && record.OutputPolicy.Reason != "tool_arguments_not_redactable" {
				t.Fatal("missing action-block reason")
			}
		})
	}
}

func TestProtectedReadContractRejectsUnsupportedBeforeIO(t *testing.T) {
	var calls atomic.Int32
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1) })
	enableOutput(t, f.engine, "block", []string{"credential"}, nil)
	for _, declaration := range []string{`{}`, `[{"type":"function","function":{"name":"shell"}}]`, strings.Replace(readDeclaration, "false", "true", 1)} {
		if f.call(f.key, readRequest(declaration)).Code != 400 {
			t.Fatal("unsupported declaration admitted")
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid tool contract reached provider")
	}
}

func TestProtectedReadProposalRejectsMalformedAndAuditFailure(t *testing.T) {
	for _, args := range []string{`{"resource_id":"a","resource_id":"b"}`, `{"resource_id":"a","url":"https://example.com"}`, `{"resource_id":null}`, `{"resource_id":"../private"}`} {
		f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, readProposal(args))
		})
		enableOutput(t, f.engine, "observe", []string{"credential"}, nil)
		if f.call(f.key, readRequest(readDeclaration)).Code != 502 {
			t.Fatal("malformed action released")
		}
	}
	var f fixture
	f = newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		f.engine.Audit.mu.Lock()
		f.engine.Audit.failed = true
		f.engine.Audit.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, readProposal(`{"resource_id":"public-guide"}`))
	})
	enableOutput(t, f.engine, "block", []string{"credential"}, nil)
	w := f.call(f.key, readRequest(readDeclaration))
	if w.Code != 503 || strings.Contains(w.Body.String(), "public-guide") {
		t.Fatal("audit failure released executable proposal")
	}
}
