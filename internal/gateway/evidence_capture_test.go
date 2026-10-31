package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func enableRuntimeEvidence(t *testing.T, g *Engine, appID, mode string) EvidenceConfig {
	t.Helper()
	input := g.Evidence.Config()
	input.Mode, input.ApplicationIDs = mode, []string{appID}
	result, err := g.Evidence.SaveConfig(input, g.Store.Snapshot(), "runtime_test")
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func evidenceChat(g *Engine, key, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+key)
	r.Header.Set("Cookie", "private-evidence-cookie")
	r.Header.Set("X-Private-Caller", "private-evidence-caller-header")
	r.Header.Set("X-GovWeave-Trace-ID", "10000000000000000000000000000001")
	w := httptest.NewRecorder()
	g.Chat(w, r)
	return w
}

func runtimeEvidence(t *testing.T, g *Engine, response *httptest.ResponseRecorder, appID string) EvidenceBundle {
	t.Helper()
	requestID := response.Header().Get("X-Request-ID")
	bundle, err := g.Evidence.Get(EvidenceID(requestID), appID)
	if err != nil {
		t.Fatal("missing captured evidence", err)
	}
	if !bundle.AuditCommitted || bundle.Record.Phase != "finished" || !reflect.DeepEqual(bundle.Record, waitRecord(t, g, requestID)) {
		t.Fatal("evidence did not preserve the exact committed terminal record")
	}
	return bundle
}

func evidenceObject(t *testing.T, bundle EvidenceBundle, kind string) EvidenceObject {
	t.Helper()
	for _, object := range bundle.Objects {
		if object.Kind == kind {
			return object
		}
	}
	t.Fatal("missing evidence object", kind)
	return EvidenceObject{}
}

func revealRuntimeEvidence(t *testing.T, g *Engine, bundle EvidenceBundle, kind string) string {
	t.Helper()
	object := evidenceObject(t, bundle, kind)
	result, err := g.Evidence.Reveal(bundle.ID, bundle.ApplicationID, object.ID, "raw", "validation", "runtime_test")
	if err != nil {
		t.Fatal("could not inspect retained evidence", err)
	}
	return result.Text
}

func assertEvidenceDiskPrivate(t *testing.T, dir string, private ...string) {
	t.Helper()
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, value := range private {
			if bytes.Contains(data, []byte(value)) {
				t.Errorf("plaintext private content in %s", filepath.Base(path))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestEvidenceRuntimeChatPinsCaptureAndPolicyVersions(t *testing.T) {
	f := newIntegrationFixture(t)
	config := enableRuntimeEvidence(t, f.g, f.app.ID, "full")
	p := enableOutput(t, f.g, "redact", []string{"email"}, nil)
	private := "evidence-original@internal.example"
	original := completionText("Contact "+private, "stop")
	f.g.client.Transport = toolRoundTripper(func(*http.Request) (*http.Response, error) {
		// Accepted calls keep their capture and detection versions even if an
		// operator changes both while the model request is in progress.
		next := f.g.Evidence.Config()
		next.Mode = "disabled"
		if _, err := f.g.Evidence.SaveConfig(next, f.g.Store.Snapshot(), "runtime_test"); err != nil {
			t.Fatal(err)
		}
		enableOutput(t, f.g, "observe", []string{"email"}, nil)
		return toolResponse(200, original), nil
	})
	body := chatBody(f.connection.Alias, false)
	w := evidenceChat(f.g, f.key, body)
	if w.Code != 200 || strings.Contains(w.Body.String(), private) {
		t.Fatal("redaction or request failed", w.Code)
	}
	bundle := runtimeEvidence(t, f.g, w, f.app.ID)
	if bundle.CaptureRevision != config.Revision || bundle.Mode != "full" || bundle.DeliveryState != "release_prepared" || bundle.Record.OutputPolicy.Revision != p.Revision {
		t.Fatal("in-flight evidence changed or delivery was overclaimed")
	}
	if revealRuntimeEvidence(t, f.g, bundle, "request") != body || revealRuntimeEvidence(t, f.g, bundle, "upstream_output") != original || revealRuntimeEvidence(t, f.g, bundle, "released_output") != w.Body.String() {
		t.Fatal("request/original/released artifacts differ from observed buffers")
	}
	var forwarded map[string]any
	if json.Unmarshal([]byte(revealRuntimeEvidence(t, f.g, bundle, "upstream_request")), &forwarded) != nil || forwarded["model"] != f.connection.Model {
		t.Fatal("actual forwarded model body was not retained")
	}
	var outputPolicy OutputPolicySnapshot
	for _, policy := range bundle.Policies {
		if policy.Kind == "output" {
			if json.Unmarshal(policy.Snapshot, &outputPolicy) != nil {
				t.Fatal("invalid policy snapshot")
			}
		}
	}
	if !reflect.DeepEqual(outputPolicy, p) {
		t.Fatal("current policy substituted for the historical applied revision")
	}
	metadata, _ := json.Marshal(bundle)
	for _, value := range []string{private, "private-prompt", "private-evidence-cookie", "private-evidence-caller-header", f.key, "provider-credential-private"} {
		if bytes.Contains(metadata, []byte(value)) {
			t.Fatal("content or credential entered metadata response")
		}
	}
	assertEvidenceDiskPrivate(t, f.dir, private, "private-prompt", f.key, "provider-credential-private", "private-evidence-cookie", "private-evidence-caller-header")
}

func TestEvidenceRuntimeInputBlockRetainsReviewWithoutProviderCall(t *testing.T) {
	f := newIntegrationFixture(t)
	enableRuntimeEvidence(t, f.g, f.app.ID, "full")
	policy := f.g.Policies.Snapshot().PolicyInput
	policy.Mode = "block"
	if _, err := f.g.Policies.Save(policy, f.g.Store.Snapshot()); err != nil {
		t.Fatal(err)
	}
	secret := "sk-" + strings.Repeat("synthetic", 5)
	body := strings.Replace(chatBody(f.connection.Alias, false), "private-prompt", secret, 1)
	w := evidenceChat(f.g, f.key, body)
	if w.Code != 403 || f.calls.Load() != 0 {
		t.Fatal("blocked input reached provider")
	}
	bundle := runtimeEvidence(t, f.g, w, f.app.ID)
	if bundle.DeliveryState != "withheld" || bundle.Record.ContentPolicy.Result != "block" || revealRuntimeEvidence(t, f.g, bundle, "request") != body {
		t.Fatal("input-block evidence incomplete")
	}
	for _, kind := range []string{"upstream_request", "upstream_output", "released_output"} {
		if evidenceObject(t, bundle, kind).ContentState != "not_observed" {
			t.Fatal("blocked input fabricated a downstream artifact")
		}
	}
	assertEvidenceDiskPrivate(t, f.dir, secret)
}

func TestEvidenceRuntimeOutputBlockPreservesOriginal(t *testing.T) {
	f := newIntegrationFixture(t)
	enableRuntimeEvidence(t, f.g, f.app.ID, "full")
	enableOutput(t, f.g, "block", []string{"email"}, nil)
	private := "blocked-original@internal.example"
	original := completionText(private, "stop")
	f.g.client.Transport = toolRoundTripper(func(*http.Request) (*http.Response, error) { return toolResponse(200, original), nil })
	w := evidenceChat(f.g, f.key, chatBody(f.connection.Alias, false))
	if w.Code != 403 || strings.Contains(w.Body.String(), private) {
		t.Fatal("blocked output released")
	}
	bundle := runtimeEvidence(t, f.g, w, f.app.ID)
	if revealRuntimeEvidence(t, f.g, bundle, "upstream_output") != original || evidenceObject(t, bundle, "released_output").ContentState != "not_observed" || bundle.DeliveryState != "withheld" {
		t.Fatal("original and withheld release were not distinguished")
	}
}

func TestEvidenceRuntimeToolBlockAndRedaction(t *testing.T) {
	for _, mode := range []string{"credential_block", "redact"} {
		t.Run(mode, func(t *testing.T) {
			text := "-----BEGIN PRIVATE KEY-----"
			if mode == "redact" {
				text = "tool-evidence@internal.example"
			}
			body, _ := json.Marshal(map[string]string{"text": text})
			f := newToolFixture(t, func(*http.Request) (*http.Response, error) { return toolResponse(200, string(body)), nil })
			enableRuntimeEvidence(t, f.g, f.app.ID, "full")
			if mode == "redact" {
				enableOutput(t, f.g, "redact", []string{"email"}, nil)
			}
			w := f.call(f.key, "support", `{"resource_id":"permitted-private-id"}`)
			wantStatus := 403
			if mode == "redact" {
				wantStatus = 200
			}
			if w.Code != wantStatus || strings.Contains(w.Body.String(), text) {
				t.Fatal("tool controls failed", w.Code)
			}
			bundle := runtimeEvidence(t, f.g, w, f.app.ID)
			if revealRuntimeEvidence(t, f.g, bundle, "upstream_output") != string(body) {
				t.Fatal("original tool envelope lost")
			}
			if mode == "redact" && revealRuntimeEvidence(t, f.g, bundle, "released_output") != w.Body.String() {
				t.Fatal("released tool envelope differs")
			}
			if mode == "credential_block" && evidenceObject(t, bundle, "released_output").ContentState != "not_observed" {
				t.Fatal("blocked tool fabricates released text")
			}
			policyFound := false
			for _, p := range bundle.Policies {
				if p.Kind == "tool" && p.ID == f.tool.ID && p.Revision == f.tool.Revision {
					policyFound = true
					for _, private := range []string{f.tool.Endpoint, "upstream-tool-private", "permitted-private-id", "forbidden-private-id"} {
						if bytes.Contains(p.Snapshot, []byte(private)) {
							t.Fatal("private tool settings leaked into metadata projection")
						}
					}
				}
			}
			if !policyFound {
				t.Fatal("accepted tool policy snapshot missing")
			}
			assertEvidenceDiskPrivate(t, f.dir, text, f.key, "upstream-tool-private")
		})
	}
}

func TestEvidenceRuntimeContentEvaluationIsNotExecution(t *testing.T) {
	f := newIntegrationFixture(t)
	enableRuntimeEvidence(t, f.g, f.app.ID, "full")
	enableOutput(t, f.g, "block", []string{"email"}, nil)
	body := `{"text":"evaluation-evidence@internal.example"}`
	w := evaluateText(f.g, f.key, body)
	if w.Code != 200 || f.calls.Load() != 0 {
		t.Fatal("content evaluation failed or executed model")
	}
	bundle := runtimeEvidence(t, f.g, w, f.app.ID)
	if bundle.Record.Operation != "content.evaluate" || bundle.Record.Decision != "evaluated" || bundle.Record.Outcome != "completed" || bundle.Record.OutputPolicy.Result != "block" {
		t.Fatal("evaluation was confused with runtime blocking")
	}
	if revealRuntimeEvidence(t, f.g, bundle, "request") != body || revealRuntimeEvidence(t, f.g, bundle, "released_output") != w.Body.String() {
		t.Fatal("evaluation evidence changed")
	}
	if evidenceObject(t, bundle, "upstream_request").ContentState != "not_observed" || evidenceObject(t, bundle, "upstream_output").ContentState != "not_observed" {
		t.Fatal("standalone evaluation fabricated upstream traffic")
	}
}

func TestEvidenceRuntimeAuthScopeAndDisabledBoundaries(t *testing.T) {
	f := newIntegrationFixture(t)
	w := evidenceChat(f.g, f.key, chatBody(f.connection.Alias, false))
	if _, err := f.g.Evidence.Get(EvidenceID(w.Header().Get("X-Request-ID")), f.app.ID); !errors.Is(err, ErrEvidenceNotFound) {
		t.Fatal("disabled capture retained content", err)
	}
	enableRuntimeEvidence(t, f.g, f.app.ID, "full")
	other, key, err := f.g.Store.SaveApplication("", ApplicationInput{Name: "Outside evidence scope", AllowedConnections: []string{f.connection.ID}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ key, appID string }{{key, other.ID}, {"invalid", f.app.ID}} {
		w = evidenceChat(f.g, tc.key, chatBody(f.connection.Alias, false))
		if _, err := f.g.Evidence.Get(EvidenceID(w.Header().Get("X-Request-ID")), tc.appID); !errors.Is(err, ErrEvidenceNotFound) {
			t.Fatal("unauthenticated or out-of-scope capture retained evidence", err)
		}
	}
	w = evidenceChat(f.g, f.key, chatBody("not-granted", false))
	if w.Code != 403 {
		t.Fatal("ungranted model accepted")
	}
	bundle := runtimeEvidence(t, f.g, w, f.app.ID)
	for _, object := range bundle.Objects {
		if object.ContentState != "not_observed" || object.Bytes != 0 {
			t.Fatal("ungranted request content was retained")
		}
	}
}

func TestEvidenceRuntimeProviderErrorsRemainUncaptured(t *testing.T) {
	for _, mode := range []string{"provider_error", "error_envelope", "invalid_json"} {
		t.Run(mode, func(t *testing.T) {
			f := newIntegrationFixture(t)
			enableRuntimeEvidence(t, f.g, f.app.ID, "full")
			private := "provider-error-private-detail"
			f.g.client.Transport = toolRoundTripper(func(*http.Request) (*http.Response, error) {
				switch mode {
				case "provider_error":
					return toolResponse(500, private), nil
				case "error_envelope":
					return toolResponse(200, `{"choices":[],"error":"`+private+`"}`), nil
				case "invalid_json":
					return toolResponse(200, private), nil
				}
				panic("unexpected fixture")
			})
			w := evidenceChat(f.g, f.key, chatBody(f.connection.Alias, false))
			bundle := runtimeEvidence(t, f.g, w, f.app.ID)
			wantState := "not_observed"
			if w.Code != 502 || bundle.DeliveryState != "withheld" {
				t.Fatal("provider error handling changed")
			}
			for _, kind := range []string{"upstream_output", "released_output"} {
				if evidenceObject(t, bundle, kind).ContentState != wantState {
					t.Fatal("unsupported/error content retained or gap hidden")
				}
			}
			assertEvidenceDiskPrivate(t, f.dir, private, "private-answer")
		})
	}
}

func TestEvidenceRuntimeRejectedStreamingHasNoOutputArtifacts(t *testing.T) {
	f := newIntegrationFixture(t)
	enableRuntimeEvidence(t, f.g, f.app.ID, "full")
	enableOutput(t, f.g, "block", []string{"email"}, nil)
	w := evidenceChat(f.g, f.key, chatBody(f.connection.Alias, true))
	if w.Code != 400 || f.calls.Load() != 0 {
		t.Fatal("protected streaming rejection was bypassed")
	}
	bundle := runtimeEvidence(t, f.g, w, f.app.ID)
	for _, kind := range []string{"upstream_request", "upstream_output", "released_output"} {
		if evidenceObject(t, bundle, kind).ContentState != "not_observed" {
			t.Fatal("rejected streaming call implied observed upstream output")
		}
	}
}

func TestEvidenceRuntimeMetadataAndOversizeDoNotRetainContent(t *testing.T) {
	for _, mode := range []string{"metadata", "full"} {
		t.Run(mode, func(t *testing.T) {
			f := newIntegrationFixture(t)
			config := enableRuntimeEvidence(t, f.g, f.app.ID, mode)
			config.MaxContentBytes = 4096
			if _, err := f.g.Evidence.SaveConfig(config, f.g.Store.Snapshot(), "runtime_test"); err != nil {
				t.Fatal(err)
			}
			f.g.client.Transport = toolRoundTripper(func(*http.Request) (*http.Response, error) {
				return toolResponse(200, completionText(strings.Repeat("x", 5000), "stop")), nil
			})
			w := evidenceChat(f.g, f.key, chatBody(f.connection.Alias, false))
			if w.Code != 200 {
				t.Fatal("bounded evidence configuration changed model admission")
			}
			bundle := runtimeEvidence(t, f.g, w, f.app.ID)
			object := evidenceObject(t, bundle, "upstream_output")
			want := "metadata_only"
			if mode == "full" {
				want = "omitted_size"
			}
			if object.ContentState != want || object.Bytes <= 4096 || object.Fingerprint == "" {
				t.Fatal("content omission hidden or captured size incorrect")
			}
			if _, err := f.g.Evidence.Reveal(bundle.ID, bundle.ApplicationID, object.ID, "raw", "validation", "runtime_test"); !errors.Is(err, ErrEvidenceContentUnavailable) {
				t.Fatal("omitted content could be revealed", err)
			}
		})
	}
}

func TestEvidenceRuntimeCapacityAndAuditFailuresDoNotClaimEvidence(t *testing.T) {
	for _, phase := range []string{"evidence_capacity", "audit_failure"} {
		t.Run(phase, func(t *testing.T) {
			f := newIntegrationFixture(t)
			enableRuntimeEvidence(t, f.g, f.app.ID, "full")
			wantStatus := 200
			if phase == "evidence_capacity" {
				f.g.Evidence.mu.Lock()
				f.g.Evidence.bytes = MaxEvidenceBytes
				f.g.Evidence.mu.Unlock()
			} else {
				wantStatus = 503
				enableOutput(t, f.g, "block", []string{"email"}, nil)
				f.g.client.Transport = toolRoundTripper(func(*http.Request) (*http.Response, error) {
					f.g.Audit.mu.Lock()
					f.g.Audit.failed = true
					f.g.Audit.mu.Unlock()
					return toolResponse(200, completion), nil
				})
			}
			w := evidenceChat(f.g, f.key, chatBody(f.connection.Alias, false))
			if w.Code != wantStatus || w.Header().Get("X-GovWeave-Evidence-ID") != "" {
				t.Fatal("supplementary failure altered contract or advertised evidence")
			}
			if _, err := f.g.Evidence.Get(EvidenceID(w.Header().Get("X-Request-ID")), f.app.ID); !errors.Is(err, ErrEvidenceNotFound) {
				t.Fatal("failed capture claimed committed evidence", err)
			}
			if phase == "evidence_capacity" && waitRecord(t, f.g, w.Header().Get("X-Request-ID")).Outcome != "completed" {
				t.Fatal("supplementary failure destroyed ordinary audit evidence")
			}
			if phase == "audit_failure" && strings.Contains(w.Body.String(), "private-answer") {
				t.Fatal("audit gate released protected content")
			}
		})
	}
}

type evidenceShortWriter struct{ http.ResponseWriter }

func (w evidenceShortWriter) Write(data []byte) (int, error) { return len(data) / 2, nil }

func TestEvidenceRuntimeShortWriteDoesNotClaimDelivery(t *testing.T) {
	f := newIntegrationFixture(t)
	enableRuntimeEvidence(t, f.g, f.app.ID, "full")
	r := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(chatBody(f.connection.Alias, false)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+f.key)
	w := httptest.NewRecorder()
	f.g.Chat(evidenceShortWriter{w}, r)
	bundle := runtimeEvidence(t, f.g, w, f.app.ID)
	if bundle.DeliveryState != "write_failed" || bundle.Record.Outcome != "cancelled" {
		t.Fatal("partial write presented as delivered content")
	}
}

type evidenceMutatingReader struct {
	io.Reader
	after func()
}

func (r *evidenceMutatingReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if err == io.EOF && r.after != nil {
		r.after()
		r.after = nil
	}
	return n, err
}

func TestEvidenceRuntimeRevocationDuringBodyReadDoesNotCapture(t *testing.T) {
	f := newIntegrationFixture(t)
	enableRuntimeEvidence(t, f.g, f.app.ID, "full")
	body := &evidenceMutatingReader{Reader: strings.NewReader(chatBody(f.connection.Alias, false)), after: func() {
		if _, _, err := f.g.Store.ChangeKey(f.app.ID, f.app.Revision, true); err != nil {
			t.Fatal(err)
		}
	}}
	r := httptest.NewRequest("POST", "/v1/chat/completions", body)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+f.key)
	w := httptest.NewRecorder()
	f.g.Chat(w, r)
	if w.Code != 401 || f.calls.Load() != 0 {
		t.Fatal("revoked request was admitted")
	}
	if _, err := f.g.Evidence.Get(EvidenceID(w.Header().Get("X-Request-ID")), f.app.ID); !errors.Is(err, ErrEvidenceNotFound) {
		t.Fatal("revoked request body retained", err)
	}
}
