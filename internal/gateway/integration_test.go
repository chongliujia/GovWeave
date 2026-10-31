package gateway

import (
	"crypto/cipher"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type integrationFixture struct {
	g          *Engine
	dir        string
	key        string
	app        Application
	connection Connection
	calls      atomic.Int32
}

func newIntegrationFixture(t *testing.T) *integrationFixture {
	t.Helper()
	f := &integrationFixture{dir: t.TempDir()}
	var err error
	f.g, err = Open(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.g.Close() })
	f.g.client = &http.Client{Transport: toolRoundTripper(func(*http.Request) (*http.Response, error) {
		f.calls.Add(1)
		return toolResponse(200, completion), nil
	})}
	f.connection, err = f.g.Store.SaveConnection("", connectionInput("https://private-provider.example/v1"))
	if err != nil {
		t.Fatal(err)
	}
	f.app, f.key, err = f.g.Store.SaveApplication("", ApplicationInput{Name: "Integration app", AllowedConnections: []string{f.connection.ID}})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func integrationRequest(g *Engine, key, rawQuery string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/v1/integration/check", nil)
	r.URL.RawQuery = rawQuery
	if key != "" {
		r.Header.Set("Authorization", "Bearer "+key)
	}
	w := httptest.NewRecorder()
	g.IntegrationCheck(w, r)
	return w
}

func integrationView(t *testing.T, w *httptest.ResponseRecorder) IntegrationCheckView {
	t.Helper()
	var view IntegrationCheckView
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &view) != nil {
		t.Fatalf("integration check failed: %d %s", w.Code, w.Body.String())
	}
	if view.SchemaVersion != 1 || view.UpstreamContacted || view.Inference != "not_tested" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("configuration snapshot overclaims inference evidence or can be cached")
	}
	return view
}

func TestIntegrationCheckLocalOnlyAndPrivate(t *testing.T) {
	f := newIntegrationFixture(t)
	before, err := os.ReadFile(filepath.Join(f.dir, "calls.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	w := integrationRequest(f.g, f.key, "model=internal-assistant")
	view := integrationView(t, w)
	if view.ApplicationID != f.app.ID || view.Model != f.connection.Alias || view.ConfigurationRevision != f.g.Store.Snapshot().Revision {
		t.Fatal("wrong authenticated application or model configuration")
	}
	if view.Checks.ModelAccess != "allowed" || !view.Checks.AuditAvailable || view.Checks.InputPolicy != (IntegrationPolicyCheck{Mode: "disabled"}) || view.Checks.OutputPolicy != (IntegrationPolicyCheck{Mode: "disabled"}) {
		t.Fatal("incorrect default policy status", view)
	}
	if !view.Supported.ChatCompletions || !view.Supported.Streaming || !view.Supported.ToolGovernanceRequiresSeparateIntegration {
		t.Fatal("incorrect capability boundaries", view)
	}
	for _, private := range []string{f.key, "provider-credential-private", f.connection.BaseURL, f.connection.Model, f.connection.Name, f.connection.ID, "allowed_connections", "application_ids", "categories", "rules"} {
		if strings.Contains(w.Body.String(), private) {
			t.Fatalf("integration response disclosed private configuration field: %q", private)
		}
	}
	after, err := os.ReadFile(filepath.Join(f.dir, "calls.jsonl"))
	if err != nil || string(before) != string(after) || f.calls.Load() != 0 || f.g.Audit.size != 0 || f.g.Audit.reserved != 0 || len(f.g.Audit.recent) != 0 {
		t.Fatal("local inspection performed I/O or reserved/wrote audit evidence", err)
	}
}

func TestIntegrationCheckRejectsInvalidAuthAndQuery(t *testing.T) {
	f := newIntegrationFixture(t)
	for _, query := range []string{"", "model=", "model=internal-assistant&model=internal-assistant", "model=internal-assistant&application_id=other", "model=%XX", "model=bad+alias", "model=" + strings.Repeat("a", 101), "model=" + strings.Repeat("%61", 180), "unexpected=internal-assistant"} {
		w := integrationRequest(f.g, f.key, query)
		if w.Code != 400 || !strings.Contains(w.Body.String(), `"code":"invalid_integration_query"`) {
			t.Errorf("invalid query accepted: %q: %d", query, w.Code)
		}
	}
	for _, key := range []string{"", "synthetic-invalid-key"} {
		w := integrationRequest(f.g, key, "invalid=%XX")
		if w.Code != 401 || !strings.Contains(w.Body.String(), `"code":"invalid_api_key"`) {
			t.Fatal("authentication must precede query validation")
		}
	}
	r := httptest.NewRequest(http.MethodGet, "/v1/integration/check?model=internal-assistant", nil)
	r.Header.Add("Authorization", "Bearer "+f.key)
	r.Header.Add("Authorization", "Bearer "+f.key)
	w := httptest.NewRecorder()
	f.g.IntegrationCheck(w, r)
	if w.Code != 401 {
		t.Fatal("duplicate authorization accepted")
	}
	_, replacement, err := f.g.Store.ChangeKey(f.app.ID, f.app.Revision, false)
	if err != nil {
		t.Fatal(err)
	}
	if integrationRequest(f.g, f.key, "model=internal-assistant").Code != 401 || integrationRequest(f.g, replacement, "model=internal-assistant").Code != 200 {
		t.Fatal("rotated application key remained valid or replacement rejected")
	}
	current := f.g.Store.Snapshot().Applications[0]
	if _, _, err := f.g.Store.ChangeKey(current.ID, current.Revision, true); err != nil {
		t.Fatal(err)
	}
	if integrationRequest(f.g, replacement, "model=internal-assistant").Code != 401 || f.calls.Load() != 0 || f.g.Audit.size != 0 {
		t.Fatal("revocation or no-I/O boundary failed")
	}
}

func TestIntegrationCheckRespectsModelAccessAndConfiguration(t *testing.T) {
	f := newIntegrationFixture(t)
	_, otherKey, err := f.g.Store.SaveApplication("", ApplicationInput{Name: "Other app", AllowedConnections: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ key, alias string }{{otherKey, "internal-assistant"}, {f.key, "unknown-model"}} {
		w := integrationRequest(f.g, tc.key, "model="+tc.alias)
		if w.Code != 403 || !strings.Contains(w.Body.String(), `"code":"model_not_allowed"`) {
			t.Fatal("ungranted or unknown model was exposed", w.Code)
		}
	}
	input := connectionInput(f.connection.BaseURL)
	input.Revision, input.Enabled = f.connection.Revision, false
	disabled, err := f.g.Store.SaveConnection(f.connection.ID, input)
	if err != nil {
		t.Fatal(err)
	}
	w := integrationRequest(f.g, f.key, "model=internal-assistant")
	if w.Code != 403 || !strings.Contains(w.Body.String(), `"code":"connection_disabled"`) {
		t.Fatal("disabled model accepted")
	}
	input.Revision, input.Enabled = disabled.Revision, true
	if _, err := f.g.Store.SaveConnection(disabled.ID, input); err != nil {
		t.Fatal(err)
	}
	// An unreadable local credential prevents a usable configuration result,
	// without probing the provider or exposing ciphertext/error details.
	f.g.Store.mu.Lock()
	f.g.Store.state.Connections[0].Credential = "synthetic-corrupt-ciphertext"
	f.g.Store.mu.Unlock()
	w = integrationRequest(f.g, f.key, "model=internal-assistant")
	if w.Code != 503 || !strings.Contains(w.Body.String(), `"code":"credential_unavailable"`) || strings.Contains(w.Body.String(), "synthetic-corrupt") {
		t.Fatal("credential failure not contained")
	}
	if f.calls.Load() != 0 || f.g.Audit.size != 0 {
		t.Fatal("failed inspection generated calls or evidence")
	}
}

func TestIntegrationCheckPolicyModesAndScopes(t *testing.T) {
	f := newIntegrationFixture(t)
	otherInput := connectionInput("https://other-private-provider.example/v1")
	otherInput.Alias = "other-model"
	otherConnection, err := f.g.Store.SaveConnection("", otherInput)
	if err != nil {
		t.Fatal(err)
	}
	otherApp, _, err := f.g.Store.SaveApplication("", ApplicationInput{Name: "Other app", AllowedConnections: []string{otherConnection.ID}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		inputMode, outputMode                   string
		inputApps, inputConnections, outputApps []string
		inputApplies, outputApplies             bool
	}{
		{"observe", "block", nil, nil, nil, true, true},
		{"block", "observe", []string{otherApp.ID}, nil, []string{otherApp.ID}, false, false},
		{"block", "redact", []string{f.app.ID}, []string{otherConnection.ID}, []string{f.app.ID}, false, true},
		{"block", "observe", []string{f.app.ID}, []string{f.connection.ID}, []string{f.app.ID}, true, true},
		{"disabled", "disabled", nil, nil, nil, false, false},
	} {
		input := f.g.Policies.Snapshot().PolicyInput
		input.Mode, input.ApplicationIDs, input.ConnectionIDs = tc.inputMode, tc.inputApps, tc.inputConnections
		inputSaved, err := f.g.Policies.Save(input, f.g.Store.Snapshot())
		if err != nil {
			t.Fatal(err)
		}
		output := f.g.OutputPolicies.Snapshot().OutputPolicyInput
		output.Mode, output.ApplicationIDs = tc.outputMode, tc.outputApps
		outputSaved, err := f.g.OutputPolicies.Save(output, f.g.Store.Snapshot())
		if err != nil {
			t.Fatal(err)
		}
		w := integrationRequest(f.g, f.key, "model=internal-assistant")
		view := integrationView(t, w)
		if view.Checks.InputPolicy != (IntegrationPolicyCheck{Mode: tc.inputMode, Applies: tc.inputApplies, Revision: inputSaved.Revision}) ||
			view.Checks.OutputPolicy != (IntegrationPolicyCheck{Mode: tc.outputMode, Applies: tc.outputApplies, Revision: outputSaved.Revision}) || view.Supported.Streaming == tc.outputApplies {
			t.Fatal("policy applicability or streaming boundary is wrong", view)
		}
		if strings.Contains(w.Body.String(), otherApp.ID) || strings.Contains(w.Body.String(), otherConnection.ID) {
			t.Fatal("another application or connection scope leaked")
		}
	}
}

func TestIntegrationCheckAuditAvailabilityDoesNotReserve(t *testing.T) {
	f := newIntegrationFixture(t)
	for _, tc := range []struct {
		failed         bool
		size, reserved int64
		available      bool
	}{
		{false, 0, 0, true},
		{true, 0, 0, false},
		{false, AuditMaxBytes - 2*maxAuditEventBytes, 0, true},
		{false, AuditMaxBytes - 2*maxAuditEventBytes, 1, false},
		{false, AuditMaxBytes, 0, false},
	} {
		f.g.Audit.mu.Lock()
		f.g.Audit.failed, f.g.Audit.size, f.g.Audit.reserved = tc.failed, tc.size, tc.reserved
		f.g.Audit.mu.Unlock()
		view := integrationView(t, integrationRequest(f.g, f.key, "model=internal-assistant"))
		if view.Checks.AuditAvailable != tc.available || f.g.Audit.size != tc.size || f.g.Audit.reserved != tc.reserved || len(f.g.Audit.pending) != 0 {
			t.Fatal("inspection changed capacity or misreported the admission boundary")
		}
	}
	if f.calls.Load() != 0 {
		t.Fatal("audit status inspection reached upstream")
	}
}

type integrationSignalAEAD struct {
	cipher.AEAD
	once   sync.Once
	opened chan struct{}
}

func (a *integrationSignalAEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	result, err := a.AEAD.Open(dst, nonce, ciphertext, additionalData)
	a.once.Do(func() { close(a.opened) })
	return result, err
}

func TestIntegrationCheckReauthenticatesBeforeReturning(t *testing.T) {
	f := newIntegrationFixture(t)
	opened := make(chan struct{})
	f.g.Store.vault = &integrationSignalAEAD{AEAD: f.g.Store.vault, opened: opened}
	// Hold the next snapshot read after Resolve so revocation is deterministic,
	// without adding hooks or sleeps to the production handler.
	f.g.Policies.mu.Lock()
	response := make(chan *httptest.ResponseRecorder, 1)
	go func() { response <- integrationRequest(f.g, f.key, "model=internal-assistant") }()
	<-opened
	_, _, err := f.g.Store.ChangeKey(f.app.ID, f.app.Revision, true)
	f.g.Policies.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	w := <-response
	if w.Code != 401 || strings.Contains(w.Body.String(), f.app.ID) || f.calls.Load() != 0 || f.g.Audit.size != 0 {
		t.Fatal("revoked identity received configuration evidence")
	}
}
