package gateway

import (
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

func TestApplicationOutputPolicyHistoryAndIsolation(t *testing.T) {
	p, resources := outputPolicyFixture(t)
	policy := ApplicationOutputPolicy{ApplicationID: "app-a", Mode: "redact", DetectorVersion: "sensitive-text-v3", Categories: []string{"email"}, PublicEmails: []string{"public@example.test"}}
	saved, err := p.SaveApplication("app-a", 0, &policy, resources)
	if err != nil || saved.SchemaVersion != 2 || saved.ForApplication("app-a").Mode != "redact" || saved.Applies("app-b") {
		t.Fatal("application save", err)
	}
	policy.Categories[0] = "credential"
	saved.ApplicationPolicies[0].PublicEmails[0] = "mutated@example.test"
	if p.Snapshot().ForApplication("app-a").Categories[0] != "email" || p.Snapshot().ForApplication("app-a").PublicEmails[0] != "public@example.test" {
		t.Fatal("mutable snapshot")
	}
	base := p.Snapshot().OutputPolicyInput
	base.Mode = "block"
	saved, err = p.Save(base, resources)
	if err != nil || saved.ForApplication("app-a").Mode != "redact" || saved.ForApplication("app-b").Mode != "block" {
		t.Fatal("default save overwrote binding")
	}
	if _, err = p.SaveApplication("app-a", 1, nil, resources); !errors.Is(err, ErrConflict) {
		t.Fatal("stale write accepted")
	}
	if _, err = p.SaveApplication("missing", 2, nil, resources); !errors.Is(err, ErrNotFound) {
		t.Fatal("unknown app accepted")
	}
	before := p.History()
	reopened, err := OpenOutputPolicies(filepath.Dir(p.path), resources)
	if err != nil || !reflect.DeepEqual(before, reopened.History()) {
		t.Fatal("restart changed history", err)
	}
	old, _ := reopened.Revision(0)
	if old.Applies("app-a") {
		t.Fatal("migration changed legacy snapshot")
	}
	if _, err = reopened.SaveApplication("app-a", 2, nil, resources); err != nil {
		t.Fatal(err)
	}
	if reopened.Snapshot().ForApplication("app-a").Mode != "block" {
		t.Fatal("inherit failed")
	}
	old, _ = reopened.Revision(1)
	if old.ForApplication("app-a").Mode != "redact" {
		t.Fatal("history rewritten")
	}
	// Failed persistence must not change effective protection.
	reopened.path = filepath.Join(t.TempDir(), "directory")
	os.Mkdir(reopened.path, 0700)
	previous := reopened.Snapshot()
	if _, err = reopened.SaveApplication("app-a", 3, &policy, resources); !errors.Is(err, ErrPersistence) || !reflect.DeepEqual(previous, reopened.Snapshot()) {
		t.Fatal("failed write changed policy")
	}
}

func TestApplicationOutputPoliciesCoexistAcrossModelAndEvaluation(t *testing.T) {
	const email = "synthetic-private@example.test"
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, completionText(email, "stop"))
	})
	apps := []Application{f.app}
	keys := []string{f.key}
	for _, name := range []string{"block-app", "observe-app"} {
		app, key, err := f.engine.Store.SaveApplication("", ApplicationInput{Revision: f.engine.Store.Snapshot().Revision, Name: name, AllowedConnections: []string{f.connection.ID}})
		if err != nil {
			t.Fatal(err)
		}
		apps = append(apps, app)
		keys = append(keys, key)
	}
	for i, mode := range []string{"redact", "block", "observe"} {
		policy := ApplicationOutputPolicy{ApplicationID: apps[i].ID, Mode: mode, DetectorVersion: []string{"sensitive-text-v3", "sensitive-text-v2", "sensitive-text-v1"}[i], Categories: []string{"email"}}
		if _, err := f.engine.OutputPolicies.SaveApplication(apps[i].ID, uint64(i), &policy, f.engine.Store.Snapshot()); err != nil {
			t.Fatal(err)
		}
	}
	for i, want := range []string{"redacted", "block", "observe"} {
		w := f.call(keys[i], chatBody("internal-assistant", false))
		status := 200
		if i == 1 {
			status = 403
		}
		if w.Code != status || strings.Contains(w.Body.String(), email) != (i == 2) {
			t.Fatalf("app %d: status/output mismatch %d", i, w.Code)
		}
		record := waitRecord(t, f.engine, w.Header().Get("X-Request-ID"))
		if record.OutputPolicy.Result != want || record.OutputPolicy.Revision != 3 {
			t.Fatal("incorrect audit attribution")
		}
		check := httptest.NewRequest("GET", "/v1/integration/check?model=internal-assistant", nil)
		check.Header.Set("Authorization", "Bearer "+keys[i])
		receipt := httptest.NewRecorder()
		f.engine.IntegrationCheck(receipt, check)
		var view IntegrationCheckView
		json.Unmarshal(receipt.Body.Bytes(), &view)
		if receipt.Code != 200 || view.Checks.OutputPolicy.Mode != []string{"redact", "block", "observe"}[i] || view.Supported.Streaming {
			t.Fatal("preflight ignored application policy")
		}
		evaluated := evaluateText(f.engine, keys[i], `{"text":"`+email+`"}`)
		var evaluation struct {
			Policy OutputAssessment `json:"policy"`
		}
		json.Unmarshal(evaluated.Body.Bytes(), &evaluation)
		if evaluated.Code != 200 || evaluation.Policy.Mode != view.Checks.OutputPolicy.Mode {
			t.Fatal("content evaluation ignored binding")
		}
	}
}

func TestApplicationOutputPolicyPinsInFlightEvidenceWithoutOtherBindings(t *testing.T) {
	f := newIntegrationFixture(t)
	other, _, err := f.g.Store.SaveApplication("", ApplicationInput{Revision: f.g.Store.Snapshot().Revision, Name: "Other app", AllowedConnections: []string{f.connection.ID}})
	if err != nil {
		t.Fatal(err)
	}
	for i, app := range []Application{f.app, other} {
		policy := ApplicationOutputPolicy{ApplicationID: app.ID, Mode: "redact", DetectorVersion: "sensitive-text-v3", Categories: []string{"email"}}
		if _, err = f.g.OutputPolicies.SaveApplication(app.ID, uint64(i), &policy, f.g.Store.Snapshot()); err != nil {
			t.Fatal(err)
		}
	}
	enableRuntimeEvidence(t, f.g, f.app.ID, "full")
	const email = "synthetic-retained@example.test"
	changed := false
	f.g.client.Transport = toolRoundTripper(func(*http.Request) (*http.Response, error) {
		if !changed {
			policy := ApplicationOutputPolicy{ApplicationID: f.app.ID, Mode: "observe", DetectorVersion: "sensitive-text-v1", Categories: []string{"email"}}
			if _, err := f.g.OutputPolicies.SaveApplication(f.app.ID, 2, &policy, f.g.Store.Snapshot()); err != nil {
				t.Fatal(err)
			}
			changed = true
		}
		return toolResponse(200, completionText(email, "stop")), nil
	})
	w := evidenceChat(f.g, f.key, chatBody(f.connection.Alias, false))
	if w.Code != 200 || strings.Contains(w.Body.String(), email) {
		t.Fatal("in-flight settings changed")
	}
	bundle := runtimeEvidence(t, f.g, w, f.app.ID)
	found := false
	for _, retained := range bundle.Policies {
		if retained.Kind != "output" {
			continue
		}
		found = true
		var policy OutputPolicySnapshot
		if json.Unmarshal(retained.Snapshot, &policy) != nil || policy.Revision != 2 || policy.Mode != "redact" || policy.DetectorVersion != "sensitive-text-v3" || len(policy.ApplicationPolicies) != 0 || strings.Contains(string(retained.Snapshot), other.ID) {
			t.Fatal("wrong or cross-application policy retained")
		}
	}
	if !found {
		t.Fatal("applied policy not retained")
	}
	w = evidenceChat(f.g, f.key, chatBody(f.connection.Alias, false))
	if w.Code != 200 || !strings.Contains(w.Body.String(), email) {
		t.Fatal("new request did not receive new application settings")
	}
}

func TestApplicationOutputPolicyAppliesToTools(t *testing.T) {
	const email = "synthetic-tool@example.test"
	f := newToolFixture(t, func(*http.Request) (*http.Response, error) { return toolResponse(200, `{"text":"`+email+`"}`), nil })
	enableOutput(t, f.g, "block", []string{"email"}, nil)
	policy := ApplicationOutputPolicy{ApplicationID: f.app.ID, Mode: "redact", DetectorVersion: "sensitive-text-v3", Categories: []string{"email"}}
	if _, err := f.g.OutputPolicies.SaveApplication(f.app.ID, 1, &policy, f.g.Store.Snapshot()); err != nil {
		t.Fatal(err)
	}
	w := f.call(f.key, "support", `{"resource_id":"permitted-private-id"}`)
	if w.Code != 200 || strings.Contains(w.Body.String(), email) {
		t.Fatal("tool did not use independent redaction", w.Code)
	}
	record := waitRecord(t, f.g, w.Header().Get("X-Request-ID"))
	if record.OutputPolicy.Result != "redacted" || record.OutputPolicy.DetectorVersion != "sensitive-text-v3" {
		t.Fatal("tool policy receipt mismatch")
	}
	if _, err := f.g.OutputPolicies.SaveApplication(f.app.ID, 2, nil, f.g.Store.Snapshot()); err != nil {
		t.Fatal(err)
	}
	if f.call(f.key, "support", `{"resource_id":"permitted-private-id"}`).Code != 403 {
		t.Fatal("tool did not resume inherited blocking")
	}
}
