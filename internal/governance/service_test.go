package governance

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"govweave/internal/compliance"
	"govweave/internal/gateway"
)

type fixture struct {
	service    *Service
	gateway    *gateway.Engine
	evaluator  *compliance.Engine
	app        gateway.Application
	connection gateway.Connection
	key        string
	dir        string
}

func setup(t *testing.T) fixture {
	t.Helper()
	dir := t.TempDir()
	g, err := gateway.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.Close() })
	c, err := g.Store.SaveConnection("", gateway.ConnectionInput{Name: "Local synthetic model", BaseURL: "http://127.0.0.1:1/v1", Model: "local", Alias: "assistant", Enabled: true, AllowInsecureHTTP: true, TimeoutSeconds: 1})
	if err != nil {
		t.Fatal(err)
	}
	app, key, err := g.Store.SaveApplication("", gateway.ApplicationInput{Name: "Synthetic app", AllowedConnections: []string{c.ID}})
	if err != nil {
		t.Fatal(err)
	}
	e, err := compliance.Open("../../examples/rule-packs")
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir, g, e)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return fixture{s, g, e, app, c, key, dir}
}

func (f fixture) input() ProductInput {
	now := time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)
	return ProductInput{Name: "Synthetic assistant", Version: "1.0.0", ApplicationIDs: []string{f.app.ID}, PackID: "demo-ai-governance", PackVersion: "1.0.0", Facts: map[string]compliance.Fact{
		"product.user_facing":              {Value: json.RawMessage("true"), EvidenceID: "profile-001", Source: "declared", ObservedAt: now},
		"transparency.disclosure_verified": {Value: json.RawMessage("true"), EvidenceID: "assessment-001", Source: "assessment", ObservedAt: now},
	}}
}

func await(t *testing.T, s *Service, id string, condition func(Report) bool) Report {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		// Inspect the cache without triggering a refresh through Latest, so
		// this verifies background events rather than read-triggered repair.
		s.mu.Lock()
		report, ok := s.reports[id]
		report = cloneReport(report)
		s.mu.Unlock()
		if ok && condition(report) {
			return report
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("automatic assessment did not reach expected state")
	return Report{}
}

func setMode(t *testing.T, f fixture, mode string) {
	t.Helper()
	in := f.gateway.Policies.Snapshot().PolicyInput
	in.Mode = mode
	if _, err := f.gateway.Policies.Save(in, f.gateway.Store.Snapshot()); err != nil {
		t.Fatal(err)
	}
	f.gateway.NotifyChange()
}

func TestAutomaticAssessmentOnProductPolicyAndCallChanges(t *testing.T) {
	f := setup(t)
	product, err := f.service.Save("", f.input())
	if err != nil {
		t.Fatal(err)
	}
	await(t, f.service, product.ID, func(r Report) bool { return r.State == "ready" && r.Evaluation.Status == "gaps_detected" })
	setMode(t, f, "block")
	before := await(t, f.service, product.ID, func(r Report) bool { return r.State == "ready" && r.Evaluation.Status == "satisfied" })
	// Blocking needs no mock listener: the synthetic credential must never be forwarded.
	body := `{"model":"assistant","messages":[{"role":"user","content":"sk-synthetic-credential-012345678901234567890"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+f.key)
	w := httptest.NewRecorder()
	f.gateway.Chat(w, req)
	if w.Code != 403 {
		t.Fatalf("synthetic call was not blocked: %d", w.Code)
	}
	after := await(t, f.service, product.ID, func(r Report) bool { return r.State == "ready" && r.Snapshot.AuditBytes > before.Snapshot.AuditBytes })
	input := capture(f.gateway).input(product, time.Now())
	if string(input.Facts["runtime.sample.request_count"].Value) != "1" || string(input.Facts["runtime.sample.policy_block_count"].Value) != "1" {
		t.Fatal("call-derived evidence missing")
	}
	serialized, _ := json.Marshal(after)
	profileData, _ := os.ReadFile(filepath.Join(f.dir, "products.json"))
	for _, secret := range []string{f.key, "sk-synthetic-credential-012345678901234567890"} {
		if bytes.Contains(serialized, []byte(secret)) || bytes.Contains(profileData, []byte(secret)) {
			t.Fatal("request content or credentials leaked into governance")
		}
	}
	// Read results must not expose mutable cache slices.
	after.Evaluation.Controls[0].Status = "mutated"
	again, err := f.service.Latest(product.ID)
	if err != nil || again.Evaluation.Controls[0].Status == "mutated" {
		t.Fatal("caller mutated cached report")
	}
}

func TestProfilePersistenceRevisionConflictsAndReservedEvidence(t *testing.T) {
	f := setup(t)
	f.service.Close()
	in := f.input()
	product, err := f.service.Save("", in)
	if err != nil {
		t.Fatal(err)
	}
	in.ApplicationIDs[0] = "mutated"
	fact := in.Facts["product.user_facing"]
	fact.Value[0] = 'f'
	stored, _ := f.service.Products.Get(product.ID)
	if stored.ApplicationIDs[0] != f.app.ID || string(stored.Facts["product.user_facing"].Value) != "true" {
		t.Fatal("input alias changed stored profile")
	}
	if _, err := f.service.Save(product.ID, f.input()); !errors.Is(err, gateway.ErrConflict) {
		t.Fatal("stale update accepted")
	}
	for _, change := range []func(*ProductInput){
		func(in *ProductInput) {
			in.Facts["runtime.audit_available"] = compliance.Fact{Value: json.RawMessage("true"), EvidenceID: "forged", Source: "declared", ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
		},
		func(in *ProductInput) {
			fact := in.Facts["product.user_facing"]
			fact.Source = "runtime"
			in.Facts["product.user_facing"] = fact
		},
		func(in *ProductInput) { in.ApplicationIDs = []string{"unknown-app"} },
		func(in *ProductInput) { in.PackVersion = "absent" },
	} {
		input := f.input()
		input.Revision = product.Revision
		change(&input)
		if _, err := f.service.Save(product.ID, input); err == nil {
			t.Fatal("invalid profile accepted")
		}
	}
	reopened, err := openProducts(f.dir)
	if err != nil || !reflect.DeepEqual(reopened.List(), f.service.Products.List()) {
		t.Fatal("profile did not persist", err)
	}
	info, _ := os.Stat(filepath.Join(f.dir, "products.json"))
	if info.Mode().Perm() != 0600 {
		t.Fatal("profile is not private")
	}
	path := f.service.Products.path
	f.service.Products.path = filepath.Join(t.TempDir(), "missing", "products.json")
	input := f.input()
	input.Revision = product.Revision
	input.Name = "Changed"
	if _, err := f.service.Save(product.ID, input); !errors.Is(err, gateway.ErrPersistence) {
		t.Fatal("failed save not reported")
	}
	f.service.Products.path = path
	current, _ := f.service.Products.Get(product.ID)
	if current.Name != product.Name || current.Revision != product.Revision {
		t.Fatal("failed save published profile")
	}
	if err := os.WriteFile(path, []byte(`{"schema_version":99,"products":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := openProducts(f.dir); err == nil {
		t.Fatal("corrupt registry silently reset")
	}
}

func TestPendingOnSourceChangesAndEvidenceExpiry(t *testing.T) {
	f := setup(t)
	f.service.Close()
	setMode(t, f, "block")
	input := f.input()
	fact := input.Facts["transparency.disclosure_verified"]
	fact.ExpiresAt = time.Now().Add(200 * time.Millisecond).UTC().Format(time.RFC3339Nano)
	input.Facts["transparency.disclosure_verified"] = fact
	product, err := f.service.Save("", input)
	if err != nil {
		t.Fatal(err)
	}
	report, err := f.service.Refresh(product.ID)
	if err != nil || report.State != "ready" || report.Evaluation.Status != "satisfied" {
		t.Fatal("initial report missing", err)
	}
	deadline, _ := time.Parse(time.RFC3339Nano, fact.ExpiresAt)
	time.Sleep(time.Until(deadline) + time.Millisecond)
	pending, _ := f.service.Latest(product.ID)
	if pending.State != "pending" || pending.Evaluation != nil {
		t.Fatal("expired evidence retained a passing report")
	}
	refreshed, err := f.service.Refresh(product.ID)
	if err != nil || refreshed.Evaluation.Status != "insufficient_evidence" {
		t.Fatal("expiry did not change assessment", err)
	}
	setMode(t, f, "observe")
	pending, _ = f.service.Latest(product.ID)
	if pending.State != "pending" || pending.Evaluation != nil {
		t.Fatal("configuration change retained stale evaluation")
	}
}

func TestRestartReassessesAndMissingPackIsVisible(t *testing.T) {
	f := setup(t)
	product, err := f.service.Save("", f.input())
	if err != nil {
		t.Fatal(err)
	}
	await(t, f.service, product.ID, func(r Report) bool { return r.State == "ready" })
	f.service.Close()
	empty, err := compliance.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(f.dir, f.gateway, empty)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	report := await(t, reopened, product.ID, func(r Report) bool { return r.State == "error" })
	if report.ErrorCode != "rule_pack_not_found" || report.Evaluation != nil {
		t.Fatal("missing pack substituted a passing report")
	}
}
