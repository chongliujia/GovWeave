package server

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"govweave/internal/compliance"
	"govweave/internal/governance"
)

func TestProductRegistryAndAutomaticEvaluationAPI(t *testing.T) {
	dir := t.TempDir()
	data, err := os.ReadFile("../../examples/rule-packs/demo-ai-governance.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "demo.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	evaluator, err := compliance.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	h := handlerWithCompliance(t, evaluator)
	base := "/api/v1/compliance/products"
	for _, route := range []struct{ method, path string }{{"GET", base}, {"POST", base}, {"GET", base + "/unknown"}, {"PUT", base + "/unknown"}, {"GET", base + "/unknown/evaluation"}, {"POST", base + "/unknown/evaluate"}} {
		if invoke(h, route.method, route.path, `{}`, "", nil).Code != 401 {
			t.Fatal("product API missing authentication")
		}
	}
	connection := `{"name":"Local synthetic provider","base_url":"http://127.0.0.1:1/v1","model":"test-model","alias":"assistant","enabled":true,"allow_insecure_http":true,"timeout_seconds":1}`
	w := invoke(h, "POST", "/api/v1/connections", connection, testPassword, nil)
	var c struct{ ID string }
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &c) != nil {
		t.Fatal("connection fixture failed")
	}
	w = invoke(h, "POST", "/api/v1/applications", fmt.Sprintf(`{"name":"Product application","allowed_connections":[%q]}`, c.ID), testPassword, nil)
	var app applicationResponse
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &app) != nil {
		t.Fatal("application fixture failed")
	}
	if invoke(h, "GET", base, "", app.APIKey, nil).Code != 401 {
		t.Fatal("inference key accessed product data")
	}
	now := time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)
	input := governance.ProductInput{Name: "Product demo", Version: "1.0.0", PackID: "demo-ai-governance", PackVersion: "1.0.0", ApplicationIDs: []string{app.Application.ID}, Facts: map[string]compliance.Fact{
		"product.user_facing":              {Value: json.RawMessage("true"), EvidenceID: "profile-test", Source: "declared", ObservedAt: now},
		"transparency.disclosure_verified": {Value: json.RawMessage("true"), EvidenceID: "assessment-test", Source: "assessment", ObservedAt: now},
	}}
	marshal := func(value any) string {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	for _, headers := range []map[string]string{{"Origin": "https://attacker.example"}, {"X-GovWeave-Request": ""}} {
		if invoke(h, "POST", base, marshal(input), testPassword, headers).Code != 403 {
			t.Fatal("cross-site product write allowed")
		}
	}
	w = invoke(h, "POST", base, marshal(input), testPassword, nil)
	var product governance.Product
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &product) != nil {
		t.Fatalf("product save failed: %s", w.Body.String())
	}
	path := base + "/" + product.ID
	poll := func(status string) governance.Report {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			w := invoke(h, "GET", path+"/evaluation", "", testPassword, nil)
			var report governance.Report
			if w.Code == 200 && json.Unmarshal(w.Body.Bytes(), &report) == nil && report.State == "ready" && report.Evaluation.Status == status {
				return report
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("automatic product evaluation did not become %s", status)
		return governance.Report{}
	}
	poll("gaps_detected")
	policy := `{"revision":0,"mode":"block","rules":["private_key","api_key"],"application_ids":[],"connection_ids":[]}`
	if invoke(h, "PUT", "/api/v1/policies/credential-egress", policy, testPassword, nil).Code != 200 {
		t.Fatal("policy fixture failed")
	}
	report := poll("satisfied")
	if report.Snapshot.PolicyRevision != 1 || !report.Evaluation.EvaluationOnly || report.Evaluation.LegalCompliance != "not_determined" {
		t.Fatal("missing trusted attribution")
	}
	// Update to an out-of-scope connection and verify that the actual PUT
	// notification refreshes coverage without manually posting an evaluation.
	connection2 := strings.Replace(strings.Replace(connection, "Local synthetic provider", "Other provider", 1), `"alias":"assistant"`, `"alias":"other"`, 1)
	w = invoke(h, "POST", "/api/v1/connections", connection2, testPassword, nil)
	var other struct{ ID string }
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &other) != nil {
		t.Fatal("second connection fixture failed")
	}
	policy = fmt.Sprintf(`{"revision":1,"mode":"block","rules":["private_key","api_key"],"application_ids":[],"connection_ids":[%q]}`, other.ID)
	if invoke(h, "PUT", "/api/v1/policies/credential-egress", policy, testPassword, nil).Code != 200 {
		t.Fatal("scope fixture failed")
	}
	poll("gaps_detected")
	input.Revision = product.Revision
	input.Facts["runtime.audit_available"] = compliance.Fact{Value: json.RawMessage("true"), EvidenceID: "forged", Source: "declared", ObservedAt: now}
	if invoke(h, "PUT", path, marshal(input), testPassword, nil).Code != 400 {
		t.Fatal("forged runtime facts accepted")
	}
	delete(input.Facts, "runtime.audit_available")
	if invoke(h, "PUT", path, marshal(input)+`{}`, testPassword, nil).Code != 400 {
		t.Fatal("multiple profile objects accepted")
	}
	w = invoke(h, "PUT", path, marshal(input), testPassword, nil)
	if w.Code != 200 {
		t.Fatal("valid product update failed")
	}
	if invoke(h, "PUT", path, marshal(input), testPassword, nil).Code != 409 {
		t.Fatal("stale product update accepted")
	}
	if invoke(h, "POST", path+"/evaluate", `{"facts":{}}`, testPassword, nil).Code != 400 {
		t.Fatal("manual override accepted on trusted evaluation route")
	}
	if invoke(h, "POST", path+"/evaluate", `{}`, testPassword, nil).Code != 200 {
		t.Fatal("explicit refresh failed")
	}
	if invoke(h, "GET", base+"/missing/evaluation", "", testPassword, nil).Code != 404 {
		t.Fatal("unknown product did not return 404")
	}
}
