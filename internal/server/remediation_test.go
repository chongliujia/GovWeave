package server

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"govweave/internal/admincli"
	"govweave/internal/compliance"
	"govweave/internal/gateway"
	"govweave/internal/governance"
)

func TestRemediationManagementAndCLI(t *testing.T) {
	evaluator, err := compliance.Open("../../examples/rule-packs")
	if err != nil {
		t.Fatal(err)
	}
	h := handlerWithCompliance(t, evaluator)
	api := func(method, path string, input, output any) {
		t.Helper()
		data, _ := json.Marshal(input)
		w := invoke(h, method, path, string(data), testPassword, nil)
		if w.Code != 200 {
			t.Fatalf("%s %s: %d %s", method, path, w.Code, w.Body.String())
		}
		if output != nil && json.Unmarshal(w.Body.Bytes(), output) != nil {
			t.Fatal("invalid API JSON")
		}
	}
	var conn gateway.Connection
	api("POST", "/api/v1/connections", gateway.ConnectionInput{Name: "Remediation fixture", Alias: "fixture", Model: "fixture", BaseURL: "http://127.0.0.1:1/v1", Enabled: true, AllowInsecureHTTP: true, TimeoutSeconds: 1}, &conn)
	var app applicationResponse
	api("POST", "/api/v1/applications", gateway.ApplicationInput{Name: "Remediation app", AllowedConnections: []string{conn.ID}}, &app)
	var product governance.Product
	api("POST", "/api/v1/compliance/products", governance.ProductInput{Name: "Remediation product", Version: "1", PackID: "demo-ai-governance", PackVersion: "1.0.0", ApplicationIDs: []string{app.Application.ID}, Facts: map[string]compliance.Fact{}}, &product)
	base := "/api/v1/compliance/products/" + product.ID + "/remediations"
	var report governance.ArchivedReport
	api("POST", "/api/v1/compliance/products/"+product.ID+"/reports", struct{}{}, &report)
	for _, route := range []struct{ method, path string }{{"GET", base}, {"POST", base}, {"GET", base + "/absent"}, {"PUT", base + "/absent"}, {"POST", base + "/absent/recheck"}} {
		for _, key := range []string{"", app.APIKey} {
			if invoke(h, route.method, route.path, `{}`, key, nil).Code != 401 {
				t.Fatal("missing administrator boundary")
			}
		}
	}
	for _, headers := range []map[string]string{{"Origin": "https://other.example"}, {"X-GovWeave-Request": ""}} {
		if invoke(h, "POST", base, `{}`, testPassword, headers).Code != 403 {
			t.Fatal("missing mutation boundary")
		}
	}
	if invoke(h, "POST", base, `{"status":"verified"}`, testPassword, nil).Code != 400 {
		t.Fatal("forged field accepted")
	}
	instance := httptest.NewServer(h)
	defer instance.Close()
	session := filepath.Join(t.TempDir(), "session.json")
	if err := admincli.Run([]string{"--url", instance.URL, "--session-file", session, "--password-stdin", "login"}, strings.NewReader(testPassword), &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	cli := func(want bool, output any, args ...string) {
		t.Helper()
		var stdout, stderr bytes.Buffer
		err := admincli.Run(append([]string{"--url", instance.URL, "--session-file", session}, args...), nil, &stdout, &stderr)
		if (err == nil) != want {
			t.Fatalf("CLI %v: %v", args, err)
		}
		if want && output != nil && json.Unmarshal(stdout.Bytes(), output) != nil {
			t.Fatal("invalid CLI result")
		}
		if strings.Contains(stdout.String()+stderr.String(), testPassword) || strings.Contains(stdout.String(), app.APIKey) {
			t.Fatal("secret in remediation output")
		}
	}
	config := filepath.Join(t.TempDir(), "input.json")
	write := func(value any) {
		data, _ := json.Marshal(value)
		if os.WriteFile(config, data, 0600) != nil {
			t.Fatal("fixture config")
		}
	}
	cli(true, nil, "products", "list")
	cli(true, nil, "reports", "list", "--product", product.ID)
	write(governance.RemediationCreate{ReportID: report.Summary.ID, ControlID: "CREDENTIAL-EGRESS", Note: "Synthetic issue"})
	var item governance.RemediationView
	cli(true, &item, "remediations", "create", "--product", product.ID, "--file", config)
	cli(false, nil, "remediations", "create", "--product", product.ID, "--file", config)
	path := base + "/" + item.ID
	if invoke(h, "PUT", path, `{"revision":1,"status":"verified","owner":"","due_date":"","note":"forged"}`, testPassword, nil).Code != 400 {
		t.Fatal("manual closure accepted")
	}
	in := item.Current.RemediationInput
	in.Status = "ready_for_recheck"
	in.Note = "Enable and recheck policy"
	write(in)
	cli(true, &item, "remediations", "update", "--product", product.ID, "--id", item.ID, "--file", config)
	cli(false, nil, "remediations", "recheck", "--product", product.ID, "--id", item.ID, "--revision", "1")
	var policy gateway.PolicySnapshot
	api("GET", "/api/v1/policies/credential-egress", nil, &policy)
	input := policy.PolicyInput
	input.Mode = "block"
	api("PUT", "/api/v1/policies/credential-egress", input, nil)
	cli(true, &item, "remediations", "recheck", "--product", product.ID, "--id", item.ID, "--revision", "2")
	if item.Current.Status != "verified" || item.VerificationState != "current" {
		t.Fatal("CLI verification failed")
	}
	cli(true, nil, "remediations", "list", "--product", product.ID)
	cli(true, nil, "remediations", "show", "--product", product.ID, "--id", item.ID)
	cli(true, nil, "reports", "show", "--id", item.Current.Verification.ReportID)
	cli(true, nil, "tests", "plans", "--product", product.ID)
	cli(true, nil, "tests", "list", "--product", product.ID)
	if invoke(h, "GET", "/api/v1/compliance/products/other/remediations/"+item.ID, "", testPassword, nil).Code != 404 {
		t.Fatal("cross-product route accepted")
	}
	cli(true, nil, "logout")
}
