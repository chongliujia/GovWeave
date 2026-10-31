package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"govweave/internal/compliance"
)

func TestCompliancePluginAPI(t *testing.T) {
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
	data, err = os.ReadFile("../../examples/compliance-evaluation.json")
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)
	for _, path := range []string{"/api/v1/compliance/packs", "/api/v1/compliance/evaluations"} {
		method := "GET"
		if strings.HasSuffix(path, "evaluations") {
			method = "POST"
		}
		for _, key := range []string{"", "gw_app_synthetic-key"} {
			if invoke(h, method, path, body, key, nil).Code != 401 {
				t.Fatal("compliance API missing administrator authentication")
			}
		}
	}
	w := invoke(h, "GET", "/api/v1/compliance/packs", "", testPassword, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"id":"demo-ai-governance"`) || !strings.Contains(w.Body.String(), `"sha256":`) {
		t.Fatal("installed plugins not listed")
	}
	path := "/api/v1/compliance/evaluations"
	for _, tc := range []struct {
		body    string
		headers map[string]string
		status  int
	}{
		{body, map[string]string{"Origin": "https://untrusted.example"}, 403},
		{body, map[string]string{"X-GovWeave-Request": ""}, 403},
		{body, map[string]string{"Content-Type": "text/plain"}, 415},
		{body + `{}`, nil, 400},
		{strings.Replace(body, `"pack_version": "1.0.0"`, `"pack_version": "absent"`, 1), nil, 404},
		{strings.TrimSuffix(strings.TrimSpace(body), "}") + `,"script":"private-test-value"}`, nil, 400},
		{strings.Repeat(" ", 16*1024) + body, nil, 413},
	} {
		w = invoke(h, "POST", path, tc.body, testPassword, tc.headers)
		if w.Code != tc.status || strings.Contains(w.Body.String(), "private-test-value") {
			t.Fatalf("API boundary mismatch: %d %s", w.Code, w.Body.String())
		}
	}
	w = invoke(h, "POST", path, body, testPassword, nil)
	var result compliance.Evaluation
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Status != "insufficient_evidence" || result.LegalCompliance != "not_determined" || !result.EvaluationOnly || result.Controls[1].Status != "pass" {
		t.Fatalf("unexpected evaluation: %s", w.Body.String())
	}
}
