package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"govweave/internal/compliance"
	"govweave/internal/gateway"
	"govweave/internal/sensitive"
)

func TestPluginCatalogAdministration(t *testing.T) {
	directory := t.TempDir()
	pack, err := os.ReadFile("../../examples/rule-packs/demo-ai-governance.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "demo.json"), pack, 0600); err != nil {
		t.Fatal(err)
	}
	engine, err := compliance.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	handler := handlerWithCompliance(t, engine)
	for _, key := range []string{"", "gw_app_synthetic"} {
		if response := invoke(handler, "GET", "/api/v1/plugins", "", key, nil); response.Code != 401 {
			t.Fatal("plugin catalog requires administrator authentication")
		}
	}
	response := invoke(handler, "GET", "/api/v1/plugins", "", testPassword, nil)
	var catalog struct {
		RulePacks []compliance.Descriptor `json:"rule_packs"`
		Detectors []sensitive.Descriptor  `json:"detectors"`
	}
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &catalog) != nil || len(catalog.RulePacks) != 1 || len(catalog.Detectors) != 3 {
		t.Fatal("missing installed plugins", response.Body.String())
	}
	if catalog.RulePacks[0] != engine.Catalog()[0] {
		t.Fatal("catalog changed installed pack provenance")
	}
	for _, detector := range catalog.Detectors {
		if !sensitive.Supports(detector.Version) {
			t.Fatal("catalog advertised an unavailable detector")
		}
	}
	policy := invoke(handler, "GET", "/api/v1/policies/sensitive-output", "", testPassword, nil)
	var snapshot struct {
		Mode     string `json:"mode"`
		Revision uint64 `json:"revision"`
	}
	if json.Unmarshal(policy.Body.Bytes(), &snapshot) != nil || snapshot.Mode != "disabled" || snapshot.Revision != 0 {
		t.Fatal("reading plugins activated runtime enforcement")
	}
}

func TestPluginPreviewAdministrationAndIsolation(t *testing.T) {
	handler := handler(t)
	path := "/api/v1/plugins/sensitive-output/preview"
	body := `{"text":"Contact private@example.test","detector_version":"sensitive-text-v3","mode":"redact","categories":["email"]}`
	for _, key := range []string{"", "gw_app_synthetic"} {
		if response := invoke(handler, "POST", path, body, key, nil); response.Code != 401 {
			t.Fatal("preview requires administrator authentication")
		}
	}
	for _, headers := range []map[string]string{
		{"Origin": "https://external.example"},
		{"Sec-Fetch-Site": "cross-site"},
		{"X-GovWeave-Request": ""},
	} {
		if response := invoke(handler, "POST", path, body, testPassword, headers); response.Code != 403 {
			t.Fatal("preview must reject cross-site requests")
		}
	}
	before := map[string]string{}
	for _, endpoint := range []string{"/api/v1/policies/sensitive-output", "/api/v1/policies/sensitive-output/history", "/api/v1/requests"} {
		response := invoke(handler, "GET", endpoint, "", testPassword, nil)
		if response.Code != 200 {
			t.Fatal(response.Body.String())
		}
		before[endpoint] = response.Body.String()
	}
	response := invoke(handler, "POST", path, body, testPassword, nil)
	var preview gateway.OutputPreview
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &preview) != nil || !preview.PreviewOnly || preview.Result != "redacted" || preview.Output == nil || *preview.Output != "Contact [REDACTED]" {
		t.Fatal(response.Body.String())
	}
	if strings.Contains(response.Body.String(), "private@example.test") || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("preview leaked source text or allowed response caching")
	}
	for endpoint, snapshot := range before {
		if after := invoke(handler, "GET", endpoint, "", testPassword, nil); after.Code != 200 || after.Body.String() != snapshot {
			t.Fatal("preview modified runtime configuration or request records", endpoint)
		}
	}
}

func TestPluginPreviewStrictValidation(t *testing.T) {
	handler := handler(t)
	path := "/api/v1/plugins/sensitive-output/preview"
	body := `{"text":"private@example.test","detector_version":"sensitive-text-v3","mode":"redact","categories":["email"]}`
	for _, test := range []struct {
		body    string
		headers map[string]string
		status  int
	}{
		{body, map[string]string{"Content-Type": "text/plain"}, 415},
		{body + `{}`, nil, 400},
		{strings.Replace(body, `"mode"`, `"revision":0,"mode"`, 1), nil, 400},
		{strings.Replace(body, `"mode"`, `"application_ids":[],"mode"`, 1), nil, 400},
		{strings.Replace(body, "sensitive-text-v3", "unsupported", 1), nil, 400},
		{strings.Replace(body, "private@example.test", strings.Repeat("a", 8193), 1), nil, 400},
		{strings.Replace(body, "private@example.test", `\ud800`, 1), nil, 400},
		{strings.Replace(body, "private@example.test", strings.Repeat("a", 17000), 1), nil, 413},
	} {
		response := invoke(handler, "POST", path, test.body, testPassword, test.headers)
		if response.Code != test.status {
			t.Fatalf("expected %d, got %d: %s", test.status, response.Code, response.Body.String())
		}
	}
}

func TestPluginCatalogEmptyPacks(t *testing.T) {
	response := invoke(handler(t), "GET", "/api/v1/plugins", "", testPassword, nil)
	var catalog struct {
		RulePacks []compliance.Descriptor `json:"rule_packs"`
	}
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &catalog) != nil || catalog.RulePacks == nil || len(catalog.RulePacks) != 0 {
		t.Fatal("uninstalled frameworks must not appear installed", response.Body.String())
	}
}
