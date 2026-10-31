package server

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"govweave/internal/gateway"
)

func TestToolsAdministrationAndIdentityBoundaries(t *testing.T) {
	h := handler(t)
	for _, route := range []struct{ method, path, body string }{
		{"GET", "/api/v1/tools", ""},
		{"GET", "/api/v1/tools/missing/history", ""},
		{"POST", "/api/v1/tools", "{}"},
		{"PUT", "/api/v1/tools/missing", "{}"},
	} {
		for _, token := range []string{"", "gw_app_synthetic"} {
			if got := invoke(h, route.method, route.path, route.body, token, nil).Code; got != 401 {
				t.Fatalf("non-administrator accessed %s: %d", route.path, got)
			}
		}
		if route.method == "POST" || route.method == "PUT" {
			for _, headers := range []map[string]string{{"Origin": "https://untrusted.example"}, {"X-GovWeave-Request": ""}} {
				if got := invoke(h, route.method, route.path, route.body, testPassword, headers).Code; got != 403 {
					t.Fatalf("tool mutation bypassed origin/header check: %d", got)
				}
			}
		}
	}
	if got := invoke(h, "GET", "/api/v1/tools/missing/history", "", testPassword, nil).Code; got != 404 {
		t.Fatalf("unknown history status: %d", got)
	}
	if got := invoke(h, "POST", "/v1/tools/support/invoke", `{"resource_id":"help"}`, testPassword, nil).Code; got != 401 {
		t.Fatalf("administrator cookie accepted as application identity: %d", got)
	}
	if got := invoke(h, "POST", "/api/v1/tools", `{"revision":0,"unexpected":true}`, testPassword, nil).Code; got != 400 {
		t.Fatalf("unknown configuration field accepted: %d", got)
	}
	if got := invoke(h, "POST", "/api/v1/tools", "{}", testPassword, map[string]string{"Content-Type": "text/plain"}).Code; got != 415 {
		t.Fatalf("non-JSON configuration accepted: %d", got)
	}
}

func TestToolsContractRevisionHistoryAndCredentialOmission(t *testing.T) {
	h := handler(t)
	w := invoke(h, "POST", "/api/v1/applications", `{"name":"Read-only assistant","allowed_connections":[]}`, testPassword, nil)
	var app applicationResponse
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &app) != nil {
		t.Fatalf("application setup failed: %d %s", w.Code, w.Body.String())
	}
	credential := "tool-provider-fixture-secret"
	body := fmt.Sprintf(`{"revision":0,"name":"Support retrieval","alias":"support","endpoint":"https://example.com/read","api_key":%q,"enabled":true,"allow_insecure_http":false,"timeout_seconds":5,"output_mode":"block","resources":[{"resource_id":"help","sensitivity":"internal","allowed_applications":[%q]}]}`, credential, app.Application.ID)
	w = invoke(h, "POST", "/api/v1/tools", body, testPassword, nil)
	var first gateway.Tool
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &first) != nil || first.ID == "" || first.Revision != 1 || !first.HasCredential || len(first.SnapshotSHA256) != 64 {
		t.Fatalf("tool creation contract: %d %s", w.Code, w.Body.String())
	}
	assertPrivate := func(body string) {
		t.Helper()
		for _, secret := range []string{credential, app.APIKey, "credential_ciphertext", `"api_key"`} {
			if strings.Contains(body, secret) {
				t.Fatalf("tool metadata exposed credential material: %s", secret)
			}
		}
	}
	assertPrivate(w.Body.String())
	if got := invoke(h, "PUT", "/api/v1/tools/"+first.ID, body, testPassword, nil).Code; got != 409 {
		t.Fatalf("stale tool revision accepted: %d", got)
	}
	updatedBody := strings.Replace(body, `"revision":0`, `"revision":1`, 1)
	updatedBody = strings.Replace(updatedBody, `"api_key":"`+credential+`",`, "", 1)
	updatedBody = strings.Replace(updatedBody, `"enabled":true`, `"enabled":false`, 1)
	w = invoke(h, "PUT", "/api/v1/tools/"+first.ID, updatedBody, testPassword, nil)
	var second gateway.Tool
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &second) != nil || second.Revision != 2 || second.Enabled || !second.HasCredential || second.SnapshotSHA256 == first.SnapshotSHA256 {
		t.Fatalf("tool update contract: %d %s", w.Code, w.Body.String())
	}
	assertPrivate(w.Body.String())
	w = invoke(h, "GET", "/api/v1/tools", "", testPassword, nil)
	var current gateway.ToolSnapshot
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &current) != nil || current.Revision != 2 || len(current.Tools) != 1 || current.Tools[0].Enabled {
		t.Fatalf("tool snapshot contract: %d %s", w.Code, w.Body.String())
	}
	assertPrivate(w.Body.String())
	w = invoke(h, "GET", "/api/v1/tools/"+first.ID+"/history", "", testPassword, nil)
	var history struct {
		ToolID    string         `json:"tool_id"`
		Revisions []gateway.Tool `json:"revisions"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &history) != nil || history.ToolID != first.ID || len(history.Revisions) != 2 {
		t.Fatalf("tool history contract: %d %s", w.Code, w.Body.String())
	}
	assertPrivate(w.Body.String())
	versions := map[uint64]gateway.Tool{}
	for _, version := range history.Revisions {
		versions[version.Revision] = version
	}
	if !versions[1].Enabled || versions[1].SnapshotSHA256 != first.SnapshotSHA256 || versions[2].Enabled {
		t.Fatal("history did not preserve the original authorization snapshot")
	}
	for _, path := range []string{"/api/v1/tools", "/api/v1/tools/" + first.ID + "/history"} {
		if invoke(h, "GET", path, "", app.APIKey, nil).Code != 401 {
			t.Fatal("application key accessed tool administration")
		}
	}
	w = invoke(h, "POST", "/v1/tools/support/invoke", `{"resource_id":"help"}`, app.APIKey, nil)
	if w.Code != 403 || strings.Contains(w.Body.String(), "https://example.com") || strings.Contains(w.Body.String(), credential) {
		t.Fatalf("disabled tool was not privately denied: %d %s", w.Code, w.Body.String())
	}
}
