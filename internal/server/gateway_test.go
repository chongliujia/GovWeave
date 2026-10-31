package server

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestGatewayAdminContractAndCredentialSeparation(t *testing.T) {
	h := handler(t)
	connection := `{"name":"Local provider","base_url":"http://127.0.0.1:12345/v1","model":"test-model","alias":"internal-assistant","api_key":"private-provider-token","enabled":true,"allow_insecure_http":true,"timeout_seconds":10}`
	if invoke(h, "POST", "/api/v1/connections", connection, "", nil).Code != 401 {
		t.Fatal("anonymous write allowed")
	}
	if invoke(h, "POST", "/api/v1/connections", connection, testPassword, map[string]string{"Origin": "https://attacker.example"}).Code != 403 {
		t.Fatal("cross origin write allowed")
	}
	w := invoke(h, "POST", "/api/v1/connections", connection, testPassword, nil)
	if w.Code != 200 || strings.Contains(w.Body.String(), "private-provider-token") {
		t.Fatal("create connection failed or leaked credential")
	}
	var c struct{ ID string }
	if err := json.Unmarshal(w.Body.Bytes(), &c); err != nil {
		t.Fatal(err)
	}
	w = invoke(h, "POST", "/api/v1/applications", fmt.Sprintf(`{"name":"Test app","allowed_connections":[%q]}`, c.ID), testPassword, nil)
	var app applicationResponse
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &app) != nil || app.APIKey == "" {
		t.Fatal("application key not returned on creation")
	}
	w = invoke(h, "GET", "/api/v1/gateway", "", testPassword, nil)
	if strings.Contains(w.Body.String(), app.APIKey) || strings.Contains(w.Body.String(), "private-provider-token") || strings.Contains(w.Body.String(), "key_hash") {
		t.Fatal("snapshot leaked secrets")
	}
	for _, path := range []string{"/api/v1/gateway", "/api/v1/requests", "/api/v1/instance", "/api/v1/policies/credential-egress/history", "/api/v1/policies/credential-egress/revisions/0"} {
		if invoke(h, "GET", path, "", app.APIKey, nil).Code != 401 {
			t.Fatal("application key accessed management")
		}
	}
	if invoke(h, "GET", "/v1/models", "", testPassword, nil).Code != 401 {
		t.Fatal("admin session accepted for models")
	}
	w = invoke(h, "GET", "/v1/models", "", app.APIKey, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "internal-assistant") {
		t.Fatal("application model list unavailable")
	}
	w = invoke(h, "POST", "/api/v1/applications/"+app.Application.ID+"/rotate", fmt.Sprintf(`{"revision":%d}`, app.Application.Revision), testPassword, nil)
	var rotated applicationResponse
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &rotated) != nil {
		t.Fatal("rotation failed")
	}
	if invoke(h, "GET", "/v1/models", "", app.APIKey, nil).Code != 401 {
		t.Fatal("old key accepted")
	}
	if invoke(h, "GET", "/v1/models", "", rotated.APIKey, nil).Code != 200 {
		t.Fatal("new key rejected")
	}
	if invoke(h, "POST", "/api/v1/applications/"+app.Application.ID+"/revoke", fmt.Sprintf(`{"revision":%d}`, app.Application.Revision), testPassword, nil).Code != 409 {
		t.Fatal("stale revocation accepted")
	}
	w = invoke(h, "GET", "/api/v1/requests", "", testPassword, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "invalid_api_key") || strings.Contains(w.Body.String(), rotated.APIKey) {
		t.Fatal("audit contract invalid")
	}
}
