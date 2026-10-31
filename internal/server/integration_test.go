package server

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"govweave/internal/gateway"
)

func TestIntegrationRouteUsesApplicationIdentityWithoutInference(t *testing.T) {
	h := handler(t)
	w := invoke(h, "POST", "/api/v1/connections", `{"name":"Local configuration only","base_url":"http://127.0.0.1:1/v1","model":"private-model-id","alias":"onboarding","api_key":"private-onboarding-provider-secret","enabled":true,"allow_insecure_http":true,"timeout_seconds":1}`, testPassword, nil)
	var connection struct{ ID string }
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &connection) != nil {
		t.Fatal("create connection failed")
	}
	w = invoke(h, "POST", "/api/v1/applications", fmt.Sprintf(`{"name":"Onboarding app","allowed_connections":[%q]}`, connection.ID), testPassword, nil)
	var app applicationResponse
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &app) != nil {
		t.Fatal("create application failed")
	}
	path := "/v1/integration/check?model=onboarding"
	for _, credential := range []string{"", testPassword} {
		if invoke(h, "GET", path, "", credential, nil).Code != 401 {
			t.Fatal("configuration check accepted non-application authorization")
		}
	}
	w = invoke(h, "GET", path, "", app.APIKey, nil)
	var view gateway.IntegrationCheckView
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &view) != nil {
		t.Fatalf("configuration check failed: %d", w.Code)
	}
	if view.ApplicationID != app.Application.ID || view.Model != "onboarding" || view.UpstreamContacted || view.Inference != "not_tested" {
		t.Fatal("configuration check misrepresented identity or inference")
	}
	for _, value := range []string{app.APIKey, "private-onboarding-provider-secret", "private-model-id", "127.0.0.1"} {
		if strings.Contains(w.Body.String(), value) {
			t.Fatal("private configuration exposed")
		}
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("configuration check response can be cached")
	}
	w = invoke(h, "GET", "/api/v1/requests", "", testPassword, nil)
	var audit gateway.AuditView
	if json.Unmarshal(w.Body.Bytes(), &audit) != nil || len(audit.Records) != 0 {
		t.Fatal("read-only configuration checks produced call records")
	}
	if w := invoke(h, "GET", "/integration.js", "", "", nil); w.Code != 200 || !strings.Contains(w.Body.String(), "integration/check") {
		t.Fatal("integration UI module unavailable")
	}
}
