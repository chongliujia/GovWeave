package server

import (
	"encoding/json"
	"fmt"
	"testing"

	"govweave/internal/gateway"
)

func TestEvidenceAPIRequiresAdministratorExplicitScopeAndProtectedMutations(t *testing.T) {
	h := handler(t)
	w := invoke(h, "POST", "/api/v1/applications", `{"name":"Evidence-only app","allowed_connections":[]}`, testPassword, nil)
	var app applicationResponse
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &app) != nil {
		t.Fatal("create app")
	}
	for _, identity := range []string{"", app.APIKey} {
		for _, route := range []string{"/api/v1/evidence/config", "/api/v1/evidence/access", "/api/v1/evidence?application_id=" + app.Application.ID} {
			if invoke(h, "GET", route, "", identity, nil).Code != 401 {
				t.Fatal("non-admin obtained evidence", route)
			}
		}
	}
	w = invoke(h, "GET", "/api/v1/evidence/config", "", testPassword, nil)
	var config gateway.EvidenceConfig
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &config) != nil || config.Mode != "disabled" || len(config.ApplicationIDs) != 0 {
		t.Fatal("capture not opt-in")
	}
	config.Mode = "full"
	data, _ := json.Marshal(config)
	if invoke(h, "PUT", "/api/v1/evidence/config", string(data), testPassword, nil).Code != 400 {
		t.Fatal("empty capture scope accepted")
	}
	config.ApplicationIDs = []string{app.Application.ID}
	data, _ = json.Marshal(config)
	if invoke(h, "PUT", "/api/v1/evidence/config", string(data), testPassword, map[string]string{"Origin": "https://untrusted.example"}).Code != 403 {
		t.Fatal("cross-origin config accepted")
	}
	if invoke(h, "PUT", "/api/v1/evidence/config", string(data), testPassword, nil).Code != 200 {
		t.Fatal("explicit capture config rejected")
	}
	if invoke(h, "PUT", "/api/v1/evidence/config", string(data), testPassword, nil).Code != 409 {
		t.Fatal("stale config accepted")
	}
	for _, query := range []string{"", "?limit=101", "?application_id=" + app.Application.ID + "&application_id=" + app.Application.ID, "?application_id=" + app.Application.ID + "&include_content=true", "?application_id=" + app.Application.ID + "&request_id=invalid"} {
		if invoke(h, "GET", "/api/v1/evidence"+query, "", testPassword, nil).Code != 400 {
			t.Fatal("invalid evidence query accepted", query)
		}
	}
	body := fmt.Sprintf(`{"application_id":%q,"object_id":"unavailable","view":"raw","reason":"validation"}`, app.Application.ID)
	if invoke(h, "POST", "/api/v1/evidence/ev_0000000000000000000000/reveal", body, testPassword, map[string]string{"X-GovWeave-Request": ""}).Code != 403 {
		t.Fatal("unprotected content reveal accepted")
	}
	if w := invoke(h, "GET", "/evidence.js", "", "", nil); w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("evidence asset missing or cacheable")
	}
}
