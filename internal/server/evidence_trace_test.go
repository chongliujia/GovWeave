package server

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"govweave/internal/gateway"
)

func TestEvidenceTraceAPIRequiresAdminAndExplicitApplications(t *testing.T) {
	h := handler(t)
	create := func(name string) applicationResponse {
		w := invoke(h, "POST", "/api/v1/applications", fmt.Sprintf(`{"name":%q,"allowed_connections":[]}`, name), testPassword, nil)
		var app applicationResponse
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &app) != nil {
			t.Fatal("create application")
		}
		return app
	}
	a, b := create("Task A"), create("Task B")
	trace := strings.Repeat("a", 32)
	base := "/api/v1/evidence-traces/" + trace
	query := "?application_id=" + a.Application.ID
	w := invoke(h, "POST", "/v1/content/evaluations", `{"text":"private task fixture"}`, b.APIKey, map[string]string{"X-GovWeave-Trace-ID": trace})
	if w.Code != 200 {
		t.Fatal("create traced call")
	}
	for _, identity := range []string{"", a.APIKey, b.APIKey} {
		if invoke(h, "GET", base+query, "", identity, nil).Code != 401 {
			t.Fatal("application key obtained administrative task evidence")
		}
	}
	for _, suffix := range []string{"", "?application_id=", "?application_id=*", "?application_id=app_abcdefghijklmnop", query + "&application_id=" + a.Application.ID, query + "&include_content=true", query + "&limit=129", query + "&limit=1&limit=2", query + "&bad=%GG"} {
		if invoke(h, "GET", base+suffix, "", testPassword, nil).Code != 400 {
			t.Fatal("invalid task evidence query accepted", suffix)
		}
	}
	for _, tc := range []struct {
		suffix string
		calls  int
	}{{query, 0}, {query + "&application_id=" + b.Application.ID, 1}} {
		w := invoke(h, "GET", base+tc.suffix, "", testPassword, nil)
		var view gateway.EvidenceTraceView
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &view) != nil || len(view.Calls) != tc.calls || view.Summary.NotFound != tc.calls || view.GraphComplete || view.TaskCompletion != "not_determined" {
			t.Fatal("scope or absent capture coverage changed", w.Code, view.Summary)
		}
		if strings.Contains(w.Body.String(), "private task fixture") || strings.Contains(w.Body.String(), b.APIKey) {
			t.Fatal("task evidence exposed content or credentials")
		}
		if tc.calls == 0 && strings.Contains(w.Body.String(), b.Application.ID) {
			t.Fatal("unselected application leaked through empty result")
		}
	}
	if invoke(h, "GET", "/v1/traces/"+trace+"?application_id="+b.Application.ID, "", a.APIKey, nil).Code != 400 {
		t.Fatal("application trace boundary weakened")
	}
}
