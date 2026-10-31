package server

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"govweave/internal/gateway"
)

func TestTraceRoutesUseApplicationAndAdministratorBoundaries(t *testing.T) {
	h := handler(t)
	create := func(name string) applicationResponse {
		w := invoke(h, "POST", "/api/v1/applications", fmt.Sprintf(`{"name":%q,"allowed_connections":[]}`, name), testPassword, nil)
		var app applicationResponse
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &app) != nil {
			t.Fatalf("create app: %d", w.Code)
		}
		return app
	}
	a, b := create("Agent A"), create("Agent B")
	traceID := strings.Repeat("a", 32)
	for _, app := range []applicationResponse{a, b} {
		w := invoke(h, "POST", "/v1/content/evaluations", `{"text":"synthetic normal content"}`, app.APIKey, map[string]string{"X-GovWeave-Trace-ID": traceID})
		if w.Code != 200 || w.Header().Get("X-GovWeave-Span-ID") == "" {
			t.Fatalf("traced content evaluation: %d", w.Code)
		}
	}
	appPath := "/v1/traces/" + traceID
	adminPath := "/api/v1/traces/" + traceID + "?application_id=" + a.Application.ID + "&application_id=" + b.Application.ID
	for _, tc := range []struct {
		path, key string
		status    int
	}{
		{appPath, "", 401}, {appPath, testPassword, 401}, {adminPath, a.APIKey, 401}, {adminPath, "", 401},
		{appPath + "?application_id=" + b.Application.ID, a.APIKey, 400},
		{"/api/v1/traces/" + traceID, testPassword, 400},
		{appPath + "?limit=0", a.APIKey, 400}, {appPath + "?limit=129", a.APIKey, 400},
		{appPath + "?limit=1&limit=2", a.APIKey, 400}, {appPath + "?bad=%GG", a.APIKey, 400},
	} {
		if w := invoke(h, "GET", tc.path, "", tc.key, nil); w.Code != tc.status {
			t.Fatalf("%s got %d want %d", tc.path, w.Code, tc.status)
		}
	}
	for _, tc := range []struct {
		path, key string
		count     int
	}{
		{appPath, a.APIKey, 1}, {appPath, b.APIKey, 1}, {adminPath, testPassword, 2},
	} {
		w := invoke(h, "GET", tc.path, "", tc.key, nil)
		var view gateway.TraceView
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &view) != nil || len(view.Records) != tc.count || view.TaskCompletion != "not_determined" {
			t.Fatalf("invalid trace projection: %d", w.Code)
		}
		if strings.Contains(w.Body.String(), "synthetic normal content") || strings.Contains(w.Body.String(), a.APIKey) || strings.Contains(w.Body.String(), b.APIKey) {
			t.Fatal("content or credential retained")
		}
	}
}
