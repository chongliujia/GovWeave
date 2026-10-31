package server

import "testing"

func TestTestingAPIAdministrativeAndMutationBoundaries(t *testing.T) {
	h := handler(t)
	for _, route := range []struct{ method, path, body string }{
		{"GET", "/api/v1/compliance/test-suites", ""},
		{"GET", "/api/v1/compliance/test-suites/unknown/versions/1", ""},
		{"GET", "/api/v1/compliance/products/unknown/test-plan", ""},
		{"PUT", "/api/v1/compliance/products/unknown/test-plan", "{}"},
		{"GET", "/api/v1/compliance/products/unknown/test-plans", ""},
		{"GET", "/api/v1/compliance/products/unknown/test-plans/model", ""},
		{"PUT", "/api/v1/compliance/products/unknown/test-plans/read_tool", "{}"},
		{"GET", "/api/v1/compliance/products/unknown/test-runs", ""},
		{"POST", "/api/v1/compliance/products/unknown/test-runs", `{"phase":"operation"}`},
		{"GET", "/api/v1/compliance/test-runs/unknown", ""},
		{"POST", "/api/v1/compliance/test-runs/unknown/replay", "{}"},
	} {
		for _, token := range []string{"", "gw_app_synthetic"} {
			if invoke(h, route.method, route.path, route.body, token, nil).Code != 401 {
				t.Fatal("testing API accepted non-administrator", route.path)
			}
		}
		if route.method == "POST" || route.method == "PUT" {
			for _, headers := range []map[string]string{{"Origin": "https://untrusted.example"}, {"X-GovWeave-Request": ""}} {
				if invoke(h, route.method, route.path, route.body, testPassword, headers).Code != 403 {
					t.Fatal("testing mutation missing origin/header check")
				}
			}
		}
	}
	if invoke(h, "GET", "/api/v1/compliance/test-suites", "", testPassword, nil).Code != 200 {
		t.Fatal("empty catalog unavailable")
	}
	if invoke(h, "POST", "/api/v1/compliance/products/unknown/test-runs", `{"phase":"operation","trigger":"scheduled"}`, testPassword, nil).Code != 400 {
		t.Fatal("caller overrode trigger")
	}
	if invoke(h, "POST", "/api/v1/compliance/products/unknown/test-runs", `{"phase":"operation"}`, testPassword, nil).Code != 404 {
		t.Fatal("missing plan not reported")
	}
	if invoke(h, "POST", "/api/v1/compliance/products/unknown/test-runs", `{"phase":"operation","plan_id":"invalid"}`, testPassword, nil).Code != 400 {
		t.Fatal("invalid named plan accepted")
	}
}
