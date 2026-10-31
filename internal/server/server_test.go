package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"govweave/internal/auth"
	"govweave/internal/compliance"
	"govweave/internal/config"
	"govweave/internal/gateway"
	"govweave/internal/governance"
	"govweave/internal/instance"
)

const testPassword = "test-only administrator password"

type testHandler struct {
	http.Handler
	session string
}

const validBody = `{"schema_version":1,"revision":0,"organization_name":"测试企业","public_url":"https://ai.example.com/"}`

func handler(t *testing.T) http.Handler {
	return handlerWithCompliance(t, nil)
}

func handlerWithCompliance(t *testing.T, evaluator *compliance.Engine) http.Handler {
	t.Helper()
	s, err := instance.Open(config.Deployment{SchemaVersion: 1, DataDir: t.TempDir(), ListenAddr: "127.0.0.1:8080", Sources: map[string]string{}})
	if err != nil {
		t.Fatal(err)
	}
	administrator, err := auth.Open(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := gateway.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { engine.Close() })
	if evaluator == nil {
		evaluator, err = compliance.Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
	}
	products, err := governance.Open(t.TempDir(), engine, evaluator)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(products.Close)
	h := New(s, administrator, engine, evaluator, products)
	w := invoke(h, "POST", "/api/v1/auth/setup", `{"password":"`+testPassword+`"}`, "", nil)
	if w.Code != 200 {
		t.Fatalf("setup authentication: %d %s", w.Code, w.Body.String())
	}
	return &testHandler{Handler: h, session: w.Result().Cookies()[0].Value}
}

func invoke(h http.Handler, method, path, body, token string, headers map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		if fixture, ok := h.(*testHandler); ok && token == testPassword {
			r.AddCookie(&http.Cookie{Name: sessionCookie, Value: fixture.session})
		} else {
			r.Header.Set("Authorization", "Bearer "+token)
		}
	}
	if method != "GET" && method != "HEAD" {
		r.Header.Set("X-GovWeave-Request", "console")
	}
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestSetupFlowAndContract(t *testing.T) {
	h := handler(t)
	for _, method := range []string{"GET", "PUT"} {
		w := invoke(h, method, "/api/v1/instance", validBody, "", nil)
		if w.Code != 401 {
			t.Fatalf("unauthorized %s: %d", method, w.Code)
		}
	}
	w := invoke(h, "GET", "/api/v1/instance", "", testPassword, nil)
	if w.Code != 200 || strings.Contains(w.Body.String(), testPassword) {
		t.Fatalf("bad initial response: %d", w.Code)
	}
	w = invoke(h, "PUT", "/api/v1/instance", validBody, testPassword, nil)
	if w.Code != 200 {
		t.Fatalf("setup: %d %s", w.Code, w.Body.String())
	}
	var view instance.View
	if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if !view.Configured || view.Revision != 1 || view.PublicURL != "https://ai.example.com" || view.Endpoints["mcp"].Status != "planned" || view.Sources["public_url"] != "console" {
		t.Fatalf("invalid contract: %+v", view)
	}
	if invoke(h, "PUT", "/api/v1/instance", validBody, testPassword, nil).Code != 409 {
		t.Fatal("stale writes not rejected")
	}
	for _, path := range []string{"/v1/responses", "/v1/embeddings", "/mcp", "/mcp/anything"} {
		w := invoke(h, "POST", path, `{}`, testPassword, nil)
		if w.Code != 501 || !strings.Contains(w.Body.String(), "not_implemented") {
			t.Fatalf("misleading capability on %s", path)
		}
	}
}

func TestRequestBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		headers    map[string]string
		status     int
	}{
		{"missing CSRF header", validBody, map[string]string{"X-GovWeave-Request": ""}, 403},
		{"cross origin", validBody, map[string]string{"Origin": "https://attacker.example"}, 403},
		{"null origin", validBody, map[string]string{"Origin": "null"}, 403},
		{"fetch site", validBody, map[string]string{"Sec-Fetch-Site": "cross-site"}, 403},
		{"proxy header cannot authorize", validBody, map[string]string{"Origin": "https://attacker.example", "X-Forwarded-Host": "attacker.example"}, 403},
		{"content type", validBody, map[string]string{"Content-Type": "text/plain"}, 415},
		{"unknown field", strings.TrimSuffix(validBody, "}") + `,"admin_token":"secret"}`, nil, 400},
		{"extra object", validBody + `{}`, nil, 400},
		{"missing revision", `{"schema_version":1,"organization_name":"A","public_url":"https://a.example"}`, nil, 400},
		{"wrong schema", strings.Replace(validBody, `"schema_version":1`, `"schema_version":2`, 1), nil, 400},
		{"null", `null`, nil, 400},
		{"invalid URL", strings.Replace(validBody, "https://ai.example.com/", "http://0.0.0.0:8080", 1), nil, 400},
		{"too large", fmt.Sprintf(`{"schema_version":1,"revision":0,"organization_name":"%s","public_url":"https://a.example"}`, strings.Repeat("x", 17000)), nil, 413},
		{"same origin", validBody, map[string]string{"Origin": "http://example.com"}, 200},
		{"TLS proxy preserves host", validBody, map[string]string{"Origin": "https://example.com"}, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := invoke(handler(t), "PUT", "/api/v1/instance", tc.body, testPassword, tc.headers)
			if w.Code != tc.status {
				t.Fatalf("got %d want %d: %s", w.Code, tc.status, w.Body.String())
			}
			if strings.Contains(w.Body.String(), "secret") {
				t.Fatal("input leaked into response")
			}
		})
	}
}

func TestPublicAssetsAndHealthDoNotExposeConfig(t *testing.T) {
	h := handler(t)
	for _, path := range []string{"/", "/app.js", "/i18n.js", "/style.css", "/logo.svg", "/healthz"} {
		w := invoke(h, "GET", path, "", "", nil)
		if w.Code != 200 {
			t.Fatalf("asset %s: %d", path, w.Code)
		}
		if w.Header().Get("Content-Security-Policy") == "" || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("missing security headers")
		}
		if strings.Contains(w.Body.String(), testPassword) {
			t.Fatal("token exposed")
		}
	}
	for _, path := range []string{"/admin.token", "/data/instance.json", "/api/v1/nope", "/web/"} {
		if invoke(h, "GET", path, "", "", nil).Code != 404 {
			t.Fatalf("unexpected public resource: %s", path)
		}
	}
}

func TestCredentialPolicyManagement(t *testing.T) {
	h := handler(t)
	path := "/api/v1/policies/credential-egress"
	body := `{"revision":0,"mode":"observe","rules":["private_key","api_key"],"application_ids":[],"connection_ids":[]}`
	for _, method := range []string{"GET", "PUT"} {
		if w := invoke(h, method, path, body, "", nil); w.Code != 401 {
			t.Fatal("policy management missing authentication")
		}
	}
	w := invoke(h, "GET", path, "", testPassword, nil)
	var initial gateway.PolicySnapshot
	if json.Unmarshal(w.Body.Bytes(), &initial) != nil || initial.Mode != "disabled" || initial.Revision != 0 {
		t.Fatal("unexpected default policy")
	}
	for _, tc := range []struct {
		body    string
		headers map[string]string
		status  int
	}{
		{body, map[string]string{"X-GovWeave-Request": ""}, 403},
		{body, map[string]string{"Origin": "https://untrusted.example"}, 403},
		{body, map[string]string{"Content-Type": "text/plain"}, 415},
		{strings.TrimSuffix(body, "}") + `,"secret":"sensitive-test-value"}`, nil, 400},
		{body + `{}`, nil, 400},
		{`null`, nil, 400},
		{strings.Replace(body, `"observe"`, `"invalid"`, 1), nil, 400},
		{strings.Replace(body, `"application_ids":[]`, `"application_ids":["unknown"]`, 1), nil, 400},
	} {
		w := invoke(h, "PUT", path, tc.body, testPassword, tc.headers)
		if w.Code != tc.status || strings.Contains(w.Body.String(), "sensitive-test-value") {
			t.Fatalf("incorrect policy boundary response %d", w.Code)
		}
	}
	w = invoke(h, "PUT", path, body, testPassword, nil)
	var saved gateway.PolicySnapshot
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &saved) != nil || saved.Mode != "observe" || saved.Revision != 1 {
		t.Fatal("could not save policy")
	}
	if invoke(h, "PUT", path, body, testPassword, nil).Code != 409 {
		t.Fatal("policy update lost revision check")
	}
	w = invoke(h, "GET", path, "", testPassword, nil)
	if !strings.Contains(w.Body.String(), `"mode":"observe"`) {
		t.Fatal("failed updates changed saved policy")
	}
	for _, route := range []string{path + "/history", path + "/revisions/0"} {
		for _, credential := range []string{"", "gw_app_synthetic-application-key"} {
			if invoke(h, "GET", route, "", credential, nil).Code != 401 {
				t.Fatal("policy history did not require administrator session")
			}
		}
	}
	w = invoke(h, "GET", path+"/history?limit=1", "", testPassword, nil)
	var page gateway.PolicyHistory
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || page.Total != 2 || len(page.Snapshots) != 1 || page.Snapshots[0].Revision != 1 || page.NextBeforeRevision == nil || *page.NextBeforeRevision != 1 {
		t.Fatalf("invalid history page: %s", w.Body.String())
	}
	w = invoke(h, "GET", path+"/history?limit=1&before_revision=1", "", testPassword, nil)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || len(page.Snapshots) != 1 || page.Snapshots[0].Revision != 0 {
		t.Fatal("initial policy missing from history")
	}
	for _, suffix := range []string{"/history?limit=0", "/history?limit=101", "/history?limit=", "/history?limit=abc", "/history?before_revision=-1", "/history?before_revision=", "/history?before_revision=18446744073709551616", "/revisions/nope", "/revisions/-1"} {
		if invoke(h, "GET", path+suffix, "", testPassword, nil).Code != 400 {
			t.Fatalf("invalid history query accepted: %s", suffix)
		}
	}
	if invoke(h, "GET", path+"/revisions/99", "", testPassword, nil).Code != 404 {
		t.Fatal("unknown history revision not reported")
	}
	updatedBody := strings.Replace(strings.Replace(body, `"revision":0`, `"revision":1`, 1), `"observe"`, `"block"`, 1)
	if invoke(h, "PUT", path, updatedBody, testPassword, nil).Code != 200 {
		t.Fatal("could not update policy")
	}
	w = invoke(h, "GET", path+"/revisions/1", "", testPassword, nil)
	var historical gateway.PolicySnapshot
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &historical) != nil || !reflect.DeepEqual(historical, saved) {
		t.Fatal("historical revision changed after policy update")
	}
}
