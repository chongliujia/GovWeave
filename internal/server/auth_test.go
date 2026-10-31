package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"govweave/internal/auth"
	"govweave/internal/compliance"
	"govweave/internal/config"
	"govweave/internal/gateway"
	"govweave/internal/governance"
	"govweave/internal/instance"
)

func newAuthHandler(t *testing.T, dir string) http.Handler {
	t.Helper()
	store, err := instance.Open(config.Deployment{SchemaVersion: 1, DataDir: dir, ListenAddr: "127.0.0.1:8080", Sources: map[string]string{}})
	if err != nil {
		t.Fatal(err)
	}
	admin, err := auth.Open(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := gateway.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { engine.Close() })
	evaluator, err := compliance.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	products, err := governance.Open(dir, engine, evaluator)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(products.Close)
	return New(store, admin, engine, evaluator, products)
}

func TestPasswordHTTPFlow(t *testing.T) {
	dir := t.TempDir()
	h := newAuthHandler(t, dir)
	initial := invoke(h, "GET", "/api/v1/auth/status", "", "", nil)
	if initial.Code != 200 || !strings.Contains(initial.Body.String(), `"setup_required":true`) {
		t.Fatal("missing setup status")
	}
	payload := `{"password":"` + testPassword + `"}`
	for _, headers := range []map[string]string{{"X-GovWeave-Request": ""}, {"Origin": "https://evil.example"}, {"Sec-Fetch-Site": "cross-site"}} {
		if invoke(h, "POST", "/api/v1/auth/setup", payload, "", headers).Code != 403 {
			t.Fatal("cross-site setup permitted")
		}
	}
	if invoke(h, "POST", "/api/v1/auth/setup", payload, "", map[string]string{"Content-Type": "text/plain"}).Code != 415 {
		t.Fatal("simple setup request allowed")
	}
	w := invoke(h, "POST", "/api/v1/auth/setup", payload, "", map[string]string{"Origin": "https://example.com"})
	if w.Code != 200 {
		t.Fatalf("setup: %d %s", w.Code, w.Body.String())
	}
	cookie := w.Result().Cookies()[0]
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/api/" || cookie.MaxAge != 28800 {
		t.Fatal("invalid session cookie flags")
	}
	fixture := &testHandler{Handler: h, session: cookie.Value}
	if invoke(fixture, "GET", "/api/v1/instance", "", testPassword, nil).Code != 200 {
		t.Fatal("session denied")
	}
	if invoke(h, "GET", "/api/v1/instance", "", cookie.Value, nil).Code != 401 {
		t.Fatal("bearer authentication still accepted")
	}
	if invoke(h, "POST", "/api/v1/auth/setup", payload, "", nil).Code != 409 {
		t.Fatal("repeat setup accepted")
	}
	w = invoke(h, "POST", "/api/v1/auth/login", `{"password":"wrong administrator password"}`, "", nil)
	if w.Code != 401 || len(w.Result().Cookies()) != 0 {
		t.Fatal("bad password created session")
	}
	if invoke(fixture, "POST", "/api/v1/auth/logout", `{}`, testPassword, map[string]string{"X-GovWeave-Request": ""}).Code != 403 {
		t.Fatal("logout CSRF allowed")
	}
	w = invoke(fixture, "POST", "/api/v1/auth/logout", `{}`, testPassword, nil)
	if w.Code != 200 || w.Result().Cookies()[0].MaxAge != -1 {
		t.Fatal("logout failed")
	}
	if invoke(fixture, "GET", "/api/v1/instance", "", testPassword, nil).Code != 401 {
		t.Fatal("logged-out session reused")
	}
	restored := newAuthHandler(t, dir)
	w = invoke(restored, "POST", "/api/v1/auth/login", payload, "", nil)
	if w.Code != 200 || len(w.Result().Cookies()) != 1 {
		t.Fatal("password did not survive restart")
	}
	if strings.Contains(w.Body.String(), testPassword) || strings.Contains(w.Body.String(), cookie.Value) {
		t.Fatal("credentials leaked to JSON")
	}
}

func TestLegacySetupRequiresDirectLocalAccess(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "admin.token"), []byte("legacy-unused-token"), 0600)
	h := newAuthHandler(t, dir)
	body := `{"password":"` + testPassword + `"}`
	if invoke(h, "POST", "/api/v1/auth/setup", body, "", nil).Code != 403 {
		t.Fatal("remote migration allowed")
	}
	for _, tc := range []struct {
		host, peer, forward string
		want                int
	}{
		{"attacker.example:8080", "127.0.0.1:1234", "", 403},
		{"localhost:8080", "192.0.2.1:1234", "", 403},
		{"localhost:8080", "127.0.0.1:1234", "192.0.2.1", 403},
		{"localhost:8080", "127.0.0.1:1234", "", 200},
	} {
		r := httptest.NewRequest("POST", "http://"+tc.host+"/api/v1/auth/setup", strings.NewReader(body))
		r.RemoteAddr = tc.peer
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-GovWeave-Request", "console")
		if tc.forward != "" {
			r.Header.Set("X-Forwarded-For", tc.forward)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("%s %s: got %d want %d", tc.host, tc.peer, w.Code, tc.want)
		}
	}
}
