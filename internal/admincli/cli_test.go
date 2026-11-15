package admincli

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestInvalidCommandsAndCredentialsNeverReachServer(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(500) }))
	defer server.Close()
	for _, args := range [][]string{
		{"policy", "set", "--mode", "block"},
		{"policy", "set", "--application", "../other", "--revision", "0", "--mode", "block"},
		{"policy", "set", "--application", "app-a", "--scope", "all", "--revision", "0"},
		{"policy", "restore", "--application", "app-a", "--revision", "1"},
		{"policy", "inherit", "--revision", "1"},
		{"applications", "list", "--mode", "block"},
		{"requests", "list", "--limit", "101"},
		{"unknown", "list"},
		{"remediations", "list"},
		{"remediations", "recheck", "--product", "prod-a", "--id", "rem-a"},
		{"tests", "run", "--product", "prod-a", "--plan", "model", "--phase", "invalid"},
		{"tests", "list", "--product", "../another"},
	} {
		err := Run(append([]string{"--url", server.URL, "--password-stdin"}, args...), strings.NewReader("synthetic-password"), &bytes.Buffer{}, &bytes.Buffer{})
		if err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	for _, target := range []string{"http://example.com", "https://user:password@example.com", "https://example.com/path", "https://example.com?x=1", "https://example.com#secret"} {
		if Run([]string{"--url", target, "status"}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{}) == nil {
			t.Fatal("accepted unsafe URL")
		}
	}
	password := filepath.Join(t.TempDir(), "password")
	os.WriteFile(password, []byte("secret"), 0644)
	if Run([]string{"--url", server.URL, "--password-file", password, "applications", "list"}, nil, &bytes.Buffer{}, &bytes.Buffer{}) == nil {
		t.Fatal("public password file accepted")
	}
	for _, password := range []string{"first\nsecond", strings.Repeat("s", 1027), ""} {
		if Run([]string{"--url", server.URL, "--password-stdin", "applications", "list"}, strings.NewReader(password), &bytes.Buffer{}, &bytes.Buffer{}) == nil {
			t.Fatal("invalid password accepted")
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid CLI input triggered network I/O")
	}
}

func TestRedirectErrorSanitizationAndFailedOperationLogout(t *testing.T) {
	var targetCalls, loginCalls, logoutCalls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { targetCalls.Add(1) }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { loginCalls.Add(1); http.Redirect(w, r, target.URL, 307) }))
	defer redirect.Close()
	var output bytes.Buffer
	err := Run([]string{"--url", redirect.URL, "--password-stdin", "applications", "list"}, strings.NewReader("synthetic-secret"), &output, &output)
	if err == nil || targetCalls.Load() != 0 || loginCalls.Load() != 1 {
		t.Fatal("redirect followed or authentication retried")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Origin") == "" || r.Header.Get("X-GovWeave-Request") != "console" {
			t.Error("missing mutation guards")
		}
		switch r.URL.Path {
		case "/api/v1/auth/login":
			http.SetCookie(w, &http.Cookie{Name: "govweave_session", Value: "private-session", Path: "/api/"})
			fmt.Fprint(w, `{"authenticated":true}`)
		case "/api/v1/auth/logout":
			logoutCalls.Add(1)
			fmt.Fprint(w, `{"authenticated":false}`)
		default:
			w.WriteHeader(409)
			fmt.Fprint(w, `{"error":{"code":"revision_conflict","message":"private-server-text"}}`)
		}
	}))
	defer server.Close()
	err = Run([]string{"--url", server.URL, "--password-stdin", "applications", "list"}, strings.NewReader("synthetic-secret"), &output, &output)
	if err == nil || !strings.Contains(err.Error(), "revision_conflict") || strings.Contains(err.Error(), "private-server-text") || logoutCalls.Load() != 1 {
		t.Fatal("failure not sanitized or session not revoked")
	}
	if output.Len() != 0 {
		t.Fatal("failed command emitted output")
	}
}

func TestSessionFilesArePrivateBoundedAndOriginBound(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(401) }))
	defer server.Close()
	file := filepath.Join(t.TempDir(), "session.json")
	for _, body := range []string{
		`{"schema_version":1,"origin":"http://other.example","session":"` + strings.Repeat("s", 43) + `","expires_at":"2099-01-01T00:00:00Z"}`,
		`{"schema_version":1,"origin":"` + server.URL + `","session":"` + strings.Repeat("s", 43) + `","expires_at":"2000-01-01T00:00:00Z"}`,
		`{"schema_version":1,"origin":"` + server.URL + `","session":"bad","expires_at":"2099-01-01T00:00:00Z"}`,
		strings.Repeat("x", 4097),
	} {
		os.WriteFile(file, []byte(body), 0600)
		if Run([]string{"--url", server.URL, "--session-file", file, "applications", "list"}, nil, &bytes.Buffer{}, &bytes.Buffer{}) == nil {
			t.Fatal("invalid session accepted")
		}
	}
	os.Chmod(file, 0644)
	if Run([]string{"--url", server.URL, "--session-file", file, "applications", "list"}, nil, &bytes.Buffer{}, &bytes.Buffer{}) == nil {
		t.Fatal("public session file accepted")
	}
	if calls.Load() != 0 {
		t.Fatal("invalid session made a request")
	}
}
