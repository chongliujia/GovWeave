package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"govweave/internal/admincli"
	"govweave/internal/gateway"
)

func TestAdminCLIApplicationPolicyLifecycleAndSessionRevocation(t *testing.T) {
	h := handler(t)
	created := invoke(h, "POST", "/api/v1/applications", `{"revision":0,"name":"CLI app","allowed_connections":[]}`, testPassword, nil)
	var app applicationResponse
	if created.Code != 200 || json.Unmarshal(created.Body.Bytes(), &app) != nil {
		t.Fatal("application fixture failed", created.Code)
	}
	var mu sync.Mutex
	var sessions []string
	instance := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/gateway" {
			if cookie, err := r.Cookie(sessionCookie); err == nil {
				mu.Lock()
				sessions = append(sessions, cookie.Value)
				mu.Unlock()
			}
		}
		h.ServeHTTP(w, r)
	}))
	defer instance.Close()
	sessionFile := filepath.Join(t.TempDir(), "session.json")
	useSession := false
	run := func(wantOK bool, args ...string) json.RawMessage {
		t.Helper()
		var stdout, stderr bytes.Buffer
		flags := []string{"--url", instance.URL, "--password-stdin"}
		if useSession {
			flags = []string{"--url", instance.URL, "--session-file", sessionFile}
		}
		err := admincli.Run(append(flags, args...), strings.NewReader(testPassword+"\n"), &stdout, &stderr)
		if (err == nil) != wantOK {
			t.Fatalf("CLI %v: %v", args, err)
		}
		if strings.Contains(stdout.String()+stderr.String(), testPassword) || strings.Contains(stdout.String(), app.APIKey) {
			t.Fatal("credential disclosure")
		}
		if wantOK && !json.Valid(stdout.Bytes()) {
			t.Fatal("missing JSON output")
		}
		return stdout.Bytes()
	}
	run(true, "status")
	run(true, "applications", "list")
	mu.Lock()
	session := sessions[len(sessions)-1]
	mu.Unlock()
	req := httptest.NewRequest("GET", "/api/v1/gateway", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: session})
	response := httptest.NewRecorder()
	h.ServeHTTP(response, req)
	if response.Code != 401 {
		t.Fatal("CLI session survived command")
	}
	var loginOutput, loginErrors bytes.Buffer
	if err := admincli.Run([]string{"--url", instance.URL, "--session-file", sessionFile, "--password-stdin", "login"}, strings.NewReader(testPassword), &loginOutput, &loginErrors); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(sessionFile)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("session file not private")
	}
	useSession = true
	run(true, "policy", "show", "--application", app.Application.ID)
	run(true, "policy", "set", "--application", app.Application.ID, "--revision", "0", "--mode", "redact", "--detector", "sensitive-text-v3", "--categories", "email")
	run(false, "policy", "set", "--application", app.Application.ID, "--revision", "0", "--mode", "block")
	run(true, "policy", "set", "--revision", "1", "--mode", "block", "--categories", "credential")
	raw := run(true, "policy", "show", "--application", app.Application.ID)
	var view struct {
		Source string                       `json:"source"`
		Policy gateway.OutputPolicySnapshot `json:"policy"`
	}
	if json.Unmarshal(raw, &view) != nil || view.Source != "application" || view.Policy.Mode != "redact" || view.Policy.DetectorVersion != "sensitive-text-v3" {
		t.Fatal("default update overwrote application policy")
	}
	run(true, "policy", "inherit", "--application", app.Application.ID, "--revision", "2")
	raw = run(true, "policy", "show", "--application", app.Application.ID)
	json.Unmarshal(raw, &view)
	if view.Source != "default" || view.Policy.Mode != "block" {
		t.Fatal("inherit failed")
	}
	run(true, "policy", "restore", "--application", app.Application.ID, "--revision", "3", "--from-revision", "1")
	raw = run(true, "policy", "show", "--application", app.Application.ID)
	json.Unmarshal(raw, &view)
	if view.Source != "application" || view.Policy.Mode != "redact" || view.Policy.Revision != 4 {
		t.Fatal("restore did not create a new revision")
	}
	run(true, "policy", "history", "--application", app.Application.ID)
	run(true, "requests", "list", "--application", app.Application.ID, "--limit", "2")
	for _, route := range []string{"", "/history", "/restore"} {
		path := "/api/v1/policies/sensitive-output/applications/" + app.Application.ID + route
		if invoke(h, "GET", path, "", app.APIKey, nil).Code != 401 && route != "/restore" {
			t.Fatal("application key read administrator policy")
		}
	}
	path := "/api/v1/policies/sensitive-output/applications/" + app.Application.ID
	if invoke(h, "DELETE", path, `{"revision":4}`, testPassword, map[string]string{"Origin": "https://untrusted.example"}).Code != 403 {
		t.Fatal("cross-origin write accepted")
	}
	if invoke(h, "PUT", path, `{"revision":4,"mode":"block","categories":["email"],"application_ids":[]}`, testPassword, nil).Code != 400 {
		t.Fatal("application policy accepted a scope override")
	}
	if invoke(h, "DELETE", path, `{"revision":0}`, testPassword, nil).Code != 409 {
		t.Fatal("stale delete accepted")
	}
	if invoke(h, "GET", "/api/v1/policies/sensitive-output/applications/missing", "", testPassword, nil).Code != 404 {
		t.Fatal("unknown application accepted")
	}
	configPath := filepath.Join(t.TempDir(), "application.json")
	if err := os.WriteFile(configPath, []byte(`{"revision":0,"name":"Created in terminal","allowed_connections":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	createdByCLI := run(true, "applications", "create", "--file", configPath)
	var terminalApp applicationResponse
	if json.Unmarshal(createdByCLI, &terminalApp) != nil || terminalApp.APIKey == "" {
		t.Fatal("headless application creation failed")
	}
	originalKey := terminalApp.APIKey
	rotated := run(true, "applications", "rotate", "--id", terminalApp.Application.ID, "--revision", fmt.Sprint(terminalApp.Application.Revision))
	if json.Unmarshal(rotated, &terminalApp) != nil || terminalApp.APIKey == "" || terminalApp.APIKey == originalKey {
		t.Fatal("CLI key rotation failed")
	}
	run(true, "applications", "revoke", "--id", terminalApp.Application.ID, "--revision", fmt.Sprint(terminalApp.Application.Revision))
	run(true, "applications", "list")
	mu.Lock()
	persistentSession := sessions[len(sessions)-1]
	mu.Unlock()
	run(true, "logout")
	if _, err := os.Stat(sessionFile); !os.IsNotExist(err) {
		t.Fatal("logout retained local session")
	}
	req = httptest.NewRequest("GET", "/api/v1/gateway", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: persistentSession})
	response = httptest.NewRecorder()
	h.ServeHTTP(response, req)
	if response.Code != 401 {
		t.Fatal("persistent session not revoked")
	}
	history := invoke(h, "GET", path+"/history", "", testPassword, nil)
	if !strings.Contains(history.Body.String(), fmt.Sprintf(`"revision":%d`, 4)) {
		t.Fatal("history missing")
	}
}
