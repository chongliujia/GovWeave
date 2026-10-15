package auth

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

const testPassword = "local test password with spaces"

func openTest(t *testing.T, dir string) *Manager {
	t.Helper()
	m, err := Open(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestPasswordPersistenceAndSessions(t *testing.T) {
	dir := t.TempDir()
	m := openTest(t, dir)
	if !m.SetupRequired() {
		t.Fatal("new instance already configured")
	}
	if err := m.Setup(testPassword); err != nil {
		t.Fatal(err)
	}
	if err := m.Setup("replacement password"); !errors.Is(err, ErrConfigured) {
		t.Fatal("password overwritten")
	}
	if err := m.Login(testPassword); err != nil {
		t.Fatal(err)
	}
	if err := m.Login("wrong password value"); !errors.Is(err, ErrPassword) {
		t.Fatal("bad password accepted")
	}
	if err := m.Login(testPassword + " "); !errors.Is(err, ErrPassword) {
		t.Fatal("password whitespace changed")
	}
	path := filepath.Join(dir, "admin.password.json")
	data, _ := os.ReadFile(path)
	if bytes.Contains(data, []byte(testPassword)) {
		t.Fatal("plaintext password stored")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("password file is not private")
	}
	session, err := m.NewSession("")
	if err != nil || !m.Valid(session) || m.Valid("Bearer "+session) {
		t.Fatal("invalid session behavior")
	}
	replacement, _ := m.NewSession(session)
	if m.Valid(session) || !m.Valid(replacement) {
		t.Fatal("login did not rotate session")
	}
	m.Logout(replacement)
	if m.Valid(replacement) {
		t.Fatal("logout did not revoke session")
	}
	session, _ = m.NewSession("")
	later := time.Now().Add(SessionLifetime + time.Second)
	m.now = func() time.Time { return later }
	if m.Valid(session) {
		t.Fatal("expired session accepted")
	}
	restored := openTest(t, dir)
	if restored.SetupRequired() || restored.Login(testPassword) != nil || restored.Valid(session) {
		t.Fatal("restart did not preserve password and expire sessions")
	}
}

func TestSetupValidationAndConcurrentClaim(t *testing.T) {
	m := openTest(t, t.TempDir())
	if !errors.Is(m.Setup("short"), ErrPasswordLength) || !m.SetupRequired() {
		t.Fatal("short password accepted")
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- m.Setup(testPassword) }()
	}
	wg.Wait()
	close(results)
	count := 0
	for err := range results {
		if err == nil {
			count++
		} else if !errors.Is(err, ErrConfigured) && !errors.Is(err, ErrRateLimited) {
			t.Fatal(err)
		}
	}
	if count != 1 {
		t.Fatal("setup must succeed exactly once")
	}
}

func TestLoginRateLimit(t *testing.T) {
	m := openTest(t, t.TempDir())
	if err := m.Setup(testPassword); err != nil {
		t.Fatal(err)
	}
	// Includes setup; the global limit bounds both CPU work and credential guesses.
	for i := 0; i < 9; i++ {
		if err := m.Login("incorrect long password"); !errors.Is(err, ErrPassword) {
			t.Fatal(err)
		}
	}
	if !errors.Is(m.Login(testPassword), ErrRateLimited) {
		t.Fatal("rate limit missing")
	}
	next := time.Now().Add(time.Minute + time.Second)
	m.now = func() time.Time { return next }
	if err := m.Login(testPassword); err != nil {
		t.Fatal("limit never expires", err)
	}
}

func TestLegacyAndCorruptCredentials(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "admin.token"), []byte("old-unused-token"), 0600); err != nil {
		t.Fatal(err)
	}
	m := openTest(t, dir)
	if !m.LegacySetup() || !m.SetupRequired() {
		t.Fatal("legacy migration not detected")
	}
	if err := m.Setup(testPassword); err != nil {
		t.Fatal(err)
	}
	if openTest(t, dir).SetupRequired() {
		t.Fatal("legacy token reopened setup")
	}
	path := filepath.Join(dir, "admin.password.json")
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, ""); err == nil {
		t.Fatal("unsafe permissions accepted")
	}
	os.Chmod(path, 0600)
	os.WriteFile(path, []byte(`{"version":1}`), 0600)
	if _, err := Open(dir, ""); err == nil {
		t.Fatal("corrupt file reset authentication")
	}
}

func TestExplicitMissingLegacyFileFailsClosed(t *testing.T) {
	dir := t.TempDir()
	if _, err := Open(dir, filepath.Join(dir, "missing.token")); err == nil {
		t.Fatal("missing explicit legacy file opened initialization")
	}
}

func TestSetupPersistenceFailureDoesNotAuthenticate(t *testing.T) {
	dir := t.TempDir()
	m := openTest(t, dir)
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := m.Setup(testPassword); !errors.Is(err, ErrPersistence) {
		t.Fatal("write failure not reported", err)
	}
	if !m.SetupRequired() || !errors.Is(m.Login(testPassword), ErrPassword) {
		t.Fatal("failed write configured authentication")
	}
}
