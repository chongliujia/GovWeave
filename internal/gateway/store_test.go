package gateway

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func connectionInput(url string) ConnectionInput {
	key := "provider-credential-private"
	return ConnectionInput{Name: "Test provider", BaseURL: url, Model: "provider-model", Alias: "internal-assistant", APIKey: &key, Enabled: true, AllowInsecureHTTP: true, TimeoutSeconds: 5}
}

func setupStore(t *testing.T, dir, url string) (*Store, Connection, Application, string) {
	t.Helper()
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.SaveConnection("", connectionInput(url))
	if err != nil {
		t.Fatal(err)
	}
	a, key, err := s.SaveApplication("", ApplicationInput{Name: "Knowledge app", AllowedConnections: []string{c.ID}})
	if err != nil {
		t.Fatal(err)
	}
	return s, c, a, key
}

func TestCredentialPrivacyPersistenceAndRevocation(t *testing.T) {
	dir := t.TempDir()
	s, c, a, key := setupStore(t, dir, "https://models.example/v1")
	disk, err := os.ReadFile(filepath.Join(dir, "gateway.json"))
	if err != nil {
		t.Fatal(err)
	}
	api, _ := json.Marshal(s.Snapshot())
	for _, secret := range []string{key, "provider-credential-private"} {
		if strings.Contains(string(disk), secret) || strings.Contains(string(api), secret) {
			t.Fatal("plaintext secret persisted or exposed")
		}
	}
	if strings.Contains(string(api), "ciphertext") || strings.Contains(string(api), "key_hash") {
		t.Fatal("private credential metadata exposed")
	}
	s, err = OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := s.Resolve("Bearer "+key, c.Alias)
	if err != nil || resolved.Credential != "provider-credential-private" {
		t.Fatal("credentials did not survive restart")
	}
	in := connectionInput(c.BaseURL)
	in.Revision = c.Revision
	in.APIKey = nil
	c, err = s.SaveConnection(c.ID, in)
	if err != nil {
		t.Fatal(err)
	}
	resolved, _ = s.Resolve("Bearer "+key, c.Alias)
	if resolved.Credential != "provider-credential-private" {
		t.Fatal("omitted credential was erased")
	}
	empty := ""
	in.Revision = c.Revision
	in.APIKey = &empty
	c, err = s.SaveConnection(c.ID, in)
	if err != nil || c.HasCredential {
		t.Fatal("explicit clearing failed")
	}
	if _, err = s.SaveConnection(c.ID, in); !errors.Is(err, ErrConflict) {
		t.Fatal("stale update accepted")
	}
	a, nextKey, err := s.ChangeKey(a.ID, a.Revision, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Authenticate("Bearer " + key); !errors.Is(err, ErrInvalidKey) {
		t.Fatal("old key still accepted")
	}
	if _, _, err := s.Authenticate("Bearer " + nextKey); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ChangeKey(a.ID, a.Revision, true); err != nil {
		t.Fatal(err)
	}
	s, err = OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Authenticate("Bearer " + nextKey); !errors.Is(err, ErrInvalidKey) {
		t.Fatal("revoked key accepted after restart")
	}
	if err := os.Remove(filepath.Join(dir, "gateway.key")); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(dir); err == nil {
		t.Fatal("missing encryption key regenerated for existing configuration")
	}
}

func TestPermissionsAndFailedSaveDoNotChangeState(t *testing.T) {
	s, c, a, key := setupStore(t, t.TempDir(), "http://127.0.0.1:12345/v1")
	in := connectionInput(c.BaseURL)
	in.Alias = "restricted"
	in.APIKey = nil
	other, err := s.SaveConnection("", in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Resolve("Bearer "+key, other.Alias); !errors.Is(err, ErrDenied) {
		t.Fatal("unauthorized model allowed")
	}
	a, _, err = s.SaveApplication(a.ID, ApplicationInput{Revision: a.Revision, Name: a.Name, AllowedConnections: []string{other.ID}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Resolve("Bearer "+key, c.Alias); !errors.Is(err, ErrDenied) {
		t.Fatal("removed permission still allowed")
	}
	in.Revision = other.Revision
	in.Enabled = false
	other, err = s.SaveConnection(other.ID, in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Resolve("Bearer "+key, other.Alias); !errors.Is(err, ErrDisabled) {
		t.Fatal("disabled connection allowed")
	}
	models, _, _, err := s.Models("Bearer " + key)
	if err != nil || len(models) != 0 {
		t.Fatal("disabled model exposed")
	}
	s.path = filepath.Join(t.TempDir(), "missing", "gateway.json")
	before := s.Snapshot().Revision
	if _, _, err := s.ChangeKey(a.ID, a.Revision, true); !errors.Is(err, ErrPersistence) {
		t.Fatal("expected save failure")
	}
	if s.Snapshot().Revision != before {
		t.Fatal("failed save changed revision")
	}
	if _, _, err := s.Authenticate("Bearer " + key); err != nil {
		t.Fatal("failed revocation changed active key")
	}
}

func TestURLAndCredentialValidation(t *testing.T) {
	for _, url := range []string{"http://169.254.169.254/v1", "http://[fe80::1]/v1", "http://0.0.0.0/v1", "https://key@models.example/v1", "https://models.example/v1?key=secret", "https://models.example/a/../v1", "https://models.example/%2e%2e/v1", "file:///tmp/a"} {
		if _, err := NormalizeUpstreamURL(url); err == nil {
			t.Errorf("accepted invalid URL %s", url)
		}
	}
	in := connectionInput("http://localhost:1234/v1")
	in.AllowInsecureHTTP = false
	if _, err := validateConnection(in); err == nil {
		t.Fatal("HTTP allowed without acknowledgment")
	}
	in.AllowInsecureHTTP = true
	key := "secret\r\nX-Injected: yes"
	in.APIKey = &key
	if _, err := validateConnection(in); err == nil {
		t.Fatal("header injection allowed")
	}
}
