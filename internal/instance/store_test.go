package instance

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"govweave/internal/config"
)

func deployment(t *testing.T) config.Deployment {
	t.Helper()
	return config.Deployment{SchemaVersion: 1, ListenAddr: "127.0.0.1:8080", DataDir: t.TempDir(), Sources: map[string]string{}}
}
func sample() config.Settings {
	return config.Settings{OrganizationName: "Enterprise", PublicURL: "https://gateway.example.com"}
}

func TestPersistRestartAndPermission(t *testing.T) {
	d := deployment(t)
	s, err := Open(d)
	if err != nil {
		t.Fatal(err)
	}
	if s.View().Configured {
		t.Fatal("new instance should need setup")
	}
	v, err := s.Update(0, sample())
	if err != nil {
		t.Fatal(err)
	}
	if !v.Configured || v.Revision != 1 || v.Endpoints["models"].URL != "https://gateway.example.com/v1" || v.Endpoints["mcp"].Status != "planned" {
		t.Fatalf("bad view: %+v", v)
	}
	info, err := os.Stat(filepath.Join(d.DataDir, "instance.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("insecure permissions: %v", info.Mode())
	}
	reopened, err := Open(d)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.View().Settings != v.Settings || reopened.View().Revision != 1 {
		t.Fatal("settings did not survive restart")
	}
	if _, err := reopened.Update(0, sample()); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
}

func TestConcurrentUpdateOnlyOneWins(t *testing.T) {
	s, err := Open(deployment(t))
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	results := make(chan error, 12)
	for i := 0; i < 12; i++ {
		group.Add(1)
		go func() { defer group.Done(); _, err := s.Update(0, sample()); results <- err }()
	}
	group.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		} else if !errors.Is(err, ErrConflict) {
			t.Fatal(err)
		}
	}
	if winners != 1 {
		t.Fatalf("%d concurrent writes succeeded", winners)
	}
}

func TestManagedFieldsAndFallback(t *testing.T) {
	d := deployment(t)
	s, _ := Open(d)
	if _, err := s.Update(0, sample()); err != nil {
		t.Fatal(err)
	}
	d.PublicURL = "https://managed.example.com"
	d.Sources["public_url"] = "environment"
	managed, err := Open(d)
	if err != nil {
		t.Fatal(err)
	}
	if managed.View().PublicURL != d.PublicURL || managed.View().Sources["public_url"] != "environment" {
		t.Fatal("deployment override not effective")
	}
	if _, err := managed.Update(1, sample()); !errors.Is(err, ErrManaged) {
		t.Fatalf("managed value was writable: %v", err)
	}
	settings := sample()
	settings.PublicURL = d.PublicURL
	settings.OrganizationName = "Renamed"
	if _, err := managed.Update(1, settings); err != nil {
		t.Fatal(err)
	}
	d.PublicURL = ""
	delete(d.Sources, "public_url")
	reopened, err := Open(d)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.View().PublicURL != settings.PublicURL || reopened.View().Sources["public_url"] != "console" {
		t.Fatal("expected last saved effective value after override removed")
	}
}

func TestFailedSaveDoesNotChangeActiveState(t *testing.T) {
	d := deployment(t)
	s, err := Open(d)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(d.DataDir, "instance.json"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Update(0, sample()); err == nil {
		t.Fatal("expected persistence failure")
	}
	if s.View().Configured || s.View().Revision != 0 {
		t.Fatal("failed save changed active state")
	}
}

func TestCorruptStateFailsClosed(t *testing.T) {
	d := deployment(t)
	for _, data := range []string{`{`, `{"schema_version":2,"revision":1}`, `null`, `{"schema_version":1,"revision":0}`} {
		if err := os.WriteFile(filepath.Join(d.DataDir, "instance.json"), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(d); err == nil {
			t.Fatalf("accepted corrupt state %s", data)
		}
	}
}

func TestDataDirectoryLock(t *testing.T) {
	dir := t.TempDir()
	first, err := LockDataDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if second, err := LockDataDir(dir); err == nil {
		second.Close()
		t.Fatal("second process lock accepted")
	}
	first.Close()
	last, err := LockDataDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	last.Close()
}
