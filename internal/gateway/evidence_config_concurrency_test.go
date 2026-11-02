package gateway

import (
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestEvidenceConfigReadDoesNotWaitForCaptureIO(t *testing.T) {
	s, _, want := evidenceFixture(t, "full")
	// Capture and other durable vault operations hold mu during file I/O.
	// A request only reading its frozen config must not wait for those writes.
	s.mu.Lock()
	defer s.mu.Unlock()
	read := make(chan EvidenceConfig, 1)
	go func() { read <- s.Config() }()
	select {
	case got := <-read:
		if !reflect.DeepEqual(got, want) {
			t.Fatal("configuration changed while the vault was busy")
		}
		got.ApplicationIDs[0] = evidenceOtherApp
		if !reflect.DeepEqual(s.Config(), want) {
			t.Fatal("request mutated the published configuration")
		}
	case <-time.After(time.Second):
		t.Fatal("configuration read waited for vault I/O")
	}
}

func TestEvidenceConfigConcurrentPublicationAndRestart(t *testing.T) {
	s, dir, c := evidenceFixture(t, "full")
	done := make(chan struct{})
	bad := make(chan struct{}, 1)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				got := s.Config()
				valid := got.Mode == "full" && got.RetentionDays == 30 && got.MaxContentBytes == 64<<10 && len(got.ApplicationIDs) == 1 && got.ApplicationIDs[0] == evidenceTestApp
				if got.Revision%2 == 0 {
					valid = got.Mode == "metadata" && got.RetentionDays == 31 && got.MaxContentBytes == 4096 && len(got.ApplicationIDs) == 1 && got.ApplicationIDs[0] == evidenceOtherApp
				}
				if !valid {
					select {
					case bad <- struct{}{}:
					default:
					}
					return
				}
				select {
				case <-done:
					return
				default:
				}
			}
		}()
	}
	var stop sync.Once
	finishReaders := func() { stop.Do(func() { close(done) }); wg.Wait() }
	defer finishReaders()
	apps := Snapshot{Applications: []Application{{ID: evidenceTestApp}, {ID: evidenceOtherApp}}}
	for i := 0; i < 12; i++ {
		next := s.Config()
		next.Mode, next.RetentionDays, next.MaxContentBytes, next.ApplicationIDs = "metadata", 31, 4096, []string{evidenceOtherApp}
		if next.Revision%2 == 0 {
			next.Mode, next.RetentionDays, next.MaxContentBytes, next.ApplicationIDs = "full", 30, 64<<10, []string{evidenceTestApp}
		}
		var err error
		c, err = s.SaveConfig(next, apps, "test_admin")
		if err != nil {
			t.Fatal(err)
		}
	}
	finishReaders()
	select {
	case <-bad:
		t.Fatal("reader saw a partially published configuration")
	default:
	}
	reopened, err := OpenEvidence(dir)
	if err != nil || !reflect.DeepEqual(reopened.Config(), c) {
		t.Fatal("published configuration not retained across reopen", err)
	}
}

func TestEvidenceConfigFailedPersistenceDoesNotPublish(t *testing.T) {
	s, dir, old := evidenceFixture(t, "full")
	path := filepath.Join(dir, "evidence", "config.json")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	changed := cloneEvidenceConfig(old)
	changed.Mode = "metadata"
	if _, err := s.SaveConfig(changed, Snapshot{Applications: []Application{{ID: evidenceTestApp}}}, "test_admin"); err == nil {
		t.Fatal("config persistence failure was ignored")
	}
	if !reflect.DeepEqual(s.Config(), old) {
		t.Fatal("failed write published a new configuration")
	}
}
