package gateway

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type captureResult struct {
	summary EvidenceSummary
	err     error
}

func concurrentCapture(s *EvidenceStore, r CallRecord, p EvidencePayload, wg *sync.WaitGroup) <-chan captureResult {
	done := make(chan captureResult, 1)
	wg.Add(1)
	go func() { defer wg.Done(); summary, err := s.Capture(r, p); done <- captureResult{summary, err} }()
	return done
}

func awaitCapture(t *testing.T, result <-chan captureResult) captureResult {
	t.Helper()
	select {
	case r := <-result:
		return r
	case <-time.After(3 * time.Second):
		t.Fatal("capture waited for an unrelated write")
		return captureResult{}
	}
}

func TestEvidenceIndependentPersistenceAndPublication(t *testing.T) {
	s, dir, c := evidenceFixture(t, "full")
	entered := make(chan struct{}, 2)
	gate := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(gate) }) }
	var wg sync.WaitGroup
	defer func() { release(); wg.Wait() }()
	s.writeEvidence = func(path string, data []byte) error {
		err := immutableEvidenceFile(path, data)
		entered <- struct{}{}
		<-gate
		return err
	}
	records := []CallRecord{evidenceTestRecord(t, evidenceTestApp), evidenceTestRecord(t, evidenceOtherApp)}
	c.ApplicationIDs = append(c.ApplicationIDs, evidenceOtherApp)
	done := []<-chan captureResult{}
	for _, r := range records {
		done = append(done, concurrentCapture(s, r, evidenceTestPayload(c), &wg))
	}
	for range records {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("independent evidence writes serialized under the index lock")
		}
	}
	for _, r := range records {
		if _, err := s.Get(EvidenceID(r.RequestID), r.ApplicationID); !errors.Is(err, ErrEvidenceNotFound) {
			t.Fatal("unconfirmed file became visible", err)
		}
		duplicate := awaitCapture(t, concurrentCapture(s, r, evidenceTestPayload(c), &wg))
		if !errors.Is(duplicate.err, ErrConflict) {
			t.Fatal("duplicate in-flight ID accepted", duplicate.err)
		}
	}
	// A configuration update cannot mutate either in-flight capture snapshot.
	next := s.Config()
	next.Mode = "disabled"
	if _, err := s.SaveConfig(next, Snapshot{Applications: []Application{{ID: evidenceTestApp}}}, "test_admin"); err != nil {
		t.Fatal(err)
	}
	release()
	for i, ch := range done {
		r := awaitCapture(t, ch)
		if r.err != nil || r.summary.Mode != "full" || r.summary.CaptureRevision != c.Revision {
			t.Fatal("frozen capture not retained", r.err)
		}
		bundle, err := s.Get(r.summary.ID, records[i].ApplicationID)
		if err != nil || bundle.RetainedBytes == 0 {
			t.Fatal("completed capture unavailable", err)
		}
		if _, err := s.Get(r.summary.ID, "app_notauthorized1"); !errors.Is(err, ErrEvidenceNotFound) {
			t.Fatal("cross-application capture exposed", err)
		}
	}
	if len(s.pending) != 0 || s.reservedBytes != 0 || len(s.entries) != 2 {
		t.Fatal("reservation leaked after publication")
	}
	var bytes int64
	for id := range s.entries {
		info, err := os.Stat(filepath.Join(s.dir, id+".sealed"))
		if err != nil {
			t.Fatal(err)
		}
		bytes += info.Size()
	}
	if s.bytes != bytes {
		t.Fatal("published byte accounting differs from disk")
	}
	reopened, err := OpenEvidence(dir)
	if err != nil || len(reopened.entries) != 2 || reopened.bytes != bytes {
		t.Fatal("concurrent writes not recoverable", err)
	}
}

func TestEvidencePendingReservationsEnforceCapacity(t *testing.T) {
	for _, budget := range []string{"records", "bytes"} {
		t.Run(budget, func(t *testing.T) {
			s, _, c := evidenceFixture(t, "metadata")
			if budget == "records" {
				for i := 0; i < MaxEvidenceRecords-1; i++ {
					s.entries[fmt.Sprint(i)] = evidenceIndexEntry{summary: EvidenceSummary{ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339Nano)}}
				}
			}
			entered, gate := make(chan struct{}, 1), make(chan struct{})
			var once sync.Once
			release := func() { once.Do(func() { close(gate) }) }
			var wg sync.WaitGroup
			defer func() { release(); wg.Wait() }()
			s.writeEvidence = func(path string, data []byte) error {
				entered <- struct{}{}
				<-gate
				return immutableEvidenceFile(path, data)
			}
			first := concurrentCapture(s, evidenceTestRecord(t, evidenceTestApp), evidenceTestPayload(c), &wg)
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("first capture did not start")
			}
			s.mu.Lock()
			if budget == "bytes" {
				s.bytes = MaxEvidenceBytes - s.reservedBytes
			}
			s.mu.Unlock()
			second := awaitCapture(t, concurrentCapture(s, evidenceTestRecord(t, evidenceTestApp), evidenceTestPayload(c), &wg))
			if !errors.Is(second.err, ErrEvidenceCapacity) {
				t.Fatal("in-flight capture bypassed capacity", second.err)
			}
			release()
			if r := awaitCapture(t, first); r.err != nil {
				t.Fatal(r.err)
			}
			if len(s.pending) != 0 || s.reservedBytes != 0 || s.bytes > MaxEvidenceBytes || len(s.entries) > MaxEvidenceRecords {
				t.Fatal("reservation accounting overflow")
			}
		})
	}
}

func TestEvidencePersistenceFailureReservationAndRecovery(t *testing.T) {
	for _, published := range []bool{false, true} {
		t.Run(fmt.Sprint(published), func(t *testing.T) {
			s, dir, c := evidenceFixture(t, "full")
			r := evidenceTestRecord(t, evidenceTestApp)
			s.writeEvidence = func(path string, data []byte) error {
				if published {
					if err := immutableEvidenceFile(path, data); err != nil {
						return err
					}
				}
				return ErrEvidenceUnavailable
			}
			if _, err := s.Capture(r, evidenceTestPayload(c)); !errors.Is(err, ErrEvidenceUnavailable) {
				t.Fatal("unconfirmed capture reported success", err)
			}
			if _, err := s.Get(EvidenceID(r.RequestID), evidenceTestApp); !errors.Is(err, ErrEvidenceNotFound) {
				t.Fatal("unconfirmed capture exposed", err)
			}
			if s.bytes != 0 || len(s.entries) != 0 {
				t.Fatal("failed capture counted as committed")
			}
			if published {
				if len(s.pending) != 1 || s.reservedBytes == 0 {
					t.Fatal("possibly published file lost its capacity reservation")
				}
				if _, err := s.Capture(r, evidenceTestPayload(c)); !errors.Is(err, ErrConflict) {
					t.Fatal("uncertain ID reused", err)
				}
				reopened, err := OpenEvidence(dir)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := reopened.Get(EvidenceID(r.RequestID), evidenceTestApp); err != nil {
					t.Fatal("valid encrypted file not recovered", err)
				}
				if len(reopened.pending) != 0 || reopened.reservedBytes != 0 {
					t.Fatal("restart retained stale reservations")
				}
			} else {
				if len(s.pending) != 0 || s.reservedBytes != 0 {
					t.Fatal("confirmed absent file leaked capacity")
				}
				s.writeEvidence = immutableEvidenceFile
				if _, err := s.Capture(r, evidenceTestPayload(c)); err != nil {
					t.Fatal("absent file could not be retried", err)
				}
			}
		})
	}
}

func TestEvidencePersistenceConcurrencyBound(t *testing.T) {
	s, _, c := evidenceFixture(t, "metadata")
	entered := make(chan struct{}, maxEvidenceWrites+1)
	gate := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(gate) }) }
	var wg sync.WaitGroup
	defer func() { release(); wg.Wait() }()
	s.writeEvidence = func(path string, data []byte) error {
		entered <- struct{}{}
		<-gate
		return immutableEvidenceFile(path, data)
	}
	results := []<-chan captureResult{}
	for i := 0; i < maxEvidenceWrites+1; i++ {
		results = append(results, concurrentCapture(s, evidenceTestRecord(t, evidenceTestApp), evidenceTestPayload(c), &wg))
	}
	for i := 0; i < maxEvidenceWrites; i++ {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("parallel writer did not start")
		}
	}
	// All requests must reserve capacity, including the writer waiting for a
	// slot. Use that observable state rather than assuming goroutine scheduling.
	deadline := time.Now().Add(3 * time.Second)
	for {
		s.mu.Lock()
		pending := len(s.pending)
		s.mu.Unlock()
		if pending == maxEvidenceWrites+1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("queued writer did not reserve capacity")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-entered:
		t.Fatal("persistence concurrency limit exceeded")
	default:
	}
	if s.Config().Mode != "metadata" {
		t.Fatal("queued writes blocked configuration reads")
	}
	release()
	for _, result := range results {
		if r := awaitCapture(t, result); r.err != nil {
			t.Fatal(r.err)
		}
	}
	if len(s.pending) != 0 || s.reservedBytes != 0 {
		t.Fatal("queued write reservation leaked")
	}
}
