package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"govweave/internal/sensitive"
	"govweave/internal/storage"
)

const evidenceTestApp = "app_abcdefghijklmnop"
const evidenceOtherApp = "app_qrstuvwxyzABCDEF"

func evidenceFixture(t *testing.T, mode string) (*EvidenceStore, string, EvidenceConfig) {
	t.Helper()
	dir := t.TempDir()
	s, err := OpenEvidence(dir)
	if err != nil {
		t.Fatal(err)
	}
	c := s.Config()
	c.Mode, c.ApplicationIDs = mode, []string{evidenceTestApp}
	c, err = s.SaveConfig(c, Snapshot{Applications: []Application{{ID: evidenceTestApp}, {ID: evidenceOtherApp}}}, "test_admin")
	if err != nil {
		t.Fatal(err)
	}
	return s, dir, c
}

func evidenceTestRecord(t *testing.T, applicationID string) CallRecord {
	t.Helper()
	id, err := storage.ID("req_", 16)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	return CallRecord{SchemaVersion: 1, RequestID: id, ApplicationID: applicationID, Operation: "chat.completions", Phase: "finished", StartedAt: now, Timestamp: now,
		Decision: "deny", Outcome: "blocked", HTTPStatus: 403, ErrorCode: "content_output_blocked"}
}

func evidenceTestPayload(c EvidenceConfig) EvidencePayload {
	return EvidencePayload{Config: c, AuditCommitted: true, DeliveryState: "withheld", Objects: []EvidenceObjectInput{
		{Kind: "request", MediaType: "application/json", Data: []byte(`{"messages":[{"role":"user","content":"Synthetic secret input phrase"}]}`)},
		{Kind: "upstream_output", MediaType: "application/json", Data: []byte(`{"text":"Contact hidden-person@private.example"}`)},
		{Kind: "released_output", MediaType: "application/json", ContentState: "not_observed"},
	}, Policies: []EvidencePolicySnapshot{{Kind: "output", ID: "sensitive-output", Revision: 3, Snapshot: json.RawMessage(`{"revision":3,"mode":"block"}`)}}}
}

func TestEvidenceVaultEncryptedRestartMetadataAndReveal(t *testing.T) {
	s, dir, c := evidenceFixture(t, "full")
	r := evidenceTestRecord(t, evidenceTestApp)
	p := evidenceTestPayload(c)
	summary, err := s.Capture(r, p)
	if err != nil {
		t.Fatal(err)
	}
	if summary.ID != EvidenceID(r.RequestID) || !summary.AuditCommitted || summary.DeliveryState != "withheld" || summary.RetainedBytes == 0 {
		t.Fatal("invalid evidence summary")
	}
	if err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if path != dir && info.Mode().Perm()&0077 != 0 {
			t.Errorf("nonprivate path: %s", entry.Name())
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, value := range []string{"Synthetic secret input phrase", "hidden-person@private.example"} {
			if bytes.Contains(data, []byte(value)) {
				t.Errorf("plaintext evidence on disk: %s", entry.Name())
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s, err = OpenEvidence(dir)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := s.Get(summary.ID, evidenceTestApp)
	if err != nil || bundle.Integrity != "authenticated" || bundle.Record.RequestID != r.RequestID || len(bundle.Policies) != 1 {
		t.Fatal("restart evidence mismatch", err)
	}
	metadata, _ := json.Marshal(bundle)
	if bytes.Contains(metadata, []byte("hidden-person")) || bytes.Contains(metadata, []byte("Synthetic secret")) {
		t.Fatal("metadata disclosed captured text")
	}
	object := bundle.Objects[1]
	if object.ContentState != "retained" || len(object.Fingerprint) != 64 {
		t.Fatal("missing retained artifact metadata")
	}
	preview, err := s.Reveal(summary.ID, evidenceTestApp, object.ID, "redacted", "incident_review", "admin:opaque_session")
	if err != nil || strings.Contains(preview.Text, "hidden-person") || preview.RedactionState != "pattern_limited" {
		t.Fatal("preview did not redact known email", err)
	}
	raw, err := s.Reveal(summary.ID, evidenceTestApp, object.ID, "raw", "validation", "admin:opaque_session")
	if err != nil || raw.Text != string(p.Objects[1].Data) {
		t.Fatal("raw content not preserved", err)
	}
	access, err := s.AccessLog(128)
	if err != nil || len(access) != 3 || access[0].Action != "reveal_authorized" || access[0].View != "raw" {
		t.Fatal("content release lacks access event", err)
	}
	if _, err := s.Reveal(summary.ID, evidenceOtherApp, object.ID, "raw", "validation", "test_admin"); !errors.Is(err, ErrEvidenceNotFound) {
		t.Fatal("cross-application reveal accepted", err)
	}
	if _, err := s.Get(summary.ID, evidenceOtherApp); !errors.Is(err, ErrEvidenceNotFound) {
		t.Fatal("cross-application metadata accepted")
	}
	if _, err := s.Capture(r, p); !errors.Is(err, ErrConflict) {
		t.Fatal("immutable evidence overwritten")
	}
}

func TestEvidenceModesLimitsScopeAndSnapshot(t *testing.T) {
	s, _, c := evidenceFixture(t, "metadata")
	r := evidenceTestRecord(t, evidenceTestApp)
	p := evidenceTestPayload(c)
	summary, err := s.Capture(r, p)
	if err != nil {
		t.Fatal(err)
	}
	bundle, _ := s.Get(summary.ID, evidenceTestApp)
	if summary.RetainedBytes != 0 || bundle.Objects[0].ContentState != "metadata_only" {
		t.Fatal("metadata mode captured content")
	}
	if _, err := s.Reveal(summary.ID, evidenceTestApp, bundle.Objects[0].ID, "raw", "validation", "test_admin"); !errors.Is(err, ErrEvidenceContentUnavailable) {
		t.Fatal("metadata-only reveal accepted")
	}
	if _, err := s.Capture(evidenceTestRecord(t, evidenceOtherApp), p); !errors.Is(err, ErrEvidenceDisabled) {
		t.Fatal("out-of-scope content captured")
	}
	if (EvidenceConfig{Mode: "full"}).Applies(evidenceTestApp) {
		t.Fatal("empty application scope matched")
	}
	c.Mode, c.MaxContentBytes = "full", 4096
	c, err = s.SaveConfig(c, Snapshot{Applications: []Application{{ID: evidenceTestApp}}}, "test_admin")
	if err != nil {
		t.Fatal(err)
	}
	frozen := c
	c.Mode, c.MaxContentBytes = "disabled", 64<<10
	if _, err := s.SaveConfig(c, Snapshot{Applications: []Application{{ID: evidenceTestApp}}}, "test_admin"); err != nil {
		t.Fatal(err)
	}
	p = evidenceTestPayload(frozen)
	p.Objects[0].Data = bytes.Repeat([]byte("x"), 4097)
	p.Objects = append(p.Objects, EvidenceObjectInput{Kind: "upstream_request", MediaType: "text/plain", Data: []byte("valid empty header-free request")})
	r = evidenceTestRecord(t, evidenceTestApp)
	summary, err = s.Capture(r, p)
	if err != nil {
		t.Fatal(err)
	}
	bundle, _ = s.Get(summary.ID, evidenceTestApp)
	if summary.MaxContentBytes != frozen.MaxContentBytes || bundle.MaxContentBytes != frozen.MaxContentBytes || bundle.CaptureRevision != frozen.Revision || bundle.Mode != "full" || bundle.Objects[0].ContentState != "omitted_size" || bundle.Objects[0].Bytes != 4097 {
		t.Fatal("frozen configuration or oversized state lost")
	}
	stored, _, err := s.read(summary.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []int{0, 4095, MaxEvidenceObjectBytes + 1} {
		stored.Bundle.MaxContentBytes = invalid
		if validStoredEvidence(summary.ID, stored) {
			t.Fatal("invalid historical content limit accepted", invalid)
		}
	}
	p.Objects[0].Data = nil
	p.Objects[0].ContentState = "streaming_not_captured"
	p.Objects[0].MediaType = "text/event-stream"
	if _, err := s.Capture(evidenceTestRecord(t, evidenceTestApp), p); err != nil {
		t.Fatal("streaming coverage metadata rejected", err)
	}
	p.Objects[0].Data = []byte("cannot claim both")
	if _, err := s.Capture(evidenceTestRecord(t, evidenceTestApp), p); !errors.Is(err, ErrEvidenceInvalid) {
		t.Fatal("contradictory content state accepted")
	}
}

func TestEvidenceTamperWrongKeyMissingAndPrivateFiles(t *testing.T) {
	for _, scenario := range []string{"ciphertext", "key", "missing", "permissions", "symlink"} {
		t.Run(scenario, func(t *testing.T) {
			s, dir, c := evidenceFixture(t, "full")
			r := evidenceTestRecord(t, evidenceTestApp)
			summary, err := s.Capture(r, evidenceTestPayload(c))
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "evidence", summary.ID+".sealed")
			switch scenario {
			case "ciphertext":
				data, _ := os.ReadFile(path)
				data[len(data)-1] ^= 1
				err = os.WriteFile(path, data, 0600)
			case "key":
				err = os.WriteFile(filepath.Join(dir, "evidence.key"), bytes.Repeat([]byte{7}, 32), 0600)
			case "missing":
				err = os.Remove(path)
			case "permissions":
				err = os.Chmod(path, 0644)
			case "symlink":
				target := filepath.Join(dir, "elsewhere")
				if err = os.Rename(path, target); err == nil {
					err = os.Symlink(target, path)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "key" {
				if _, err := OpenEvidence(dir); !errors.Is(err, ErrEvidenceUnavailable) {
					t.Fatal("wrong key accepted", err)
				}
				return
			}
			if _, err := s.Get(summary.ID, evidenceTestApp); !errors.Is(err, ErrEvidenceUnavailable) {
				t.Fatal("invalid evidence returned", err)
			}
			if scenario != "missing" {
				if _, err := OpenEvidence(dir); !errors.Is(err, ErrEvidenceUnavailable) {
					t.Fatal("invalid on-disk evidence accepted on restart", err)
				}
			}
		})
	}
}

func TestEvidenceExpiryPurgeAndCapacity(t *testing.T) {
	s, dir, c := evidenceFixture(t, "full")
	fixed := time.Now().UTC()
	s.now = func() time.Time { return fixed }
	c.RetentionDays = 1
	summary, err := s.Capture(evidenceTestRecord(t, evidenceTestApp), evidenceTestPayload(c))
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return fixed.Add(24 * time.Hour) }
	if _, err := s.Get(summary.ID, evidenceTestApp); !errors.Is(err, ErrEvidenceExpired) {
		t.Fatal("expired content readable", err)
	}
	listed, err := s.List(evidenceTestApp, 128)
	if err != nil || len(listed) != 0 {
		t.Fatal("expired evidence remains in list", err)
	}
	n, err := s.PurgeExpired("test_admin")
	if err != nil || n != 1 {
		t.Fatal("expiry purge failed", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "evidence", summary.ID+".sealed")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("expired ciphertext retained")
	}
	access, _ := s.AccessLog(1)
	if len(access) != 1 || access[0].Action != "expiry_deletion_authorized" {
		t.Fatal("expiry deletion not recorded")
	}
	s.bytes = MaxEvidenceBytes
	if _, err := s.Capture(evidenceTestRecord(t, evidenceTestApp), evidenceTestPayload(c)); !errors.Is(err, ErrEvidenceCapacity) {
		t.Fatal("capacity gate bypassed")
	}
}

func TestEvidenceRevealFailsClosedWhenAccessRecordUnavailable(t *testing.T) {
	for _, scenario := range []string{"full", "directory", "same_size_change"} {
		t.Run(scenario, func(t *testing.T) {
			s, dir, c := evidenceFixture(t, "full")
			summary, err := s.Capture(evidenceTestRecord(t, evidenceTestApp), evidenceTestPayload(c))
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "evidence", "access.jsonl")
			switch scenario {
			case "full":
				s.accessBytes = MaxEvidenceAccessBytes
			case "directory":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "same_size_change":
				data, _ := os.ReadFile(path)
				data[2] ^= 1
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			content, err := s.Reveal(summary.ID, evidenceTestApp, summary.ID+":request", "raw", "validation", "test_admin")
			if err == nil || content.Text != "" {
				t.Fatal("content released without durable access record")
			}
		})
	}
}

func TestEvidenceConcurrentCaptureAndScopedTraceIndex(t *testing.T) {
	s, _, c := evidenceFixture(t, "full")
	c.ApplicationIDs = append(c.ApplicationIDs, evidenceOtherApp)
	const trace = "1234567890abcdef1234567890abcdef"
	var wg sync.WaitGroup
	errorsCh := make(chan error, 32)
	for i := 0; i < 32; i++ {
		r := evidenceTestRecord(t, evidenceTestApp)
		if i%2 == 1 {
			r.ApplicationID = evidenceOtherApp
		}
		r.Trace = &TraceContext{Version: traceVersion, TraceID: trace, SpanID: "1234567890abcdef"}
		wg.Add(1)
		go func(r CallRecord) { defer wg.Done(); _, err := s.Capture(r, evidenceTestPayload(c)); errorsCh <- err }(r)
	}
	wg.Wait()
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	list, err := s.ListTrace(evidenceTestApp, trace, 128)
	if err != nil || len(list) != 16 {
		t.Fatal("scoped trace count wrong", err, len(list))
	}
	for _, item := range list {
		if item.ApplicationID != evidenceTestApp {
			t.Fatal("cross-scope list leak")
		}
	}
	if _, err := s.ListTrace(evidenceTestApp, "invalid", 128); !errors.Is(err, ErrEvidenceInvalid) {
		t.Fatal("invalid trace accepted")
	}
	if _, err := s.List(evidenceTestApp, 129); !errors.Is(err, ErrEvidenceInvalid) {
		t.Fatal("unbounded list accepted")
	}
}

func TestEvidenceFingerprintScopeAndConservativePreview(t *testing.T) {
	s, _, _ := evidenceFixture(t, "full")
	if s.fingerprint(evidenceTestApp, []byte("same")) == s.fingerprint(evidenceOtherApp, []byte("same")) {
		t.Fatal("cross-application content linkability")
	}
	for _, content := range [][]byte{[]byte("-----BEGIN PRIVATE KEY----- secret body"), bytes.Repeat([]byte("x"), sensitive.MaxBytes+1)} {
		preview, state := evidencePreview(content)
		if state != "withheld" || !strings.HasPrefix(preview, "[CONTENT WITHHELD") {
			t.Fatal("unsupported preview not withheld")
		}
	}
}

func TestEvidenceRestartPurgeTemporaryRecoveryAndMissingKey(t *testing.T) {
	s, dir, c := evidenceFixture(t, "full")
	s.now = func() time.Time { return time.Now().Add(-48 * time.Hour) }
	c.RetentionDays = 1
	summary, err := s.Capture(evidenceTestRecord(t, evidenceTestApp), evidenceTestPayload(c))
	if err != nil {
		t.Fatal(err)
	}
	orphan := filepath.Join(dir, "evidence", ".evidence-crash-fixture")
	if err := os.WriteFile(orphan, []byte("synthetic interrupted ciphertext"), 0600); err != nil {
		t.Fatal(err)
	}
	s, err = OpenEvidence(dir)
	if err != nil {
		t.Fatal("restart recovery failed", err)
	}
	for _, path := range []string{orphan, filepath.Join(dir, "evidence", summary.ID+".sealed")} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("expired/interrupted file remains", err)
		}
	}
	if _, err := s.Get(summary.ID, evidenceTestApp); !errors.Is(err, ErrEvidenceNotFound) {
		t.Fatal("purged record still readable")
	}
	if err := os.Remove(filepath.Join(dir, "evidence.key")); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenEvidence(dir); !errors.Is(err, ErrEvidenceUnavailable) {
		t.Fatal("missing key regenerated over existing evidence configuration", err)
	}
}

func TestEvidenceConfigValidationAndFractionalOrdering(t *testing.T) {
	s, _, c := evidenceFixture(t, "full")
	snapshot := Snapshot{Applications: []Application{{ID: evidenceTestApp}}}
	for _, mutate := range []func(*EvidenceConfig){
		func(c *EvidenceConfig) { c.ApplicationIDs = nil },
		func(c *EvidenceConfig) { c.ApplicationIDs = []string{evidenceOtherApp} },
		func(c *EvidenceConfig) { c.ApplicationIDs = []string{evidenceTestApp, evidenceTestApp} },
		func(c *EvidenceConfig) { c.RetentionDays = 366 },
		func(c *EvidenceConfig) { c.MaxContentBytes = MaxEvidenceObjectBytes + 1 },
	} {
		invalid := cloneEvidenceConfig(c)
		mutate(&invalid)
		if _, err := s.SaveConfig(invalid, snapshot, "test_admin"); !errors.Is(err, ErrEvidenceInvalid) {
			t.Fatal("invalid evidence configuration accepted", err)
		}
	}
	badRevision := cloneEvidenceConfig(c)
	badRevision.Revision--
	if _, err := s.SaveConfig(badRevision, snapshot, "test_admin"); !errors.Is(err, ErrConflict) {
		t.Fatal("stale revision accepted")
	}
	fixed := time.Now().UTC().Truncate(time.Second)
	s.now = func() time.Time { return fixed }
	older, err := s.Capture(evidenceTestRecord(t, evidenceTestApp), evidenceTestPayload(c))
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return fixed.Add(time.Millisecond) }
	newer, err := s.Capture(evidenceTestRecord(t, evidenceTestApp), evidenceTestPayload(c))
	if err != nil {
		t.Fatal(err)
	}
	list, err := s.List(evidenceTestApp, 128)
	if err != nil || len(list) != 2 || list[0].ID != newer.ID || list[1].ID != older.ID {
		t.Fatal("fractional timestamp ordering wrong", err)
	}
}
