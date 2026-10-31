package gateway

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"govweave/internal/config"
	"govweave/internal/sensitive"
	"govweave/internal/storage"
)

const maxEvidenceFileBytes = 6 << 20
const maxEvidencePolicyBytes = 64 << 10
const evidenceAAD = "govweave-evidence-v1\x00"

type storedEvidence struct {
	Bundle  EvidenceBundle    `json:"bundle"`
	Content map[string][]byte `json:"content"`
}

type evidenceIndexEntry struct {
	summary EvidenceSummary
	bytes   int64
}

type storedEvidenceAccess struct {
	EvidenceAccess
	MAC string `json:"mac"`
}

// EvidenceStore is a bounded supplementary content vault. It is separate from
// call admission/audit and cannot establish that a client received an output.
type EvidenceStore struct {
	mu             sync.Mutex
	dir            string
	aead           cipher.AEAD
	fingerprintKey []byte
	accessKey      []byte
	configuration  EvidenceConfig
	entries        map[string]evidenceIndexEntry
	bytes          int64
	accessBytes    int64
	accessDigest   [sha256.Size]byte
	access         []EvidenceAccess
	accessFailed   bool
	now            func() time.Time
}

func defaultEvidenceConfig() EvidenceConfig {
	return EvidenceConfig{SchemaVersion: 1, Mode: "disabled", ApplicationIDs: []string{}, RetentionDays: 30, MaxContentBytes: 64 << 10}
}

func cloneEvidenceConfig(c EvidenceConfig) EvidenceConfig {
	c.ApplicationIDs = append([]string{}, c.ApplicationIDs...)
	return c
}

func validEvidenceConfig(c EvidenceConfig) bool {
	if c.SchemaVersion != 1 || !slices.Contains([]string{"disabled", "metadata", "full"}, c.Mode) ||
		c.RetentionDays < 1 || c.RetentionDays > 365 || c.MaxContentBytes < 4096 || c.MaxContentBytes > MaxEvidenceObjectBytes ||
		len(c.ApplicationIDs) > 64 || (c.Mode != "disabled" && len(c.ApplicationIDs) == 0) {
		return false
	}
	seen := map[string]bool{}
	for _, id := range c.ApplicationIDs {
		if !evidenceApplicationID.MatchString(id) || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

func privateEvidenceFile(path string, max int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > max {
		return nil, ErrEvidenceUnavailable
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrEvidenceUnavailable
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, ErrEvidenceUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(data)) > max {
		return nil, ErrEvidenceUnavailable
	}
	return data, nil
}

func syncEvidenceDirectory(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func immutableEvidenceFile(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".evidence-*")
	if err != nil {
		return ErrEvidenceUnavailable
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return ErrEvidenceUnavailable
	}
	// Link gives immutable create-if-absent semantics even across processes.
	if err = os.Link(f.Name(), path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrConflict
		}
		return ErrEvidenceUnavailable
	}
	if syncEvidenceDirectory(filepath.Dir(path)) != nil {
		return ErrEvidenceUnavailable
	}
	return nil
}

func OpenEvidence(dir string) (*EvidenceStore, error) {
	vaultDir := filepath.Join(dir, "evidence")
	if err := os.MkdirAll(vaultDir, 0700); err != nil {
		return nil, ErrEvidenceUnavailable
	}
	info, err := os.Lstat(vaultDir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, ErrEvidenceUnavailable
	}
	f, err := os.Open(vaultDir)
	if err != nil {
		return nil, ErrEvidenceUnavailable
	}
	files, err := f.ReadDir(MaxEvidenceRecords*2 + 4)
	f.Close()
	if err != nil && err != io.EOF || len(files) > MaxEvidenceRecords*2+2 {
		return nil, ErrEvidenceUnavailable
	}
	// The process-wide data-directory lock is held by the server before Open.
	// A crash may leave a private temporary ciphertext/config file before its
	// atomic publication. It is not evidence and must not prevent recovery.
	retainedFiles := files[:0]
	for _, file := range files {
		if strings.HasPrefix(file.Name(), ".evidence-") || strings.HasPrefix(file.Name(), ".govweave-") {
			info, err := os.Lstat(filepath.Join(vaultDir, file.Name()))
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > maxEvidenceFileBytes || os.Remove(filepath.Join(vaultDir, file.Name())) != nil {
				return nil, ErrEvidenceUnavailable
			}
			continue
		}
		retainedFiles = append(retainedFiles, file)
	}
	files = retainedFiles
	if len(files) > MaxEvidenceRecords+2 {
		return nil, ErrEvidenceUnavailable
	}
	keyPath := filepath.Join(dir, "evidence.key")
	if _, err := os.Lstat(keyPath); errors.Is(err, os.ErrNotExist) {
		if len(files) != 0 {
			return nil, ErrEvidenceUnavailable
		}
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, ErrEvidenceUnavailable
		}
		if err := immutableEvidenceFile(keyPath, key); err != nil {
			return nil, err
		}
	}
	key, err := privateEvidenceFile(keyPath, 32)
	if err != nil || len(key) != 32 {
		return nil, ErrEvidenceUnavailable
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrEvidenceUnavailable
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrEvidenceUnavailable
	}
	derive := func(purpose string) []byte {
		m := hmac.New(sha256.New, key)
		m.Write([]byte(purpose))
		return m.Sum(nil)
	}
	s := &EvidenceStore{dir: vaultDir, aead: aead, fingerprintKey: derive("evidence-fingerprint-v1"), accessKey: derive("evidence-access-v1"),
		configuration: defaultEvidenceConfig(), entries: map[string]evidenceIndexEntry{}, access: []EvidenceAccess{}, accessDigest: sha256.Sum256(nil), now: time.Now}
	configPath := filepath.Join(vaultDir, "config.json")
	if _, err := os.Lstat(configPath); err == nil {
		data, err := privateEvidenceFile(configPath, 16<<10)
		if err != nil || config.DecodeStrict(bytes.NewReader(data), &s.configuration) != nil || !validEvidenceConfig(s.configuration) {
			return nil, ErrEvidenceUnavailable
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, ErrEvidenceUnavailable
	}
	if err := s.loadAccess(); err != nil {
		return nil, err
	}
	for _, file := range files {
		name := file.Name()
		if name == "config.json" || name == "access.jsonl" {
			continue
		}
		if !strings.HasSuffix(name, ".sealed") || !evidenceIDPattern.MatchString(strings.TrimSuffix(name, ".sealed")) {
			return nil, ErrEvidenceUnavailable
		}
		id := strings.TrimSuffix(name, ".sealed")
		stored, n, err := s.read(id)
		if err != nil || s.bytes+n > MaxEvidenceBytes || len(s.entries) == MaxEvidenceRecords {
			return nil, ErrEvidenceUnavailable
		}
		s.entries[id] = evidenceIndexEntry{summary: stored.Bundle.EvidenceSummary, bytes: n}
		s.bytes += n
	}
	if _, err := s.purgeExpiredLocked("system"); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *EvidenceStore) Config() EvidenceConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneEvidenceConfig(s.configuration)
}

func (s *EvidenceStore) SaveConfig(in EvidenceConfig, gateway Snapshot, actor string) (EvidenceConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validEvidenceConfig(in) || !evidenceActor.MatchString(actor) {
		return EvidenceConfig{}, ErrEvidenceInvalid
	}
	if in.Revision != s.configuration.Revision {
		return EvidenceConfig{}, ErrConflict
	}
	known := map[string]bool{}
	for _, app := range gateway.Applications {
		known[app.ID] = true
	}
	for _, id := range in.ApplicationIDs {
		if !known[id] {
			return EvidenceConfig{}, ErrEvidenceInvalid
		}
	}
	in = cloneEvidenceConfig(in)
	in.Revision++
	slices.Sort(in.ApplicationIDs)
	if err := s.appendAccess(EvidenceAccess{Action: "configuration_change_authorized", Actor: actor, Revision: in.Revision}); err != nil {
		return EvidenceConfig{}, err
	}
	data, _ := json.Marshal(in)
	if storage.AtomicWrite(filepath.Join(s.dir, "config.json"), data) != nil || syncEvidenceDirectory(s.dir) != nil {
		return EvidenceConfig{}, ErrEvidenceUnavailable
	}
	s.configuration = in
	return cloneEvidenceConfig(in), nil
}

func (s *EvidenceStore) fingerprint(applicationID string, data []byte) string {
	m := s.newEvidenceFingerprint(applicationID)
	m.Write(data)
	return hex.EncodeToString(m.Sum(nil))
}

func (s *EvidenceStore) newEvidenceFingerprint(applicationID string) hash.Hash {
	m := hmac.New(sha256.New, s.fingerprintKey)
	m.Write([]byte(applicationID))
	m.Write([]byte{0})
	return m
}

func evidenceKind(kind string) bool {
	return slices.Contains([]string{"request", "upstream_request", "upstream_output", "released_output"}, kind)
}

func evidenceDelivery(state string) bool {
	return slices.Contains([]string{"not_observed", "withheld", "release_prepared", "write_completed", "write_failed", "stream_incomplete"}, state)
}

func (s *EvidenceStore) Capture(record CallRecord, payload EvidencePayload) (EvidenceSummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !payload.Config.Applies(record.ApplicationID) {
		return EvidenceSummary{}, ErrEvidenceDisabled
	}
	if !validEvidenceConfig(payload.Config) || EvidenceID(record.RequestID) == "" || record.SchemaVersion != 1 ||
		len(payload.Objects) > 4 || len(payload.Policies) > 8 || !validTrace(record.Trace) || len(record.Operation) > 100 {
		return EvidenceSummary{}, ErrEvidenceInvalid
	}
	if payload.DeliveryState == "" {
		payload.DeliveryState = "not_observed"
	}
	if !evidenceDelivery(payload.DeliveryState) {
		return EvidenceSummary{}, ErrEvidenceInvalid
	}
	id := EvidenceID(record.RequestID)
	if _, exists := s.entries[id]; exists {
		return EvidenceSummary{}, ErrConflict
	}
	if _, err := s.purgeExpiredLocked("system"); err != nil {
		return EvidenceSummary{}, err
	}
	if len(s.entries) >= MaxEvidenceRecords {
		return EvidenceSummary{}, ErrEvidenceCapacity
	}
	now := s.now().UTC()
	summary := EvidenceSummary{SchemaVersion: 1, ID: id, RequestID: record.RequestID, ApplicationID: record.ApplicationID, Operation: record.Operation,
		CreatedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Duration(payload.Config.RetentionDays) * 24 * time.Hour).Format(time.RFC3339Nano),
		CaptureRevision: payload.Config.Revision, MaxContentBytes: payload.Config.MaxContentBytes, Mode: payload.Config.Mode, AuditCommitted: payload.AuditCommitted, DeliveryState: payload.DeliveryState}
	if record.Trace != nil {
		summary.TraceID = record.Trace.TraceID
	}
	stored := storedEvidence{Bundle: EvidenceBundle{EvidenceSummary: summary, Record: cloneCallRecord(record), Objects: []EvidenceObject{}, Policies: []EvidencePolicySnapshot{}, Integrity: "authenticated"}, Content: map[string][]byte{}}
	seen := map[string]bool{}
	for _, input := range payload.Objects {
		if input.Stream != nil {
			if seen[input.Kind] {
				return EvidenceSummary{}, ErrEvidenceInvalid
			}
			object, content, err := s.streamEvidenceObject(id, record, input, payload.Config)
			if err != nil {
				return EvidenceSummary{}, err
			}
			seen[input.Kind] = true
			if object.ContentState == "retained" {
				stored.Content[object.ID] = content
				stored.Bundle.RetainedBytes += len(content)
			}
			stored.Bundle.Objects = append(stored.Bundle.Objects, object)
			continue
		}
		validMedia := slices.Contains([]string{"application/json", "text/plain"}, input.MediaType) || input.MediaType == "text/event-stream" && input.Data == nil && input.ContentState == "streaming_not_captured"
		if !evidenceKind(input.Kind) || seen[input.Kind] || !validMedia || len(input.Data) > maxResponseBytes {
			return EvidenceSummary{}, ErrEvidenceInvalid
		}
		seen[input.Kind] = true
		object := EvidenceObject{ID: id + ":" + input.Kind, Kind: input.Kind, MediaType: input.MediaType, Bytes: len(input.Data)}
		if input.Data == nil {
			object.ContentState = input.ContentState
			if object.ContentState == "" {
				object.ContentState = "not_observed"
			}
			if !slices.Contains([]string{"not_observed", "streaming_not_captured"}, object.ContentState) {
				return EvidenceSummary{}, ErrEvidenceInvalid
			}
		} else {
			if input.ContentState != "" {
				return EvidenceSummary{}, ErrEvidenceInvalid
			}
			object.Fingerprint = s.fingerprint(record.ApplicationID, input.Data)
			switch {
			case payload.Config.Mode == "metadata":
				object.ContentState = "metadata_only"
			case len(input.Data) > payload.Config.MaxContentBytes:
				object.ContentState = "omitted_size"
			case !utf8.Valid(input.Data):
				object.ContentState = "unsupported_encoding"
			default:
				object.ContentState = "retained"
				stored.Content[object.ID] = bytes.Clone(input.Data)
				stored.Bundle.RetainedBytes += len(input.Data)
			}
		}
		stored.Bundle.Objects = append(stored.Bundle.Objects, object)
	}
	policyBytes := 0
	for _, policy := range payload.Policies {
		policyBytes += len(policy.Snapshot)
		if !slices.Contains([]string{"input", "output", "tool"}, policy.Kind) || len(policy.ID) > 100 || policy.ID == "" ||
			policyBytes > maxEvidencePolicyBytes || !json.Valid(policy.Snapshot) {
			return EvidenceSummary{}, ErrEvidenceInvalid
		}
		policy.Snapshot = bytes.Clone(policy.Snapshot)
		stored.Bundle.Policies = append(stored.Bundle.Policies, policy)
	}
	stored.Bundle.ObjectCount = len(stored.Bundle.Objects)
	plain, err := json.Marshal(stored)
	if err != nil || len(plain)+s.aead.NonceSize()+s.aead.Overhead() > maxEvidenceFileBytes {
		return EvidenceSummary{}, ErrEvidenceCapacity
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return EvidenceSummary{}, ErrEvidenceUnavailable
	}
	sealed := s.aead.Seal(nonce, nonce, plain, []byte(evidenceAAD+id))
	if s.bytes+int64(len(sealed)) > MaxEvidenceBytes {
		return EvidenceSummary{}, ErrEvidenceCapacity
	}
	if err := immutableEvidenceFile(filepath.Join(s.dir, id+".sealed"), sealed); err != nil {
		return EvidenceSummary{}, err
	}
	s.entries[id] = evidenceIndexEntry{summary: stored.Bundle.EvidenceSummary, bytes: int64(len(sealed))}
	s.bytes += int64(len(sealed))
	return stored.Bundle.EvidenceSummary, nil
}

func (s *EvidenceStore) read(id string) (storedEvidence, int64, error) {
	var result storedEvidence
	data, err := privateEvidenceFile(filepath.Join(s.dir, id+".sealed"), maxEvidenceFileBytes)
	if err != nil || len(data) < s.aead.NonceSize()+s.aead.Overhead() {
		return result, 0, ErrEvidenceUnavailable
	}
	plain, err := s.aead.Open(nil, data[:s.aead.NonceSize()], data[s.aead.NonceSize():], []byte(evidenceAAD+id))
	if err != nil || config.DecodeStrict(bytes.NewReader(plain), &result) != nil || !validStoredEvidence(id, result) {
		return storedEvidence{}, 0, ErrEvidenceUnavailable
	}
	for _, object := range result.Bundle.Objects {
		if object.Stream != nil && object.ContentState == "retained" && s.fingerprint(result.Bundle.ApplicationID, result.Content[object.ID]) != object.Fingerprint {
			return storedEvidence{}, 0, ErrEvidenceUnavailable
		}
	}
	return result, int64(len(data)), nil
}

func validStoredEvidence(id string, stored storedEvidence) bool {
	b := stored.Bundle
	created, e1 := time.Parse(time.RFC3339Nano, b.CreatedAt)
	expires, e2 := time.Parse(time.RFC3339Nano, b.ExpiresAt)
	if b.SchemaVersion != 1 || b.ID != id || EvidenceID(b.RequestID) != id || b.ApplicationID != b.Record.ApplicationID || !evidenceApplicationID.MatchString(b.ApplicationID) ||
		b.RequestID != b.Record.RequestID || b.Operation != b.Record.Operation || !validTrace(b.Record.Trace) || !slices.Contains([]string{"metadata", "full"}, b.Mode) ||
		b.MaxContentBytes < 4096 || b.MaxContentBytes > MaxEvidenceObjectBytes ||
		!evidenceDelivery(b.DeliveryState) || e1 != nil || e2 != nil || !expires.After(created) || expires.Sub(created) > 365*24*time.Hour ||
		b.Integrity != "authenticated" || len(b.Objects) > 4 || b.ObjectCount != len(b.Objects) || len(b.Policies) > 8 {
		return false
	}
	if b.Record.Trace != nil && b.TraceID != b.Record.Trace.TraceID || b.Record.Trace == nil && b.TraceID != "" {
		return false
	}
	seen, retained := map[string]bool{}, 0
	for _, o := range b.Objects {
		if !evidenceKind(o.Kind) || o.ID != id+":"+o.Kind || seen[o.ID] {
			return false
		}
		if o.Stream != nil {
			if !validStoredEvidenceStream(o, b) {
				return false
			}
		} else if o.Bytes < 0 || o.Bytes > maxResponseBytes ||
			!(slices.Contains([]string{"application/json", "text/plain"}, o.MediaType) || o.MediaType == "text/event-stream" && o.ContentState == "streaming_not_captured") {
			return false
		}
		seen[o.ID] = true
		content, exists := stored.Content[o.ID]
		if o.ContentState == "retained" {
			if b.Mode != "full" || !exists || len(content) != o.Bytes || len(content) > MaxEvidenceObjectBytes || !utf8.Valid(content) {
				return false
			}
			retained += len(content)
		} else if exists || !slices.Contains([]string{"metadata_only", "omitted_size", "not_observed", "streaming_not_captured", "unsupported_encoding"}, o.ContentState) {
			return false
		}
	}
	for id := range stored.Content {
		if !seen[id] {
			return false
		}
	}
	return retained == b.RetainedBytes
}

func (s *EvidenceStore) lookup(id, applicationID string) (storedEvidence, error) {
	if !evidenceIDPattern.MatchString(id) || !evidenceApplicationID.MatchString(applicationID) {
		return storedEvidence{}, ErrEvidenceNotFound
	}
	entry, exists := s.entries[id]
	if !exists || entry.summary.ApplicationID != applicationID {
		return storedEvidence{}, ErrEvidenceNotFound
	}
	expires, _ := time.Parse(time.RFC3339Nano, entry.summary.ExpiresAt)
	if !s.now().Before(expires) {
		return storedEvidence{}, ErrEvidenceExpired
	}
	stored, n, err := s.read(id)
	if err != nil || n != entry.bytes || !reflect.DeepEqual(stored.Bundle.EvidenceSummary, entry.summary) {
		return storedEvidence{}, ErrEvidenceUnavailable
	}
	return stored, nil
}

func (s *EvidenceStore) Get(id, applicationID string) (EvidenceBundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, err := s.lookup(id, applicationID)
	if err != nil {
		return EvidenceBundle{}, err
	}
	return stored.Bundle, nil
}

func (s *EvidenceStore) list(applicationID, traceID string, limit int) ([]EvidenceSummary, error) {
	if !evidenceApplicationID.MatchString(applicationID) || limit < 1 || limit > 128 || traceID != "" && !traceHex(traceID, 32) {
		return nil, ErrEvidenceInvalid
	}
	result := []EvidenceSummary{}
	now := s.now()
	for _, entry := range s.entries {
		expires, _ := time.Parse(time.RFC3339Nano, entry.summary.ExpiresAt)
		if entry.summary.ApplicationID == applicationID && (traceID == "" || entry.summary.TraceID == traceID) && now.Before(expires) {
			result = append(result, entry.summary)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		first, _ := time.Parse(time.RFC3339Nano, result[i].CreatedAt)
		second, _ := time.Parse(time.RFC3339Nano, result[j].CreatedAt)
		if !first.Equal(second) {
			return first.After(second)
		}
		return result[i].ID > result[j].ID
	})
	if len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

func (s *EvidenceStore) List(applicationID string, limit int) ([]EvidenceSummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.list(applicationID, "", limit)
}

func (s *EvidenceStore) ListTrace(applicationID, traceID string, limit int) ([]EvidenceSummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !traceHex(traceID, 32) {
		return nil, ErrEvidenceInvalid
	}
	return s.list(applicationID, traceID, limit)
}

func (s *EvidenceStore) Reveal(id, applicationID, objectID, view, reason, actor string) (EvidenceContent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !slices.Contains([]string{"raw", "redacted"}, view) || !slices.Contains([]string{"incident_review", "validation"}, reason) || !evidenceActor.MatchString(actor) {
		return EvidenceContent{}, ErrEvidenceInvalid
	}
	stored, err := s.lookup(id, applicationID)
	if err != nil {
		return EvidenceContent{}, err
	}
	content, exists := stored.Content[objectID]
	if !exists {
		return EvidenceContent{}, ErrEvidenceContentUnavailable
	}
	if err := s.appendAccess(EvidenceAccess{Action: "reveal_authorized", Actor: actor, EvidenceID: id, ApplicationID: applicationID, ObjectID: objectID, View: view, Reason: reason}); err != nil {
		return EvidenceContent{}, err
	}
	result := EvidenceContent{EvidenceID: id, ObjectID: objectID, View: view, Text: string(content), RedactionState: "raw"}
	if view == "redacted" {
		result.Text, result.RedactionState = evidencePreview(content)
	}
	return result, nil
}

// Preview covers the shipped finite patterns only, not general anonymization.
// Incomplete scans and any credential pattern with potentially partial spans
// cause the entire object to be withheld. Encoded/unknown PII can still escape
// the supported detector, so previews require the same privileged access audit.
func evidencePreview(content []byte) (string, string) {
	result := sensitive.Scan(content, "sensitive-text-v3")
	if result.State == "unknown" || result.Truncated {
		return "[CONTENT WITHHELD: preview coverage unavailable]", "withheld"
	}
	for _, finding := range result.Findings {
		if finding.Category == "credential" {
			return "[CONTENT WITHHELD: credential pattern]", "withheld"
		}
	}
	spans := make([]redactionSpan, 0, len(result.Findings))
	for _, finding := range result.Findings {
		if finding.StartByte < 0 || finding.EndByte <= finding.StartByte || finding.EndByte > len(content) {
			return "[CONTENT WITHHELD: preview coverage unavailable]", "withheld"
		}
		spans = append(spans, redactionSpan{finding.StartByte, finding.EndByte})
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	var text strings.Builder
	previous := 0
	for _, span := range spans {
		if span.start < previous {
			if span.end > previous {
				previous = span.end
			}
			continue
		}
		text.Write(content[previous:span.start])
		text.WriteString("[REDACTED]")
		previous = span.end
	}
	text.Write(content[previous:])
	return text.String(), "pattern_limited"
}

func (s *EvidenceStore) accessMAC(event EvidenceAccess) string {
	data, _ := json.Marshal(event)
	m := hmac.New(sha256.New, s.accessKey)
	m.Write(data)
	return hex.EncodeToString(m.Sum(nil))
}

func (s *EvidenceStore) loadAccess() error {
	path := filepath.Join(s.dir, "access.jsonl")
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	data, err := privateEvidenceFile(path, MaxEvidenceAccessBytes)
	if err != nil || len(data) > 0 && data[len(data)-1] != '\n' {
		return ErrEvidenceUnavailable
	}
	s.accessBytes = int64(len(data))
	s.accessDigest = sha256.Sum256(data)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 1024), 2048)
	for scanner.Scan() {
		var event storedEvidenceAccess
		if config.DecodeStrict(bytes.NewReader(scanner.Bytes()), &event) != nil || event.SchemaVersion != 1 || !hmac.Equal([]byte(event.MAC), []byte(s.accessMAC(event.EvidenceAccess))) {
			return ErrEvidenceUnavailable
		}
		s.rememberAccess(event.EvidenceAccess)
	}
	if scanner.Err() != nil {
		return ErrEvidenceUnavailable
	}
	return nil
}

func (s *EvidenceStore) rememberAccess(event EvidenceAccess) {
	s.access = append(s.access, event)
	if len(s.access) > 128 {
		s.access = s.access[len(s.access)-128:]
	}
}

func (s *EvidenceStore) appendAccess(event EvidenceAccess) error {
	if s.accessFailed {
		return ErrEvidenceUnavailable
	}
	event.SchemaVersion = 1
	event.Timestamp = s.now().UTC().Format(time.RFC3339Nano)
	data, _ := json.Marshal(storedEvidenceAccess{EvidenceAccess: event, MAC: s.accessMAC(event)})
	data = append(data, '\n')
	if s.accessBytes+int64(len(data)) > MaxEvidenceAccessBytes {
		return ErrEvidenceCapacity
	}
	previous, err := s.checkAccess()
	if err != nil {
		return err
	}
	path := filepath.Join(s.dir, "access.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		s.accessFailed = true
		return ErrEvidenceUnavailable
	}
	n, err := f.Write(data)
	if err == nil && n == len(data) {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil || n != len(data) {
		s.accessFailed = true
		return ErrEvidenceUnavailable
	}
	s.accessBytes += int64(n)
	h := sha256.New()
	h.Write(previous)
	h.Write(data)
	copy(s.accessDigest[:], h.Sum(nil))
	s.rememberAccess(event)
	return nil
}

func (s *EvidenceStore) checkAccess() ([]byte, error) {
	if s.accessFailed {
		return nil, ErrEvidenceUnavailable
	}
	path := filepath.Join(s.dir, "access.jsonl")
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) && s.accessBytes == 0 {
		return nil, nil
	}
	data, err := privateEvidenceFile(path, MaxEvidenceAccessBytes)
	if err != nil || int64(len(data)) != s.accessBytes || sha256.Sum256(data) != s.accessDigest {
		s.accessFailed = true
		return nil, ErrEvidenceUnavailable
	}
	return data, nil
}

func (s *EvidenceStore) AccessLog(limit int) ([]EvidenceAccess, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit < 1 || limit > 128 {
		return nil, ErrEvidenceInvalid
	}
	if _, err := s.checkAccess(); err != nil {
		return nil, err
	}
	result := []EvidenceAccess{}
	for i := len(s.access) - 1; i >= 0 && len(result) < limit; i-- {
		result = append(result, s.access[i])
	}
	return result, nil
}

func (s *EvidenceStore) purgeExpiredLocked(actor string) (int, error) {
	if !evidenceActor.MatchString(actor) {
		return 0, ErrEvidenceInvalid
	}
	ids := []string{}
	for id, entry := range s.entries {
		expires, _ := time.Parse(time.RFC3339Nano, entry.summary.ExpiresAt)
		if !s.now().Before(expires) {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	deleted := 0
	for _, id := range ids {
		entry := s.entries[id]
		if err := s.appendAccess(EvidenceAccess{Action: "expiry_deletion_authorized", Actor: actor, EvidenceID: id, ApplicationID: entry.summary.ApplicationID}); err != nil {
			return deleted, err
		}
		if os.Remove(filepath.Join(s.dir, id+".sealed")) != nil || syncEvidenceDirectory(s.dir) != nil {
			return deleted, ErrEvidenceUnavailable
		}
		delete(s.entries, id)
		s.bytes -= entry.bytes
		deleted++
	}
	return deleted, nil
}

func (s *EvidenceStore) PurgeExpired(actor string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.purgeExpiredLocked(actor)
}
