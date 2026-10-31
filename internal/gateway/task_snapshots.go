package gateway

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"govweave/internal/config"
	"govweave/internal/storage"
)

const MaxTaskSnapshots = 256
const MaxTaskSnapshotBytes = 2 << 20
const MaxTaskSnapshotStoreBytes int64 = 64 << 20

var ErrTaskSnapshotChanged = errors.New("task_view_changed")
var ErrTaskSnapshotBusy = errors.New("task_snapshot_busy")
var taskSnapshotID = regexp.MustCompile(`^tsk_[A-Za-z0-9_-]{22}$`)
var taskDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

type TaskSnapshot struct {
	SchemaVersion int               `json:"schema_version"`
	ID            string            `json:"id"`
	CreatedAt     string            `json:"created_at"`
	CreatedBy     string            `json:"created_by"`
	View          EvidenceTraceView `json:"view"`
}

type TaskSnapshotSummary struct {
	ID             string   `json:"id"`
	CreatedAt      string   `json:"created_at"`
	TraceID        string   `json:"trace_id"`
	ApplicationIDs []string `json:"application_ids"`
	Calls          int      `json:"calls"`
	Bytes          int64    `json:"bytes"`
	SHA256         string   `json:"sha256"`
}

type ArchivedTaskEvidence struct {
	Summary   TaskSnapshotSummary `json:"summary"`
	Snapshot  TaskSnapshot        `json:"snapshot"`
	Integrity string              `json:"integrity"`
}

type taskSnapshotEntry struct {
	summary TaskSnapshotSummary
	bytes   int64
}

type storedTaskSnapshot struct {
	Snapshot json.RawMessage `json:"snapshot"`
	MAC      string          `json:"mac"`
}

// Metadata archives have independent capacity and lifetime from content
// captures. The local MAC detects edits without the key, not whole-file loss.
type TaskSnapshotStore struct {
	mu      sync.RWMutex
	dir     string
	key     []byte
	entries map[string]taskSnapshotEntry
	bytes   int64
	slots   chan struct{}
}

func openTaskSnapshots(dir string, evidenceAccessKey []byte) (*TaskSnapshotStore, error) {
	if len(evidenceAccessKey) != sha256.Size {
		return nil, ErrEvidenceUnavailable
	}
	derive := hmac.New(sha256.New, evidenceAccessKey)
	derive.Write([]byte("govweave-task-snapshots-v1"))
	s := &TaskSnapshotStore{dir: filepath.Join(dir, "task-evidence"), key: derive.Sum(nil), entries: map[string]taskSnapshotEntry{}, slots: make(chan struct{}, 4)}
	info, err := os.Lstat(s.dir)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, ErrEvidenceUnavailable
	}
	f, err := os.Open(s.dir)
	if err != nil {
		return nil, ErrEvidenceUnavailable
	}
	defer f.Close()
	files, err := f.ReadDir(MaxTaskSnapshots*2 + 1)
	if (err != nil && err != io.EOF) || len(files) > MaxTaskSnapshots*2 {
		return nil, ErrEvidenceCapacity
	}
	for _, file := range files {
		if strings.HasPrefix(file.Name(), ".evidence-") {
			continue // An interrupted immutable write can leave a private temp file.
		}
		id := strings.TrimSuffix(file.Name(), ".json")
		if !strings.HasSuffix(file.Name(), ".json") || !taskSnapshotID.MatchString(id) || len(s.entries) >= MaxTaskSnapshots {
			return nil, ErrEvidenceUnavailable
		}
		value, size, err := s.read(id)
		if err != nil {
			return nil, err
		}
		if s.bytes+size > MaxTaskSnapshotStoreBytes {
			return nil, ErrEvidenceCapacity
		}
		s.entries[id] = taskSnapshotEntry{value.Summary, size}
		s.bytes += size
	}
	return s, nil
}

func (s *TaskSnapshotStore) mac(data []byte) string {
	m := hmac.New(sha256.New, s.key)
	m.Write(data)
	return hex.EncodeToString(m.Sum(nil))
}

func taskSnapshotJSON(v TaskSnapshot) []byte {
	data, _ := json.Marshal(v)
	return append(data, '\n')
}

func taskSnapshotSummary(v TaskSnapshot) TaskSnapshotSummary {
	data := taskSnapshotJSON(v)
	digest := sha256.Sum256(data)
	return TaskSnapshotSummary{ID: v.ID, CreatedAt: v.CreatedAt, TraceID: v.View.TraceID, ApplicationIDs: slices.Clone(v.View.ApplicationIDs), Calls: len(v.View.Calls), Bytes: int64(len(data)), SHA256: hex.EncodeToString(digest[:])}
}

func validTaskSnapshot(v TaskSnapshot) bool {
	view := v.View
	if v.SchemaVersion != 1 || !taskSnapshotID.MatchString(v.ID) || !evidenceActor.MatchString(v.CreatedBy) || view.SchemaVersion != 1 ||
		!validEvidenceTraceScope(view.TraceID, view.ApplicationIDs, view.CallLimit) || !slices.IsSorted(view.ApplicationIDs) ||
		view.EvidenceLimit != min(view.CallLimit, maxEvidenceTraceCaptures) || view.Scope != "selected_applications" ||
		view.Coverage != "retained_evidence_and_recent_audit" || view.FindingCoverage != "retained_evidence_only" ||
		view.TaskCompletion != "not_determined" || !view.HistoryMayBeMissing || view.GraphComplete ||
		view.Calls == nil || view.Edges == nil || len(view.Calls) > view.CallLimit || len(view.Edges) > maxTraceRecords*6 ||
		view.ViewSHA256 != evidenceTraceDigest(view) {
		return false
	}
	if _, err := time.Parse(time.RFC3339Nano, v.CreatedAt); err != nil {
		return false
	}
	seen := map[string]bool{}
	for _, row := range view.Calls {
		if !evidenceRequestID.MatchString(row.RequestID) || seen[row.RequestID] || !slices.Contains(view.ApplicationIDs, row.ApplicationID) || row.Findings == nil {
			return false
		}
		seen[row.RequestID] = true
		if row.Record != nil && (row.Record.RequestID != row.RequestID || row.Record.ApplicationID != row.ApplicationID || row.Record.Trace == nil || row.Record.Trace.TraceID != view.TraceID) {
			return false
		}
		if row.RecordSource == "evidence_index" {
			if row.Record != nil || row.EvidenceState != "unavailable" {
				return false
			}
		} else if row.Record == nil || !slices.Contains([]string{"recent_audit", "retained_evidence"}, row.RecordSource) {
			return false
		}
		if row.EvidenceState == "retained" {
			if row.RecordSource != "retained_evidence" {
				return false
			}
		} else if len(row.Findings) != 0 || row.RecordSource == "retained_evidence" {
			return false
		}
		switch row.EvidenceState {
		case "retained", "not_loaded", "unavailable":
			if row.EvidenceID != EvidenceID(row.RequestID) || row.EvidenceState == "not_loaded" && row.RecordSource != "recent_audit" {
				return false
			}
		case "not_found":
			if row.EvidenceID != "" || row.RecordSource != "recent_audit" {
				return false
			}
		default:
			return false
		}
	}
	calculated := view
	calculated.Summary, calculated.Edges = EvidenceTraceSummary{}, []EvidenceTraceEdge{}
	calculated.summarize()
	return calculated.Summary == view.Summary && reflect.DeepEqual(calculated.Edges, view.Edges)
}

func (s *TaskSnapshotStore) read(id string) (ArchivedTaskEvidence, int64, error) {
	data, err := privateEvidenceFile(filepath.Join(s.dir, id+".json"), MaxTaskSnapshotBytes)
	var wire storedTaskSnapshot
	if err != nil || config.DecodeStrict(bytes.NewReader(data), &wire) != nil || !hmac.Equal([]byte(wire.MAC), []byte(s.mac(wire.Snapshot))) {
		return ArchivedTaskEvidence{}, 0, ErrEvidenceUnavailable
	}
	var snapshot TaskSnapshot
	if config.DecodeStrict(bytes.NewReader(wire.Snapshot), &snapshot) != nil || snapshot.ID != id || !validTaskSnapshot(snapshot) {
		return ArchivedTaskEvidence{}, 0, ErrEvidenceUnavailable
	}
	return ArchivedTaskEvidence{taskSnapshotSummary(snapshot), snapshot, "authenticated_local"}, int64(len(data)), nil
}

// Creation always uses a freshly observed server view, never client-submitted
// call records. The expected digest prevents silently archiving another view.
func (g *Engine) CreateTaskSnapshot(traceID string, ids []string, limit int, expected, actor string) (ArchivedTaskEvidence, error) {
	if !validEvidenceTraceScope(traceID, ids, limit) || !taskDigest.MatchString(expected) || !evidenceActor.MatchString(actor) {
		return ArchivedTaskEvidence{}, ErrEvidenceInvalid
	}
	s := g.TaskSnapshots
	if s == nil {
		return ArchivedTaskEvidence{}, ErrEvidenceUnavailable
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		return ArchivedTaskEvidence{}, ErrTaskSnapshotBusy
	}
	view, err := g.EvidenceTraceView(traceID, ids, limit)
	if err != nil {
		return ArchivedTaskEvidence{}, err
	}
	if view.ViewSHA256 != expected {
		return ArchivedTaskEvidence{}, ErrTaskSnapshotChanged
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.entries) >= MaxTaskSnapshots {
		return ArchivedTaskEvidence{}, ErrEvidenceCapacity
	}
	id, err := storage.ID("tsk_", 16)
	if err != nil {
		return ArchivedTaskEvidence{}, ErrEvidenceUnavailable
	}
	snapshot := TaskSnapshot{1, id, time.Now().UTC().Format(time.RFC3339Nano), actor, view}
	if !validTaskSnapshot(snapshot) {
		return ArchivedTaskEvidence{}, ErrEvidenceUnavailable
	}
	payload, _ := json.Marshal(snapshot)
	data, err := json.Marshal(storedTaskSnapshot{payload, s.mac(payload)})
	if err != nil || len(data) > MaxTaskSnapshotBytes || s.bytes+int64(len(data)) > MaxTaskSnapshotStoreBytes {
		return ArchivedTaskEvidence{}, ErrEvidenceCapacity
	}
	if os.MkdirAll(s.dir, 0700) != nil {
		return ArchivedTaskEvidence{}, ErrEvidenceUnavailable
	}
	info, err := os.Lstat(s.dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return ArchivedTaskEvidence{}, ErrEvidenceUnavailable
	}
	if err := immutableEvidenceFile(filepath.Join(s.dir, id+".json"), data); err != nil {
		return ArchivedTaskEvidence{}, err
	}
	summary := taskSnapshotSummary(snapshot)
	s.entries[id] = taskSnapshotEntry{summary, int64(len(data))}
	s.bytes += int64(len(data))
	// Detach the response from index slices and any future in-process mutation.
	var saved TaskSnapshot
	_ = json.Unmarshal(payload, &saved)
	return ArchivedTaskEvidence{taskSnapshotSummary(saved), saved, "authenticated_local"}, nil
}

// List requires the exact trace and application set, not overlap or a subset.
func (s *TaskSnapshotStore) List(traceID string, ids []string) ([]TaskSnapshotSummary, error) {
	if !validEvidenceTraceScope(traceID, ids, 128) {
		return nil, ErrEvidenceInvalid
	}
	ids = slices.Clone(ids)
	slices.Sort(ids)
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := []TaskSnapshotSummary{}
	for _, entry := range s.entries {
		v := entry.summary
		if v.TraceID == traceID && slices.Equal(v.ApplicationIDs, ids) {
			v.ApplicationIDs = slices.Clone(v.ApplicationIDs)
			result = append(result, v)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		a, _ := time.Parse(time.RFC3339Nano, result[i].CreatedAt)
		b, _ := time.Parse(time.RFC3339Nano, result[j].CreatedAt)
		if a.Equal(b) {
			return result[i].ID > result[j].ID
		}
		return a.After(b)
	})
	return result, nil
}

func (s *TaskSnapshotStore) Get(id, traceID string, ids []string) (ArchivedTaskEvidence, error) {
	if !taskSnapshotID.MatchString(id) || !validEvidenceTraceScope(traceID, ids, 128) {
		return ArchivedTaskEvidence{}, ErrEvidenceInvalid
	}
	ids = slices.Clone(ids)
	slices.Sort(ids)
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		return ArchivedTaskEvidence{}, ErrTaskSnapshotBusy
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.entries[id]
	if !ok || entry.summary.TraceID != traceID || !slices.Equal(entry.summary.ApplicationIDs, ids) {
		return ArchivedTaskEvidence{}, ErrEvidenceNotFound
	}
	v, size, err := s.read(id)
	if err != nil || size != entry.bytes || !reflect.DeepEqual(v.Summary, entry.summary) {
		return ArchivedTaskEvidence{}, ErrEvidenceUnavailable
	}
	return v, nil
}

// JSON export is exactly the bytes covered by summary.sha256 and summary.bytes.
func (v ArchivedTaskEvidence) JSON() []byte { return taskSnapshotJSON(v.Snapshot) }
