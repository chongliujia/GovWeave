package gateway

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const AuditMaxBytes int64 = 128 << 20
const maxAuditEventBytes int64 = 4096
const recentRequestLimit = 1000

var ErrAuditUnavailable = errors.New("audit_unavailable")

// CallRecord intentionally has no generic metadata or body fields. Never add
// prompts, responses, credentials, arbitrary headers, URLs or raw error strings.
type CallRecord struct {
	SchemaVersion     int               `json:"schema_version"`
	RequestID         string            `json:"request_id"`
	Phase             string            `json:"phase"`
	StartedAt         string            `json:"started_at"`
	Timestamp         string            `json:"timestamp"`
	Operation         string            `json:"operation"`
	ApplicationID     string            `json:"application_id,omitempty"`
	ConnectionID      string            `json:"connection_id,omitempty"`
	Model             string            `json:"model,omitempty"`
	PolicyRevision    uint64            `json:"policy_revision"`
	Decision          string            `json:"decision"`
	Outcome           string            `json:"outcome"`
	HTTPStatus        int               `json:"http_status"`
	UpstreamStatus    int               `json:"upstream_status,omitempty"`
	UpstreamAttempted bool              `json:"upstream_attempted"`
	Streaming         bool              `json:"streaming"`
	DurationMS        int64             `json:"duration_ms"`
	FirstByteMS       *int64            `json:"first_byte_ms,omitempty"`
	ErrorCode         string            `json:"error_code,omitempty"`
	ContentPolicy     *PolicyAssessment `json:"content_policy,omitempty"`
}

type Audit struct {
	mu       sync.Mutex
	file     *os.File
	size     int64
	reserved int64
	failed   bool
	recent   []CallRecord
	pending  map[string]bool
}

type AuditView struct {
	Available bool         `json:"available"`
	Bytes     int64        `json:"bytes"`
	MaxBytes  int64        `json:"max_bytes"`
	Records   []CallRecord `json:"records"`
}

func OpenAudit(dir string) (*Audit, error) {
	f, err := os.OpenFile(filepath.Join(dir, "calls.jsonl"), os.O_CREATE|os.O_APPEND|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	a := &Audit{file: f, pending: map[string]bool{}, recent: []CallRecord{}}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		f.Close()
		return nil, errors.New("calls.jsonl must be a private regular file")
	}
	if info.Size() > AuditMaxBytes {
		f.Close()
		return nil, errors.New("audit file exceeds 128 MiB; archive it while the service is stopped")
	}
	a.size = info.Size()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), int(maxAuditEventBytes))
	for scanner.Scan() {
		var record CallRecord
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil || record.SchemaVersion != 1 || record.RequestID == "" || (record.Phase != "started" && record.Phase != "finished") {
			f.Close()
			return nil, errors.New("invalid audit log; restore or repair it before starting")
		}
		a.remember(record)
	}
	if err := scanner.Err(); err != nil {
		f.Close()
		return nil, errors.New("cannot read audit log")
	}
	for i := range a.recent {
		if a.recent[i].Phase == "started" {
			a.recent[i].Outcome = "incomplete"
		}
	}
	// A partial final line must not be merged into the next event after a crash.
	if a.size > 0 {
		last := make([]byte, 1)
		if _, err := f.ReadAt(last, a.size-1); err != nil || last[0] != '\n' {
			f.Close()
			return nil, errors.New("incomplete final audit line; repair or archive it before starting")
		}
	}
	return a, nil
}

func (a *Audit) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.failed = true
	return a.file.Close()
}

func (a *Audit) remember(record CallRecord) {
	for i := len(a.recent) - 1; i >= 0; i-- {
		if a.recent[i].RequestID == record.RequestID {
			a.recent[i] = record
			return
		}
	}
	a.recent = append(a.recent, record)
	if len(a.recent) > recentRequestLimit {
		copy(a.recent, a.recent[len(a.recent)-recentRequestLimit:])
		a.recent = a.recent[:recentRequestLimit]
	}
}

func (a *Audit) append(record CallRecord) error {
	if a.failed {
		return ErrAuditUnavailable
	}
	record.SchemaVersion = 1
	record.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	data, err := json.Marshal(record)
	if err != nil || int64(len(data)+1) > maxAuditEventBytes {
		return ErrAuditUnavailable
	}
	data = append(data, '\n')
	if a.size+int64(len(data)) > AuditMaxBytes {
		return ErrAuditUnavailable
	}
	n, err := a.file.Write(data)
	a.size += int64(n)
	if err == nil {
		err = a.file.Sync()
	}
	if err != nil || n != len(data) {
		a.failed = true
		return ErrAuditUnavailable
	}
	a.remember(record)
	return nil
}

// Begin must succeed before any upstream I/O. Reserve enough space for Finish.
func (a *Audit) Begin(record CallRecord) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failed || a.size+a.reserved+2*maxAuditEventBytes > AuditMaxBytes {
		return ErrAuditUnavailable
	}
	record.Phase, record.Outcome = "started", "in_progress"
	if err := a.append(record); err != nil {
		return err
	}
	a.pending[record.RequestID] = true
	a.reserved += maxAuditEventBytes
	return nil
}

func (a *Audit) Finish(record CallRecord) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pending[record.RequestID] {
		delete(a.pending, record.RequestID)
		a.reserved -= maxAuditEventBytes
	} else if a.size+a.reserved+maxAuditEventBytes > AuditMaxBytes {
		return ErrAuditUnavailable
	}
	record.Phase = "finished"
	return a.append(record)
}

func (a *Audit) View(limit int, applicationID string) AuditView {
	a.mu.Lock()
	defer a.mu.Unlock()
	if limit < 1 || limit > 100 {
		limit = 100
	}
	v := AuditView{Available: !a.failed && a.size+a.reserved+2*maxAuditEventBytes <= AuditMaxBytes, Bytes: a.size, MaxBytes: AuditMaxBytes, Records: []CallRecord{}}
	for i := len(a.recent) - 1; i >= 0 && len(v.Records) < limit; i-- {
		if applicationID == "" || a.recent[i].ApplicationID == applicationID {
			v.Records = append(v.Records, a.recent[i])
		}
	}
	return v
}
