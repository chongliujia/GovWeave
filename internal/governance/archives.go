package governance

import (
	"bytes"
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

	"govweave/internal/compliance"
	"govweave/internal/config"
	"govweave/internal/gateway"
	"govweave/internal/storage"
)

const MaxArchivedReports = 256
const MaxArchivedReportBytes = 1 << 20
const MaxArchiveBytes int64 = 64 << 20

var ErrArchiveCapacity = errors.New("report archive capacity reached; existing snapshots are retained")
var ErrArchiveBusy = errors.New("the concurrent report archive limit has been reached")
var ErrArchiveUnavailable = errors.New("the saved report is unavailable, invalid or changed")
var ErrAssessmentUnavailable = errors.New("a ready assessment is required to archive a report")
var ErrReplayVersion = errors.New("this evaluator version cannot replay the saved report")

var reportIDPattern = regexp.MustCompile(`^rpt_[A-Za-z0-9_-]{22}$`)

type ReportSnapshot struct {
	SchemaVersion int              `json:"schema_version"`
	ID            string           `json:"id"`
	CreatedAt     string           `json:"created_at"`
	Product       Product          `json:"product"`
	RulePack      compliance.Pack  `json:"rule_pack"`
	Input         compliance.Input `json:"input"`
	Report        Report           `json:"report"`
}

type ReportSummary struct {
	ID              string `json:"id"`
	CreatedAt       string `json:"created_at"`
	ProductID       string `json:"product_id"`
	ProductVersion  string `json:"product_version"`
	ProductRevision uint64 `json:"product_revision"`
	PackID          string `json:"pack_id"`
	PackVersion     string `json:"pack_version"`
	PackSHA256      string `json:"pack_sha256"`
	Status          string `json:"status"`
	Bytes           int64  `json:"bytes"`
	SHA256          string `json:"sha256"`
}

type ArchivedReport struct {
	Summary  ReportSummary  `json:"summary"`
	Snapshot ReportSnapshot `json:"snapshot"`
}

type ReplayResult struct {
	ReportID   string                `json:"report_id"`
	Matches    bool                  `json:"matches"`
	Evaluation compliance.Evaluation `json:"evaluation"`
}

type Archives struct {
	mu      sync.RWMutex
	dir     string
	entries map[string]ReportSummary
	bytes   int64
	slots   chan struct{}
}

func openArchives(dir string) (*Archives, error) {
	a := &Archives{dir: filepath.Join(dir, "assessment-reports"), entries: map[string]ReportSummary{}, slots: make(chan struct{}, 8)}
	info, err := os.Lstat(a.dir)
	if errors.Is(err, os.ErrNotExist) {
		return a, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, ErrArchiveUnavailable
	}
	f, err := os.Open(a.dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(MaxArchivedReports*2 + 1)
	if (err != nil && err != io.EOF) || len(entries) > MaxArchivedReports*2 {
		return nil, ErrArchiveUnavailable
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		if !reportIDPattern.MatchString(id) || len(a.entries) >= MaxArchivedReports {
			return nil, ErrArchiveUnavailable
		}
		snapshot, data, err := readSnapshot(filepath.Join(a.dir, entry.Name()))
		if err != nil || snapshot.ID != id {
			return nil, ErrArchiveUnavailable
		}
		summary := summarize(snapshot, data)
		if a.bytes+summary.Bytes > MaxArchiveBytes {
			return nil, ErrArchiveCapacity
		}
		a.entries[id] = summary
		a.bytes += summary.Bytes
	}
	return a, nil
}

func summarize(snapshot ReportSnapshot, data []byte) ReportSummary {
	digest := sha256.Sum256(data)
	return ReportSummary{ID: snapshot.ID, CreatedAt: snapshot.CreatedAt, ProductID: snapshot.Product.ID, ProductVersion: snapshot.Product.Version, ProductRevision: snapshot.Product.Revision, PackID: snapshot.RulePack.ID, PackVersion: snapshot.RulePack.Version, PackSHA256: snapshot.Report.Evaluation.PackSHA256, Status: snapshot.Report.Evaluation.Status, Bytes: int64(len(data)), SHA256: hex.EncodeToString(digest[:])}
}

func validateSnapshot(snapshot ReportSnapshot) error {
	if snapshot.SchemaVersion != 1 || !reportIDPattern.MatchString(snapshot.ID) || snapshot.Product.SchemaVersion != 1 || snapshot.Product.Revision == 0 {
		return ErrArchiveUnavailable
	}
	if _, err := time.Parse(time.RFC3339Nano, snapshot.CreatedAt); err != nil {
		return ErrArchiveUnavailable
	}
	if err := validateProduct(snapshot.Product.ProductInput); err != nil {
		return ErrArchiveUnavailable
	}
	if err := compliance.ValidatePack(snapshot.RulePack); err != nil {
		return ErrArchiveUnavailable
	}
	if err := compliance.ValidateInput(snapshot.Input); err != nil {
		return ErrArchiveUnavailable
	}
	r := snapshot.Report
	e := r.Evaluation
	in := snapshot.Input
	p := snapshot.Product
	if r.SchemaVersion != 1 || r.State != "ready" || e == nil || r.Snapshot == nil || r.ProductID != p.ID || r.ProductRevision != p.Revision || r.Snapshot.ProductRevision != p.Revision || in.ProductID != p.ID || in.ProductVersion != p.Version || in.PackID != p.PackID || in.PackVersion != p.PackVersion || snapshot.RulePack.ID != p.PackID || snapshot.RulePack.Version != p.PackVersion {
		return ErrArchiveUnavailable
	}
	if !e.EvaluationOnly || e.SchemaVersion != 1 || e.LegalCompliance != "not_determined" || e.ProductID != p.ID || e.ProductVersion != p.Version || !identifier.MatchString(e.EngineVersion) || e.PackReview != snapshot.RulePack.Review.Status || !slices.Contains([]string{"satisfied", "gaps_detected", "insufficient_evidence", "not_applicable"}, e.Status) || len(e.Controls) != len(snapshot.RulePack.Controls) || r.SampleLimit != SampleLimit {
		return ErrArchiveUnavailable
	}
	for key, fact := range in.Facts {
		if slices.Contains([]string{"testing.output.pre_deployment.passed", "testing.output.operation.passed", "testing.tools.output.pre_deployment.passed", "testing.tools.output.operation.passed"}, key) {
			var passed bool
			if fact.Source != "assessment" || !testRunID.MatchString(fact.EvidenceID) || fact.ExpiresAt == "" || (string(fact.Value) != "true" && string(fact.Value) != "false") || json.Unmarshal(fact.Value, &passed) != nil {
				return ErrArchiveUnavailable
			}
			continue
		}
		if strings.HasPrefix(key, "runtime.") {
			if fact.Source != "runtime" {
				return ErrArchiveUnavailable
			}
			continue
		}
		profileFact, ok := p.Facts[key]
		if !ok || !reflect.DeepEqual(profileFact, fact) {
			return ErrArchiveUnavailable
		}
	}
	for key := range p.Facts {
		if _, ok := in.Facts[key]; !ok {
			return ErrArchiveUnavailable
		}
	}
	packJSON, _ := json.Marshal(snapshot.RulePack)
	digest := sha256.Sum256(packJSON)
	if e.PackID != p.PackID || e.PackVersion != p.PackVersion || e.PackSHA256 != hex.EncodeToString(digest[:]) {
		return ErrArchiveUnavailable
	}
	at, err := time.Parse(time.RFC3339Nano, e.EvaluatedAt)
	if err != nil {
		return ErrArchiveUnavailable
	}
	if e.EngineVersion == compliance.EngineVersion {
		replay, err := compliance.EvaluateSnapshot(snapshot.RulePack, in, at)
		if err != nil || !reflect.DeepEqual(replay, *e) {
			return ErrArchiveUnavailable
		}
	}
	return validateRuntimeEvidence(r.RuntimeEvidence, snapshot)
}

func readSnapshot(path string) (ReportSnapshot, []byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > MaxArchivedReportBytes {
		return ReportSnapshot{}, nil, ErrArchiveUnavailable
	}
	f, err := os.Open(path)
	if err != nil {
		return ReportSnapshot{}, nil, ErrArchiveUnavailable
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxArchivedReportBytes+1))
	if err != nil || len(data) > MaxArchivedReportBytes {
		return ReportSnapshot{}, nil, ErrArchiveUnavailable
	}
	var snapshot ReportSnapshot
	if config.DecodeStrict(bytes.NewReader(data), &snapshot) != nil || validateSnapshot(snapshot) != nil {
		return ReportSnapshot{}, nil, ErrArchiveUnavailable
	}
	return snapshot, data, nil
}

func (a *Archives) save(snapshot ReportSnapshot) (ArchivedReport, error) {
	select {
	case a.slots <- struct{}{}:
		defer func() { <-a.slots }()
	default:
		return ArchivedReport{}, ErrArchiveBusy
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.entries) >= MaxArchivedReports {
		return ArchivedReport{}, ErrArchiveCapacity
	}
	id, err := storage.ID("rpt_", 16)
	if err != nil {
		return ArchivedReport{}, gateway.ErrPersistence
	}
	if _, exists := a.entries[id]; exists {
		return ArchivedReport{}, gateway.ErrPersistence
	}
	snapshot.ID = id
	snapshot.SchemaVersion = 1
	snapshot.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := validateSnapshot(snapshot); err != nil {
		return ArchivedReport{}, err
	}
	data, err := json.MarshalIndent(snapshot, "", "  ")
	data = append(data, '\n')
	if err != nil {
		return ArchivedReport{}, gateway.ErrPersistence
	}
	if len(data) > MaxArchivedReportBytes || a.bytes+int64(len(data)) > MaxArchiveBytes {
		return ArchivedReport{}, ErrArchiveCapacity
	}
	if err := os.MkdirAll(a.dir, 0700); err != nil {
		return ArchivedReport{}, gateway.ErrPersistence
	}
	info, err := os.Lstat(a.dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return ArchivedReport{}, ErrArchiveUnavailable
	}
	path := filepath.Join(a.dir, id+".json")
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return ArchivedReport{}, ErrArchiveUnavailable
	}
	if storage.AtomicWrite(path, data) != nil {
		return ArchivedReport{}, gateway.ErrPersistence
	}
	summary := summarize(snapshot, data)
	a.entries[id] = summary
	a.bytes += summary.Bytes
	// Decode the exact committed bytes to return an independently owned value.
	var saved ReportSnapshot
	_ = json.Unmarshal(data, &saved)
	return ArchivedReport{Summary: summary, Snapshot: saved}, nil
}

func (a *Archives) List(productID string) []ReportSummary {
	a.mu.RLock()
	defer a.mu.RUnlock()
	items := []ReportSummary{}
	for _, summary := range a.entries {
		if summary.ProductID == productID {
			items = append(items, summary)
		}
	}
	sort.Slice(items, func(i, j int) bool {
		left, _ := time.Parse(time.RFC3339Nano, items[i].CreatedAt)
		right, _ := time.Parse(time.RFC3339Nano, items[j].CreatedAt)
		if left.Equal(right) {
			return items[i].ID > items[j].ID
		}
		return left.After(right)
	})
	return items
}

func (a *Archives) Get(id string) (ArchivedReport, error) {
	if !reportIDPattern.MatchString(id) {
		return ArchivedReport{}, gateway.ErrNotFound
	}
	select {
	case a.slots <- struct{}{}:
		defer func() { <-a.slots }()
	default:
		return ArchivedReport{}, ErrArchiveBusy
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	summary, ok := a.entries[id]
	if !ok {
		return ArchivedReport{}, gateway.ErrNotFound
	}
	snapshot, data, err := readSnapshot(filepath.Join(a.dir, id+".json"))
	if err != nil {
		return ArchivedReport{}, err
	}
	if snapshot.ID != id || summarize(snapshot, data) != summary {
		return ArchivedReport{}, ErrArchiveUnavailable
	}
	return ArchivedReport{Summary: summary, Snapshot: snapshot}, nil
}

func (a *Archives) Replay(id string) (ReplayResult, error) {
	archive, err := a.Get(id)
	if err != nil {
		return ReplayResult{}, err
	}
	if archive.Snapshot.Report.Evaluation.EngineVersion != compliance.EngineVersion {
		return ReplayResult{}, ErrReplayVersion
	}
	select {
	case a.slots <- struct{}{}:
		defer func() { <-a.slots }()
	default:
		return ReplayResult{}, ErrArchiveBusy
	}
	at, _ := time.Parse(time.RFC3339Nano, archive.Snapshot.Report.Evaluation.EvaluatedAt)
	result, err := compliance.EvaluateSnapshot(archive.Snapshot.RulePack, archive.Snapshot.Input, at)
	if err != nil {
		return ReplayResult{}, err
	}
	return ReplayResult{ReportID: id, Matches: reflect.DeepEqual(result, *archive.Snapshot.Report.Evaluation), Evaluation: result}, nil
}
