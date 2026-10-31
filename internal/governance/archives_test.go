package governance

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"govweave/internal/gateway"
)

func TestArchivedReportKeepsPackProfileAndEvidenceAcrossUpdates(t *testing.T) {
	f := setup(t)
	product, err := f.service.Save("", f.input())
	if err != nil {
		t.Fatal(err)
	}
	archive, err := f.service.Archive(product.ID)
	if err != nil {
		t.Fatal(err)
	}
	if archive.Snapshot.Input.Facts["runtime.credential_policy_mode"].Source != "runtime" || archive.Summary.PackSHA256 != archive.Snapshot.Report.Evaluation.PackSHA256 {
		t.Fatal("archived provenance missing")
	}
	data, err := os.ReadFile(filepath.Join(f.dir, "assessment-reports", archive.Summary.ID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(f.key)) {
		t.Fatal("inference key leaked into report snapshot")
	}
	info, _ := os.Stat(filepath.Join(f.dir, "assessment-reports", archive.Summary.ID+".json"))
	if info.Mode().Perm() != 0600 {
		t.Fatal("report file is not private")
	}
	input := f.input()
	input.Revision = product.Revision
	input.Version = "2.0.0"
	fact := input.Facts["product.user_facing"]
	fact.Value = json.RawMessage("false")
	input.Facts["product.user_facing"] = fact
	if _, err := f.service.Save(product.ID, input); err != nil {
		t.Fatal(err)
	}
	setMode(t, f, "block")
	saved, err := f.service.Archives.Get(archive.Summary.ID)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Snapshot.Product.Version != "1.0.0" || string(saved.Snapshot.Input.Facts["product.user_facing"].Value) != "true" || saved.Summary != archive.Summary {
		t.Fatal("historical snapshot followed live changes")
	}
	replay, err := f.service.Archives.Replay(archive.Summary.ID)
	if err != nil || !replay.Matches || !reflect.DeepEqual(replay.Evaluation, *archive.Snapshot.Report.Evaluation) {
		t.Fatal("saved inputs were not reproducible", err)
	}
	reopened, err := openArchives(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := reopened.Get(archive.Summary.ID); err != nil || got.Summary != archive.Summary {
		t.Fatal("archive lost after restart", err)
	}
	// Returned maps and slices cannot mutate either the retained file or future reads.
	saved.Snapshot.Input.Facts["runtime.credential_policy_mode"] = fact
	saved.Snapshot.RulePack.Controls[0].Title = "mutated"
	again, err := reopened.Get(archive.Summary.ID)
	if err != nil || again.Snapshot.RulePack.Controls[0].Title == "mutated" {
		t.Fatal("archive exposed shared mutable state")
	}
}

func TestArchivesRetainUnknownResultsAndFixedEvidenceTime(t *testing.T) {
	f := setup(t)
	f.service.Close()
	setMode(t, f, "block")
	in := f.input()
	fact := in.Facts["transparency.disclosure_verified"]
	fact.ExpiresAt = time.Now().Add(200 * time.Millisecond).UTC().Format(time.RFC3339Nano)
	in.Facts["transparency.disclosure_verified"] = fact
	product, err := f.service.Save("", in)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := f.service.Archive(product.ID)
	if err != nil {
		t.Fatal(err)
	}
	deadline, _ := time.Parse(time.RFC3339Nano, fact.ExpiresAt)
	time.Sleep(time.Until(deadline) + time.Millisecond)
	replay, err := f.service.Archives.Replay(archive.Summary.ID)
	if err != nil || !replay.Matches || replay.Evaluation.Status != "satisfied" {
		t.Fatal("archive replay used current time instead of retained time", err)
	}
	current, err := f.service.Refresh(product.ID)
	if err != nil || current.Evaluation.Status != "insufficient_evidence" {
		t.Fatal("live expired evidence still passed", err)
	}
	second, err := f.service.Archive(product.ID)
	if err != nil || second.Summary.Status != "insufficient_evidence" {
		t.Fatal("unknown result could not be retained", err)
	}
}

func TestArchiveCorruptionCapacityAndWriteFailurePreserveExistingReports(t *testing.T) {
	f := setup(t)
	product, err := f.service.Save("", f.input())
	if err != nil {
		t.Fatal(err)
	}
	first, err := f.service.Archive(product.ID)
	if err != nil {
		t.Fatal(err)
	}
	a := f.service.Archives
	path := filepath.Join(a.dir, first.Summary.ID+".json")
	data, _ := os.ReadFile(path)
	if err := os.WriteFile(path, append(data, ' '), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Get(first.Summary.ID); !errors.Is(err, ErrArchiveUnavailable) {
		t.Fatal("changed file returned using stale index hash")
	}
	if err := os.WriteFile(path, []byte(`{"schema_version":99}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := openArchives(f.dir); err == nil {
		t.Fatal("invalid persisted report accepted")
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	oldBytes := a.bytes
	a.bytes = MaxArchiveBytes
	if _, err := f.service.Archive(product.ID); !errors.Is(err, ErrArchiveCapacity) {
		t.Fatal("archive byte limit bypassed")
	}
	a.bytes = oldBytes
	oldDir := a.dir
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	a.dir = filepath.Join(blocker, "reports")
	if _, err := f.service.Archive(product.ID); !errors.Is(err, gateway.ErrPersistence) {
		t.Fatal("archive write failure not reported")
	}
	a.dir = oldDir
	if len(a.List(product.ID)) != 1 {
		t.Fatal("failed archive operation published an index entry")
	}
	if saved, err := a.Get(first.Summary.ID); err != nil || saved.Summary != first.Summary {
		t.Fatal("existing report changed on failure", err)
	}
	if _, err := a.Get("../../products"); !errors.Is(err, gateway.ErrNotFound) {
		t.Fatal("archive path traversal accepted")
	}
}

func TestConcurrentArchiveIDsAreDistinct(t *testing.T) {
	f := setup(t)
	product, err := f.service.Save("", f.input())
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	ids := make(chan string, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			archive, err := f.service.Archive(product.ID)
			if err != nil {
				t.Error(err)
				return
			}
			ids <- archive.Summary.ID
		}()
	}
	wg.Wait()
	close(ids)
	seen := map[string]bool{}
	for id := range ids {
		if seen[id] {
			t.Fatal("archive overwritten by concurrent capture")
		}
		seen[id] = true
	}
	if len(seen) != 8 || len(f.service.Archives.List(product.ID)) != 8 {
		t.Fatal("concurrent reports lost")
	}
}

func TestArchiveReadableButReplayRejectsUnsupportedEngineVersion(t *testing.T) {
	f := setup(t)
	product, err := f.service.Save("", f.input())
	if err != nil {
		t.Fatal(err)
	}
	archive, err := f.service.Archive(product.ID)
	if err != nil {
		t.Fatal(err)
	}
	archive.Snapshot.Report.Evaluation.EngineVersion = "future-evaluator"
	data, _ := json.Marshal(archive.Snapshot)
	if err := os.WriteFile(filepath.Join(f.dir, "assessment-reports", archive.Summary.ID+".json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	reopened, err := openArchives(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Get(archive.Summary.ID); err != nil {
		t.Fatal("unsupported evaluator erased readable history", err)
	}
	if _, err := reopened.Replay(archive.Summary.ID); !errors.Is(err, ErrReplayVersion) {
		t.Fatal("unsupported evaluator version silently replayed")
	}
}
