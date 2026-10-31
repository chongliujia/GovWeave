package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func taskSnapshotFixture(t *testing.T) (*Engine, string, EvidenceTraceView) {
	t.Helper()
	g, dir, capture := evidenceTraceFixture(t)
	var err error
	g.TaskSnapshots, err = openTaskSnapshots(dir, g.Evidence.accessKey)
	if err != nil {
		t.Fatal(err)
	}
	trace := strings.Repeat("b", 32)
	a, b := evidenceTestRecord(t, evidenceTestApp), evidenceTestRecord(t, evidenceOtherApp)
	a.Trace = &TraceContext{Version: traceVersion, TraceID: trace, SpanID: strings.Repeat("1", 16)}
	b.Trace = &TraceContext{Version: traceVersion, TraceID: trace, SpanID: strings.Repeat("2", 16), ParentSpanID: a.Trace.SpanID}
	a.OutputPolicy = &OutputAssessment{Revision: 3, DetectorVersion: "sensitive-text-v1", Result: "block", State: "observed", MatchedCategories: []string{"email"}}
	if _, err := g.Evidence.Capture(a, evidenceTestPayload(capture)); err != nil {
		t.Fatal(err)
	}
	g.Audit.recent = []CallRecord{a, b}
	v, err := g.EvidenceTraceView(trace, []string{evidenceTestApp, evidenceOtherApp}, 128)
	if err != nil {
		t.Fatal(err)
	}
	return g, dir, v
}

func TestTaskSnapshotHistoricalScopePrivacyAndRestart(t *testing.T) {
	g, dir, view := taskSnapshotFixture(t)
	saved, err := g.CreateTaskSnapshot(view.TraceID, view.ApplicationIDs, view.CallLimit, view.ViewSHA256, "test_admin")
	if err != nil || !reflect.DeepEqual(saved.Snapshot.View, view) || saved.Integrity != "authenticated_local" {
		t.Fatal("snapshot did not freeze the viewed metadata", err)
	}
	jsonExport, markdown := saved.JSON(), saved.Markdown()
	digest := sha256.Sum256(jsonExport)
	if hex.EncodeToString(digest[:]) != saved.Summary.SHA256 || int64(len(jsonExport)) != saved.Summary.Bytes || !strings.Contains(string(markdown), saved.Summary.SHA256) || !strings.Contains(string(markdown), "caller_declared") {
		t.Fatal("export checksum or declared provenance missing")
	}
	var exported TaskSnapshot
	if json.Unmarshal(jsonExport, &exported) != nil || !reflect.DeepEqual(exported, saved.Snapshot) {
		t.Fatal("JSON export diverged from saved snapshot")
	}
	for _, secret := range []string{"Synthetic secret input phrase", "hidden-person@private.example", "prompt", "api_key"} {
		if strings.Contains(string(jsonExport), secret) || strings.Contains(string(markdown), secret) && secret != "prompt" {
			t.Fatal("captured content entered a metadata archive")
		}
	}
	if items, err := g.TaskSnapshots.List(view.TraceID, []string{evidenceTestApp}); err != nil || len(items) != 0 {
		t.Fatal("partial scope listed cross-application snapshot", err)
	}
	if _, err := g.TaskSnapshots.Get(saved.Summary.ID, view.TraceID, []string{evidenceTestApp}); err != ErrEvidenceNotFound {
		t.Fatal("partial scope obtained cross-application snapshot", err)
	}
	if _, err := g.TaskSnapshots.Get(saved.Summary.ID, strings.Repeat("c", 32), view.ApplicationIDs); err != ErrEvidenceNotFound {
		t.Fatal("different task obtained the snapshot", err)
	}
	// Removing live audit observations and expiring content cannot rewrite history.
	g.Audit.recent = nil
	g.Evidence.now = func() time.Time { return time.Now().Add(400 * 24 * time.Hour) }
	if _, err := g.Evidence.PurgeExpired("test_admin"); err != nil {
		t.Fatal(err)
	}
	current, err := g.EvidenceTraceView(view.TraceID, view.ApplicationIDs, 128)
	if err != nil || len(current.Calls) != 0 {
		t.Fatal("expired capture remained live", err)
	}
	reopened, err := openTaskSnapshots(dir, g.Evidence.accessKey)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := reopened.Get(saved.Summary.ID, view.TraceID, view.ApplicationIDs)
	if err != nil || !reflect.DeepEqual(saved, loaded) {
		t.Fatal("history depended on live content or audit", err)
	}
	loaded.Summary.ApplicationIDs[0] = "changed"
	loaded.Snapshot.View.Calls[0].Record.Trace.SpanID = "changed"
	items, _ := reopened.List(view.TraceID, view.ApplicationIDs)
	items[0].ApplicationIDs[0] = "changed"
	again, err := reopened.Get(saved.Summary.ID, view.TraceID, view.ApplicationIDs)
	if err != nil || !reflect.DeepEqual(saved, again) {
		t.Fatal("returned metadata aliases persistent state", err)
	}
}

func TestTaskSnapshotStaleViewAndBounds(t *testing.T) {
	g, _, view := taskSnapshotFixture(t)
	g.Audit.failed = true
	if _, err := g.CreateTaskSnapshot(view.TraceID, view.ApplicationIDs, 128, view.ViewSHA256, "test_admin"); err != ErrTaskSnapshotChanged || len(g.TaskSnapshots.entries) != 0 {
		t.Fatal("changed view was silently saved", err)
	}
	g.Audit.failed = false
	for _, expected := range []string{"", "fake", strings.Repeat("A", 64)} {
		if _, err := g.CreateTaskSnapshot(view.TraceID, view.ApplicationIDs, 128, expected, "test_admin"); err != ErrEvidenceInvalid {
			t.Fatal("invalid digest accepted", err)
		}
	}
	for i := 0; i < cap(g.TaskSnapshots.slots); i++ {
		g.TaskSnapshots.slots <- struct{}{}
	}
	if _, err := g.CreateTaskSnapshot(view.TraceID, view.ApplicationIDs, 128, view.ViewSHA256, "test_admin"); err != ErrTaskSnapshotBusy {
		t.Fatal("snapshot creation was not bounded", err)
	}
	for len(g.TaskSnapshots.slots) > 0 {
		<-g.TaskSnapshots.slots
	}
	g.TaskSnapshots.bytes = MaxTaskSnapshotStoreBytes
	if _, err := g.CreateTaskSnapshot(view.TraceID, view.ApplicationIDs, 128, view.ViewSHA256, "test_admin"); err != ErrEvidenceCapacity {
		t.Fatal("total byte budget ignored", err)
	}
	g.TaskSnapshots.bytes = 0
	for i := 0; i < MaxTaskSnapshots; i++ {
		g.TaskSnapshots.entries[fmt.Sprint(i)] = taskSnapshotEntry{}
	}
	if _, err := g.CreateTaskSnapshot(view.TraceID, view.ApplicationIDs, 128, view.ViewSHA256, "test_admin"); err != ErrEvidenceCapacity {
		t.Fatal("snapshot count budget ignored", err)
	}
	g.TaskSnapshots.entries = map[string]taskSnapshotEntry{}
	g.Audit.recent[1].Model = strings.Repeat("x", MaxTaskSnapshotBytes)
	large, _ := g.EvidenceTraceView(view.TraceID, view.ApplicationIDs, 128)
	if _, err := g.CreateTaskSnapshot(large.TraceID, large.ApplicationIDs, 128, large.ViewSHA256, "test_admin"); err != ErrEvidenceCapacity || len(g.TaskSnapshots.entries) != 0 {
		t.Fatal("single file byte budget ignored", err)
	}
}

func TestTaskSnapshotRejectsTamperingUnsafeFilesAndWrongKeys(t *testing.T) {
	for _, mode := range []string{"content", "symlink", "permissions", "key", "missing"} {
		t.Run(mode, func(t *testing.T) {
			g, dir, view := taskSnapshotFixture(t)
			saved, err := g.CreateTaskSnapshot(view.TraceID, view.ApplicationIDs, 128, view.ViewSHA256, "test_admin")
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "task-evidence", saved.Summary.ID+".json")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			key := g.Evidence.accessKey
			switch mode {
			case "content":
				data = []byte(strings.Replace(string(data), "test_admin", "evil_admin", 1))
				err = os.WriteFile(path, data, 0600)
			case "symlink":
				target := filepath.Join(dir, "replacement.json")
				if err = os.WriteFile(target, data, 0600); err == nil {
					err = os.Remove(path)
				}
				if err == nil {
					err = os.Symlink(target, path)
				}
			case "permissions":
				err = os.Chmod(path, 0644)
			case "key":
				key = make([]byte, 32)
			case "missing":
				err = os.Remove(path)
			}
			if err != nil {
				t.Fatal(err)
			}
			if mode != "key" {
				if _, err := g.TaskSnapshots.Get(saved.Summary.ID, view.TraceID, view.ApplicationIDs); err != ErrEvidenceUnavailable {
					t.Fatal("unsafe or changed archive disclosed", err)
				}
			}
			reopened, err := openTaskSnapshots(dir, key)
			if mode == "missing" {
				// No external inventory: whole-file loss before restart is not proved.
				if err != nil || len(reopened.entries) != 0 {
					t.Fatal("missing-file boundary changed", err)
				}
			} else if err != ErrEvidenceUnavailable {
				t.Fatal("restart trusted unsafe archive", err)
			}
		})
	}
}
