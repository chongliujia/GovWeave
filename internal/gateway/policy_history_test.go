package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestPolicyHistoryPersistenceAndIsolation(t *testing.T) {
	p, resources := testPolicies(t)
	initial, err := p.Revision(0)
	if err != nil || !reflect.DeepEqual(initial, defaultPolicy()) {
		t.Fatal("initial revision unavailable", err)
	}
	in := initial.PolicyInput
	in.Mode, in.ApplicationIDs = "observe", []string{"app-a"}
	first, err := p.Save(in, resources)
	if err != nil {
		t.Fatal(err)
	}
	in = first.PolicyInput
	in.Mode, in.Rules, in.ApplicationIDs = "block", []string{"api_key"}, []string{"app-b"}
	second, err := p.Save(in, resources)
	if err != nil {
		t.Fatal(err)
	}
	old, err := p.Revision(first.Revision)
	if err != nil || !reflect.DeepEqual(old, first) {
		t.Fatal("historical snapshot changed", err)
	}
	// Neither reads nor caller-owned slices can change current or historical state.
	old.Rules[0], first.ApplicationIDs[0], in.Rules[0] = "mutated", "mutated", "mutated"
	page := p.History(2, nil)
	if page.Total != 3 || len(page.Snapshots) != 2 || page.Snapshots[0].Revision != 2 || page.Snapshots[1].Revision != 1 || page.NextBeforeRevision == nil || *page.NextBeforeRevision != 1 {
		t.Fatalf("invalid history page: %+v", page)
	}
	page.Snapshots[0].Rules[0] = "mutated"
	if got, _ := p.Revision(2); !reflect.DeepEqual(got, second) {
		t.Fatal("history read mutated active policy")
	}
	if got, _ := p.Revision(1); got.Mode != "observe" || got.Rules[0] != "private_key" || got.ApplicationIDs[0] != "app-a" {
		t.Fatal("mutable historical policy")
	}
	// Appending a revision between pages must not duplicate or skip older entries.
	in = p.Snapshot().PolicyInput
	in.Mode = "disabled"
	if _, err := p.Save(in, resources); err != nil {
		t.Fatal(err)
	}
	next := p.History(2, page.NextBeforeRevision)
	if len(next.Snapshots) != 1 || next.Snapshots[0].Revision != 0 || next.NextBeforeRevision != nil {
		t.Fatal("unstable history pagination")
	}
	zero := uint64(0)
	if len(p.History(2, &zero).Snapshots) != 0 {
		t.Fatal("revision cursor is not exclusive")
	}
	if _, err := p.Revision(99); !errors.Is(err, ErrNotFound) {
		t.Fatal("unknown revision fabricated")
	}
	if _, err := p.Save(second.PolicyInput, resources); !errors.Is(err, ErrConflict) || p.History(100, nil).Total != 4 {
		t.Fatal("stale save added history")
	}
	reopened, err := OpenPolicies(filepath.Dir(p.path), resources)
	if err != nil || !reflect.DeepEqual(p.History(100, nil), reopened.History(100, nil)) {
		t.Fatal("history lost on restart", err)
	}
	data, err := os.ReadFile(p.path)
	var persisted policyHistoryState
	if err != nil || json.Unmarshal(data, &persisted) != nil || persisted.SchemaVersion != 2 || len(persisted.Snapshots) != 4 {
		t.Fatal("history not committed with current policy", err)
	}
	info, _ := os.Stat(p.path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("history is not private")
	}
}

func TestPolicyHistoryLegacyMigration(t *testing.T) {
	p, resources := testPolicies(t)
	legacy := defaultPolicy()
	legacy.Revision, legacy.Mode, legacy.UpdatedAt = 7, "block", "2026-10-01T00:00:00Z"
	data := mustPolicyJSON(t, legacy)
	if err := os.WriteFile(p.path, data, 0600); err != nil {
		t.Fatal(err)
	}
	p, err := OpenPolicies(filepath.Dir(p.path), resources)
	if err != nil || !reflect.DeepEqual(p.Snapshot(), legacy) {
		t.Fatal("legacy enforcement changed", err)
	}
	if got, _ := os.ReadFile(p.path); !bytes.Equal(got, data) {
		t.Fatal("opening rewrote legacy state")
	}
	for _, missing := range []uint64{0, 1, 6} {
		if _, err := p.Revision(missing); !errors.Is(err, ErrNotFound) {
			t.Fatal("invented pre-migration revision")
		}
	}
	in := p.Snapshot().PolicyInput
	in.Mode = "observe"
	if _, err := p.Save(in, resources); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenPolicies(filepath.Dir(p.path), resources)
	if err != nil {
		t.Fatal(err)
	}
	view := reopened.History(100, nil)
	if view.Total != 2 || view.Snapshots[0].Revision != 8 || !reflect.DeepEqual(view.Snapshots[1], legacy) {
		t.Fatal("migration lost baseline")
	}
}

func TestPolicyHistorySaveFailureAndCapacity(t *testing.T) {
	p, resources := testPolicies(t)
	before := p.History(100, nil)
	in := p.Snapshot().PolicyInput
	in.Mode = "block"
	p.path = filepath.Join(t.TempDir(), "missing", "policies.json")
	if _, err := p.Save(in, resources); !errors.Is(err, ErrPersistence) || !reflect.DeepEqual(before, p.History(100, nil)) || p.Snapshot().Revision != 0 {
		t.Fatal("failed write published history")
	}
	p.path = filepath.Join(t.TempDir(), "policies.json")
	for i := 1; i < maxPolicySnapshots; i++ {
		snapshot := defaultPolicy()
		snapshot.Revision, snapshot.UpdatedAt = uint64(i), "2026-10-01T00:00:00Z"
		p.history = append(p.history, snapshot)
	}
	p.state = clonePolicy(p.history[len(p.history)-1])
	in = p.Snapshot().PolicyInput
	in.Mode = "block"
	if _, err := p.Save(in, resources); !errors.Is(err, ErrPolicyHistoryFull) || p.Snapshot().Mode != "disabled" || len(p.history) != maxPolicySnapshots {
		t.Fatal("history overflow changed enforcement or evicted snapshots")
	}
	if _, err := os.Stat(p.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("capacity failure wrote state")
	}
	// The byte limit is independent of the snapshot-count limit.
	p, resources = testPolicies(t)
	largeID := strings.Repeat("a", maxPolicyHistoryBytes)
	resources.Applications = append(resources.Applications, Application{ID: largeID})
	in = p.Snapshot().PolicyInput
	in.ApplicationIDs = []string{largeID}
	if _, err := p.Save(in, resources); !errors.Is(err, ErrPolicyHistoryFull) || p.Snapshot().Revision != 0 || p.History(100, nil).Total != 1 {
		t.Fatal("oversized history published")
	}
}

func TestPolicyHistoryRejectsCorruption(t *testing.T) {
	p, resources := testPolicies(t)
	saved := defaultPolicy()
	saved.Revision, saved.Mode, saved.UpdatedAt = 1, "block", "2026-10-01T00:00:00Z"
	for _, tc := range []struct {
		name      string
		snapshots []PolicySnapshot
	}{
		{"empty", nil},
		{"duplicate revision", []PolicySnapshot{saved, saved}},
		{"reversed", []PolicySnapshot{saved, defaultPolicy()}},
		{"gap", []PolicySnapshot{defaultPolicy(), func() PolicySnapshot { s := saved; s.Revision = 2; return s }()}},
		{"invalid initial", []PolicySnapshot{func() PolicySnapshot { s := defaultPolicy(); s.Mode = "block"; return s }(), saved}},
		{"unknown historical rule", []PolicySnapshot{func() PolicySnapshot { s := defaultPolicy(); s.Rules = []string{"unknown"}; return s }(), saved}},
		{"invalid timestamp", []PolicySnapshot{func() PolicySnapshot { s := saved; s.UpdatedAt = "invalid"; return s }()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, _ := json.Marshal(policyHistoryState{SchemaVersion: 2, Snapshots: tc.snapshots})
			if err := os.WriteFile(p.path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenPolicies(filepath.Dir(p.path), resources); err == nil {
				t.Fatal("corrupt history accepted")
			}
		})
	}
}
