package gateway

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func outputPolicyFixture(t *testing.T) (*OutputPolicyStore, Snapshot) {
	t.Helper()
	resources := Snapshot{Applications: []Application{{ID: "app-a"}, {ID: "app-b", Revoked: true}}}
	p, err := OpenOutputPolicies(t.TempDir(), resources)
	if err != nil {
		t.Fatal(err)
	}
	return p, resources
}

func TestOutputPolicyHistoryIsolationAndRestart(t *testing.T) {
	p, resources := outputPolicyFixture(t)
	zero := p.Snapshot()
	if !reflect.DeepEqual(zero, defaultOutputPolicy()) || zero.Applies("app-a") {
		t.Fatal("initial policy must be disabled")
	}
	input := zero.OutputPolicyInput
	input.Mode, input.Categories, input.ApplicationIDs = "observe", []string{"phone", "credential", "email"}, []string{"app-b", "app-a"}
	first, err := p.Save(input, resources)
	if err != nil || first.Revision != 1 || first.Categories[0] != "credential" || first.ApplicationIDs[0] != "app-a" {
		t.Fatal("save or canonical ordering failed", err)
	}
	if !first.Applies("app-a") || first.Applies("app-other") {
		t.Fatal("incorrect application scope")
	}
	input.Categories[0], input.ApplicationIDs[0] = "changed", "changed"
	first.Categories[0], first.ApplicationIDs[0] = "changed", "changed"
	current := p.Snapshot()
	if current.Categories[0] != "credential" || current.ApplicationIDs[0] != "app-a" {
		t.Fatal("caller-owned slices mutated active policy")
	}
	input = current.OutputPolicyInput
	input.Mode, input.Categories, input.ApplicationIDs = "block", []string{"email"}, nil
	second, err := p.Save(input, resources)
	if err != nil || second.Revision != 2 || !second.Applies("new-app") {
		t.Fatal("global scope failed", err)
	}
	history := p.History()
	if len(history) != 3 || history[0].Revision != 2 || history[1].Revision != 1 || history[2].Revision != 0 {
		t.Fatal("invalid immutable history order")
	}
	history[1].Categories[0] = "changed"
	old, err := p.Revision(1)
	if err != nil || old.Categories[0] != "credential" || old.Mode != "observe" {
		t.Fatal("historical snapshot was mutated")
	}
	if _, err := p.Revision(3); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing historical revision fabricated")
	}
	if _, err := p.Save(current.OutputPolicyInput, resources); !errors.Is(err, ErrConflict) {
		t.Fatal("stale revision accepted")
	}
	reopened, err := OpenOutputPolicies(filepath.Dir(p.path), resources)
	if err != nil || !reflect.DeepEqual(p.History(), reopened.History()) {
		t.Fatal("history did not survive restart", err)
	}
	info, err := os.Stat(p.path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("policy history must be private")
	}
}

func TestOutputPolicyRejectsInvalidSettingsAndFailedPersistence(t *testing.T) {
	p, resources := outputPolicyFixture(t)
	for _, edit := range []func(*OutputPolicyInput){
		func(in *OutputPolicyInput) { in.Mode = "invalid" },
		func(in *OutputPolicyInput) { in.Categories = nil },
		func(in *OutputPolicyInput) { in.Categories = []string{"email", "email"} },
		func(in *OutputPolicyInput) { in.Categories = []string{"unknown"} },
		func(in *OutputPolicyInput) { in.ApplicationIDs = []string{"missing"} },
		func(in *OutputPolicyInput) { in.ApplicationIDs = []string{"app-a", "app-a"} },
		func(in *OutputPolicyInput) { in.ApplicationIDs = make([]string, 65) },
	} {
		input := p.Snapshot().OutputPolicyInput
		edit(&input)
		if _, err := p.Save(input, resources); err == nil {
			t.Fatal("invalid policy accepted")
		}
		if len(p.History()) != 1 {
			t.Fatal("rejected save changed history")
		}
	}
	if err := os.Mkdir(p.path, 0700); err != nil {
		t.Fatal(err)
	}
	input := p.Snapshot().OutputPolicyInput
	input.Mode = "block"
	if _, err := p.Save(input, resources); !errors.Is(err, ErrPersistence) || p.Snapshot().Mode != "disabled" || len(p.History()) != 1 {
		t.Fatal("failed save changed accepted policy")
	}
}

func TestOutputPolicyHistoryCapacityRetainsPreviousConfiguration(t *testing.T) {
	p, resources := outputPolicyFixture(t)
	for i := 1; i < maxOutputSnapshots; i++ {
		input := p.Snapshot().OutputPolicyInput
		input.Mode = "observe"
		if _, err := p.Save(input, resources); err != nil {
			t.Fatal(err)
		}
	}
	before := p.Snapshot()
	input := before.OutputPolicyInput
	input.Mode = "block"
	if _, err := p.Save(input, resources); !errors.Is(err, ErrOutputHistoryFull) || !reflect.DeepEqual(before, p.Snapshot()) || len(p.History()) != maxOutputSnapshots {
		t.Fatal("capacity changed current policy or evicted history")
	}
}

func TestOutputPolicyCorruptionRefusesStartup(t *testing.T) {
	for _, edit := range []func(*outputPolicyState){
		func(s *outputPolicyState) { s.SchemaVersion = 2 },
		func(s *outputPolicyState) { s.Snapshots = nil },
		func(s *outputPolicyState) { s.Snapshots[0].Mode = "block" },
		func(s *outputPolicyState) { s.Snapshots[1].Revision = 3 },
		func(s *outputPolicyState) { s.Snapshots[1].DetectorVersion = "unknown" },
		func(s *outputPolicyState) { s.Snapshots[1].RedactionVersion = "unknown" },
		func(s *outputPolicyState) { s.Snapshots[1].Mode = "redact" },
		func(s *outputPolicyState) { s.Snapshots[1].UpdatedAt = "invalid" },
		func(s *outputPolicyState) { s.Snapshots[1].Categories = []string{"phone", "email"} },
		func(s *outputPolicyState) { s.Snapshots[1].ApplicationIDs = []string{"missing"} },
	} {
		p, resources := outputPolicyFixture(t)
		input := p.Snapshot().OutputPolicyInput
		input.Mode = "block"
		if _, err := p.Save(input, resources); err != nil {
			t.Fatal(err)
		}
		data, _ := os.ReadFile(p.path)
		var state outputPolicyState
		if json.Unmarshal(data, &state) != nil {
			t.Fatal("invalid test setup")
		}
		edit(&state)
		data, _ = json.Marshal(state)
		if err := os.WriteFile(p.path, data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenOutputPolicies(filepath.Dir(p.path), resources); err == nil {
			t.Fatal("corrupt policy silently loaded/reset")
		}
	}
	p, resources := outputPolicyFixture(t)
	if err := os.WriteFile(p.path, []byte(`{}`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenOutputPolicies(filepath.Dir(p.path), resources); err == nil {
		t.Fatal("public configuration accepted")
	}
}

func TestOutputDetectorSelectionRetainsHistoryAndOmittedVersion(t *testing.T) {
	p, resources := outputPolicyFixture(t)
	in := p.Snapshot().OutputPolicyInput
	in.Mode, in.DetectorVersion = "block", "sensitive-text-v2"
	first, err := p.Save(in, resources)
	if err != nil || first.DetectorVersion != "sensitive-text-v2" {
		t.Fatal("v2 selection failed", err)
	}
	in = first.OutputPolicyInput
	in.DetectorVersion = ""
	in.Mode = "observe"
	second, err := p.Save(in, resources)
	if err != nil || second.DetectorVersion != "sensitive-text-v2" {
		t.Fatal("omission changed generation", err)
	}
	old, _ := p.Revision(0)
	if old.DetectorVersion != "sensitive-text-v1" {
		t.Fatal("old snapshot changed")
	}
	reopened, err := OpenOutputPolicies(filepath.Dir(p.path), resources)
	if err != nil || !reflect.DeepEqual(p.History(), reopened.History()) {
		t.Fatal("mixed generation history failed", err)
	}
	in = second.OutputPolicyInput
	in.DetectorVersion = "unknown"
	if _, err = p.Save(in, resources); err == nil {
		t.Fatal("unsupported detector accepted")
	}
	in.DetectorVersion = "sensitive-text-v1"
	rollback, err := p.Save(in, resources)
	if err != nil || rollback.DetectorVersion != "sensitive-text-v1" || rollback.Revision != 3 {
		t.Fatal("explicit rollback failed", err)
	}
}
