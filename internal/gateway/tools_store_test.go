package gateway

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func readToolInput(appID string) ToolInput {
	key := "read-provider-private-credential"
	return ToolInput{Name: "Knowledge reader", Alias: "knowledge-read", Endpoint: "https://tools.example/read", APIKey: &key, Enabled: true, TimeoutSeconds: 5, OutputMode: "block", Resources: []ToolResource{{ID: "support-public", Sensitivity: "public", AllowedApplications: []string{appID}}, {ID: "payroll", Sensitivity: "restricted", AllowedApplications: []string{}}}}
}

func setupToolStore(t *testing.T) (string, *Store, *ToolStore, Application, string) {
	t.Helper()
	dir := t.TempDir()
	store, _, app, key := setupStore(t, dir, "https://models.example/v1")
	tools, err := OpenTools(dir, store)
	if err != nil {
		t.Fatal(err)
	}
	return dir, store, tools, app, key
}

func TestToolPrivatePersistenceSnapshotsAndCredentialLifecycle(t *testing.T) {
	dir, store, tools, app, key := setupToolStore(t)
	in := readToolInput(app.ID)
	saved, err := tools.Save("", in)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Revision != 1 || saved.SnapshotSHA256 != toolHash(saved) || !saved.HasCredential {
		t.Fatalf("invalid saved snapshot: %#v", saved)
	}
	before := tools.Snapshot()
	in.Resources[0].AllowedApplications[0] = "mutated-input"
	saved.Resources[0].ID = "mutated-result"
	before.Tools[0].Resources[0].AllowedApplications = []string{"mutated-snapshot"}
	resolved, identity, revision, err := tools.ResolveAuthorized("Bearer "+key, "knowledge-read", "support-public")
	if err != nil || resolved.APIKey != "read-provider-private-credential" || identity.ID != app.ID || revision != store.Snapshot().Revision {
		t.Fatalf("resolve: %#v %#v %d %v", resolved, identity, revision, err)
	}
	first := tools.Snapshot().Tools[0]
	public, _ := json.Marshal(tools.Snapshot())
	disk, err := os.ReadFile(filepath.Join(dir, "tools.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{key, "read-provider-private-credential"} {
		if strings.Contains(string(public), secret) || strings.Contains(string(disk), secret) {
			t.Fatal("tool secret exposed or persisted as plaintext")
		}
	}
	if strings.Contains(string(public), "ciphertext") || strings.Contains(string(public), "api_key") {
		t.Fatal("private fields exposed in snapshot")
	}
	info, err := os.Stat(filepath.Join(dir, "tools.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("tool configuration is not private")
	}
	in = toolInput(first, nil)
	in.OutputMode = "observe"
	second, err := tools.Save(first.ID, in)
	if err != nil || second.Revision != 2 || first.SnapshotSHA256 == second.SnapshotSHA256 {
		t.Fatal("tool update did not create a new snapshot", err)
	}
	resolved, err = tools.Resolve("knowledge-read", "support-public", app.ID)
	if err != nil || resolved.APIKey != "read-provider-private-credential" {
		t.Fatal("omitted credential was not retained", err)
	}
	empty := ""
	in = toolInput(second, &empty)
	third, err := tools.Save(first.ID, in)
	if err != nil || third.HasCredential {
		t.Fatal("explicit credential clearing failed", err)
	}
	tools, err = OpenTools(dir, store)
	if err != nil {
		t.Fatal("reopen", err)
	}
	resolved, err = tools.Resolve("knowledge-read", "support-public", app.ID)
	if err != nil || resolved.APIKey != "" || resolved.Tool.Revision != 3 {
		t.Fatal("active snapshot did not survive restart", err)
	}
	history, err := tools.History(first.ID)
	if err != nil || len(history) != 3 || history[0].Revision != 3 || !reflect.DeepEqual(history[2], first) {
		t.Fatalf("history changed or is not newest first: %#v %v", history, err)
	}
	history[2].Resources[0].ID = "changed-history"
	again, _ := tools.History(first.ID)
	if !reflect.DeepEqual(again[2], first) {
		t.Fatal("history returned a mutable reference")
	}
	if _, err := tools.History("unknown"); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing history did not return not found")
	}
}

func TestToolGlobalRevisionAndFailedSave(t *testing.T) {
	_, _, tools, app, _ := setupToolStore(t)
	first, err := tools.Save("", readToolInput(app.ID))
	if err != nil {
		t.Fatal(err)
	}
	in := readToolInput(app.ID)
	in.Alias, in.Revision = "other-reader", first.Revision
	second, err := tools.Save("", in)
	if err != nil || second.Revision != 2 {
		t.Fatal(err)
	}
	in = toolInput(first, nil)
	if _, err := tools.Save(first.ID, in); !errors.Is(err, ErrConflict) {
		t.Fatal("per-tool revision used in place of global revision")
	}
	in.Revision = 2
	before := tools.Snapshot()
	tools.path = filepath.Join(t.TempDir(), "missing", "tools.json")
	if _, err := tools.Save(first.ID, in); !errors.Is(err, ErrPersistence) {
		t.Fatal("expected persistence failure", err)
	}
	if !reflect.DeepEqual(before, tools.Snapshot()) {
		t.Fatal("failed persistence changed live state")
	}
	if history, _ := tools.History(first.ID); len(history) != 1 {
		t.Fatal("failed persistence appended history")
	}
}

func TestToolAuthorizationDenialAndRevocation(t *testing.T) {
	dir, store, tools, app, key := setupToolStore(t)
	tool, err := tools.Save("", readToolInput(app.ID))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ alias, resource, app string }{{"unknown", "support-public", app.ID}, {tool.Alias, "missing", app.ID}, {tool.Alias, "payroll", app.ID}, {tool.Alias, "support-public", "invented-app"}} {
		out, err := tools.Resolve(tc.alias, tc.resource, tc.app)
		if !errors.Is(err, ErrToolDenied) || out.APIKey != "" {
			t.Fatalf("permission denial failed: %#v %v", tc, err)
		}
	}
	denied, _, _, err := tools.ResolveAuthorized("Bearer "+key, tool.Alias, "payroll")
	if !errors.Is(err, ErrToolDenied) || denied.Tool.SnapshotSHA256 != tool.SnapshotSHA256 || denied.Resource.Sensitivity != "restricted" {
		t.Fatal("denial lacked immutable decision metadata", err)
	}
	in := toolInput(tool, nil)
	in.Enabled = false
	tool, err = tools.Save(tool.ID, in)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := tools.Resolve(tool.Alias, "support-public", app.ID); !errors.Is(err, ErrToolDenied) || out.APIKey != "" {
		t.Fatal("disabled tool allowed")
	}
	if _, _, err := store.ChangeKey(app.ID, app.Revision, true); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := tools.ResolveAuthorized("Bearer "+key, tool.Alias, "support-public"); !errors.Is(err, ErrInvalidKey) {
		t.Fatal("revoked credential accepted")
	}
	if _, err := tools.Resolve(tool.Alias, "support-public", app.ID); !errors.Is(err, ErrToolDenied) {
		t.Fatal("revoked application ID accepted")
	}
	if _, err := OpenTools(dir, store); err != nil {
		t.Fatal("historical revoked grants prevented restart", err)
	}
	in = toolInput(tool, nil)
	if _, err := tools.Save(tool.ID, in); err == nil {
		t.Fatal("new grant to revoked application accepted")
	}
}

func TestToolValidationAndBounds(t *testing.T) {
	_, _, tools, app, _ := setupToolStore(t)
	tests := []struct {
		name   string
		change func(*ToolInput)
	}{
		{"http_without_consent", func(in *ToolInput) { in.Endpoint = "http://localhost/read" }},
		{"metadata_endpoint", func(in *ToolInput) { in.Endpoint = "https://169.254.169.254/read" }},
		{"caller_query", func(in *ToolInput) { in.Endpoint += "?key=secret" }},
		{"alias_path", func(in *ToolInput) { in.Alias = "read/tool" }},
		{"empty_resources", func(in *ToolInput) { in.Resources = nil }},
		{"too_many_resources", func(in *ToolInput) { in.Resources = make([]ToolResource, 33) }},
		{"duplicate_resource", func(in *ToolInput) { in.Resources[1].ID = in.Resources[0].ID }},
		{"resource_path", func(in *ToolInput) { in.Resources[0].ID = "../secret" }},
		{"unknown_sensitivity", func(in *ToolInput) { in.Resources[0].Sensitivity = "automatic" }},
		{"unknown_application", func(in *ToolInput) { in.Resources[0].AllowedApplications = []string{"app_unknown"} }},
		{"duplicate_application", func(in *ToolInput) { in.Resources[0].AllowedApplications = []string{app.ID, app.ID} }},
		{"too_many_grants", func(in *ToolInput) { in.Resources[0].AllowedApplications = make([]string, 33) }},
		{"timeout_zero", func(in *ToolInput) { in.TimeoutSeconds = 0 }},
		{"timeout_large", func(in *ToolInput) { in.TimeoutSeconds = 31 }},
		{"output_disabled", func(in *ToolInput) { in.OutputMode = "disabled" }},
		{"credential_header_injection", func(in *ToolInput) { key := "secret\r\nInjected: value"; in.APIKey = &key }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := readToolInput(app.ID)
			tc.change(&in)
			if _, err := tools.Save("", in); err == nil {
				t.Fatal("invalid settings accepted")
			}
			if tools.Snapshot().Revision != 0 {
				t.Fatal("invalid input changed state")
			}
		})
	}
}

func TestToolCorruptPersistenceRejected(t *testing.T) {
	dir, store, tools, app, _ := setupToolStore(t)
	first, err := tools.Save("", readToolInput(app.ID))
	if err != nil {
		t.Fatal(err)
	}
	second, err := tools.Save(first.ID, toolInput(first, nil))
	if err != nil || second.Revision != 2 {
		t.Fatal(err)
	}
	baseline, err := os.ReadFile(filepath.Join(dir, "tools.json"))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		change func(*toolsState)
	}{
		{"revision_gap", func(s *toolsState) { s.Snapshots[1].Revision = 3 }},
		{"state_revision", func(s *toolsState) { s.Revision = 1 }},
		{"hash", func(s *toolsState) { s.Snapshots[0].SnapshotSHA256 = strings.Repeat("0", 64) }},
		{"swapped_ciphertext", func(s *toolsState) { s.Snapshots[1].Credential = s.Snapshots[0].Credential }},
		{"credential_flag", func(s *toolsState) { s.Snapshots[0].HasCredential = false }},
		{"unknown_grant", func(s *toolsState) {
			s.Snapshots[0].Resources[1].AllowedApplications = []string{"app_unknown"}
			s.Snapshots[0].SnapshotSHA256 = toolHash(s.Snapshots[0].Tool)
		}},
		{"changed_creation", func(s *toolsState) {
			s.Snapshots[1].CreatedAt = "2020-01-01T00:00:00Z"
			s.Snapshots[1].SnapshotSHA256 = toolHash(s.Snapshots[1].Tool)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var corrupted toolsState
			if err := json.Unmarshal(baseline, &corrupted); err != nil {
				t.Fatal(err)
			}
			tc.change(&corrupted)
			data, _ := json.Marshal(corrupted)
			if err := os.WriteFile(filepath.Join(dir, "tools.json"), data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenTools(dir, store); err == nil {
				t.Fatal("corrupt history accepted")
			}
		})
	}
	if err := os.WriteFile(filepath.Join(dir, "tools.json"), baseline, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "tools.json"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenTools(dir, store); err == nil {
		t.Fatal("public configuration accepted")
	}
}

func TestToolHistoryCapacityPreservesActiveState(t *testing.T) {
	_, _, tools, app, _ := setupToolStore(t)
	tool, err := tools.Save("", readToolInput(app.ID))
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < maxToolSnapshots; i++ {
		tool, err = tools.Save(tool.ID, toolInput(tool, nil))
		if err != nil {
			t.Fatal(err)
		}
	}
	before := tools.Snapshot()
	if _, err := tools.Save(tool.ID, toolInput(tool, nil)); !errors.Is(err, ErrToolHistoryFull) {
		t.Fatal("tool history overflow accepted", err)
	}
	if !reflect.DeepEqual(before, tools.Snapshot()) {
		t.Fatal("capacity failure changed active configuration")
	}
}
