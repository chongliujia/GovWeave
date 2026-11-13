package sensitive

import "testing"

func TestPluginCatalogMatchesExecution(t *testing.T) {
	items := Catalog()
	if len(items) != 3 {
		t.Fatal("expected three pinned detector versions")
	}
	seen := map[string]bool{}
	for _, item := range items {
		if seen[item.Version] || !Supports(item.Version) || item.ID != "sensitive-text" || item.Execution != "compiled_local" || item.Streaming || item.MaxBytes != MaxBytes || item.MaxFindings != MaxFindings {
			t.Fatal("invalid descriptor", item)
		}
		seen[item.Version] = true
		result := Scan([]byte("person@example.com"), item.Version)
		if result.DetectorVersion != item.Version || result.State != "observed" {
			t.Fatal("catalog version does not dispatch to its implementation", result)
		}
	}
	items[0].Categories[0] = "modified"
	items[0].Modes[0] = "modified"
	items[0].Version = "modified"
	if fresh := Catalog(); fresh[0].Categories[0] != "credential" || fresh[0].Modes[0] != "disabled" || fresh[0].Version != Version {
		t.Fatal("catalog is externally mutable")
	}
	if Supports("latest") || Scan(nil, "latest").Reason != "unsupported_version" {
		t.Fatal("unknown plugin must never silently fall back")
	}
	if SupportedVersion(Version3) || DetectVersion(nil, Version3).Reason != "unsupported_version" {
		t.Fatal("historical v1/v2 dispatch changed")
	}
}
