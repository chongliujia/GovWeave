package governance

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"govweave/internal/gateway"
)

func toolsAdapterFixture() (sources, Product) {
	s, p := adapterFixture()
	s.tools = gateway.ToolSnapshot{SchemaVersion: 1, Revision: 7, Tools: []gateway.Tool{{ID: "tool-a", Enabled: true, OutputMode: "block", Resources: []gateway.ToolResource{
		{ID: "private-resource-one", Sensitivity: "restricted", AllowedApplications: []string{"app-a"}},
		{ID: "private-resource-two", Sensitivity: "internal", AllowedApplications: []string{"app-a"}},
	}}}}
	return s, p
}

func TestToolFactsCoverageUsesAllBoundAppsAndDistinctEnabledTools(t *testing.T) {
	for _, tc := range []struct {
		name, count, covered, blocking string
		change                         func(*sources, *Product)
	}{
		{"multiple grants count tool once", "1", "true", "true", func(*sources, *Product) {}},
		{"no configured tools", "0", "false", "false", func(s *sources, _ *Product) { s.tools.Tools = nil }},
		{"no bound applications", "0", "false", "false", func(_ *sources, p *Product) { p.ApplicationIDs = nil }},
		{"no matching grants", "0", "false", "false", func(s *sources, _ *Product) {
			for i := range s.tools.Tools[0].Resources {
				s.tools.Tools[0].Resources[i].AllowedApplications = []string{"app-other"}
			}
		}},
		{"partially covered applications", "1", "false", "false", func(s *sources, p *Product) {
			s.resources.Applications = append(s.resources.Applications, gateway.Application{ID: "app-b"})
			p.ApplicationIDs = append(p.ApplicationIDs, "app-b")
		}},
		{"all applications covered", "1", "true", "true", func(s *sources, p *Product) {
			s.resources.Applications = append(s.resources.Applications, gateway.Application{ID: "app-b"})
			p.ApplicationIDs = append(p.ApplicationIDs, "app-b")
			s.tools.Tools[0].Resources[1].AllowedApplications = []string{"app-b"}
		}},
		{"observe grant prevents blocking coverage", "2", "true", "false", func(s *sources, _ *Product) {
			s.tools.Tools = append(s.tools.Tools, gateway.Tool{ID: "tool-b", Enabled: true, OutputMode: "observe", Resources: []gateway.ToolResource{{ID: "other", AllowedApplications: []string{"app-a"}}}})
		}},
		{"unrelated observe tool ignored", "1", "true", "true", func(s *sources, _ *Product) {
			s.tools.Tools = append(s.tools.Tools, gateway.Tool{ID: "tool-b", Enabled: true, OutputMode: "observe", Resources: []gateway.ToolResource{{ID: "other", AllowedApplications: []string{"app-other"}}}})
		}},
		{"disabled observe tool ignored", "1", "true", "true", func(s *sources, _ *Product) {
			s.tools.Tools = append(s.tools.Tools, gateway.Tool{ID: "tool-b", Enabled: false, OutputMode: "observe", Resources: []gateway.ToolResource{{ID: "other", AllowedApplications: []string{"app-a"}}}})
		}},
		{"disabled tool cannot provide coverage", "0", "false", "false", func(s *sources, _ *Product) { s.tools.Tools[0].Enabled = false }},
		{"missing app leaves coverage unknown", "1", "", "", func(s *sources, _ *Product) { s.resources.Applications = nil }},
		{"revocation independent of configured grants", "1", "true", "true", func(s *sources, _ *Product) { s.resources.Applications[0].Revoked = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, p := toolsAdapterFixture()
			tc.change(&s, &p)
			facts := s.input(p, time.Now()).Facts
			for key, want := range map[string]string{"granted_tool_count": tc.count, "applications_covered": tc.covered, "output_blocking_covers_product": tc.blocking} {
				fact, exists := facts["runtime.tools."+key]
				if exists != (want != "") || string(fact.Value) != want {
					t.Fatalf("%s: got %s (present %v), want %s", key, fact.Value, exists, want)
				}
			}
			if tc.name == "revocation independent of configured grants" && string(facts["runtime.applications_active"].Value) != "false" {
				t.Fatal("revocation fact lost")
			}
		})
	}
}

func TestToolFactsSampleFilteringAndUnknownOutputs(t *testing.T) {
	s, p := toolsAdapterFixture()
	record := func(outcome, code, decision, content string, attempted bool) gateway.CallRecord {
		return gateway.CallRecord{ApplicationID: "app-a", Operation: "tools.invoke", Phase: "finished", Outcome: outcome, ErrorCode: code, UpstreamAttempted: attempted, ToolGovernance: &gateway.ToolGovernance{Decision: decision, Content: gateway.ToolContent{State: content}}}
	}
	s.audit.Records = []gateway.CallRecord{
		record("completed", "", "allow", "not_observed", true),
		record("blocked", "tool_not_allowed", "block", "unknown", false),
		record("blocked", "tool_output_blocked", "block", "observed", true),
		record("completed", "", "observe", "observed", true),
		record("failed", "upstream_error", "observe", "unknown", true),
		record("cancelled", "client_cancelled", "block", "unknown", true),
		{ApplicationID: "app-a", Operation: "tools.invoke", Phase: "finished", Outcome: "failed", UpstreamAttempted: true},
		record("failed", "upstream_error", "block", "unsupported", true),
		record("failed", "credential_unavailable", "block", "unknown", false),
		{ApplicationID: "app-a", Operation: "tools.invoke", Phase: "started", Outcome: "incomplete", UpstreamAttempted: true},
		{ApplicationID: "app-a", Operation: "tools.invoke", Phase: "started", Outcome: "in_progress", UpstreamAttempted: true},
		{ApplicationID: "app-other", Operation: "tools.invoke", Phase: "finished", Outcome: "completed"},
		{ApplicationID: "app-a", Operation: "chat.completions", Phase: "finished", Outcome: "completed"},
		{ApplicationID: "app-a", Operation: "assessment.chat.completions", Phase: "finished", Outcome: "completed"},
		{ApplicationID: "", Operation: "tools.invoke", Phase: "finished", ErrorCode: "invalid_api_key"},
	}
	wants := map[string]string{"request_count": "9", "completed_count": "2", "authorization_denied_count": "1", "output_block_count": "1", "observed_release_count": "1", "failed_count": "4", "cancelled_count": "1", "incomplete_count": "1", "output_checked_count": "3", "unknown_output_count": "4"}
	for _, missingApp := range []bool{false, true} {
		if missingApp {
			s.resources.Applications = nil
		}
		facts := s.input(p, time.Now()).Facts
		for key, want := range wants {
			fact := facts["runtime.tools.sample."+key]
			if string(fact.Value) != want || fact.EvidenceID != "audit-bytes-100" || fact.Source != "runtime" {
				t.Fatalf("%s: incorrect sample: %+v", key, fact)
			}
		}
		if string(facts["runtime.sample.request_count"].Value) != "1" {
			t.Fatal("existing model sample semantics changed")
		}
	}
	s.audit.Available = false
	facts := s.input(p, time.Now()).Facts
	for key := range wants {
		if _, exists := facts["runtime.tools.sample."+key]; exists {
			t.Fatal("unavailable audit yielded authoritative sample", key)
		}
	}
	if string(facts["runtime.tools.revision"].Value) != "7" || string(facts["runtime.audit_available"].Value) != "false" {
		t.Fatal("unavailable audit removed independent configuration evidence")
	}
	s.audit.Available, s.audit.Records = true, nil
	facts = s.input(p, time.Now()).Facts
	for key := range wants {
		if string(facts["runtime.tools.sample."+key].Value) != "0" {
			t.Fatal("available empty sample not represented as zero", key)
		}
	}
}

func TestToolFactsContainMetadataOnlyAndVersionedProvenance(t *testing.T) {
	s, p := toolsAdapterFixture()
	s.tools.Tools[0].Endpoint = "https://private-provider.example/read"
	s.tools.Tools[0].Name = "private-tool-name"
	now := time.Now().UTC()
	input := s.input(p, now)
	for name, fact := range input.Facts {
		if !strings.HasPrefix(name, "runtime.tools.") {
			continue
		}
		if fact.Source != "runtime" || fact.ObservedAt != now.Format(time.RFC3339Nano) {
			t.Fatal("tool fact provenance missing", name)
		}
		if !strings.HasPrefix(name, "runtime.tools.sample.") && fact.EvidenceID != "tool-config-gw-3-tools-7" {
			t.Fatal("tool configuration evidence is not versioned", name)
		}
	}
	encoded, _ := json.Marshal(input)
	for _, private := range []string{"private-resource", "private-provider.example", "private-tool-name", "allowed_applications", "app-a"} {
		if strings.Contains(string(encoded), private) {
			t.Fatal("resource, provider or grant metadata escaped into facts")
		}
	}
	if s.stamp(p).ToolRevision != 7 {
		t.Fatal("tool revision absent from source stamp")
	}
}
