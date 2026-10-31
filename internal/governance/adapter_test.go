package governance

import (
	"testing"
	"time"

	"govweave/internal/gateway"
)

func adapterFixture() (sources, Product) {
	s := sources{resources: gateway.Snapshot{Revision: 3, Applications: []gateway.Application{{ID: "app-a", AllowedConnections: []string{"conn-a"}}}, Connections: []gateway.Connection{{ID: "conn-a", Enabled: true}}}, policy: gateway.PolicySnapshot{PolicyInput: gateway.PolicyInput{Revision: 2, Mode: "block", Rules: []string{"private_key"}}}, audit: gateway.AuditView{Available: true, Bytes: 100}}
	p := Product{ID: "prod-a", ProductInput: ProductInput{Revision: 1, Version: "1", PackID: "demo", PackVersion: "1", ApplicationIDs: []string{"app-a"}}}
	return s, p
}

func TestAdapterCoverageUsesAllGrantsAndNoVacuousProtection(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		change     func(*sources)
	}{
		{"all scopes", "true", func(*sources) {}},
		{"wrong application", "false", func(s *sources) { s.policy.ApplicationIDs = []string{"app-b"} }},
		{"disabled granted model excluded", "false", func(s *sources) {
			s.resources.Connections = append(s.resources.Connections, gateway.Connection{ID: "conn-b", Enabled: false})
			s.resources.Applications[0].AllowedConnections = append(s.resources.Applications[0].AllowedConnections, "conn-b")
			s.policy.ConnectionIDs = []string{"conn-a"}
		}},
		{"no grants", "", func(s *sources) { s.resources.Applications[0].AllowedConnections = nil }},
		{"missing application", "", func(s *sources) { s.resources.Applications = nil }},
		{"missing connection", "", func(s *sources) { s.resources.Connections = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, p := adapterFixture()
			tc.change(&s)
			input := s.input(p, time.Now())
			fact, exists := input.Facts["runtime.credential_policy_covers_product"]
			if (tc.want == "") == exists || string(fact.Value) != tc.want {
				t.Fatalf("unexpected coverage: %s", fact.Value)
			}
			if string(input.Facts["runtime.credential_api_key_rule_enabled"].Value) != "false" {
				t.Fatal("disabled detector reported as enabled")
			}
		})
	}
}

func TestAdapterSampleFilteringAndUnavailableAudit(t *testing.T) {
	s, p := adapterFixture()
	s.audit.Records = []gateway.CallRecord{
		{ApplicationID: "app-a", Operation: "chat.completions", Phase: "finished", ErrorCode: "policy_blocked", Outcome: "blocked"},
		{ApplicationID: "app-b", Operation: "chat.completions", Phase: "finished", ErrorCode: "policy_blocked"},
		{ApplicationID: "app-a", Operation: "models.list", Phase: "finished"},
		{ApplicationID: "app-a", Operation: "chat.completions", Phase: "started", Outcome: "in_progress"},
		{ApplicationID: "app-a", Operation: "chat.completions", Phase: "started", Outcome: "incomplete"},
	}
	facts := s.input(p, time.Now()).Facts
	for _, key := range []string{"request_count", "policy_block_count", "incomplete_count"} {
		if string(facts["runtime.sample."+key].Value) != "1" {
			t.Fatal("incorrect sample filter", key)
		}
	}
	s.audit.Available = false
	facts = s.input(p, time.Now()).Facts
	if _, exists := facts["runtime.sample.request_count"]; exists || string(facts["runtime.audit_available"].Value) != "false" {
		t.Fatal("unavailable audit produced authoritative sample counts")
	}
}
