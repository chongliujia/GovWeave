package governance

import (
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"govweave/internal/compliance"
	"govweave/internal/gateway"
	"govweave/internal/sensitive"
)

const SampleLimit = 100

// Samples use the last 100 global audit records, filtered to this product's
// applications and operation. They are not time-window metrics.
type SourceStamp struct {
	ProductRevision      uint64 `json:"product_revision"`
	GatewayRevision      uint64 `json:"gateway_revision"`
	PolicyRevision       uint64 `json:"policy_revision"`
	ToolRevision         uint64 `json:"tool_revision,omitempty"`
	OutputPolicyRevision uint64 `json:"output_policy_revision,omitempty"`
	TestEvidenceRevision uint64 `json:"test_evidence_revision,omitempty"`
	AuditBytes           int64  `json:"audit_bytes"`
	AuditAvailable       bool   `json:"audit_available"`
}

type sources struct {
	resources    gateway.Snapshot
	policy       gateway.PolicySnapshot
	tools        gateway.ToolSnapshot
	outputPolicy gateway.OutputPolicySnapshot
	audit        gateway.AuditView
}

func capture(g *gateway.Engine) sources {
	return sources{resources: g.Store.Snapshot(), policy: g.Policies.Snapshot(), tools: g.Tools.Snapshot(), outputPolicy: g.OutputPolicies.Snapshot(), audit: g.Audit.View(SampleLimit, "")}
}

func (s sources) stamp(product Product) SourceStamp {
	return SourceStamp{ProductRevision: product.Revision, GatewayRevision: s.resources.Revision, PolicyRevision: s.policy.Revision, ToolRevision: s.tools.Revision, OutputPolicyRevision: s.outputPolicy.Revision, AuditBytes: s.audit.Bytes, AuditAvailable: s.audit.Available}
}

func currentStamp(g *gateway.Engine, product Product) SourceStamp {
	audit := g.Audit.View(1, "")
	return SourceStamp{ProductRevision: product.Revision, GatewayRevision: g.Store.Snapshot().Revision, PolicyRevision: g.Policies.Snapshot().Revision, ToolRevision: g.Tools.Snapshot().Revision, OutputPolicyRevision: g.OutputPolicies.Snapshot().Revision, AuditBytes: audit.Bytes, AuditAvailable: audit.Available}
}

func (s sources) input(product Product, now time.Time) compliance.Input {
	input := compliance.Input{PackID: product.PackID, PackVersion: product.PackVersion, ProductID: product.ID, ProductVersion: product.Version, Facts: cloneProduct(product).Facts}
	observed := now.UTC().Format(time.RFC3339Nano)
	configEvidence := fmt.Sprintf("gw-%d-policy-%d", s.resources.Revision, s.policy.Revision)
	add := func(name string, value any, evidence string) {
		data, _ := json.Marshal(value)
		input.Facts["runtime."+name] = compliance.Fact{Value: data, EvidenceID: evidence, Source: "runtime", ObservedAt: observed}
	}
	add("credential_policy_mode", s.policy.Mode, configEvidence)
	add("credential_policy_revision", s.policy.Revision, configEvidence)
	add("gateway_revision", s.resources.Revision, configEvidence)
	add("credential_private_key_rule_enabled", slices.Contains(s.policy.Rules, "private_key"), configEvidence)
	add("credential_api_key_rule_enabled", slices.Contains(s.policy.Rules, "api_key"), configEvidence)
	apps, connections := map[string]gateway.Application{}, map[string]bool{}
	for _, app := range s.resources.Applications {
		apps[app.ID] = app
	}
	for _, connection := range s.resources.Connections {
		connections[connection.ID] = true
	}
	selectedApps, selectedConnections := map[string]bool{}, map[string]bool{}
	for _, id := range s.policy.ApplicationIDs {
		selectedApps[id] = true
	}
	for _, id := range s.policy.ConnectionIDs {
		selectedConnections[id] = true
	}
	appsKnown, coverageKnown, covered, active := true, true, true, true
	for _, id := range product.ApplicationIDs {
		app, exists := apps[id]
		if !exists {
			appsKnown, coverageKnown = false, false
			continue
		}
		active = active && !app.Revoked
		if len(app.AllowedConnections) == 0 {
			coverageKnown = false
		}
		if len(selectedApps) > 0 && !selectedApps[id] {
			covered = false
		}
		for _, connection := range app.AllowedConnections {
			if !connections[connection] {
				coverageKnown = false
			}
			if len(selectedConnections) > 0 && !selectedConnections[connection] {
				covered = false
			}
		}
	}
	if appsKnown {
		add("applications_active", active, configEvidence)
	}
	if coverageKnown {
		add("credential_policy_covers_product", covered, configEvidence)
	}
	auditEvidence := fmt.Sprintf("audit-bytes-%d", s.audit.Bytes)
	add("audit_available", s.audit.Available, auditEvidence)
	if s.audit.Available {
		count, blocked, observedMatches, failed, incomplete := 0, 0, 0, 0, 0
		for _, record := range s.audit.Records {
			if record.Operation != "chat.completions" || !slices.Contains(product.ApplicationIDs, record.ApplicationID) {
				continue
			}
			if record.Outcome == "incomplete" {
				incomplete++
				continue
			}
			if record.Phase != "finished" {
				continue
			}
			count++
			if record.ErrorCode == "policy_blocked" {
				blocked++
			}
			if record.ContentPolicy != nil && record.ContentPolicy.Result == "observe" {
				observedMatches++
			}
			if record.Outcome == "failed" {
				failed++
			}
		}
		for name, value := range map[string]int{"request_count": count, "policy_block_count": blocked, "observed_match_count": observedMatches, "failed_count": failed, "incomplete_count": incomplete} {
			add("sample."+name, value, auditEvidence)
		}
	}
	s.addToolFacts(product, add)
	s.addOutputFacts(product, add)
	return input
}

func (s sources) addOutputFacts(product Product, add func(string, any, string)) {
	evidence := fmt.Sprintf("gw-%d-output-%d", s.resources.Revision, s.outputPolicy.Revision)
	add("output_policy_revision", s.outputPolicy.Revision, evidence)
	mode := s.outputPolicy.Mode
	if mode == "" {
		mode = "disabled"
	}
	add("output_policy_mode", mode, evidence)
	add("output_detector_version", s.outputPolicy.DetectorVersion, evidence)
	for _, category := range []string{"credential", "email", "phone"} {
		add("output_"+category+"_enabled", slices.Contains(s.outputPolicy.Categories, category), evidence)
	}
	known, covered := true, len(product.ApplicationIDs) > 0
	for _, id := range product.ApplicationIDs {
		found := false
		for _, app := range s.resources.Applications {
			if app.ID == id {
				found = true
				break
			}
		}
		known = known && found
		covered = covered && s.outputPolicy.Applies(id)
	}
	if known {
		add("output_policy_covers_product", covered, evidence)
	}
	if !s.audit.Available {
		return
	}
	blocked, observed, unknown, redacted := 0, 0, 0, 0
	currentChecked, uncheckedReleases, incomplete := 0, 0, 0
	for _, record := range s.audit.Records {
		if (record.Operation != "chat.completions" && record.Operation != "tools.invoke") || !slices.Contains(product.ApplicationIDs, record.ApplicationID) {
			continue
		}
		if record.Outcome == "incomplete" {
			incomplete++
			continue
		}
		if record.Phase != "finished" {
			continue
		}
		checked := outputInspected(record)
		if record.Outcome == "completed" && (!checked || !allOutputCategories(record.OutputPolicy.Categories)) {
			// Includes old records, disabled/out-of-scope calls and partial
			// category checks. Missing checks are not observed disclosures.
			uncheckedReleases++
		}
		if record.OutputPolicy == nil {
			continue
		}
		if checked && record.OutputPolicy.Revision == s.outputPolicy.Revision && record.OutputPolicy.DetectorVersion == s.outputPolicy.DetectorVersion {
			currentChecked++
		}
		if record.ErrorCode == "content_output_blocked" {
			blocked++
		}
		if record.Outcome == "completed" && record.OutputPolicy.Result == "observe" {
			observed++
		}
		if record.Outcome == "completed" && record.OutputPolicy.Result == "redacted" && record.OutputPolicy.Redaction != nil {
			redacted++
		}
		if record.OutputPolicy.Result == "error" {
			unknown++
		}
	}
	auditEvidence := fmt.Sprintf("audit-bytes-%d", s.audit.Bytes)
	add("sample.output_block_count", blocked, auditEvidence)
	add("sample.output_observed_release_count", observed, auditEvidence)
	add("sample.output_unknown_count", unknown, auditEvidence)
	add("sample.output_redacted_count", redacted, auditEvidence)
	// Current-version evidence must not be borrowed from an older policy.
	add("sample.output_current_checked_count", currentChecked, fmt.Sprintf("%s-output-%d", auditEvidence, s.outputPolicy.Revision))
	add("sample.output_unchecked_release_count", uncheckedReleases, auditEvidence)
	add("sample.output_incomplete_count", incomplete, auditEvidence)
}

func allOutputCategories(categories []string) bool {
	return slices.Contains(categories, "credential") && slices.Contains(categories, "email") && slices.Contains(categories, "phone")
}

// Count actual model/tool checks, never standalone recommendations, pending
// findings, unknown results or failed attempts. Legacy tool blocking may take
// precedence after the sensitive-output detector has already inspected text.
func outputInspected(record gateway.CallRecord) bool {
	a := record.OutputPolicy
	if a == nil || a.ID != "sensitive-output" || !sensitive.Supports(a.DetectorVersion) || !record.UpstreamAttempted ||
		(a.State != "observed" && a.State != "not_observed") || (record.Outcome != "completed" && record.Outcome != "blocked") {
		return false
	}
	switch a.Result {
	case "allow", "observe":
		return true
	case "block", "redact":
		return record.Outcome == "blocked"
	case "redacted":
		return record.Outcome == "completed" && a.Redaction != nil
	default:
		return false
	}
}
