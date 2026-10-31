package governance

import "fmt"

// Tool coverage describes server-owned grants and output policy configuration.
// It does not establish that a product routes every call through this gateway,
// that a declared read provider has no side effects, or that end users are
// authorized. Application activity remains a separate runtime fact.
func (s sources) addToolFacts(product Product, add func(string, any, string)) {
	configEvidence := fmt.Sprintf("tool-config-gw-%d-tools-%d", s.resources.Revision, s.tools.Revision)
	add("tools.revision", s.tools.Revision, configEvidence)
	boundApps, knownApps := map[string]bool{}, map[string]bool{}
	for _, id := range product.ApplicationIDs {
		boundApps[id] = true
	}
	for _, app := range s.resources.Applications {
		knownApps[app.ID] = true
	}
	appsKnown := true
	for id := range boundApps {
		appsKnown = appsKnown && knownApps[id]
	}
	coveredApps := map[string]bool{}
	grantedTools := map[string]bool{}
	blocking := true
	for _, tool := range s.tools.Tools {
		if !tool.Enabled {
			continue
		}
		granted := false
		for _, resource := range tool.Resources {
			for _, id := range resource.AllowedApplications {
				if boundApps[id] {
					coveredApps[id], granted = true, true
				}
			}
		}
		if granted {
			grantedTools[tool.ID] = true
			blocking = blocking && tool.OutputMode == "block"
		}
	}
	add("tools.granted_tool_count", len(grantedTools), configEvidence)
	if appsKnown {
		covered := len(boundApps) > 0 && len(coveredApps) == len(boundApps)
		add("tools.applications_covered", covered, configEvidence)
		add("tools.output_blocking_covers_product", covered && blocking, configEvidence)
	}
	if !s.audit.Available {
		return
	}
	counts := map[string]int{
		"request_count":              0,
		"completed_count":            0,
		"authorization_denied_count": 0,
		"output_block_count":         0,
		"observed_release_count":     0,
		"failed_count":               0,
		"cancelled_count":            0,
		"incomplete_count":           0,
		"output_checked_count":       0,
		"unknown_output_count":       0,
	}
	for _, record := range s.audit.Records {
		// ApplicationID in audit records comes from authenticated gateway
		// identity. Preserve historical evidence even if a bound app is now
		// absent; caller-provided identities never populate this field.
		if record.Operation != "tools.invoke" || !boundApps[record.ApplicationID] {
			continue
		}
		if record.Outcome == "incomplete" {
			counts["incomplete_count"]++
			continue
		}
		if record.Phase != "finished" {
			continue
		}
		counts["request_count"]++
		switch record.Outcome {
		case "completed":
			counts["completed_count"]++
			if tool := record.ToolGovernance; tool != nil {
				// An instruction-only observation is not a credential release.
				released := tool.Decision == "observe" && tool.Content.State == "observed"
				// Redacting selected contact fields does not remove a legacy
				// credential observation outside that policy's categories.
				if tool.Decision == "redact" && tool.Content.State == "observed" && tool.OutputPolicy != nil && tool.OutputPolicy.Redaction != nil && tool.OutputPolicy.Redaction.Scope != "full_output" {
					released = true
				}
				if released {
					counts["observed_release_count"]++
				}
			}
		case "failed":
			counts["failed_count"]++
		case "cancelled":
			counts["cancelled_count"]++
		}
		switch record.ErrorCode {
		case "tool_not_allowed":
			counts["authorization_denied_count"]++
		case "tool_output_blocked":
			counts["output_block_count"]++
		}
		if record.UpstreamAttempted {
			state := ""
			if record.ToolGovernance != nil {
				state = record.ToolGovernance.Content.State
			}
			if state == "observed" || state == "not_observed" {
				counts["output_checked_count"]++
			} else {
				// Missing or unsupported states never count as checked output.
				counts["unknown_output_count"]++
			}
		}
	}
	auditEvidence := fmt.Sprintf("audit-bytes-%d", s.audit.Bytes)
	for name, value := range counts {
		add("tools.sample."+name, value, auditEvidence)
	}
}
