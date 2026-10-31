package governance

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"

	"govweave/internal/compliance"
	"govweave/internal/gateway"
)

// RuntimeEvidence freezes the exact, application-scoped audit sample behind
// numeric runtime facts. It is independent of the optional encrypted content
// vault, and never embeds request/response bodies or application credentials.
type RuntimeEvidence struct {
	Version             string                `json:"version"`
	Selection           string                `json:"selection"`
	Coverage            string                `json:"coverage"`
	AuditBytes          int64                 `json:"audit_bytes"`
	GlobalSampleSize    int                   `json:"global_sample_size"`
	HistoryMayBeMissing bool                  `json:"history_may_be_missing"`
	Records             []gateway.CallRecord  `json:"records"`
	Facts               []RuntimeFactEvidence `json:"facts"`
}

type RuntimeFactEvidence struct {
	Fact              string   `json:"fact"`
	EvidenceID        string   `json:"evidence_id"`
	Value             int      `json:"value"`
	SourceRequestIDs  []string `json:"source_request_ids"`
	MatchedRequestIDs []string `json:"matched_request_ids"`
}

func runtimeEvidence(product Product, input compliance.Input, source sources) *RuntimeEvidence {
	if !source.audit.Available {
		return nil
	}
	e := &RuntimeEvidence{Version: "runtime-evidence-v1", Selection: "product_applications_from_global_recent_100",
		Coverage: "gateway_observed_sample", AuditBytes: source.audit.Bytes, GlobalSampleSize: len(source.audit.Records),
		HistoryMayBeMissing: true, Records: []gateway.CallRecord{}, Facts: []RuntimeFactEvidence{}}
	for _, record := range source.audit.Records {
		if slices.Contains(product.ApplicationIDs, record.ApplicationID) && (record.Operation == "chat.completions" || record.Operation == "tools.invoke") {
			e.Records = append(e.Records, record)
		}
	}
	keys := make([]string, 0)
	for name := range input.Facts {
		if strings.HasPrefix(name, "runtime.sample.") || strings.HasPrefix(name, "runtime.tools.sample.") {
			keys = append(keys, name)
		}
	}
	sort.Strings(keys)
	for _, name := range keys {
		fact := input.Facts[name]
		var value int
		if json.Unmarshal(fact.Value, &value) != nil {
			continue
		}
		ref := RuntimeFactEvidence{Fact: name, EvidenceID: fact.EvidenceID, Value: value, SourceRequestIDs: []string{}, MatchedRequestIDs: []string{}}
		for _, record := range e.Records {
			included, matched := runtimeFactMatch(name, record, source.outputPolicy.Revision, source.outputPolicy.DetectorVersion)
			if included {
				ref.SourceRequestIDs = append(ref.SourceRequestIDs, record.RequestID)
			}
			if matched {
				ref.MatchedRequestIDs = append(ref.MatchedRequestIDs, record.RequestID)
			}
		}
		e.Facts = append(e.Facts, ref)
	}
	return cloneRuntimeEvidence(e)
}

func runtimeFactMatch(name string, r gateway.CallRecord, outputRevision uint64, detector string) (bool, bool) {
	tool := strings.HasPrefix(name, "runtime.tools.sample.")
	output := strings.HasPrefix(name, "runtime.sample.output_")
	if tool && r.Operation != "tools.invoke" || !tool && !output && r.Operation != "chat.completions" {
		return false, false
	}
	key := strings.TrimPrefix(strings.TrimPrefix(name, "runtime.tools.sample."), "runtime.sample.")
	if r.Outcome == "incomplete" {
		return true, key == "incomplete_count" || output && key == "output_incomplete_count"
	}
	if r.Phase != "finished" {
		return true, false
	}
	if output {
		p := r.OutputPolicy
		switch key {
		case "output_unchecked_release_count":
			return true, r.Outcome == "completed" && (!outputInspected(r) || !allOutputCategories(p.Categories))
		case "output_current_checked_count":
			return true, outputInspected(r) && p.Revision == outputRevision && p.DetectorVersion == detector
		case "output_block_count":
			return true, p != nil && r.ErrorCode == "content_output_blocked"
		case "output_observed_release_count":
			return true, p != nil && r.Outcome == "completed" && p.Result == "observe"
		case "output_redacted_count":
			return true, p != nil && r.Outcome == "completed" && p.Result == "redacted" && p.Redaction != nil
		case "output_unknown_count":
			return true, p != nil && p.Result == "error"
		default:
			return true, false
		}
	}
	switch key {
	case "request_count":
		return true, true
	case "failed_count":
		return true, r.Outcome == "failed"
	case "cancelled_count":
		return true, r.Outcome == "cancelled"
	case "completed_count":
		return true, r.Outcome == "completed"
	case "policy_block_count":
		return true, r.ErrorCode == "policy_blocked"
	case "observed_match_count":
		return true, r.ContentPolicy != nil && r.ContentPolicy.Result == "observe"
	case "authorization_denied_count":
		return true, r.ErrorCode == "tool_not_allowed"
	case "output_block_count":
		return true, r.ErrorCode == "tool_output_blocked"
	case "observed_release_count":
		g := r.ToolGovernance
		return true, r.Outcome == "completed" && g != nil && g.Content.State == "observed" && (g.Decision == "observe" || g.Decision == "redact" && g.OutputPolicy != nil && g.OutputPolicy.Redaction != nil && g.OutputPolicy.Redaction.Scope != "full_output")
	case "output_checked_count", "unknown_output_count":
		checked := r.ToolGovernance != nil && (r.ToolGovernance.Content.State == "observed" || r.ToolGovernance.Content.State == "not_observed")
		return true, r.UpstreamAttempted && (checked == (key == "output_checked_count"))
	default:
		return true, false
	}
}

func cloneRuntimeEvidence(value *RuntimeEvidence) *RuntimeEvidence {
	if value == nil {
		return nil
	}
	data, _ := json.Marshal(value)
	var copy RuntimeEvidence
	_ = json.Unmarshal(data, &copy)
	return &copy
}

func validateRuntimeEvidence(e *RuntimeEvidence, snapshot ReportSnapshot) error {
	if e == nil { // Reports created before this feature remain replayable.
		return nil
	}
	if e.Version != "runtime-evidence-v1" || e.Selection != "product_applications_from_global_recent_100" || e.Coverage != "gateway_observed_sample" || !e.HistoryMayBeMissing || e.AuditBytes != snapshot.Report.Snapshot.AuditBytes || e.GlobalSampleSize < len(e.Records) || e.GlobalSampleSize > SampleLimit || len(e.Facts) > 32 || !snapshot.Report.Snapshot.AuditAvailable {
		return ErrArchiveUnavailable
	}
	seen := map[string]bool{}
	for _, r := range e.Records {
		if seen[r.RequestID] || !slices.Contains(snapshot.Product.ApplicationIDs, r.ApplicationID) || (r.Operation != "chat.completions" && r.Operation != "tools.invoke") || r.RequestID == "" {
			return ErrArchiveUnavailable
		}
		seen[r.RequestID] = true
	}
	var detector string
	_ = json.Unmarshal(snapshot.Input.Facts["runtime.output_detector_version"].Value, &detector)
	source := sources{audit: gateway.AuditView{Available: true, Bytes: e.AuditBytes, Records: e.Records}, outputPolicy: gateway.OutputPolicySnapshot{OutputPolicyInput: gateway.OutputPolicyInput{Revision: snapshot.Report.Snapshot.OutputPolicyRevision, DetectorVersion: detector}}}
	expected := runtimeEvidence(snapshot.Product, snapshot.Input, source)
	if !reflect.DeepEqual(expected.Facts, e.Facts) {
		return ErrArchiveUnavailable
	}
	for _, ref := range e.Facts {
		expectedID := fmt.Sprintf("audit-bytes-%d", e.AuditBytes)
		if ref.Fact == "runtime.sample.output_current_checked_count" {
			expectedID = fmt.Sprintf("%s-output-%d", expectedID, snapshot.Report.Snapshot.OutputPolicyRevision)
		}
		if ref.Value != len(ref.MatchedRequestIDs) || ref.EvidenceID != expectedID {
			return ErrArchiveUnavailable
		}
	}
	return nil
}
