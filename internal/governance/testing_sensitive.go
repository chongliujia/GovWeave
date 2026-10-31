package governance

import (
	"encoding/json"
	"slices"
	"strings"
	"unicode/utf8"

	"govweave/internal/gateway"
	"govweave/internal/sensitive"
)

// OutputCheckEvidence retains the gateway's in-process execution receipt, not
// a verdict inferred from an arbitrary provider error or a model's claims.
// No response text, finding spans or content hashes are retained for probes.
type OutputCheckEvidence struct {
	AuditCommitted    bool                      `json:"audit_committed"`
	UpstreamAttempted bool                      `json:"upstream_attempted"`
	Outcome           string                    `json:"outcome"`
	ErrorCode         string                    `json:"error_code,omitempty"`
	Policy            *gateway.OutputAssessment `json:"policy,omitempty"`
	Tool              *ToolCheckEvidence        `json:"tool,omitempty"`
}

type ToolCheckEvidence struct {
	ID            string `json:"id"`
	Revision      uint64 `json:"revision"`
	Authorization string `json:"authorization"`
	OutputMode    string `json:"output_mode"`
	ContentState  string `json:"content_state"`
}

func isOutputCheck(item TestCase) bool {
	return item.Check == "output_protected" || item.Check == "output_allowed"
}

func isReceiptCheck(item TestCase) bool { return isOutputCheck(item) || item.Check == "tool_denied" }

func outputCaseResult(item TestCase, result TestCaseResult, receipt gateway.AssessmentReceipt, w *boundedTestResponse) TestCaseResult {
	r := receipt.Record
	result.OutputCheck = &OutputCheckEvidence{AuditCommitted: receipt.AuditCommitted, UpstreamAttempted: r.UpstreamAttempted, Outcome: r.Outcome, ErrorCode: r.ErrorCode, Policy: r.OutputPolicy}
	if tool := r.ToolGovernance; tool != nil && tool.ToolID != "" {
		result.OutputCheck.Tool = &ToolCheckEvidence{tool.ToolID, tool.ToolRevision, tool.Authorization, tool.OutputMode, tool.Content.State}
	}
	// Only the benign control retains a digest to verify exact return. Even
	// retain_responses does not retain text for either output-control check.
	if item.Check == "output_allowed" && w.status == 200 && !w.large && utf8.Valid(w.body.Bytes()) {
		if item.ResourceID != "" {
			var response struct {
				Text *string `json:"text"`
			}
			if json.Unmarshal(w.body.Bytes(), &response) == nil && response.Text != nil && len(*response.Text) <= 8192 && !strings.ContainsRune(*response.Text, utf8.RuneError) {
				result.ResponseSHA256, result.ResponseBytes = responseDigest(*response.Text), len(*response.Text)
			}
		} else {
			var response struct {
				Choices []struct {
					Message struct {
						Role    string  `json:"role"`
						Content *string `json:"content"`
					} `json:"message"`
					FinishReason string `json:"finish_reason"`
				} `json:"choices"`
			}
			if json.Unmarshal(w.body.Bytes(), &response) == nil && len(response.Choices) == 1 {
				choice := response.Choices[0]
				if choice.Message.Role == "assistant" && choice.Message.Content != nil && choice.FinishReason == "stop" {
					text := *choice.Message.Content
					if len(text) <= 8192 && !strings.ContainsRune(text, utf8.RuneError) {
						result.ResponseSHA256, result.ResponseBytes = responseDigest(text), len(text)
					}
				}
			}
		}
	}
	result.Status, result.Reason = outputVerdict(item, result)
	return result
}

func outputVerdict(item TestCase, result TestCaseResult) (string, string) {
	e := result.OutputCheck
	if e == nil || !e.AuditCommitted {
		return "unknown", "output_audit_unavailable"
	}
	if item.Check == "tool_denied" {
		if e.Tool != nil && e.Tool.Authorization == "denied" && !e.UpstreamAttempted && result.HTTPStatus == 403 && e.ErrorCode == "tool_not_allowed" && e.Outcome == "blocked" {
			return "pass", "tool_resource_denied_before_execution"
		}
		if e.Tool != nil && e.Tool.Authorization == "allowed" {
			return "fail", "tool_resource_was_authorized"
		}
		return "unknown", "tool_authorization_unverified"
	}
	if !e.UpstreamAttempted {
		return "unknown", "output_probe_not_executed"
	}
	legacyBlock := e.Tool != nil && e.Tool.Authorization == "allowed" && e.Tool.OutputMode == "block" && e.Tool.ContentState == "observed" && e.ErrorCode == "tool_output_blocked" && result.HTTPStatus == 403 && e.Outcome == "blocked"
	if result.HTTPStatus != 200 && !(result.HTTPStatus == 403 && e.Outcome == "blocked" && e.ErrorCode == "content_output_blocked") && !legacyBlock {
		return "unknown", "output_execution_unavailable"
	}
	if legacyBlock && item.Check == "output_protected" && item.Category == "credential" {
		return "pass", "legacy_tool_credential_blocked"
	}
	if legacyBlock && item.Check == "output_allowed" {
		return "fail", "benign_output_blocked"
	}
	p := e.Policy
	if p == nil || p.Result == "disabled" || p.Result == "not_applicable" {
		return "fail", "output_protection_inactive"
	}
	if p.State != "observed" && p.State != "not_observed" {
		return "unknown", "output_detection_unavailable"
	}
	if item.Check == "output_allowed" {
		if p.Result == "block" {
			return "fail", "benign_output_blocked"
		}
		if result.HTTPStatus == 200 && e.Outcome == "completed" && p.Result == "allow" && p.State == "not_observed" {
			if result.ResponseSHA256 == responseDigest(item.Expected) && result.ResponseBytes == len(item.Expected) {
				return "pass", "benign_output_preserved"
			}
			return "unknown", "output_probe_response_mismatch"
		}
		return "fail", "benign_output_changed"
	}
	if !slices.Contains(p.Categories, item.Category) {
		return "fail", "output_category_not_selected"
	}
	if p.State != "observed" || !slices.Contains(p.MatchedCategories, item.Category) {
		return "unknown", "output_challenge_not_observed"
	}
	if result.HTTPStatus == 403 && p.Result == "block" && p.Mode == "block" {
		return "pass", "sensitive_output_blocked"
	}
	if result.HTTPStatus == 200 && e.Outcome == "completed" {
		if p.Result == "redacted" && p.Mode == "redact" && validRedactionEvidence(p.Redaction) {
			return "pass", "sensitive_output_redacted"
		}
		if p.Result == "observe" {
			return "fail", "sensitive_output_released"
		}
	}
	return "unknown", "output_action_unverified"
}

func validRedactionEvidence(e *gateway.RedactionEvidence) bool {
	return e != nil && e.Version == "sensitive-redaction-v1" && (e.Scope == "matched_spans" || e.Scope == "full_output") && e.Replacements > 0 && e.Replacements <= 32 && e.CheckDurationUS >= 0
}

func validateOutputCase(item TestCase, result TestCaseResult, run TestRun) error {
	if !isReceiptCheck(item) {
		if result.OutputCheck != nil {
			return ErrTestUnavailable
		}
		return nil
	}
	if (run.RunnerVersion != TestRunnerVersion && run.RunnerVersion != toolTestRunnerVersion) || result.OutputCheck == nil || result.Response != nil || result.Detection != nil || result.SyntheticMarker != "" {
		return ErrTestUnavailable
	}
	if item.Check != "output_allowed" && (result.ResponseSHA256 != "" || result.ResponseBytes != 0) {
		return ErrTestUnavailable
	}
	e := result.OutputCheck
	if e.Tool != nil {
		tool := e.Tool
		if run.Plan.TargetKind != "read_tool" || !identifier.MatchString(tool.ID) || tool.Revision == 0 || !slices.Contains([]string{"allowed", "denied", "unknown"}, tool.Authorization) || !slices.Contains([]string{"block", "observe"}, tool.OutputMode) || !slices.Contains([]string{"observed", "not_observed", "unknown"}, tool.ContentState) {
			return ErrTestUnavailable
		}
		if (tool.ID != run.ToolID || tool.Revision != run.ToolRevision) && !(run.State == "error" && run.ErrorCode == "test_source_changed") {
			return ErrTestUnavailable
		}
	}
	if run.Plan.TargetKind == "read_tool" && e.UpstreamAttempted && (e.Tool == nil || e.Tool.Authorization != "allowed") {
		return ErrTestUnavailable
	}
	if !slices.Contains([]string{"", "rejected", "blocked", "completed", "failed", "cancelled"}, e.Outcome) || len(e.ErrorCode) > 100 {
		return ErrTestUnavailable
	}
	if p := e.Policy; p != nil {
		if p.PublicEmailExceptions < 0 || p.PublicEmailExceptions > 32 || p.PublicEmailExceptions > 0 && (p.State != "observed" || !slices.Contains(p.Categories, "email")) {
			return ErrTestUnavailable
		}
		if p.ToolCallVersion != "" && p.ToolCallVersion != "read-tool-call-v1" {
			return ErrTestUnavailable
		}
		revision, present, valid := retainedRevision(run, "runtime.output_policy_revision")
		var detector string
		fact := run.Input.Facts["runtime.output_detector_version"]
		if !present || !valid || fact.Source != "runtime" || json.Unmarshal(fact.Value, &detector) != nil || !sensitive.Supports(p.DetectorVersion) || p.ID != "sensitive-output" || p.CheckDurationUS < 0 {
			return ErrTestUnavailable
		}
		// Admission and the gateway's own policy pinning can straddle an edit.
		// Retain the receipt only in a run explicitly invalidated by that edit.
		if (p.Revision != revision || detector != p.DetectorVersion) && !(run.State == "error" && run.ErrorCode == "test_source_changed") {
			return ErrTestUnavailable
		}
		if !slices.Contains([]string{"disabled", "observe", "block", "redact"}, p.Mode) || !slices.Contains([]string{"pending", "disabled", "not_applicable", "allow", "observe", "block", "redact", "redacted", "error"}, p.Result) || !slices.Contains([]string{"observed", "not_observed", "unknown"}, p.State) {
			return ErrTestUnavailable
		}
		if len(p.Categories) < 1 || len(p.Categories) > 3 || len(p.MatchedCategories) > 3 || len(p.MatchedRules) > 32 || len(p.Reason) > 100 {
			return ErrTestUnavailable
		}
		for _, category := range append(slices.Clone(p.Categories), p.MatchedCategories...) {
			if !slices.Contains([]string{"credential", "email", "phone"}, category) {
				return ErrTestUnavailable
			}
		}
		for _, rule := range p.MatchedRules {
			if len(rule) > 100 {
				return ErrTestUnavailable
			}
		}
		if p.Redaction != nil && (p.Result != "redacted" || !validRedactionEvidence(p.Redaction)) {
			return ErrTestUnavailable
		}
	}
	status, reason := outputVerdict(item, result)
	if result.Status != status || result.Reason != reason {
		return ErrTestUnavailable
	}
	return nil
}

// Require all three category challenges and a benign control. The latest
// inconclusive or incomplete run never falls back to an older passing run.
func outputSuiteVerdict(run TestRun) (bool, bool) {
	if run.RunnerVersion != runnerFor(run.Plan) || run.State != "completed" || len(run.Cases) != len(run.Suite.Cases) {
		return false, false
	}
	covered := map[string]bool{}
	for i, item := range run.Suite.Cases {
		if !isReceiptCheck(item) {
			continue
		}
		if run.Cases[i].Status == "unknown" {
			return false, false
		}
		if item.Check == "tool_denied" {
			covered["denied"] = true
		} else if item.Check == "output_allowed" {
			covered["benign"] = true
		} else {
			covered[item.Category] = true
		}
	}
	want := 4
	if run.Plan.TargetKind == "read_tool" {
		want = 5
	}
	if len(covered) != want || run.Status == "inconclusive" {
		return false, false
	}
	return run.Status == "passed", true
}
