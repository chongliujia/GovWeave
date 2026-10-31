package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"govweave/internal/sensitive"
)

const ToolGovernanceVersion = "read-tool-governance-v1"
const maxToolRequestBytes = 4 << 10
const maxToolEnvelopeBytes = 64 << 10
const maxToolTextBytes = 8192

var toolArgumentID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,99}$`)

// These fixed fields deliberately exclude resource identifiers, grant lists,
// content, caller metadata, endpoints and credentials. Sensitivity is an
// administrator-supplied classification, not an inferred risk probability.
type ToolGovernance struct {
	InstructionPolicy *InstructionAssessment `json:"instruction_policy,omitempty"`
	PolicyVersion     string                 `json:"policy_version"`
	RulesetVersion    string                 `json:"ruleset_version"`
	ToolID            string                 `json:"tool_id,omitempty"`
	ToolRevision      uint64                 `json:"tool_revision"`
	SnapshotSHA256    string                 `json:"snapshot_sha256,omitempty"`
	OutputMode        string                 `json:"output_mode,omitempty"`
	Action            string                 `json:"action"`
	Authorization     string                 `json:"authorization"`
	DataSensitivity   string                 `json:"data_sensitivity"`
	Content           ToolContent            `json:"content"`
	Decision          string                 `json:"decision"`
	Reasons           []string               `json:"reasons"`
	OutputPolicy      *OutputAssessment      `json:"output_policy,omitempty"`
}

type ToolContent struct {
	State   string   `json:"state"`
	RuleIDs []string `json:"rule_ids"`
}

func newToolGovernance() *ToolGovernance {
	return &ToolGovernance{
		PolicyVersion: ToolGovernanceVersion, RulesetVersion: credentialRuleset,
		Action: "read", Authorization: "unknown", DataSensitivity: "unknown",
		Content:  ToolContent{State: "unknown", RuleIDs: []string{}},
		Decision: "block", Reasons: []string{},
	}
}

// ToolInvoke executes only the fixed read protocol. The application key and a
// server-owned resource grant are the authority; a model's proposed arguments
// never supply identity, permission, endpoint or an executable command.
func (g *Engine) ToolInvoke(w http.ResponseWriter, r *http.Request) {
	g.toolInvoke(w, r, "", nil)
}

// ToolAssessmentEvidence is an in-process path for administrator-owned jobs.
// Public HTTP handlers never accept an application ID instead of an API key.
func (g *Engine) ToolAssessmentEvidence(w http.ResponseWriter, r *http.Request, applicationID string) AssessmentReceipt {
	var receipt AssessmentReceipt
	if applicationID == "" {
		failure(w, 401, "invalid_api_key", "")
		return receipt
	}
	g.toolInvoke(w, r, applicationID, &receipt)
	return receipt
}

func (g *Engine) toolInvoke(w http.ResponseWriter, r *http.Request, applicationID string, receipt *AssessmentReceipt) {
	operation := "tools.invoke"
	if applicationID != "" {
		operation = "assessment.tools.invoke"
	}
	record, start, err := g.newRecord(operation)
	if err != nil {
		failure(w, 503, "gateway_unavailable", "")
		return
	}
	w.Header().Set("X-Request-ID", record.RequestID)
	assessment := newToolGovernance()
	record.ToolGovernance = assessment
	finished := false
	committed := false
	var evidence *callEvidence
	defer func() {
		if !finished {
			committed = g.finish(&record, start)
		}
		g.finishCallEvidence(evidence, record.RequestID, committed, "withheld")
		if receipt != nil {
			receipt.Record, receipt.AuditCommitted = cloneCallRecord(record), committed
		}
	}()
	// Persist the terminal decision before releasing any provider text. Audit
	// failure after admission therefore also prevents output release.
	reply := func(status int, code, text string) {
		record.HTTPStatus, record.ErrorCode = status, code
		if code != "" {
			unavailableOutput(record.OutputPolicy)
			assessment.Decision, assessment.Reasons = "block", []string{code}
			record.Decision = "deny"
		} else {
			record.Decision = "allow"
		}
		record.DurationMS = time.Since(start).Milliseconds()
		auditErr := g.Audit.Finish(record)
		committed = auditErr == nil
		if auditErr != nil {
			status, code, text = 503, "audit_unavailable", ""
			assessment.Decision, assessment.Reasons = "block", []string{code}
		}
		finished = true
		g.NotifyChange()
		if code != "" {
			g.finishCallEvidence(evidence, record.RequestID, committed, "withheld")
			respond(w, status, map[string]any{
				"request_id": record.RequestID, "governance": assessment,
				"error": map[string]string{"code": code, "type": "tool_governance_error", "message": toolErrorMessage(code)},
			})
			return
		}
		if record.OutputPolicy != nil && record.OutputPolicy.Result == "redacted" {
			w.Header().Set("X-GovWeave-Output-Action", "redacted")
		}
		result := map[string]any{"request_id": record.RequestID, "text": text, "governance": assessment}
		evidence.response(result)
		g.finishCallEvidence(evidence, record.RequestID, committed, "release_prepared")
		respond(w, status, result)
	}
	app, revision, err := g.Store.Authenticate(r.Header.Get("Authorization"))
	if applicationID != "" {
		_, app, revision, err = g.Tools.ResolveAssessment(applicationID, r.PathValue("alias"), "")
		if errors.Is(err, ErrToolDenied) {
			err = nil
		}
	}
	record.ApplicationID, record.PolicyRevision = app.ID, revision
	if err != nil {
		assessment.Authorization, record.Outcome = "denied", "blocked"
		reply(401, "invalid_api_key", "")
		return
	}
	initialApplicationID := app.ID
	if err := captureTrace(w, r, &record); err != nil {
		status, code := traceContextError(err)
		reply(status, code, "")
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		reply(415, "unsupported_media_type", "")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxToolRequestBytes))
	if err != nil {
		var large *http.MaxBytesError
		if errors.As(err, &large) {
			reply(413, "request_too_large", "")
		} else {
			reply(400, "invalid_tool_request", "")
		}
		return
	}
	resourceID, err := toolStringObject(body, "resource_id")
	if err != nil || !toolArgumentID.MatchString(resourceID) || !toolArgumentID.MatchString(r.PathValue("alias")) {
		reply(400, "invalid_tool_request", "")
		return
	}
	// Recheck key revocation/rotation and resolve grants under a consistent
	// application->tool lock order after the body is read. This immutable
	// snapshot governs the admitted call; subsequent edits affect later calls.
	resolved, app, revision, err := g.Tools.ResolveAuthorized(r.Header.Get("Authorization"), r.PathValue("alias"), resourceID)
	if applicationID != "" {
		resolved, app, revision, err = g.Tools.ResolveAssessment(applicationID, r.PathValue("alias"), resourceID)
	}
	record.ApplicationID, record.PolicyRevision = app.ID, revision
	rebindTrace(w, &record, initialApplicationID)
	assessment.ToolID, assessment.ToolRevision = resolved.Tool.ID, resolved.Tool.Revision
	assessment.SnapshotSHA256, assessment.OutputMode = resolved.Tool.SnapshotSHA256, resolved.Tool.OutputMode
	if resolved.Resource.Sensitivity != "" {
		assessment.DataSensitivity = resolved.Resource.Sensitivity
	}
	if err != nil {
		evidence = g.beginCallEvidence(record, nil)
		assessment.Authorization, record.Outcome = "denied", "blocked"
		switch {
		case errors.Is(err, ErrInvalidKey):
			reply(401, "invalid_api_key", "")
		case errors.Is(err, ErrToolDenied):
			reply(403, "tool_not_allowed", "")
		default:
			assessment.Authorization, record.Outcome = "unknown", "failed"
			reply(503, "credential_unavailable", "")
		}
		return
	}
	evidence = g.beginCallEvidence(record, body)
	evidence.toolPolicy(resolved)
	assessment.Authorization, assessment.Decision = "allowed", "pending"
	outputSnapshot := g.OutputPolicies.Snapshot()
	protected := outputSnapshot.Applies(app.ID)
	if protected {
		record.OutputPolicy = pendingOutputPolicy(outputSnapshot)
		assessment.OutputPolicy = record.OutputPolicy
	}
	assessment.Reasons = []string{"resource_grant_allowed", "output_check_pending"}
	select {
	case g.slots <- struct{}{}:
		defer func() { <-g.slots }()
	default:
		reply(429, "gateway_busy", "")
		return
	}
	if err := r.Context().Err(); err != nil {
		record.Outcome = "cancelled"
		reply(499, "client_cancelled", "")
		return
	}
	if err := g.Audit.Begin(record); err != nil {
		reply(503, "audit_unavailable", "")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(resolved.Tool.TimeoutSeconds)*time.Second)
	defer cancel()
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(time.Duration(resolved.Tool.TimeoutSeconds+5) * time.Second))
	payload, _ := json.Marshal(map[string]string{"resource_id": resourceID})
	// The NopCloser prevents GetBody from being set: no automatic POST replay.
	upstream, err := http.NewRequestWithContext(ctx, http.MethodPost, resolved.Tool.Endpoint, io.NopCloser(bytes.NewReader(payload)))
	if err != nil {
		record.Outcome = "failed"
		reply(502, "upstream_unreachable", "")
		return
	}
	upstream.ContentLength = int64(len(payload))
	upstream.Header.Set("Content-Type", "application/json")
	upstream.Header.Set("Accept", "application/json")
	upstream.Header.Set("User-Agent", "GovWeave/0.2")
	upstream.Header.Set("X-GovWeave-Request-ID", record.RequestID)
	if resolved.APIKey != "" {
		upstream.Header.Set("Authorization", "Bearer "+resolved.APIKey)
	}
	evidence.observe("upstream_request", payload)
	record.UpstreamAttempted, record.Outcome = true, "failed"
	response, err := g.client.Do(upstream)
	if err != nil {
		status, code := requestError(ctx, r.Context(), err)
		if code == "client_cancelled" {
			record.Outcome = "cancelled"
		}
		reply(status, code, "")
		return
	}
	defer response.Body.Close()
	record.UpstreamStatus = response.StatusCode
	if response.StatusCode != http.StatusOK {
		reply(502, "upstream_error", "")
		return
	}
	media, _, err = mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		reply(502, "invalid_upstream_response", "")
		return
	}
	data, err := io.ReadAll(io.LimitReader(&firstByteReader{reader: response.Body, record: &record, start: start}, maxToolEnvelopeBytes+1))
	if err != nil {
		status, code := requestError(ctx, r.Context(), err)
		if code == "client_cancelled" {
			record.Outcome = "cancelled"
		}
		reply(status, code, "")
		return
	}
	if len(data) > maxToolEnvelopeBytes {
		reply(502, "response_too_large", "")
		return
	}
	text, err := toolStringObject(data, "text")
	if err != nil {
		reply(502, "invalid_upstream_response", "")
		return
	}
	if protected && strings.ContainsRune(text, utf8.RuneError) {
		reply(502, "content_output_unavailable", "")
		return
	}
	if len(text) > maxToolTextBytes {
		reply(502, "response_too_large", "")
		return
	}
	evidence.observe("upstream_output", data)
	if err := ctx.Err(); err != nil {
		status, code := requestError(ctx, r.Context(), err)
		if code == "client_cancelled" {
			record.Outcome = "cancelled"
		}
		reply(status, code, "")
		return
	}
	assessment.Content.State = "not_observed"
	assessment.InstructionPolicy = assessInstructions(resolved.Tool.InstructionPolicy, text, resolved.Resource.InstructionReview)
	var detection sensitive.Result
	if protected {
		detection = sensitive.Scan([]byte(text), outputSnapshot.DetectorVersion)
		record.OutputPolicy = assessOutputText(outputSnapshot, app.ID, text, detection)
		assessment.OutputPolicy = record.OutputPolicy
	}
	for _, rule := range credentialRules {
		if rule.pattern.MatchString(text) {
			assessment.Content.State = "observed"
			assessment.Content.RuleIDs = append(assessment.Content.RuleIDs, rule.id)
		}
	}
	if assessment.Content.State == "observed" && resolved.Tool.OutputMode == "block" {
		record.Outcome = "blocked"
		reply(403, "tool_output_blocked", "")
		return
	}
	if a := assessment.InstructionPolicy; a != nil {
		if a.Decision == "block" {
			record.Outcome = "blocked"
			reply(403, "tool_instruction_blocked", "")
			return
		}
		if a.Decision == "error" {
			record.Outcome = "failed"
			reply(502, "tool_instruction_unavailable", "")
			return
		}
	}
	if protected && record.OutputPolicy.Result == "block" {
		record.Outcome = "blocked"
		reply(403, "content_output_blocked", "")
		return
	}
	if protected && record.OutputPolicy.Result == "error" {
		record.Outcome = "failed"
		reply(502, "content_output_unavailable", "")
		return
	}
	assessment.Decision, assessment.Reasons = "allow", []string{"resource_grant_allowed", "credential_patterns_not_observed"}
	if a := assessment.InstructionPolicy; a != nil && a.State == "observed" && a.Decision == "allow" {
		assessment.Reasons = []string{"resource_grant_allowed", "instruction_review_applied"}
	}
	if assessment.Content.State == "observed" {
		assessment.Decision, assessment.Reasons = "observe", []string{"resource_grant_allowed", "credential_patterns_observed"}
	}
	if protected && record.OutputPolicy.Result == "observe" {
		assessment.Decision, assessment.Reasons = "observe", []string{"resource_grant_allowed", "content_patterns_observed"}
	}
	if a := assessment.InstructionPolicy; a != nil && a.Decision == "observe" {
		assessment.Decision, assessment.Reasons = "observe", []string{"resource_grant_allowed", "instruction_patterns_observed"}
	}
	if protected && record.OutputPolicy.Result == "redact" {
		text, err = applyOutputRedaction(text, outputSnapshot, detection, record.OutputPolicy)
		if err != nil {
			record.Outcome = "failed"
			reply(502, "content_output_unavailable", "")
			return
		}
		assessment.Decision, assessment.Reasons = "redact", []string{"resource_grant_allowed", "content_redacted"}
	}
	if ctx.Err() != nil {
		status, code := requestError(ctx, r.Context(), ctx.Err())
		record.Outcome = "failed"
		if code == "client_cancelled" {
			record.Outcome = "cancelled"
		}
		reply(status, code, "")
		return
	}
	record.Outcome = "completed"
	reply(200, "", text)
}

// Exactly one named string field, with no duplicate keys, extras, trailing
// values or invalid UTF-8. This also rejects missing and null text values.
func toolStringObject(data []byte, field string) (string, error) {
	invalid := errors.New("invalid_tool_object")
	if !utf8.Valid(data) {
		return "", invalid
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') || !decoder.More() {
		return "", invalid
	}
	name, err := decoder.Token()
	if err != nil || name != field {
		return "", invalid
	}
	value, err := decoder.Token()
	text, ok := value.(string)
	if err != nil || !ok || decoder.More() {
		return "", invalid
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return "", invalid
	}
	if _, err := decoder.Token(); err != io.EOF {
		return "", invalid
	}
	return text, nil
}

func toolErrorMessage(code string) string {
	switch code {
	case "invalid_api_key":
		return "Use a valid application key."
	case "tool_not_allowed":
		return "This application is not permitted to read this resource through this tool."
	case "invalid_tool_request":
		return "Provide exactly one resource_id string using 1–100 letters, digits, dots, underscores or hyphens."
	case "invalid_trace_context":
		return "Use bounded hexadecimal trace identifiers and at most four unique span links."
	case "trace_unavailable":
		return "A trace span could not be allocated. No tool request was sent."
	case "request_too_large":
		return "Tool requests must not exceed 4 KiB."
	case "unsupported_media_type":
		return "Use application/json."
	case "tool_output_blocked":
		return "Tool output was withheld by the credential policy. Use the request ID to inspect the decision."
	case "tool_instruction_blocked":
		return "Tool output was withheld by the instruction policy. Use the request ID to inspect the decision."
	case "tool_instruction_unavailable":
		return "Tool output could not be checked for instruction patterns and was withheld."
	case "content_output_blocked":
		return "Tool output was withheld by the sensitive-output policy. Use the request ID to inspect the decision."
	case "content_output_unavailable":
		return "Tool output could not be completely checked and was withheld."
	case "audit_unavailable":
		return "The decision could not be saved reliably. No tool output was released."
	case "gateway_busy":
		return "The concurrent request limit has been reached."
	case "upstream_timeout":
		return "The configured tool timed out."
	case "client_cancelled":
		return "The client cancelled the request."
	case "response_too_large":
		return "Tool output exceeds the supported size limit."
	case "invalid_upstream_response":
		return "The configured tool returned an invalid or unsupported response."
	default:
		return "The configured tool could not complete this request."
	}
}
