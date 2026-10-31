package gateway

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"govweave/internal/sensitive"
)

// OutputAssessment contains fixed metadata only. Finding offsets are returned
// only by the explicit evaluation API, never persisted in the call log.
type OutputAssessment struct {
	PublicEmailExceptions int                `json:"public_email_exceptions,omitempty"`
	ToolCallVersion       string             `json:"tool_call_version,omitempty"`
	Redaction             *RedactionEvidence `json:"redaction,omitempty"`
	ID                    string             `json:"id"`
	Revision              uint64             `json:"revision"`
	DetectorVersion       string             `json:"detector_version"`
	Mode                  string             `json:"mode"`
	Result                string             `json:"result"`
	State                 string             `json:"state"`
	Reason                string             `json:"reason"`
	Categories            []string           `json:"categories"`
	MatchedCategories     []string           `json:"matched_categories"`
	MatchedRules          []string           `json:"matched_rules"`
	CheckDurationUS       int64              `json:"check_duration_us"`
}

func cloneOutputAssessment(in *OutputAssessment) *OutputAssessment {
	if in == nil {
		return nil
	}
	out := *in
	if in.Redaction != nil {
		value := *in.Redaction
		out.Redaction = &value
	}
	out.Categories = append([]string{}, in.Categories...)
	out.MatchedCategories = append([]string{}, in.MatchedCategories...)
	out.MatchedRules = append([]string{}, in.MatchedRules...)
	return &out
}

func pendingOutputPolicy(p OutputPolicySnapshot) *OutputAssessment {
	return &OutputAssessment{ID: p.ID, Revision: p.Revision, DetectorVersion: p.DetectorVersion, Mode: p.Mode,
		Result: "pending", State: "unknown", Reason: "output_check_pending", Categories: append([]string{}, p.Categories...),
		MatchedCategories: []string{}, MatchedRules: []string{}}
}

func assessOutput(p OutputPolicySnapshot, appID string, result sensitive.Result) *OutputAssessment {
	a := pendingOutputPolicy(p)
	a.State, a.Reason, a.CheckDurationUS = result.State, result.Reason, result.DurationUS
	for _, finding := range result.Findings {
		if !slices.Contains(p.Categories, finding.Category) {
			continue
		}
		if !slices.Contains(a.MatchedCategories, finding.Category) {
			a.MatchedCategories = append(a.MatchedCategories, finding.Category)
		}
		if !slices.Contains(a.MatchedRules, finding.RuleID) {
			a.MatchedRules = append(a.MatchedRules, finding.RuleID)
		}
	}
	slices.Sort(a.MatchedCategories)
	slices.Sort(a.MatchedRules)
	switch {
	case p.Mode == "disabled":
		a.Result = "disabled"
	case !p.Applies(appID):
		a.Result = "not_applicable"
	case result.State == "unknown":
		a.Result = "error"
	case len(a.MatchedCategories) == 0:
		a.Result = "allow"
	default:
		a.Result = p.Mode
	}
	return a
}

func unavailableOutput(a *OutputAssessment) {
	if a != nil && a.Result == "pending" {
		a.Result, a.State, a.Reason = "error", "unknown", "output_unavailable"
	}
}

func (g *Engine) EvaluateContent(w http.ResponseWriter, r *http.Request) {
	record, start, err := g.newRecord("content.evaluate")
	if err != nil {
		failure(w, 503, "gateway_unavailable", "")
		return
	}
	w.Header().Set("X-Request-ID", record.RequestID)
	var evidence *callEvidence
	reply := func(status int, code string, result any) {
		record.HTTPStatus, record.ErrorCode, record.DurationMS = status, code, time.Since(start).Milliseconds()
		if code != "" {
			record.Decision = "deny"
		}
		committed := g.Audit.Finish(record) == nil
		if !committed {
			status, code = 503, "audit_unavailable"
		}
		g.NotifyChange()
		if code != "" {
			g.finishCallEvidence(evidence, record.RequestID, committed, "withheld")
			failure(w, status, code, record.RequestID)
		} else {
			evidence.response(result)
			g.finishCallEvidence(evidence, record.RequestID, committed, "release_prepared")
			respond(w, status, result)
		}
	}
	app, revision, err := g.Store.Authenticate(r.Header.Get("Authorization"))
	record.ApplicationID, record.PolicyRevision = app.ID, revision
	if err != nil {
		reply(401, "invalid_api_key", nil)
		return
	}
	initialApplicationID := app.ID
	if err := captureTrace(w, r, &record); err != nil {
		status, code := traceContextError(err)
		reply(status, code, nil)
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		reply(415, "unsupported_media_type", nil)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxToolEnvelopeBytes))
	if err != nil {
		var large *http.MaxBytesError
		if errors.As(err, &large) {
			reply(413, "content_input_too_large", nil)
		} else {
			reply(400, "invalid_content_request", nil)
		}
		return
	}
	text, err := toolStringObject(body, "text")
	if err != nil || strings.ContainsRune(text, utf8.RuneError) {
		reply(400, "invalid_content_request", nil)
		return
	}
	if len(text) > sensitive.MaxBytes {
		reply(413, "content_input_too_large", nil)
		return
	}
	app, revision, err = g.Store.Authenticate(r.Header.Get("Authorization"))
	record.ApplicationID, record.PolicyRevision = app.ID, revision
	rebindTrace(w, &record, initialApplicationID)
	if err != nil {
		reply(401, "invalid_api_key", nil)
		return
	}
	evidence = g.beginCallEvidence(record, body)
	select {
	case g.slots <- struct{}{}:
		defer func() { <-g.slots }()
	default:
		reply(429, "gateway_busy", nil)
		return
	}
	if r.Context().Err() != nil {
		record.Outcome = "cancelled"
		reply(499, "client_cancelled", nil)
		return
	}
	p := g.OutputPolicies.Snapshot()
	record.OutputPolicy = pendingOutputPolicy(p)
	if err := g.Audit.Begin(record); err != nil {
		unavailableOutput(record.OutputPolicy)
		reply(503, "audit_unavailable", nil)
		return
	}
	result := sensitive.Scan([]byte(text), p.DetectorVersion)
	record.OutputPolicy = assessOutputText(p, app.ID, text, result)
	record.Outcome, record.Decision = "completed", "evaluated"
	reply(200, "", map[string]any{"request_id": record.RequestID, "detection": result, "policy": record.OutputPolicy})
}

// Project a complete text completion into a small known envelope. Provider
// extension fields, reasoning, arbitrary identifiers and alternate output
// channels are never forwarded unchecked when output protection is enabled.
func protectedCompletion(data []byte, alias, requestID string) ([]byte, string, error) {
	data, text, _, err := protectedCompletionWithTools(data, alias, requestID, false)
	return data, text, err
}

func protectedCompletionWithTools(data []byte, alias, requestID string, allowTools bool) ([]byte, string, bool, error) {
	invalid := errors.New("unsupported_output")
	if len(data) > maxToolEnvelopeBytes || !utf8.Valid(data) {
		return nil, "", false, invalid
	}
	var response struct {
		Choices []struct {
			Message struct {
				Role         string          `json:"role"`
				Content      *string         `json:"content"`
				ToolCalls    json.RawMessage `json:"tool_calls"`
				FunctionCall json.RawMessage `json:"function_call"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Usage *struct {
			PromptTokens     uint64 `json:"prompt_tokens"`
			CompletionTokens uint64 `json:"completion_tokens"`
			TotalTokens      uint64 `json:"total_tokens"`
		} `json:"usage"`
	}
	if json.Unmarshal(data, &response) != nil || len(response.Choices) != 1 {
		return nil, "", false, invalid
	}
	choice := response.Choices[0]
	if choice.Message.Role != "assistant" || (len(choice.Message.FunctionCall) > 0 && string(choice.Message.FunctionCall) != "null") {
		return nil, "", false, invalid
	}
	isTool := choice.FinishReason == "tool_calls"
	var message any
	var text string
	if isTool {
		if !allowTools || (choice.Message.Content != nil && *choice.Message.Content != "") {
			return nil, "", false, invalid
		}
		calls, resource, err := projectReadToolCall(choice.Message.ToolCalls, requestID)
		if err != nil {
			return nil, "", false, invalid
		}
		text = resource
		message = map[string]any{"role": "assistant", "content": nil, "tool_calls": calls}
	} else {
		if choice.FinishReason != "stop" || choice.Message.Content == nil || (len(choice.Message.ToolCalls) > 0 && string(choice.Message.ToolCalls) != "null" && string(choice.Message.ToolCalls) != "[]") {
			return nil, "", false, invalid
		}
		text = *choice.Message.Content
		message = map[string]string{"role": "assistant", "content": text}
	}
	if len(text) > sensitive.MaxBytes || strings.ContainsRune(text, utf8.RuneError) {
		return nil, "", false, invalid
	}
	out := map[string]any{
		"id": "chatcmpl-" + requestID, "object": "chat.completion", "created": time.Now().Unix(), "model": alias,
		"choices": []any{map[string]any{"index": 0, "finish_reason": choice.FinishReason, "message": message}},
	}
	if response.Usage != nil {
		out["usage"] = response.Usage
	}
	encoded, err := json.Marshal(out)
	return encoded, text, isTool, err
}
