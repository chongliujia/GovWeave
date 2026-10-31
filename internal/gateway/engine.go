package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"govweave/internal/sensitive"
	"govweave/internal/storage"
)

const MaxRequestBytes = 1 << 20
const maxResponseBytes = 8 << 20
const maxStreamBytes = 64 << 20

type Engine struct {
	Store          *Store
	Audit          *Audit
	Policies       *PolicyStore
	Tools          *ToolStore
	OutputPolicies *OutputPolicyStore
	Evidence       *EvidenceStore
	TaskSnapshots  *TaskSnapshotStore
	client         *http.Client
	slots          chan struct{}
	changeMu       sync.RWMutex
	changes        chan<- struct{}
}

func Open(dir string) (*Engine, error) {
	store, err := OpenStore(dir)
	if err != nil {
		return nil, err
	}
	policies, err := OpenPolicies(dir, store.Snapshot())
	if err != nil {
		return nil, err
	}
	toolStore, err := OpenTools(dir, store)
	if err != nil {
		return nil, err
	}
	outputPolicies, err := OpenOutputPolicies(dir, store.Snapshot())
	if err != nil {
		return nil, err
	}
	evidence, err := OpenEvidence(dir)
	if err != nil {
		return nil, err
	}
	taskSnapshots, err := openTaskSnapshots(dir, evidence.accessKey)
	if err != nil {
		return nil, err
	}
	audit, err := OpenAudit(dir)
	if err != nil {
		return nil, err
	}
	return &Engine{Store: store, Audit: audit, Policies: policies, Tools: toolStore, OutputPolicies: outputPolicies, Evidence: evidence, TaskSnapshots: taskSnapshots, client: newHTTPClient(), slots: make(chan struct{}, 64)}, nil
}

func (g *Engine) Close() error { g.client.CloseIdleConnections(); return g.Audit.Close() }

// SetChangeChannel installs one advisory observer. Signals are coalesced and
// never block the model request or alter durable audit admission.
func (g *Engine) SetChangeChannel(ch chan<- struct{}) {
	g.changeMu.Lock()
	defer g.changeMu.Unlock()
	g.changes = ch
}

func (g *Engine) NotifyChange() {
	g.changeMu.RLock()
	ch := g.changes
	g.changeMu.RUnlock()
	if ch != nil {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func respond(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func failure(w http.ResponseWriter, status int, code, requestID string) {
	messages := map[string]string{
		"invalid_api_key":   "The application key is invalid or revoked. Use a valid application key.",
		"model_not_allowed": "This application is not allowed to use this model.", "connection_disabled": "The model connection is disabled.",
		"invalid_request":   "Include a model alias and a non-empty messages array. The stream field must be a boolean.",
		"request_too_large": "The request exceeds the 1 MiB limit.", "unsupported_media_type": "Use application/json.",
		"audit_unavailable":  "Request records could not be saved reliably. Upstream requests have been stopped.",
		"gateway_busy":       "The concurrent request limit has been reached. Try again later.",
		"policy_blocked":     "The request was blocked by a credential egress policy. Contact your administrator with the request ID.",
		"policy_unavailable": "The request could not be checked. No upstream request was sent.",
		"upstream_timeout":   "The upstream model request timed out.", "upstream_unreachable": "Could not connect to the configured model provider.",
		"upstream_error":            "The upstream model returned an error. Ask your administrator to check the connection.",
		"invalid_upstream_response": "The upstream response is invalid or unsupported.", "response_too_large": "The upstream response exceeds the size limit.",
		"client_cancelled": "The client cancelled the request.", "credential_unavailable": "Could not read the upstream credential.",
		"invalid_content_request":    "Provide exactly one text string containing valid UTF-8.",
		"content_input_too_large":    "Content evaluation accepts at most 8192 UTF-8 text bytes in a 64 KiB JSON request.",
		"content_output_blocked":     "The output was withheld by the sensitive-output policy. Use the request ID to inspect the decision.",
		"content_output_unavailable": "The output could not be completely checked and was withheld.",
		"content_tools_unsupported":  "Protected tool calls require the single read_resource function contract.",
		"content_stream_unsupported": "Streaming is unavailable while the sensitive-output policy applies. Use stream: false.",
		"invalid_trace_context":      "Use bounded hexadecimal trace identifiers and at most four unique span links.",
		"trace_unavailable":          "A trace span could not be allocated. No upstream request was sent.",
		"invalid_trace_query":        "Use a valid trace ID, explicit application scope for administrator queries, and a limit from 1 to 128.",
		"trace_not_found":            "No trace records are available in this application's selected audit view.",
		"invalid_integration_query":  "Provide exactly one model alias and no other query fields.",
	}
	message := messages[code]
	if message == "" {
		message = "The gateway cannot complete this request right now."
	}
	respond(w, status, map[string]any{"error": map[string]any{"message": message, "type": "gateway_error", "param": nil, "code": code}, "request_id": requestID})
}

func (g *Engine) newRecord(operation string) (CallRecord, time.Time, error) {
	start := time.Now()
	id, err := storage.ID("req_", 16)
	return CallRecord{SchemaVersion: 1, RequestID: id, Operation: operation, StartedAt: start.UTC().Format(time.RFC3339Nano), Decision: "not_evaluated", Outcome: "rejected"}, start, err
}

func (g *Engine) finish(record *CallRecord, start time.Time) bool {
	record.DurationMS = time.Since(start).Milliseconds()
	err := g.Audit.Finish(*record)
	if err != nil {
		log.Print("govweave: call record could not be persisted; audit coverage is incomplete")
	}
	g.NotifyChange()
	return err == nil
}

func (g *Engine) Chat(w http.ResponseWriter, r *http.Request) {
	g.chat(w, r, "", nil)
}

// ChatAssessment can only be called inside this process. The HTTP inference
// handler never accepts an application ID in place of its bearer credential.
func (g *Engine) ChatAssessment(w http.ResponseWriter, r *http.Request, applicationID string) {
	if applicationID == "" {
		failure(w, 401, "invalid_api_key", "")
		return
	}
	g.chat(w, r, applicationID, nil)
}

// AssessmentReceipt is available only to in-process tests, never an HTTP
// caller. It avoids racing with eviction from the bounded recent audit view.
type AssessmentReceipt struct {
	Record         CallRecord
	AuditCommitted bool
}

func (g *Engine) ChatAssessmentEvidence(w http.ResponseWriter, r *http.Request, applicationID string) AssessmentReceipt {
	var receipt AssessmentReceipt
	if applicationID == "" {
		failure(w, 401, "invalid_api_key", "")
		return receipt
	}
	g.chat(w, r, applicationID, &receipt)
	return receipt
}

func (g *Engine) chat(w http.ResponseWriter, r *http.Request, applicationID string, receipt *AssessmentReceipt) {
	operation := "chat.completions"
	if applicationID != "" {
		operation = "assessment.chat.completions"
	}
	record, start, err := g.newRecord(operation)
	if err != nil {
		failure(w, 503, "gateway_unavailable", "")
		return
	}
	w.Header().Set("X-Request-ID", record.RequestID)
	finished := false
	committed := false
	var evidence *callEvidence
	delivery := "not_observed"
	defer func() {
		if !finished {
			committed = g.finish(&record, start)
		}
		g.finishCallEvidence(evidence, record.RequestID, committed, delivery)
		if receipt != nil {
			receipt.Record, receipt.AuditCommitted = cloneCallRecord(record), committed
		}
	}()
	reject := func(status int, code string) {
		delivery = "withheld"
		record.HTTPStatus, record.ErrorCode = status, code
		unavailableOutput(record.OutputPolicy)
		failure(w, status, code, record.RequestID)
	}
	app, revision, err := g.Store.Authenticate(r.Header.Get("Authorization"))
	if applicationID != "" {
		// Admission is rechecked with the selected alias below.
		var resolved Resolved
		resolved, err = g.Store.ResolveAssessment(applicationID, "")
		app, revision = resolved.Application, resolved.PolicyRevision
		if errors.Is(err, ErrDenied) {
			err = nil
		}
	}
	record.ApplicationID, record.PolicyRevision = app.ID, revision
	if err != nil {
		record.Decision = "deny"
		record.Outcome = "blocked"
		reject(401, "invalid_api_key")
		return
	}
	initialApplicationID := app.ID
	if err := captureTrace(w, r, &record); err != nil {
		status, code := traceContextError(err)
		reject(status, code)
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		reject(415, "unsupported_media_type")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxRequestBytes))
	if err != nil {
		var large *http.MaxBytesError
		if errors.As(err, &large) {
			reject(413, "request_too_large")
		} else {
			reject(400, "invalid_request")
		}
		return
	}
	var input map[string]json.RawMessage
	if json.Unmarshal(body, &input) != nil || input == nil {
		reject(400, "invalid_request")
		return
	}
	var model string
	var messages []json.RawMessage
	streaming := false
	if json.Unmarshal(input["model"], &model) != nil || model == "" || len(model) > 100 || json.Unmarshal(input["messages"], &messages) != nil || len(messages) == 0 {
		reject(400, "invalid_request")
		return
	}
	for _, message := range messages {
		var object map[string]json.RawMessage
		if json.Unmarshal(message, &object) != nil || object == nil {
			reject(400, "invalid_request")
			return
		}
	}
	if value, ok := input["stream"]; ok {
		if string(value) == "null" || json.Unmarshal(value, &streaming) != nil {
			reject(400, "invalid_request")
			return
		}
	}
	record.Streaming = streaming
	// Recheck under one lock after reading the body: a revoked key or edited
	// permission must not be admitted using an earlier authentication snapshot.
	resolved, err := g.Store.Resolve(r.Header.Get("Authorization"), model)
	if applicationID != "" {
		resolved, err = g.Store.ResolveAssessment(applicationID, model)
	}
	record.ApplicationID, record.PolicyRevision = resolved.Application.ID, resolved.PolicyRevision
	rebindTrace(w, &record, initialApplicationID)
	if err != nil {
		// An authenticated denial may retain its fixed decision metadata,
		// but no ungranted request body is collected.
		evidence = g.beginCallEvidence(record, nil)
		record.Decision, record.Outcome = "deny", "blocked"
		if errors.Is(err, ErrInvalidKey) {
			reject(401, "invalid_api_key")
		} else if errors.Is(err, ErrDisabled) {
			reject(403, "connection_disabled")
		} else if errors.Is(err, ErrDenied) {
			reject(403, "model_not_allowed")
		} else {
			reject(503, "credential_unavailable")
		}
		return
	}
	evidence = g.beginCallEvidence(record, body)
	record.Decision, record.ConnectionID, record.Model = "allow", resolved.Connection.ID, resolved.Connection.Alias
	outputSnapshot := g.OutputPolicies.Snapshot()
	protected := outputSnapshot.Applies(resolved.Application.ID)
	allowTools := false
	if protected {
		record.OutputPolicy = pendingOutputPolicy(outputSnapshot)
		w.Header().Set("X-GovWeave-Output-Policy-Revision", strconv.FormatUint(outputSnapshot.Revision, 10))
		if streaming {
			record.OutputPolicy.Result, record.OutputPolicy.Reason = "error", "stream_unsupported"
			record.Decision, record.Outcome = "deny", "blocked"
			reject(400, "content_stream_unsupported")
			return
		}
		allowTools, err = protectedToolDeclaration(input)
		if err != nil {
			record.Outcome = "blocked"
			record.Decision = "deny"
			reject(400, "content_tools_unsupported")
			return
		}
	}
	select {
	case g.slots <- struct{}{}:
		defer func() { <-g.slots }()
	default:
		reject(429, "gateway_busy")
		return
	}
	record.ContentPolicy, err = g.Policies.Evaluate(body, resolved.Application.ID, resolved.Connection.ID)
	if err != nil {
		reject(503, "policy_unavailable")
		return
	}
	if err := g.Audit.Begin(record); err != nil {
		reject(503, "audit_unavailable")
		return
	}
	if record.ContentPolicy.Result == "block" {
		record.Outcome = "blocked"
		reject(403, "policy_blocked")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(resolved.Connection.TimeoutSeconds)*time.Second)
	defer cancel()
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(time.Duration(resolved.Connection.TimeoutSeconds+5) * time.Second))
	input["model"], _ = json.Marshal(resolved.Connection.Model)
	payload, _ := json.Marshal(input)
	upstream, err := http.NewRequestWithContext(ctx, http.MethodPost, resolved.Connection.BaseURL+"/chat/completions", io.NopCloser(bytes.NewReader(payload)))
	if err != nil {
		reject(502, "upstream_unreachable")
		return
	}
	upstream.ContentLength = int64(len(payload))
	upstream.Header.Set("Content-Type", "application/json")
	upstream.Header.Set("User-Agent", "GovWeave/0.2")
	upstream.Header.Set("X-GovWeave-Request-ID", record.RequestID)
	if streaming {
		upstream.Header.Set("Accept", "text/event-stream")
	} else {
		upstream.Header.Set("Accept", "application/json")
	}
	if resolved.Credential != "" {
		upstream.Header.Set("Authorization", "Bearer "+resolved.Credential)
	}
	// GetBody is nil and no idempotency header is forwarded: inference POSTs
	// are not replayed automatically by the HTTP transport.
	record.UpstreamAttempted = true
	evidence.observe("upstream_request", payload)
	response, err := g.client.Do(upstream)
	if err != nil {
		status, code := requestError(ctx, r.Context(), err)
		record.Outcome = "failed"
		if code == "client_cancelled" {
			record.Outcome = "cancelled"
		}
		reject(status, code)
		return
	}
	defer response.Body.Close()
	record.UpstreamStatus = response.StatusCode
	if response.StatusCode != http.StatusOK {
		status := 502
		if response.StatusCode == 429 {
			status = 429
		}
		if response.StatusCode == 400 || response.StatusCode == 422 {
			status = response.StatusCode
		}
		record.Outcome = "failed"
		reject(status, "upstream_error")
		return
	}
	contentType, _, _ := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if streaming {
		if contentType != "text/event-stream" {
			record.Outcome = "failed"
			reject(502, "invalid_upstream_response")
			return
		}
		g.stream(w, r, ctx, response.Body, &record, start, evidence, &delivery)
		return
	}
	if contentType != "application/json" {
		record.Outcome = "failed"
		reject(502, "invalid_upstream_response")
		return
	}
	responseLimit := maxResponseBytes
	if protected {
		responseLimit = maxToolEnvelopeBytes
	}
	data, err := io.ReadAll(io.LimitReader(&firstByteReader{reader: response.Body, record: &record, start: start}, int64(responseLimit+1)))
	if err != nil {
		status, code := requestError(ctx, r.Context(), err)
		record.Outcome = "failed"
		if code == "client_cancelled" {
			record.Outcome = "cancelled"
		}
		reject(status, code)
		return
	}
	if len(data) > responseLimit {
		record.Outcome = "failed"
		if protected {
			reject(502, "content_output_unavailable")
		} else {
			reject(502, "response_too_large")
		}
		return
	}
	var envelope map[string]json.RawMessage
	var choices []json.RawMessage
	if json.Unmarshal(data, &envelope) != nil || envelope == nil || json.Unmarshal(envelope["choices"], &choices) != nil || choices == nil || (envelope["error"] != nil && string(envelope["error"]) != "null") {
		record.Outcome = "failed"
		reject(502, "invalid_upstream_response")
		return
	}
	evidence.observe("upstream_output", data)
	if protected {
		canonical, text, toolCall, err := protectedCompletionWithTools(data, resolved.Connection.Alias, record.RequestID, allowTools)
		if err != nil {
			record.Outcome = "failed"
			reject(502, "content_output_unavailable")
			return
		}
		detection := sensitive.Scan([]byte(text), outputSnapshot.DetectorVersion)
		record.OutputPolicy = assessOutput(outputSnapshot, resolved.Application.ID, detection)
		if !toolCall {
			record.OutputPolicy = assessOutputText(outputSnapshot, resolved.Application.ID, text, detection)
		}
		if toolCall {
			record.OutputPolicy.ToolCallVersion = readToolCallVersion
			if record.OutputPolicy.Result == "redact" {
				record.OutputPolicy.Result = "block"
				record.OutputPolicy.Reason = "tool_arguments_not_redactable"
			}
		}
		if record.OutputPolicy.Result == "block" {
			record.Decision, record.Outcome = "deny", "blocked"
			reject(403, "content_output_blocked")
			return
		}
		if record.OutputPolicy.Result == "error" {
			record.Decision, record.Outcome = "deny", "failed"
			reject(502, "content_output_unavailable")
			return
		}
		if record.OutputPolicy.Result == "redact" {
			text, err = applyOutputRedaction(text, outputSnapshot, detection, record.OutputPolicy)
			if err == nil {
				canonical, err = replaceProtectedText(canonical, text)
			}
			if err != nil {
				record.OutputPolicy.Result, record.OutputPolicy.State, record.OutputPolicy.Reason = "error", "unknown", "redaction_unavailable"
				record.OutputPolicy.Redaction = nil
				record.Decision, record.Outcome = "deny", "failed"
				reject(502, "content_output_unavailable")
				return
			}
		}
		if ctx.Err() != nil {
			status, code := requestError(ctx, r.Context(), ctx.Err())
			record.Outcome = "failed"
			if code == "client_cancelled" {
				record.Outcome = "cancelled"
			}
			reject(status, code)
			return
		}
		data = canonical
		evidence.observe("released_output", data)
		record.HTTPStatus, record.Outcome, record.DurationMS = 200, "completed", time.Since(start).Milliseconds()
		err = g.Audit.Finish(record)
		committed = err == nil
		finished = true
		g.NotifyChange()
		if err != nil {
			delivery = "withheld"
			failure(w, 503, "audit_unavailable", record.RequestID)
			return
		}
		// This records the prepared release after the audit commit. It does
		// not claim the client received these bytes.
		delivery = "release_prepared"
		g.finishCallEvidence(evidence, record.RequestID, true, delivery)
	}
	evidence.observe("released_output", data)
	if record.OutputPolicy != nil && record.OutputPolicy.Result == "redacted" {
		w.Header().Set("X-GovWeave-Output-Action", "redacted")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	record.HTTPStatus = 200
	delivery = "write_failed"
	if written, err := w.Write(data); err != nil || written != len(data) {
		record.Outcome = "cancelled"
		record.ErrorCode = "client_cancelled"
		return
	}
	delivery = "write_completed"
	record.Outcome = "completed"
}

func requestError(ctx, caller context.Context, cause error) (int, string) {
	if caller.Err() != nil {
		return 499, "client_cancelled"
	}
	var networkError net.Error
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || (errors.As(cause, &networkError) && networkError.Timeout()) {
		return 504, "upstream_timeout"
	}
	return 502, "upstream_unreachable"
}

func (g *Engine) stream(w http.ResponseWriter, r *http.Request, ctx context.Context, body io.Reader, record *CallRecord, start time.Time, evidence *callEvidence, delivery *string) {
	capture := g.beginStreamEvidence(evidence, start)
	endState := "upstream_unreachable"
	defer func() {
		// This runs before chat's audit/capture defer, including ErrAbortHandler.
		capture.finish(endState)
		*delivery = "stream_incomplete"
		if record.Outcome == "completed" {
			*delivery = "write_completed"
		} else if endState == "write_failed" || endState == "flush_failed" {
			*delivery = "write_failed"
		}
	}()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(200)
	record.HTTPStatus = 200
	controller := http.NewResponseController(w)
	observer := streamObserver{}
	if capture != nil {
		observer.accepted = capture.accepted
	}
	buffer := make([]byte, 16*1024)
	total := 0
	for {
		n, readErr := body.Read(buffer)
		if n > 0 {
			if record.FirstByteMS == nil {
				elapsed := time.Since(start).Milliseconds()
				record.FirstByteMS = &elapsed
			}
			total += n
			if total > maxStreamBytes {
				endState = "response_too_large"
				record.Outcome = "failed"
				record.ErrorCode = "response_too_large"
				panic(http.ErrAbortHandler)
			}
			if err := observer.observe(buffer[:n]); err != nil {
				record.Outcome = "failed"
				record.ErrorCode = "invalid_upstream_stream"
				if observer.Failed {
					record.ErrorCode = "upstream_error"
				}
				endState = record.ErrorCode
				panic(http.ErrAbortHandler)
			}
			if data := observer.take(); len(data) > 0 {
				capture.attempt(data)
				written, err := w.Write(data)
				capture.written(written, len(data))
				if err != nil || written != len(data) {
					endState = "write_failed"
					record.Outcome = "cancelled"
					record.ErrorCode = "client_cancelled"
					return
				}
				if err := controller.Flush(); err != nil {
					endState = "flush_failed"
					record.Outcome = "cancelled"
					record.ErrorCode = "client_cancelled"
					return
				}
			}
		}
		if readErr != nil {
			if readErr == io.EOF && observer.Done && !observer.Failed && len(observer.pending) == 0 {
				endState = "completed"
				record.Outcome = "completed"
				return
			}
			record.Outcome = "failed"
			if observer.Failed {
				record.ErrorCode = "upstream_error"
			} else if readErr == io.EOF {
				record.ErrorCode = "incomplete_stream"
			} else {
				_, record.ErrorCode = requestError(ctx, r.Context(), readErr)
				if record.ErrorCode == "client_cancelled" {
					record.Outcome = "cancelled"
				}
			}
			endState = record.ErrorCode
			panic(http.ErrAbortHandler)
		}
	}
}

func (g *Engine) Models(w http.ResponseWriter, r *http.Request) {
	record, start, err := g.newRecord("models.list")
	if err != nil {
		failure(w, 503, "gateway_unavailable", "")
		return
	}
	w.Header().Set("X-Request-ID", record.RequestID)
	defer g.finish(&record, start)
	models, app, revision, err := g.Store.Models(r.Header.Get("Authorization"))
	record.ApplicationID, record.PolicyRevision = app.ID, revision
	if err != nil {
		record.Decision = "deny"
		record.Outcome = "blocked"
		record.HTTPStatus = 401
		record.ErrorCode = "invalid_api_key"
		failure(w, 401, "invalid_api_key", record.RequestID)
		return
	}
	if !g.Audit.View(1, "").Available {
		record.HTTPStatus = 503
		record.ErrorCode = "audit_unavailable"
		failure(w, 503, "audit_unavailable", record.RequestID)
		return
	}
	data := []map[string]any{}
	for _, model := range models {
		data = append(data, map[string]any{"id": model.Alias, "object": "model", "created": 0, "owned_by": "govweave"})
	}
	record.Decision, record.Outcome, record.HTTPStatus = "allow", "completed", 200
	respond(w, 200, map[string]any{"object": "list", "data": data})
}

type ProbeResult struct {
	OK         bool   `json:"ok"`
	ModelFound bool   `json:"model_found"`
	HTTPStatus int    `json:"http_status"`
	DurationMS int64  `json:"duration_ms"`
	Message    string `json:"message"`
	RequestID  string `json:"request_id"`
}

func (g *Engine) Probe(ctx context.Context, id string) (ProbeResult, error) {
	resolved, err := g.Store.Connection(id)
	if err != nil {
		return ProbeResult{}, err
	}
	record, start, err := g.newRecord("connection.test")
	if err != nil {
		return ProbeResult{}, err
	}
	record.ConnectionID, record.Model, record.PolicyRevision, record.Decision = resolved.Connection.ID, resolved.Connection.Alias, resolved.PolicyRevision, "allow"
	defer g.finish(&record, start)
	result := ProbeResult{RequestID: record.RequestID}
	select {
	case g.slots <- struct{}{}:
		defer func() { <-g.slots }()
	default:
		record.HTTPStatus = 429
		record.ErrorCode = "gateway_busy"
		return result, ErrBusy
	}
	if err := g.Audit.Begin(record); err != nil {
		record.ErrorCode = "audit_unavailable"
		record.HTTPStatus = 503
		return result, ErrAuditUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", resolved.Connection.BaseURL+"/models", nil)
	if resolved.Credential != "" {
		req.Header.Set("Authorization", "Bearer "+resolved.Credential)
	}
	req.Header.Set("Accept", "application/json")
	record.UpstreamAttempted = true
	response, err := g.client.Do(req)
	result.DurationMS = time.Since(start).Milliseconds()
	if err != nil {
		record.Outcome = "failed"
		record.HTTPStatus = 200 // The administration API returns a completed probe result with ok=false.
		record.ErrorCode = "upstream_unreachable"
		result.Message = "Connection failed. Check the network, certificates and provider URL."
		return result, nil
	}
	defer response.Body.Close()
	record.UpstreamStatus = response.StatusCode
	record.HTTPStatus = 200
	result.HTTPStatus = response.StatusCode
	data, err := io.ReadAll(io.LimitReader(response.Body, MaxRequestBytes+1))
	result.DurationMS = time.Since(start).Milliseconds()
	var list struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err != nil || len(data) > MaxRequestBytes || response.StatusCode != 200 || json.Unmarshal(data, &list) != nil || list.Data == nil {
		record.Outcome = "failed"
		record.ErrorCode = "upstream_error"
		result.Message = "The provider did not return a valid model list. This check only tests GET /models, not inference."
		return result, nil
	}
	for _, model := range list.Data {
		if model.ID == resolved.Connection.Model {
			result.ModelFound = true
			break
		}
	}
	result.OK = true
	result.Message = "Connected and retrieved the model list. Use an application key to verify inference."
	if !result.ModelFound {
		result.Message = "Connected, but the configured model was not in the list. Check its name."
	}
	record.Outcome = "completed"
	result.DurationMS = time.Since(start).Milliseconds()
	return result, nil
}

type firstByteReader struct {
	reader io.Reader
	record *CallRecord
	start  time.Time
}

func (r *firstByteReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 && r.record.FirstByteMS == nil {
		elapsed := time.Since(r.start).Milliseconds()
		r.record.FirstByteMS = &elapsed
	}
	return n, err
}
