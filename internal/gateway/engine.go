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
	"time"

	"govweave/internal/storage"
)

const MaxRequestBytes = 1 << 20
const maxResponseBytes = 8 << 20
const maxStreamBytes = 64 << 20

type Engine struct {
	Store  *Store
	Audit  *Audit
	client *http.Client
	slots  chan struct{}
}

func Open(dir string) (*Engine, error) {
	store, err := OpenStore(dir)
	if err != nil {
		return nil, err
	}
	audit, err := OpenAudit(dir)
	if err != nil {
		return nil, err
	}
	return &Engine{Store: store, Audit: audit, client: newHTTPClient(), slots: make(chan struct{}, 64)}, nil
}

func (g *Engine) Close() error { g.client.CloseIdleConnections(); return g.Audit.Close() }

func respond(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func failure(w http.ResponseWriter, status int, code, requestID string) {
	messages := map[string]string{
		"invalid_api_key":   "应用密钥无效或已撤销，请使用有效的应用密钥。",
		"model_not_allowed": "当前应用未获准使用此模型。", "connection_disabled": "模型连接已停用。",
		"invalid_request":   "请求须包含模型别名和非空 messages 数组；stream 必须为布尔值。",
		"request_too_large": "请求体超过 1 MiB 限制。", "unsupported_media_type": "请使用 application/json。",
		"audit_unavailable": "调用记录无法可靠保存，已停止向上游发送请求。",
		"gateway_busy":      "当前并发请求已达上限，请稍后重试。",
		"upstream_timeout":  "上游模型请求超时。", "upstream_unreachable": "无法连接已配置的上游模型服务。",
		"upstream_error":            "上游模型返回错误，请联系管理员检查连接配置。",
		"invalid_upstream_response": "上游返回了不支持或无效的响应。", "response_too_large": "上游响应超过限制。",
		"client_cancelled": "客户端已取消请求。", "credential_unavailable": "无法读取上游凭证。",
	}
	message := messages[code]
	if message == "" {
		message = "网关暂时无法完成请求。"
	}
	respond(w, status, map[string]any{"error": map[string]any{"message": message, "type": "gateway_error", "param": nil, "code": code}, "request_id": requestID})
}

func (g *Engine) newRecord(operation string) (CallRecord, time.Time, error) {
	start := time.Now()
	id, err := storage.ID("req_", 16)
	return CallRecord{SchemaVersion: 1, RequestID: id, Operation: operation, StartedAt: start.UTC().Format(time.RFC3339Nano), Decision: "not_evaluated", Outcome: "rejected"}, start, err
}

func (g *Engine) finish(record *CallRecord, start time.Time) {
	record.DurationMS = time.Since(start).Milliseconds()
	if err := g.Audit.Finish(*record); err != nil {
		log.Print("govweave: call record could not be persisted; audit coverage is incomplete")
	}
}

func (g *Engine) Chat(w http.ResponseWriter, r *http.Request) {
	record, start, err := g.newRecord("chat.completions")
	if err != nil {
		failure(w, 503, "gateway_unavailable", "")
		return
	}
	w.Header().Set("X-Request-ID", record.RequestID)
	defer g.finish(&record, start)
	reject := func(status int, code string) {
		record.HTTPStatus, record.ErrorCode = status, code
		failure(w, status, code, record.RequestID)
	}
	app, revision, err := g.Store.Authenticate(r.Header.Get("Authorization"))
	record.ApplicationID, record.PolicyRevision = app.ID, revision
	if err != nil {
		record.Decision = "deny"
		record.Outcome = "blocked"
		reject(401, "invalid_api_key")
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
	record.ApplicationID, record.PolicyRevision = resolved.Application.ID, resolved.PolicyRevision
	if err != nil {
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
	record.Decision, record.ConnectionID, record.Model = "allow", resolved.Connection.ID, resolved.Connection.Alias
	select {
	case g.slots <- struct{}{}:
		defer func() { <-g.slots }()
	default:
		reject(429, "gateway_busy")
		return
	}
	if err := g.Audit.Begin(record); err != nil {
		reject(503, "audit_unavailable")
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
		g.stream(w, r, ctx, response.Body, &record, start)
		return
	}
	if contentType != "application/json" {
		record.Outcome = "failed"
		reject(502, "invalid_upstream_response")
		return
	}
	data, err := io.ReadAll(io.LimitReader(&firstByteReader{reader: response.Body, record: &record, start: start}, maxResponseBytes+1))
	if err != nil {
		status, code := requestError(ctx, r.Context(), err)
		record.Outcome = "failed"
		if code == "client_cancelled" {
			record.Outcome = "cancelled"
		}
		reject(status, code)
		return
	}
	if len(data) > maxResponseBytes {
		record.Outcome = "failed"
		reject(502, "response_too_large")
		return
	}
	var envelope map[string]json.RawMessage
	var choices []json.RawMessage
	if json.Unmarshal(data, &envelope) != nil || envelope == nil || json.Unmarshal(envelope["choices"], &choices) != nil || choices == nil || (envelope["error"] != nil && string(envelope["error"]) != "null") {
		record.Outcome = "failed"
		reject(502, "invalid_upstream_response")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	record.HTTPStatus = 200
	if _, err := w.Write(data); err != nil {
		record.Outcome = "cancelled"
		record.ErrorCode = "client_cancelled"
		return
	}
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

func (g *Engine) stream(w http.ResponseWriter, r *http.Request, ctx context.Context, body io.Reader, record *CallRecord, start time.Time) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(200)
	record.HTTPStatus = 200
	controller := http.NewResponseController(w)
	observer := streamObserver{}
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
				panic(http.ErrAbortHandler)
			}
			if data := observer.take(); len(data) > 0 {
				if _, err := w.Write(data); err != nil {
					record.Outcome = "cancelled"
					record.ErrorCode = "client_cancelled"
					return
				}
				if err := controller.Flush(); err != nil {
					record.Outcome = "cancelled"
					record.ErrorCode = "client_cancelled"
					return
				}
			}
		}
		if readErr != nil {
			if readErr == io.EOF && observer.Done && !observer.Failed && len(observer.pending) == 0 {
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
		result.Message = "连接失败，请检查网络、证书和上游地址。"
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
		result.Message = "上游未返回有效的模型列表；此检查只测试 GET /models，不等于推理测试。"
		return result, nil
	}
	for _, model := range list.Data {
		if model.ID == resolved.Connection.Model {
			result.ModelFound = true
			break
		}
	}
	result.OK = true
	result.Message = "连接成功，已读取模型列表。请通过应用密钥验证实际推理。"
	if !result.ModelFound {
		result.Message = "连接成功，但列表中没有配置的模型名称，请检查名称。"
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
