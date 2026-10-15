package server

import (
	"errors"
	"mime"
	"net/http"
	"strconv"

	"govweave/internal/config"
	"govweave/internal/gateway"
)

func (s *Server) registerGateway(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/chat/completions", s.gateway.Chat)
	mux.HandleFunc("GET /v1/models", s.gateway.Models)
	mux.HandleFunc("GET /api/v1/gateway", s.authorize(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, s.gateway.Store.Snapshot()) }))
	mux.HandleFunc("GET /api/v1/policies/credential-egress", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, s.gateway.Policies.Snapshot())
	}))
	mux.HandleFunc("PUT /api/v1/policies/credential-egress", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		var input gateway.PolicyInput
		if !s.readMutation(w, r, &input) {
			return
		}
		policy, err := s.gateway.Policies.Save(input, s.gateway.Store.Snapshot())
		if err != nil {
			gatewayError(w, err)
			return
		}
		writeJSON(w, 200, policy)
	}))
	mux.HandleFunc("GET /api/v1/requests", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		writeJSON(w, 200, s.gateway.Audit.View(limit, r.URL.Query().Get("application_id")))
	}))
	for _, route := range []string{"POST /api/v1/connections", "PUT /api/v1/connections/{id}"} {
		mux.HandleFunc(route, s.authorize(s.saveConnection))
	}
	for _, route := range []string{"POST /api/v1/applications", "PUT /api/v1/applications/{id}"} {
		mux.HandleFunc(route, s.authorize(s.saveApplication))
	}
	mux.HandleFunc("POST /api/v1/connections/{id}/test", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		var input struct{}
		if !s.readMutation(w, r, &input) {
			return
		}
		result, err := s.gateway.Probe(r.Context(), r.PathValue("id"))
		if err != nil {
			gatewayError(w, err)
			return
		}
		writeJSON(w, 200, result)
	}))
	for _, action := range []string{"rotate", "revoke"} {
		revoke := action == "revoke"
		mux.HandleFunc("POST /api/v1/applications/{id}/"+action, s.authorize(func(w http.ResponseWriter, r *http.Request) {
			var input struct {
				Revision uint64 `json:"revision"`
			}
			if !s.readMutation(w, r, &input) {
				return
			}
			app, key, err := s.gateway.Store.ChangeKey(r.PathValue("id"), input.Revision, revoke)
			if err != nil {
				gatewayError(w, err)
				return
			}
			writeJSON(w, 200, applicationResponse{Application: app, APIKey: key})
		}))
	}
}

// Administrator credentials are distinct from application keys. Writes also
// reject cross-site requests; forwarded headers never authorize an origin.
func (s *Server) readMutation(w http.ResponseWriter, r *http.Request, input any) bool {
	if !s.allowMutation(w, r) {
		return false
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		apiError(w, 415, "unsupported_media_type", "Use application/json")
		return false
	}
	if err := config.DecodeStrict(http.MaxBytesReader(w, r.Body, 16*1024), input); err != nil {
		var large *http.MaxBytesError
		if errors.As(err, &large) {
			apiError(w, 413, "request_too_large", "Configuration requests must not exceed 16 KiB.")
		} else {
			apiError(w, 400, "invalid_json", "Invalid configuration JSON. Unknown fields and multiple objects are not allowed.")
		}
		return false
	}
	return true
}

func gatewayError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, gateway.ErrConflict):
		apiError(w, 409, "revision_conflict", err.Error())
	case errors.Is(err, gateway.ErrNotFound):
		apiError(w, 404, "not_found", err.Error())
	case errors.Is(err, gateway.ErrPersistence):
		apiError(w, 500, "persistence_failed", err.Error())
	case errors.Is(err, gateway.ErrAuditUnavailable):
		apiError(w, 503, "audit_unavailable", "Could not save request records. Check disk space and log capacity.")
	case errors.Is(err, gateway.ErrBusy):
		apiError(w, 429, "gateway_busy", "The concurrent request limit has been reached.")
	default:
		apiError(w, 400, "invalid_settings", err.Error())
	}
}

func (s *Server) saveConnection(w http.ResponseWriter, r *http.Request) {
	var input gateway.ConnectionInput
	if !s.readMutation(w, r, &input) {
		return
	}
	connection, err := s.gateway.Store.SaveConnection(r.PathValue("id"), input)
	if err != nil {
		gatewayError(w, err)
		return
	}
	writeJSON(w, 200, connection)
}

type applicationResponse struct {
	Application gateway.Application `json:"application"`
	APIKey      string              `json:"api_key,omitempty"`
}

func (s *Server) saveApplication(w http.ResponseWriter, r *http.Request) {
	var input gateway.ApplicationInput
	if !s.readMutation(w, r, &input) {
		return
	}
	app, key, err := s.gateway.Store.SaveApplication(r.PathValue("id"), input)
	if err != nil {
		gatewayError(w, err)
		return
	}
	writeJSON(w, 200, applicationResponse{Application: app, APIKey: key})
}
