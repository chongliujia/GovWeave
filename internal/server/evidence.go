package server

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"govweave/internal/gateway"
)

func evidenceActor(r *http.Request) string {
	// This installation has one administrator identity. A random session's
	// digest distinguishes sessions without retaining its bearer cookie.
	digest := sha256.Sum256([]byte(sessionValue(r)))
	return "admin_session:" + hex.EncodeToString(digest[:16])
}

func evidenceError(w http.ResponseWriter, err error) {
	status, code, message := 503, "evidence_unavailable", "Evidence could not be verified or stored. Its absence is not proof of safety."
	switch {
	case errors.Is(err, gateway.ErrEvidenceNotFound):
		status, code, message = 404, "evidence_not_found", "No retained evidence is available in the selected application."
	case errors.Is(err, gateway.ErrEvidenceExpired):
		status, code, message = 410, "evidence_expired", "The evidence retention period has ended."
	case errors.Is(err, gateway.ErrEvidenceContentUnavailable):
		status, code, message = 409, "evidence_content_unavailable", "Content was not retained for this object."
	case errors.Is(err, gateway.ErrEvidenceCapacity):
		status, code, message = 507, "evidence_capacity", "The evidence store has reached its bounded capacity."
	case errors.Is(err, gateway.ErrConflict):
		status, code, message = 409, "revision_conflict", "The configuration revision has changed. Refresh and try again."
	case errors.Is(err, gateway.ErrEvidenceInvalid), errors.Is(err, gateway.ErrEvidenceDisabled):
		status, code, message = 400, "invalid_evidence_request", "Use a valid explicit application scope, retention settings and evidence identifiers."
	}
	apiError(w, status, code, message)
}

func (s *Server) evidenceApplication(id string) bool {
	if id == "" {
		return false
	}
	for _, app := range s.gateway.Store.Snapshot().Applications {
		if app.ID == id {
			return true
		}
	}
	return false
}

func evidenceQuery(r *http.Request, allowed ...string) (url.Values, int, bool) {
	if len(r.URL.RawQuery) > 512 {
		return nil, 0, false
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, 0, false
	}
	for name, values := range query {
		found := false
		for _, key := range allowed {
			if name == key {
				found = true
			}
		}
		if !found || len(values) != 1 || values[0] == "" {
			return nil, 0, false
		}
	}
	limit := 50
	if query.Has("limit") {
		limit, err = strconv.Atoi(query.Get("limit"))
		if err != nil || limit < 1 || limit > 100 {
			return nil, 0, false
		}
	}
	return query, limit, true
}

func (s *Server) registerEvidence(mux *http.ServeMux) {
	s.registerTaskSnapshots(mux)
	mux.HandleFunc("GET /api/v1/evidence-traces/{trace_id}", s.authorize(s.gateway.GetAdminEvidenceTrace))
	mux.HandleFunc("GET /api/v1/evidence/config", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" {
			evidenceError(w, gateway.ErrEvidenceInvalid)
			return
		}
		writeJSON(w, 200, s.gateway.Evidence.Config())
	}))
	mux.HandleFunc("PUT /api/v1/evidence/config", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		var input gateway.EvidenceConfig
		if !s.readMutation(w, r, &input) {
			return
		}
		value, err := s.gateway.Evidence.SaveConfig(input, s.gateway.Store.Snapshot(), evidenceActor(r))
		if err != nil {
			evidenceError(w, err)
			return
		}
		writeJSON(w, 200, value)
	}))
	mux.HandleFunc("GET /api/v1/evidence", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		query, limit, ok := evidenceQuery(r, "application_id", "limit", "request_id")
		if !ok || !s.evidenceApplication(query.Get("application_id")) {
			evidenceError(w, gateway.ErrEvidenceInvalid)
			return
		}
		var items []gateway.EvidenceSummary
		var err error
		if query.Has("request_id") {
			id := gateway.EvidenceID(query.Get("request_id"))
			if id == "" {
				evidenceError(w, gateway.ErrEvidenceInvalid)
				return
			}
			var bundle gateway.EvidenceBundle
			bundle, err = s.gateway.Evidence.Get(id, query.Get("application_id"))
			items = []gateway.EvidenceSummary{}
			if err == nil {
				items = append(items, bundle.EvidenceSummary)
			}
			if errors.Is(err, gateway.ErrEvidenceNotFound) || errors.Is(err, gateway.ErrEvidenceExpired) {
				err = nil
			}
		} else {
			items, err = s.gateway.Evidence.List(query.Get("application_id"), limit)
		}
		if err != nil {
			evidenceError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"items": items, "coverage": "retained_gateway_evidence", "history_may_be_missing": true, "limit": limit})
	}))
	mux.HandleFunc("GET /api/v1/evidence/access", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		_, limit, ok := evidenceQuery(r, "limit")
		if !ok {
			evidenceError(w, gateway.ErrEvidenceInvalid)
			return
		}
		items, err := s.gateway.Evidence.AccessLog(limit)
		if err != nil {
			evidenceError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
	}))
	mux.HandleFunc("POST /api/v1/evidence/purge", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		var input struct{}
		if !s.readMutation(w, r, &input) {
			return
		}
		count, err := s.gateway.Evidence.PurgeExpired(evidenceActor(r))
		if err != nil {
			evidenceError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"expired_records_removed": count})
	}))
	mux.HandleFunc("GET /api/v1/evidence/{id}", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		query, _, ok := evidenceQuery(r, "application_id")
		if !ok || !s.evidenceApplication(query.Get("application_id")) {
			evidenceError(w, gateway.ErrEvidenceInvalid)
			return
		}
		bundle, err := s.gateway.Evidence.Get(r.PathValue("id"), query.Get("application_id"))
		if err != nil {
			evidenceError(w, err)
			return
		}
		writeJSON(w, 200, struct {
			gateway.EvidenceBundle
			Findings []gateway.EvidenceFinding `json:"findings"`
		}{bundle, gateway.EvidenceFindings(bundle)})
	}))
	mux.HandleFunc("GET /api/v1/evidence/{id}/graph", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		query, _, ok := evidenceQuery(r, "application_id")
		if !ok || !s.evidenceApplication(query.Get("application_id")) {
			evidenceError(w, gateway.ErrEvidenceInvalid)
			return
		}
		graph, err := s.gateway.Evidence.Graph(r.PathValue("id"), query.Get("application_id"))
		if err != nil {
			evidenceError(w, err)
			return
		}
		writeJSON(w, 200, graph)
	}))
	mux.HandleFunc("POST /api/v1/evidence/{id}/reveal", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			ApplicationID string `json:"application_id"`
			ObjectID      string `json:"object_id"`
			View          string `json:"view"`
			Reason        string `json:"reason"`
		}
		if !s.readMutation(w, r, &input) {
			return
		}
		if !s.evidenceApplication(input.ApplicationID) {
			evidenceError(w, gateway.ErrEvidenceInvalid)
			return
		}
		value, err := s.gateway.Evidence.Reveal(r.PathValue("id"), input.ApplicationID, input.ObjectID, input.View, input.Reason, evidenceActor(r))
		if err != nil {
			evidenceError(w, err)
			return
		}
		writeJSON(w, 200, value)
	}))
}
