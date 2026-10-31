package server

import (
	"errors"
	"net/http"
	"strconv"

	"govweave/internal/gateway"
)

func (s *Server) registerOutputPolicy(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/content/evaluations", s.gateway.EvaluateContent)
	mux.HandleFunc("GET /api/v1/policies/sensitive-output", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, s.gateway.OutputPolicies.Snapshot())
	}))
	mux.HandleFunc("GET /api/v1/policies/sensitive-output/history", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		history := s.gateway.OutputPolicies.History()
		writeJSON(w, 200, map[string]any{"snapshots": history, "total": len(history)})
	}))
	mux.HandleFunc("GET /api/v1/policies/sensitive-output/revisions/{revision}", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		revision, err := strconv.ParseUint(r.PathValue("revision"), 10, 64)
		if err != nil {
			apiError(w, 400, "invalid_history_query", "Provide a non-negative policy revision.")
			return
		}
		snapshot, err := s.gateway.OutputPolicies.Revision(revision)
		if err != nil {
			gatewayError(w, err)
			return
		}
		writeJSON(w, 200, snapshot)
	}))
	mux.HandleFunc("PUT /api/v1/policies/sensitive-output", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		var input gateway.OutputPolicyInput
		if !s.readMutation(w, r, &input) {
			return
		}
		snapshot, err := s.gateway.OutputPolicies.Save(input, s.gateway.Store.Snapshot())
		if err != nil {
			if errors.Is(err, gateway.ErrOutputHistoryFull) {
				apiError(w, 409, "output_history_full", err.Error())
			} else {
				gatewayError(w, err)
			}
			return
		}
		writeJSON(w, 200, snapshot)
		s.gateway.NotifyChange()
	}))
}
