package server

import (
	"errors"
	"net/http"
	"slices"
	"strconv"

	"govweave/internal/gateway"
)

func (s *Server) registerOutputPolicy(mux *http.ServeMux) {
	s.registerApplicationOutputPolicies(mux)
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

func (s *Server) registerApplicationOutputPolicies(mux *http.ServeMux) {
	const base = "/api/v1/policies/sensitive-output/applications/{id}"
	known := func(w http.ResponseWriter, r *http.Request) bool {
		if !slices.ContainsFunc(s.gateway.Store.Snapshot().Applications, func(a gateway.Application) bool { return a.ID == r.PathValue("id") }) {
			gatewayError(w, gateway.ErrNotFound)
			return false
		}
		return true
	}
	view := func(snapshot gateway.OutputPolicySnapshot, id string) any {
		source := "default"
		if snapshot.HasApplicationPolicy(id) {
			source = "application"
		}
		return map[string]any{"application_id": id, "source": source, "policy": snapshot.ForApplication(id)}
	}
	mux.HandleFunc("GET "+base, s.authorize(func(w http.ResponseWriter, r *http.Request) {
		if known(w, r) {
			writeJSON(w, 200, view(s.gateway.OutputPolicies.Snapshot(), r.PathValue("id")))
		}
	}))
	mux.HandleFunc("GET "+base+"/history", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		if !known(w, r) {
			return
		}
		items := []any{}
		for _, snapshot := range s.gateway.OutputPolicies.History() {
			items = append(items, view(snapshot, r.PathValue("id")))
		}
		writeJSON(w, 200, map[string]any{"snapshots": items, "total": len(items)})
	}))
	finish := func(w http.ResponseWriter, snapshot gateway.OutputPolicySnapshot, err error) {
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
	}
	mux.HandleFunc("PUT "+base, s.authorize(func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Revision        uint64   `json:"revision"`
			Mode            string   `json:"mode"`
			DetectorVersion string   `json:"detector_version"`
			Categories      []string `json:"categories"`
			PublicEmails    []string `json:"public_emails,omitempty"`
		}
		if !s.readMutation(w, r, &input) || !known(w, r) {
			return
		}
		id := r.PathValue("id")
		if input.DetectorVersion == "" {
			input.DetectorVersion = s.gateway.OutputPolicies.Snapshot().ForApplication(id).DetectorVersion
		}
		policy := gateway.ApplicationOutputPolicy{ApplicationID: id, Mode: input.Mode, DetectorVersion: input.DetectorVersion, Categories: input.Categories, PublicEmails: input.PublicEmails}
		snapshot, err := s.gateway.OutputPolicies.SaveApplication(id, input.Revision, &policy, s.gateway.Store.Snapshot())
		finish(w, snapshot, err)
	}))
	mux.HandleFunc("DELETE "+base, s.authorize(func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Revision uint64 `json:"revision"`
		}
		if !s.readMutation(w, r, &input) {
			return
		}
		snapshot, err := s.gateway.OutputPolicies.SaveApplication(r.PathValue("id"), input.Revision, nil, s.gateway.Store.Snapshot())
		finish(w, snapshot, err)
	}))
	mux.HandleFunc("POST "+base+"/restore", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Revision     uint64 `json:"revision"`
			FromRevision uint64 `json:"from_revision"`
		}
		if !s.readMutation(w, r, &input) || !known(w, r) {
			return
		}
		history, err := s.gateway.OutputPolicies.Revision(input.FromRevision)
		if err != nil {
			gatewayError(w, err)
			return
		}
		id := r.PathValue("id")
		previous := history.ForApplication(id)
		if !previous.Applies(id) {
			previous.Mode = "disabled"
		}
		policy := gateway.ApplicationOutputPolicy{ApplicationID: id, Mode: previous.Mode, DetectorVersion: previous.DetectorVersion, Categories: previous.Categories, PublicEmails: previous.PublicEmails}
		snapshot, err := s.gateway.OutputPolicies.SaveApplication(id, input.Revision, &policy, s.gateway.Store.Snapshot())
		finish(w, snapshot, err)
	}))
}
