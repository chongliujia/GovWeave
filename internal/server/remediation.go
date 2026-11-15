package server

import (
	"errors"
	"net/http"

	"govweave/internal/governance"
)

func (s *Server) registerRemediations(mux *http.ServeMux) {
	const base = "/api/v1/compliance/products/{id}/remediations"
	mux.HandleFunc("GET "+base, s.authorize(func(w http.ResponseWriter, r *http.Request) {
		items, err := s.governance.Remediations.List(r.PathValue("id"))
		if err != nil {
			remediationError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"remediations": items, "total": len(items)})
	}))
	mux.HandleFunc("POST "+base, s.authorize(func(w http.ResponseWriter, r *http.Request) {
		var input governance.RemediationCreate
		if !s.readMutation(w, r, &input) {
			return
		}
		item, err := s.governance.Remediations.Create(r.PathValue("id"), input)
		if err != nil {
			remediationError(w, err)
			return
		}
		writeJSON(w, 200, item)
	}))
	mux.HandleFunc("GET "+base+"/{remediation}", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		item, err := s.governance.Remediations.Get(r.PathValue("id"), r.PathValue("remediation"))
		if err != nil {
			remediationError(w, err)
			return
		}
		writeJSON(w, 200, item)
	}))
	mux.HandleFunc("PUT "+base+"/{remediation}", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		var input governance.RemediationInput
		if !s.readMutation(w, r, &input) {
			return
		}
		item, err := s.governance.Remediations.Update(r.PathValue("id"), r.PathValue("remediation"), input)
		if err != nil {
			remediationError(w, err)
			return
		}
		writeJSON(w, 200, item)
	}))
	mux.HandleFunc("POST "+base+"/{remediation}/recheck", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		var input governance.RemediationCheck
		if !s.readMutation(w, r, &input) {
			return
		}
		item, err := s.governance.Remediations.Check(r.PathValue("id"), r.PathValue("remediation"), input)
		if err != nil {
			remediationError(w, err)
			return
		}
		writeJSON(w, 200, item)
	}))
}

func remediationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, governance.ErrRemediationCapacity):
		apiError(w, 409, "remediation_capacity", err.Error())
	case errors.Is(err, governance.ErrRemediationDuplicate):
		apiError(w, 409, "remediation_exists", err.Error())
	case errors.Is(err, governance.ErrRemediationState):
		apiError(w, 409, "remediation_state", err.Error())
	case errors.Is(err, governance.ErrRemediationScope):
		apiError(w, 409, "remediation_scope_changed", err.Error())
	case errors.Is(err, governance.ErrRemediationTest):
		apiError(w, 409, "remediation_test_invalid", err.Error())
	case errors.Is(err, governance.ErrRemediationUnavailable):
		apiError(w, 500, "remediation_unavailable", err.Error())
	default:
		archiveError(w, err)
	}
}
