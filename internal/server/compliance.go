package server

import (
	"errors"
	"net/http"

	"govweave/internal/compliance"
	"govweave/internal/governance"
)

func (s *Server) registerCompliance(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/compliance/packs/{id}/versions/{version}", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		pack, err := s.compliance.PackSnapshot(r.PathValue("id"), r.PathValue("version"))
		if errors.Is(err, compliance.ErrPackNotFound) {
			apiError(w, 404, "rule_pack_not_found", err.Error())
			return
		}
		if err != nil {
			apiError(w, 500, "pack_unavailable", "Could not read the installed rule pack.")
			return
		}
		writeJSON(w, 200, pack)
	}))
	mux.HandleFunc("GET /api/v1/compliance/products/{id}/reports", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		if _, err := s.governance.Products.Get(r.PathValue("id")); err != nil {
			gatewayError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"reports": s.governance.Archives.List(r.PathValue("id"))})
	}))
	mux.HandleFunc("POST /api/v1/compliance/products/{id}/reports", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		var input struct{}
		if !s.readMutation(w, r, &input) {
			return
		}
		report, err := s.governance.Archive(r.PathValue("id"))
		if err != nil {
			archiveError(w, err)
			return
		}
		writeJSON(w, 200, report)
	}))
	mux.HandleFunc("GET /api/v1/compliance/reports/{report}", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		report, err := s.governance.Archives.Get(r.PathValue("report"))
		if err != nil {
			archiveError(w, err)
			return
		}
		writeJSON(w, 200, report)
	}))
	mux.HandleFunc("POST /api/v1/compliance/reports/{report}/replay", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		var input struct{}
		if !s.readMutation(w, r, &input) {
			return
		}
		replay, err := s.governance.Archives.Replay(r.PathValue("report"))
		if err != nil {
			archiveError(w, err)
			return
		}
		writeJSON(w, 200, replay)
	}))
	mux.HandleFunc("GET /api/v1/compliance/products", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"products": s.governance.Products.List()})
	}))
	mux.HandleFunc("GET /api/v1/compliance/products/{id}", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		product, err := s.governance.Products.Get(r.PathValue("id"))
		if err != nil {
			gatewayError(w, err)
			return
		}
		writeJSON(w, 200, product)
	}))
	for _, route := range []string{"POST /api/v1/compliance/products", "PUT /api/v1/compliance/products/{id}"} {
		mux.HandleFunc(route, s.authorize(func(w http.ResponseWriter, r *http.Request) {
			var input governance.ProductInput
			if !s.readMutation(w, r, &input) {
				return
			}
			product, err := s.governance.Save(r.PathValue("id"), input)
			if errors.Is(err, compliance.ErrPackNotFound) {
				apiError(w, 404, "rule_pack_not_found", err.Error())
				return
			}
			if err != nil {
				gatewayError(w, err)
				return
			}
			writeJSON(w, 200, product)
		}))
	}
	mux.HandleFunc("GET /api/v1/compliance/products/{id}/evaluation", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		report, err := s.governance.Latest(r.PathValue("id"))
		if err != nil {
			gatewayError(w, err)
			return
		}
		writeJSON(w, 200, report)
	}))
	mux.HandleFunc("POST /api/v1/compliance/products/{id}/evaluate", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		var input struct{}
		if !s.readMutation(w, r, &input) {
			return
		}
		report, err := s.governance.Refresh(r.PathValue("id"))
		if errors.Is(err, governance.ErrSnapshotChanged) {
			apiError(w, 429, "assessment_busy", err.Error())
			return
		}
		if err != nil {
			gatewayError(w, err)
			return
		}
		writeJSON(w, 200, report)
	}))
	mux.HandleFunc("GET /api/v1/compliance/packs", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"packs": s.compliance.Catalog()})
	}))
	mux.HandleFunc("POST /api/v1/compliance/evaluations", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		var input compliance.Input
		if !s.readMutation(w, r, &input) {
			return
		}
		result, err := s.compliance.Evaluate(input)
		if errors.Is(err, compliance.ErrBusy) {
			apiError(w, 429, "compliance_busy", err.Error())
			return
		}
		if errors.Is(err, compliance.ErrPackNotFound) {
			apiError(w, 404, "rule_pack_not_found", err.Error())
			return
		}
		if err != nil {
			apiError(w, 400, "invalid_evaluation", err.Error())
			return
		}
		writeJSON(w, 200, result)
	}))
}

func archiveError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, governance.ErrArchiveCapacity):
		apiError(w, 409, "archive_capacity", err.Error())
	case errors.Is(err, governance.ErrArchiveBusy):
		apiError(w, 429, "archive_busy", err.Error())
	case errors.Is(err, governance.ErrSnapshotChanged):
		apiError(w, 429, "assessment_busy", err.Error())
	case errors.Is(err, governance.ErrAssessmentUnavailable):
		apiError(w, 409, "assessment_unavailable", err.Error())
	case errors.Is(err, governance.ErrReplayVersion):
		apiError(w, 409, "replay_version_unsupported", err.Error())
	case errors.Is(err, governance.ErrArchiveUnavailable):
		apiError(w, 500, "archive_unavailable", err.Error())
	default:
		gatewayError(w, err)
	}
}
