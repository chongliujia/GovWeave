package server

import (
	"net/http"

	"govweave/internal/gateway"
	"govweave/internal/sensitive"
)

func (s *Server) registerPlugins(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/plugins/sensitive-output/preview", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		var input gateway.OutputPreviewInput
		if !s.readMutation(w, r, &input) {
			return
		}
		preview, err := gateway.PreviewSensitiveOutput(input)
		if err != nil {
			apiError(w, http.StatusBadRequest, "invalid_preview", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, preview)
	}))
	mux.HandleFunc("GET /api/v1/plugins", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"rule_packs": s.compliance.Catalog(),
			"detectors":  sensitive.Catalog(),
		})
	}))
}
