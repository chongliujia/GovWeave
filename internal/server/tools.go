package server

import (
	"errors"
	"net/http"

	"govweave/internal/gateway"
)

func (s *Server) registerTools(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/tools/{alias}/invoke", s.gateway.ToolInvoke)
	mux.HandleFunc("GET /api/v1/tools", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.gateway.Tools.Snapshot())
	}))
	mux.HandleFunc("GET /api/v1/tools/{id}/history", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		history, err := s.gateway.Tools.History(r.PathValue("id"))
		if err != nil {
			gatewayError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"tool_id": r.PathValue("id"), "revisions": history})
	}))
	for _, route := range []string{"POST /api/v1/tools", "PUT /api/v1/tools/{id}"} {
		mux.HandleFunc(route, s.authorize(s.saveTool))
	}
}

func (s *Server) saveTool(w http.ResponseWriter, r *http.Request) {
	var input gateway.ToolInput
	if !s.readMutation(w, r, &input) {
		return
	}
	tool, err := s.gateway.Tools.Save(r.PathValue("id"), input)
	if err != nil {
		if errors.Is(err, gateway.ErrToolHistoryFull) {
			apiError(w, http.StatusConflict, "tool_history_full", err.Error())
		} else {
			gatewayError(w, err)
		}
		return
	}
	status := http.StatusOK
	if r.Method == http.MethodPost {
		status = http.StatusCreated
	}
	writeJSON(w, status, tool)
	s.gateway.NotifyChange()
}
