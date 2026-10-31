package server

import (
	"errors"
	"net/http"

	"govweave/internal/gateway"
)

func taskSnapshotError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, gateway.ErrTaskSnapshotChanged):
		apiError(w, 409, "task_view_changed", "Task evidence changed. Reload the view before saving a snapshot.")
	case errors.Is(err, gateway.ErrTaskSnapshotBusy):
		apiError(w, 429, "task_snapshot_busy", "The task snapshot concurrency limit has been reached.")
	default:
		evidenceError(w, err)
	}
}

func (s *Server) taskSnapshotScope(w http.ResponseWriter, r *http.Request, allowLimit bool) (string, []string, int, bool) {
	trace, ids, limit, ok := gateway.ParseEvidenceTraceQuery(r)
	if !allowLimit && r.URL.Query().Has("limit") {
		ok = false
	}
	for _, id := range ids {
		ok = ok && s.evidenceApplication(id)
	}
	if !ok {
		apiError(w, 400, "invalid_trace_query", "Select an explicit trace and application scope.")
		return "", nil, 0, false
	}
	if s.gateway.TaskSnapshots == nil {
		taskSnapshotError(w, gateway.ErrEvidenceUnavailable)
		return "", nil, 0, false
	}
	return trace, ids, limit, true
}

func (s *Server) registerTaskSnapshots(mux *http.ServeMux) {
	const base = "/api/v1/evidence-traces/{trace_id}/snapshots"
	mux.HandleFunc("POST "+base, s.authorize(func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			ExpectedViewSHA256 string `json:"expected_view_sha256"`
		}
		if !s.readMutation(w, r, &input) {
			return
		}
		trace, ids, limit, ok := s.taskSnapshotScope(w, r, true)
		if !ok {
			return
		}
		value, err := s.gateway.CreateTaskSnapshot(trace, ids, limit, input.ExpectedViewSHA256, evidenceActor(r))
		if err != nil {
			taskSnapshotError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, value)
	}))
	mux.HandleFunc("GET "+base, s.authorize(func(w http.ResponseWriter, r *http.Request) {
		trace, ids, _, ok := s.taskSnapshotScope(w, r, false)
		if !ok {
			return
		}
		items, err := s.gateway.TaskSnapshots.List(trace, ids)
		if err != nil {
			taskSnapshotError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"items": items, "scope": "exact_trace_and_applications", "max_items": gateway.MaxTaskSnapshots})
	}))
	load := func(w http.ResponseWriter, r *http.Request) (gateway.ArchivedTaskEvidence, bool) {
		trace, ids, _, ok := s.taskSnapshotScope(w, r, false)
		if !ok {
			return gateway.ArchivedTaskEvidence{}, false
		}
		value, err := s.gateway.TaskSnapshots.Get(r.PathValue("snapshot_id"), trace, ids)
		if err != nil {
			taskSnapshotError(w, err)
			return gateway.ArchivedTaskEvidence{}, false
		}
		return value, true
	}
	mux.HandleFunc("GET "+base+"/{snapshot_id}", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		if value, ok := load(w, r); ok {
			writeJSON(w, 200, value)
		}
	}))
	mux.HandleFunc("GET "+base+"/{snapshot_id}/export/{format}", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		format := r.PathValue("format")
		if format != "json" && format != "markdown" {
			taskSnapshotError(w, gateway.ErrEvidenceInvalid)
			return
		}
		value, ok := load(w, r)
		if !ok {
			return
		}
		data, extension, media := value.JSON(), "json", "application/json; charset=utf-8"
		if format == "markdown" {
			data, extension, media = value.Markdown(), "md", "text/markdown; charset=utf-8"
		} else {
			w.Header().Set("X-GovWeave-SHA256", value.Summary.SHA256)
		}
		w.Header().Set("Content-Type", media)
		w.Header().Set("Content-Disposition", `attachment; filename="govweave-`+value.Summary.ID+`.`+extension+`"`)
		w.WriteHeader(200)
		_, _ = w.Write(data)
	}))
}
