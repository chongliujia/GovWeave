package server

import (
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"mime"
	"net/http"
	"strings"

	"govweave/internal/auth"
	"govweave/internal/config"
	"govweave/internal/gateway"
	"govweave/internal/instance"
)

const Version = "0.2.0-dev"

//go:embed web/*
var assets embed.FS

type Server struct {
	store   *instance.Store
	admin   *auth.Manager
	gateway *gateway.Engine
}

func New(store *instance.Store, admin *auth.Manager, engine *gateway.Engine) http.Handler {
	s := &Server{store: store, admin: admin, gateway: engine}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]string{"status": "ok", "service": "govweave", "version": Version})
	})
	mux.HandleFunc("GET /api/v1/instance", s.authorize(s.getInstance))
	mux.HandleFunc("PUT /api/v1/instance", s.authorize(s.updateInstance))
	s.registerAuth(mux)
	s.registerGateway(mux)
	reserved := func(w http.ResponseWriter, r *http.Request) {
		apiError(w, 501, "not_implemented", "This endpoint is not implemented. Only Chat Completions and model listing are currently supported.")
	}
	mux.HandleFunc("/v1", reserved)
	mux.HandleFunc("/v1/", reserved)
	mux.HandleFunc("/mcp", reserved)
	mux.HandleFunc("/mcp/", reserved)
	web, _ := fs.Sub(assets, "web")
	files := http.FileServer(http.FS(web))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			apiError(w, 404, "not_found", "Endpoint or page not found.")
			return
		}
		switch r.URL.Path {
		case "/", "/app.js", "/gateway.js", "/policies.js", "/i18n.js", "/style.css", "/logo.svg":
			files.ServeHTTP(w, r)
		default:
			apiError(w, 404, "not_found", "Endpoint or page not found.")
		}
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		mux.ServeHTTP(w, r)
	})
}

func (s *Server) authorize(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.admin.Valid(sessionValue(r)) {
			apiError(w, 401, "unauthorized", "Please sign in to the management console.")
			return
		}
		next(w, r)
	}
}

func (s *Server) getInstance(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.store.View())
}

func (s *Server) updateInstance(w http.ResponseWriter, r *http.Request) {
	// Cookie-authenticated writes require a custom header and an allowed origin.
	if !s.allowMutation(w, r) {
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		apiError(w, 415, "unsupported_media_type", "Use application/json")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	var request struct {
		SchemaVersion int     `json:"schema_version"`
		Revision      *uint64 `json:"revision"`
		config.Settings
	}
	if err := config.DecodeStrict(r.Body, &request); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			apiError(w, 413, "request_too_large", "Configuration requests must not exceed 16 KiB.")
			return
		}
		apiError(w, 400, "invalid_json", "Invalid configuration JSON. Unknown fields and multiple objects are not allowed.")
		return
	}
	if request.SchemaVersion != config.SchemaVersion || request.Revision == nil {
		apiError(w, 400, "invalid_schema", "Provide schema_version: 1 and revision.")
		return
	}
	normalized, err := config.Normalize(request.Settings)
	if err != nil {
		apiError(w, 400, "invalid_settings", err.Error())
		return
	}
	view, err := s.store.Update(*request.Revision, normalized)
	if errors.Is(err, instance.ErrConflict) {
		apiError(w, 409, "revision_conflict", err.Error())
		return
	}
	if errors.Is(err, instance.ErrManaged) {
		apiError(w, 409, "deployment_managed", err.Error())
		return
	}
	if err != nil {
		apiError(w, 500, "persistence_failed", "Could not save. The previous configuration remains active. Check data directory permissions and disk space.")
		return
	}
	writeJSON(w, 200, view)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func apiError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": strings.TrimSpace(code), "message": message}})
}
