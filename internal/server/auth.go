package server

import (
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"govweave/internal/auth"
)

const sessionCookie = "govweave_session"

func sessionValue(r *http.Request) string {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func (s *Server) allowMutation(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if r.Header.Get("X-GovWeave-Request") != "console" || r.Header.Get("Sec-Fetch-Site") == "cross-site" || (origin != "" && origin != "http://"+r.Host && origin != "https://"+r.Host && origin != s.store.View().PublicURL) {
		apiError(w, 403, "origin_denied", "Cross-site configuration changes are not allowed.")
		return false
	}
	return true
}

// Upgrading an existing token-protected instance must not open remote account
// takeover. Only a direct loopback connection with a loopback Host can claim it.
func directLocal(r *http.Request) bool {
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || net.ParseIP(peer) == nil || !net.ParseIP(peer).IsLoopback() {
		return false
	}
	host := r.Host
	if value, _, err := net.SplitHostPort(host); err == nil {
		host = value
	}
	if host != "localhost" && (net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback()) {
		return false
	}
	for name := range r.Header {
		if strings.EqualFold(name, "Forwarded") || strings.HasPrefix(strings.ToLower(name), "x-forwarded-") {
			return false
		}
	}
	return true
}

func (s *Server) setupAllowed(r *http.Request) bool { return !s.admin.LegacySetup() || directLocal(r) }

func (s *Server) authStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]bool{"setup_required": s.admin.SetupRequired(), "setup_allowed": s.setupAllowed(r), "authenticated": s.admin.Valid(sessionValue(r))})
}

func (s *Server) cookie(w http.ResponseWriter, r *http.Request, value string, clear bool) {
	c := &http.Cookie{Name: sessionCookie, Value: value, Path: "/api/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil || strings.HasPrefix(r.Header.Get("Origin"), "https://") || (r.Header.Get("Origin") == "" && strings.HasPrefix(s.store.View().PublicURL, "https://")), MaxAge: int(auth.SessionLifetime.Seconds()), Expires: time.Now().Add(auth.SessionLifetime)}
	if clear {
		c.MaxAge = -1
		c.Expires = time.Unix(1, 0)
	}
	http.SetCookie(w, c)
}

func (s *Server) registerAuth(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/auth/status", s.authStatus)
	for _, action := range []string{"setup", "login"} {
		setup := action == "setup"
		mux.HandleFunc("POST /api/v1/auth/"+action, func(w http.ResponseWriter, r *http.Request) {
			var input struct {
				Password string `json:"password"`
			}
			if !s.readMutation(w, r, &input) {
				return
			}
			if setup && !s.setupAllowed(r) {
				apiError(w, 403, "local_setup_required", "For a legacy instance, set the initial password from localhost on the deployment host, or follow the operator migration guide.")
				return
			}
			var err error
			if setup {
				err = s.admin.Setup(input.Password)
			} else {
				err = s.admin.Login(input.Password)
			}
			if err != nil {
				switch {
				case errors.Is(err, auth.ErrConfigured):
					apiError(w, 409, "already_configured", err.Error())
				case errors.Is(err, auth.ErrPasswordLength):
					apiError(w, 400, "invalid_password", err.Error())
				case errors.Is(err, auth.ErrRateLimited):
					w.Header().Set("Retry-After", "60")
					apiError(w, 429, "login_limited", err.Error())
				case errors.Is(err, auth.ErrPersistence):
					apiError(w, 500, "password_save_failed", err.Error())
				default:
					apiError(w, 401, "invalid_password", auth.ErrPassword.Error())
				}
				return
			}
			value, err := s.admin.NewSession(sessionValue(r))
			if err != nil {
				apiError(w, 503, "session_unavailable", "Could not create a session. Try signing in again later.")
				return
			}
			s.cookie(w, r, value, false)
			s.authStatusWithLogin(w)
		})
	}
	mux.HandleFunc("POST /api/v1/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		var input struct{}
		if !s.readMutation(w, r, &input) {
			return
		}
		s.admin.Logout(sessionValue(r))
		s.cookie(w, r, "", true)
		writeJSON(w, 200, map[string]bool{"authenticated": false})
	})
}

func (s *Server) authStatusWithLogin(w http.ResponseWriter) {
	writeJSON(w, 200, map[string]bool{"setup_required": false, "authenticated": true})
}
