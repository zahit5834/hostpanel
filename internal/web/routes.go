package web

import (
	"io/fs"
	"net/http"
)

func (s *Server) routes(mux *http.ServeMux) {
	static, _ := fs.Sub(assets, "static")
	fileServer := http.FileServerFS(static)
	mux.Handle("GET /static/", http.StripPrefix("/static/", cacheStatic(fileServer, s.Cfg.Dev)))

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := s.DB.PingContext(r.Context()); err != nil {
			http.Error(w, "db down", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ok " + s.Version))
	})

	// Auth (no session required)
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.loginSubmit)
	mux.HandleFunc("GET /login/2fa", s.mfaPage)
	mux.HandleFunc("POST /login/2fa", s.mfaSubmit)
	mux.HandleFunc("POST /logout", s.logout)

	// Authenticated
	mux.Handle("GET /{$}", s.requireAuth(s.dashboard))

	mux.Handle("GET /logs", http.RedirectHandler("/logs/activity", http.StatusSeeOther))
	mux.Handle("GET /logs/activity", s.requireAuth(s.activityList))
	mux.Handle("GET /logs/activity/{id}", s.requireAuth(s.activityDetail))
	mux.Handle("GET /logs/jobs", s.requireAuth(s.jobList))
	mux.Handle("GET /logs/jobs/{id}", s.requireAuth(s.jobDetail))
	mux.Handle("GET /logs/jobs/{id}/stream", s.requireAuth(s.jobStream))
	mux.Handle("POST /logs/jobs/{id}/cancel", s.requireAuth(s.jobCancel))
	mux.Handle("POST /logs/jobs/{id}/retry", s.requireAuth(s.jobRetry))
	mux.Handle("POST /logs/selftest", s.requireAuth(s.selftestStart))
	mux.Handle("GET /logs/system", s.requireAuth(s.systemLogs))

	mux.Handle("GET /settings", http.RedirectHandler("/settings/security", http.StatusSeeOther))
	mux.Handle("GET /settings/security", s.requireAuth(s.securityPage))
	mux.Handle("POST /settings/password", s.requireAuth(s.changePassword))
	mux.Handle("POST /settings/2fa/start", s.requireAuth(s.totpStart))
	mux.Handle("POST /settings/2fa/enable", s.requireAuth(s.totpEnable))
	mux.Handle("POST /settings/2fa/disable", s.requireAuth(s.totpDisable))
	mux.Handle("POST /settings/recovery", s.requireAuth(s.recoveryRegenerate))
	mux.Handle("POST /settings/allowlist", s.requireAuth(s.saveAllowlist))
}

func cacheStatic(h http.Handler, dev bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if dev {
			w.Header().Set("Cache-Control", "no-cache")
		} else {
			// Asset URLs carry ?v=<version>, so long caching is safe.
			w.Header().Set("Cache-Control", "public, max-age=604800")
		}
		h.ServeHTTP(w, r)
	})
}
