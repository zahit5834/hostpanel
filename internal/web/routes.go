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

	mux.Handle("GET /customers", s.requireAuth(s.customerList))
	mux.Handle("GET /customers/new", s.requireAuth(s.customerNew))
	mux.Handle("POST /customers", s.requireAuth(s.customerCreate))
	mux.Handle("GET /customers/{id}", s.requireAuth(s.customerDetail))
	mux.Handle("GET /customers/{id}/edit", s.requireAuth(s.customerEdit))
	mux.Handle("POST /customers/{id}", s.requireAuth(s.customerUpdate))
	mux.Handle("POST /customers/{id}/delete", s.requireAuth(s.customerDelete))

	mux.Handle("GET /sites", s.requireAuth(s.siteList))
	mux.Handle("GET /sites/new", s.requireAuth(s.siteNew))
	mux.Handle("GET /sites/runtime-fields", s.requireAuth(s.siteRuntimeFields))
	mux.Handle("POST /sites", s.requireAuth(s.siteCreate))
	mux.Handle("GET /sites/{id}", s.requireAuth(s.siteDetail))
	mux.Handle("POST /sites/{id}/op/{op}", s.requireAuth(s.siteOperate))
	mux.Handle("POST /sites/{id}/deploy", s.requireAuth(s.siteUpload))
	mux.Handle("POST /sites/{id}/rollback", s.requireAuth(s.siteRollback))
	mux.Handle("POST /sites/{id}/env", s.requireAuth(s.siteSaveEnv))
	mux.Handle("POST /sites/{id}/settings", s.requireAuth(s.siteSaveSettings))
	mux.Handle("POST /sites/{id}/delete", s.requireAuth(s.siteDelete))

	mux.Handle("GET /sites/{id}/ssl/check", s.requireAuth(s.siteSSLCheck))
	mux.Handle("POST /sites/{id}/ssl/letsencrypt", s.requireAuth(s.siteSSLLetsEncrypt))
	mux.Handle("POST /sites/{id}/ssl/renew", s.requireAuth(s.siteSSLRenew))
	mux.Handle("POST /sites/{id}/ssl/remove", s.requireAuth(s.siteSSLRemove))

	mux.Handle("GET /ssl", s.requireAuth(s.sslList))
	mux.Handle("GET /ssl/csr/new", s.requireAuth(s.csrNew))
	mux.Handle("POST /ssl/csr", s.requireAuth(s.csrCreate))
	mux.Handle("GET /ssl/csr/{id}", s.requireAuth(s.csrDetail))
	mux.Handle("POST /ssl/csr/{id}/delete", s.requireAuth(s.csrDelete))
	mux.Handle("GET /ssl/install", s.requireAuth(s.sslInstallPage))
	mux.Handle("POST /ssl/install/verify", s.requireAuth(s.sslVerify))
	mux.Handle("POST /ssl/install", s.requireAuth(s.sslInstall))
	mux.Handle("POST /ssl/{id}/export", s.requireAuth(s.sslExport))

	mux.Handle("GET /runtimes", s.requireAuth(s.runtimesPage))
	mux.Handle("POST /runtimes/{id}/{action}", s.requireAuth(s.runtimeAction))

	mux.Handle("GET /settings", http.RedirectHandler("/settings/security", http.StatusSeeOther))
	mux.Handle("GET /settings/security", s.requireAuth(s.securityPage))
	mux.Handle("GET /settings/general", s.requireAuth(s.generalPage))
	mux.Handle("POST /settings/general", s.requireAuth(s.saveGeneral))
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
