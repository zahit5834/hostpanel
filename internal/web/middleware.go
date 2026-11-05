package web

import (
	"context"
	"crypto/subtle"
	"net"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"

	"hostpanel/internal/auth"
	"hostpanel/internal/logs"
)

const sessionCookie = "hp_session"

type ctxKey int

const (
	keyIP ctxKey = iota
	keySession
	keyToken
)

func clientIP(r *http.Request) string {
	ip, _ := r.Context().Value(keyIP).(string)
	return ip
}

func sessionFrom(r *http.Request) *auth.Session {
	se, _ := r.Context().Value(keySession).(*auth.Session)
	return se
}

func tokenFrom(r *http.Request) string {
	t, _ := r.Context().Value(keyToken).(string)
	return t
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				s.Log.Error("panic", "path", r.URL.Path, "panic", v, "stack", string(debug.Stack()))
				http.Error(w, "Sunucu hatası", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// securityHeaders sets a strict CSP: no inline scripts or styles anywhere.
// img-src allows data: only for the 2FA QR code.
func securityHeaders(next http.Handler, hsts bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "+
			"connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if hsts {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// withClientIP resolves the client address. X-Real-IP is honoured only when
// trust_proxy is on AND the TCP peer is loopback (our own nginx), so it can't be spoofed.
func (s *Server) withClientIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if s.Cfg.TrustProxy && (host == "127.0.0.1" || host == "::1") {
			if xr := strings.TrimSpace(r.Header.Get("X-Real-IP")); net.ParseIP(xr) != nil {
				host = xr
			}
		}
		ctx := context.WithValue(r.Context(), keyIP, host)
		ctx = logs.WithActor(ctx, logs.Actor{Source: logs.SourceUser, IP: host})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) withAllowlist(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := s.allowlist.Load(); p != nil && !allowed(*p, clientIP(r)) && r.URL.Path != "/healthz" {
			http.Error(w, "Erişim engellendi", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// withSession loads the session (if any) and enforces CSRF on unsafe methods.
func (s *Server) withSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if c, err := r.Cookie(sessionCookie); err == nil {
			if se, err := s.Auth.LookupSession(ctx, c.Value); err == nil {
				ctx = context.WithValue(ctx, keySession, se)
				ctx = context.WithValue(ctx, keyToken, c.Value)
			}
		}
		r = r.WithContext(ctx)
		if !isSafeMethod(r.Method) {
			if !sameOrigin(r) {
				http.Error(w, "Geçersiz istek kaynağı", http.StatusForbidden)
				return
			}
			// Pre-login forms (no session yet) are protected by the origin check
			// plus SameSite=Strict; everything after login also needs the token.
			if se := sessionFrom(r); se != nil && !validCSRF(r, se.CSRF) {
				http.Error(w, "Geçersiz CSRF anahtarı, sayfayı yenileyin", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func isSafeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// sameOrigin rejects cross-site requests using Fetch Metadata, falling back to Origin.
func sameOrigin(r *http.Request) bool {
	if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" {
		return sfs == "same-origin" || sfs == "none"
	}
	if o := r.Header.Get("Origin"); o != "" {
		u, err := url.Parse(o)
		return err == nil && u.Host == r.Host
	}
	return true // non-browser client (curl); CSRF token still required when logged in
}

func validCSRF(r *http.Request, want string) bool {
	got := r.Header.Get("X-CSRF-Token")
	// Multipart uploads must send the header: parsing the body here would buffer
	// the whole upload (memory/temp files) before the handler can stream it.
	if got == "" && !strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/") {
		got = r.PostFormValue("_csrf")
	}
	return got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// requireAuth wraps handlers that need a fully logged-in admin.
func (s *Server) requireAuth(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		se := sessionFrom(r)
		if se == nil || se.Stage != auth.StageFull {
			if r.Header.Get("HX-Request") == "true" {
				w.Header().Set("HX-Redirect", "/login")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		h(w, r)
	})
}

func (s *Server) setSessionCookie(w http.ResponseWriter, tok string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    tok,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   s.Cfg.SecureCookies,
		SameSite: http.SameSiteStrictMode,
	})
}
