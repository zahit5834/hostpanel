package web

import (
	"errors"
	"net/http"

	"github.com/zahit5834/hostpanel/internal/auth"
	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/notify"
)

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if se := sessionFrom(r); se != nil && se.Stage == auth.StageFull {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, r, http.StatusOK, "login", "layout", Page{Title: "Giriş"})
}

func (s *Server) loginFail(w http.ResponseWriter, r *http.Request, page, reason, msg string) {
	ip := clientIP(r)
	s.Auth.RecordAttempt(r.Context(), ip, false)
	s.writeAuthLog("login failed", ip, reason)
	s.Activity.Record(r.Context(), logs.Entry{Action: "login.failed", Status: logs.StatusFailed, Summary: msg, Error: reason}, nil)
	if s.Notify != nil {
		// Key per IP: one message per IP and hour however many attempts follow.
		s.Notify.Send(r.Context(), notify.Event{Kind: notify.KindLoginFailed, Key: "login.failed:" + ip,
			Title: "Başarısız panel girişi: " + ip, Text: "Sebep: " + reason + " (15 dk'da 5 hatada IP engellenir)"})
	}
	s.render(w, r, http.StatusUnauthorized, page, "layout", Page{Title: "Giriş", Error: msg})
}

func (s *Server) rateLimited(w http.ResponseWriter, r *http.Request, page string) bool {
	if err := s.Auth.CheckRate(r.Context(), clientIP(r)); err != nil {
		if errors.Is(err, auth.ErrRateLimited) {
			s.writeAuthLog("login blocked", clientIP(r), "rate_limited")
		}
		s.render(w, r, http.StatusTooManyRequests, page, "layout",
			Page{Title: "Giriş", Error: "Çok fazla başarısız deneme. 15 dakika sonra tekrar deneyin."})
		return true
	}
	return false
}

func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, "login") {
		return
	}
	u, ok := s.Auth.CheckPassword(r.Context(), r.PostFormValue("username"), r.PostFormValue("password"))
	if !ok {
		s.loginFail(w, r, "login", "password", "Kullanıcı adı veya şifre hatalı.")
		return
	}
	stage := auth.StageFull
	if u.TOTPEnabled {
		stage = auth.StageMFA
	}
	if old := tokenFrom(r); old != "" {
		s.Auth.DeleteSession(r.Context(), old)
	}
	tok, err := s.Auth.CreateSession(r.Context(), u.ID, stage, clientIP(r), r.UserAgent())
	if err != nil {
		http.Error(w, "Oturum oluşturulamadı", http.StatusInternalServerError)
		return
	}
	s.setSessionCookie(w, tok, int(auth.SessionIdle.Seconds()))
	if stage == auth.StageMFA {
		http.Redirect(w, r, "/login/2fa", http.StatusSeeOther)
		return
	}
	s.loginSuccess(r, "şifre")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) loginSuccess(r *http.Request, method string) {
	ip := clientIP(r)
	newIP := !s.Auth.IsKnownIP(r.Context(), ip)
	s.Auth.RecordAttempt(r.Context(), ip, true)
	summary := "Giriş yapıldı (" + method + ")"
	if newIP {
		summary += " — yeni IP adresi"
	}
	s.Activity.Record(r.Context(), logs.Entry{Action: "login.success", Summary: summary}, nil)
	// notify keeps its own list of the last 20 IPs (login_attempts are purged).
	if s.Notify != nil && s.Notify.NewIP(r.Context(), ip) {
		s.Notify.Send(r.Context(), notify.Event{Kind: notify.KindLoginNewIP, Key: "login.newip:" + ip,
			Title: "Panele yeni bir IP adresinden giriş yapıldı: " + ip,
			Text:  "Yöntem: " + method + "\nTarayıcı: " + truncate(r.UserAgent(), 120) + "\nSiz değilseniz şifreyi değiştirin ve oturumları kapatın."})
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func (s *Server) mfaPage(w http.ResponseWriter, r *http.Request) {
	se := sessionFrom(r)
	if se == nil || se.Stage != auth.StageMFA {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.render(w, r, http.StatusOK, "login_2fa", "layout", Page{Title: "İki adımlı doğrulama"})
}

func (s *Server) mfaSubmit(w http.ResponseWriter, r *http.Request) {
	se := sessionFrom(r)
	if se == nil || se.Stage != auth.StageMFA {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if s.rateLimited(w, r, "login_2fa") {
		return
	}
	u, err := s.Auth.Admin(r.Context())
	if err != nil {
		http.Error(w, "Hesap bulunamadı", http.StatusInternalServerError)
		return
	}
	usedRecovery, ok := s.Auth.VerifySecondFactor(r.Context(), u, r.PostFormValue("code"))
	if !ok {
		s.loginFail(w, r, "login_2fa", "totp", "Doğrulama kodu hatalı.")
		return
	}
	tok, err := s.Auth.PromoteSession(r.Context(), tokenFrom(r), se, clientIP(r), r.UserAgent())
	if err != nil {
		http.Error(w, "Oturum oluşturulamadı", http.StatusInternalServerError)
		return
	}
	s.setSessionCookie(w, tok, int(auth.SessionIdle.Seconds()))
	method := "şifre + TOTP"
	if usedRecovery {
		method = "şifre + kurtarma kodu"
	}
	s.loginSuccess(r, method)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if tok := tokenFrom(r); tok != "" {
		s.Auth.DeleteSession(r.Context(), tok)
		s.Activity.Record(r.Context(), logs.Entry{Action: "logout", Summary: "Çıkış yapıldı"}, nil)
	}
	s.setSessionCookie(w, "", -1)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
