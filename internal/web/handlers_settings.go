package web

import (
	"net/http"
	"strings"

	"github.com/zahit5834/hostpanel/internal/auth"
	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/store"
)

type securityData struct {
	Username      string
	TOTPEnabled   bool
	RecoveryLeft  int
	Allowlist     string
	ClientIP      string
	Setup         *auth.TOTPSetup
	RecoveryCodes []string
	Sessions      []sessionRow
	Attempts      []attemptRow
}

func (s *Server) securityData(r *http.Request) (securityData, error) {
	u, err := s.Auth.Admin(r.Context())
	if err != nil {
		return securityData{}, err
	}
	d := securityData{
		Username:     u.Username,
		TOTPEnabled:  u.TOTPEnabled,
		RecoveryLeft: s.Auth.RecoveryCodesLeft(r.Context()),
		Allowlist:    store.GetSetting(r.Context(), s.DB, "ip_allowlist", ""),
		ClientIP:     clientIP(r),
	}
	d.Sessions, d.Attempts = s.sessionsData(r)
	return d, nil
}

func (s *Server) renderSecurity(w http.ResponseWriter, r *http.Request, status int, d securityData, errMsg, notice string) {
	s.render(w, r, status, "settings_security", "layout", Page{Title: "Güvenlik", Nav: "settings", Data: d, Error: errMsg, Notice: notice})
}

func (s *Server) securityPage(w http.ResponseWriter, r *http.Request) {
	d, err := s.securityData(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.renderSecurity(w, r, http.StatusOK, d, "", "")
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	d, _ := s.securityData(r)
	cur, next, confirm := r.PostFormValue("current"), r.PostFormValue("new"), r.PostFormValue("confirm")
	if _, ok := s.Auth.CheckPassword(r.Context(), d.Username, cur); !ok {
		s.Activity.Record(r.Context(), logs.Entry{Action: "settings.password", Status: logs.StatusFailed, Error: "mevcut şifre hatalı"}, nil)
		s.renderSecurity(w, r, http.StatusBadRequest, d, "Mevcut şifre hatalı.", "")
		return
	}
	if len(next) < 12 {
		s.renderSecurity(w, r, http.StatusBadRequest, d, "Yeni şifre en az 12 karakter olmalı.", "")
		return
	}
	if next != confirm {
		s.renderSecurity(w, r, http.StatusBadRequest, d, "Yeni şifreler eşleşmiyor.", "")
		return
	}
	if err := s.Auth.SetAdminPassword(r.Context(), d.Username, next); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.Activity.Record(r.Context(), logs.Entry{Action: "settings.password", Summary: "Admin şifresi değiştirildi"}, nil)
	// All sessions were revoked; issue a new one for this browser.
	tok, err := s.Auth.CreateSession(r.Context(), auth.AdminID, auth.StageFull, clientIP(r), r.UserAgent())
	if err == nil {
		s.setSessionCookie(w, tok, int(auth.SessionIdle.Seconds()))
	}
	http.Redirect(w, r, "/settings/security", http.StatusSeeOther)
}

func (s *Server) totpStart(w http.ResponseWriter, r *http.Request) {
	d, _ := s.securityData(r)
	setup, err := s.Auth.NewTOTP(d.Username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	d.Setup = &setup
	s.renderSecurity(w, r, http.StatusOK, d, "", "")
}

func (s *Server) totpEnable(w http.ResponseWriter, r *http.Request) {
	d, _ := s.securityData(r)
	codes, err := s.Auth.EnableTOTP(r.Context(), r.PostFormValue("sealed"), r.PostFormValue("code"))
	if err != nil {
		// Keep the same QR on screen so the admin can retry.
		if setup, e := s.Auth.NewTOTP(d.Username); e == nil {
			d.Setup = &setup
		}
		s.Activity.Record(r.Context(), logs.Entry{Action: "settings.2fa.enable", Status: logs.StatusFailed, Error: err.Error()}, nil)
		s.renderSecurity(w, r, http.StatusBadRequest, d, err.Error()+" Yeni QR kod oluşturuldu, tekrar tarayın.", "")
		return
	}
	s.Activity.Record(r.Context(), logs.Entry{Action: "settings.2fa.enable", Summary: "İki adımlı doğrulama etkinleştirildi"}, nil)
	d, _ = s.securityData(r)
	d.RecoveryCodes = codes
	s.renderSecurity(w, r, http.StatusOK, d, "", "İki adımlı doğrulama etkin. Kurtarma kodlarını güvenli bir yere kaydedin; tekrar gösterilmeyecek.")
}

func (s *Server) totpDisable(w http.ResponseWriter, r *http.Request) {
	d, _ := s.securityData(r)
	u, _ := s.Auth.Admin(r.Context())
	if _, ok := s.Auth.CheckPassword(r.Context(), u.Username, r.PostFormValue("password")); !ok {
		s.renderSecurity(w, r, http.StatusBadRequest, d, "Şifre hatalı.", "")
		return
	}
	if _, ok := s.Auth.VerifySecondFactor(r.Context(), u, r.PostFormValue("code")); !ok {
		s.renderSecurity(w, r, http.StatusBadRequest, d, "Doğrulama kodu hatalı.", "")
		return
	}
	if err := s.Auth.DisableTOTP(r.Context()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.Activity.Record(r.Context(), logs.Entry{Action: "settings.2fa.disable", Summary: "İki adımlı doğrulama kapatıldı"}, nil)
	s.securityAlert(r, "Panelde iki adımlı doğrulama kapatıldı", "Ayarlar → Güvenlik'ten kapatıldı.")
	http.Redirect(w, r, "/settings/security", http.StatusSeeOther)
}

func (s *Server) recoveryRegenerate(w http.ResponseWriter, r *http.Request) {
	d, _ := s.securityData(r)
	if !d.TOTPEnabled {
		http.Redirect(w, r, "/settings/security", http.StatusSeeOther)
		return
	}
	codes, err := s.Auth.RegenerateRecoveryCodes(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.Activity.Record(r.Context(), logs.Entry{Action: "settings.2fa.recovery", Summary: "Kurtarma kodları yenilendi"}, nil)
	d.RecoveryCodes = codes
	d.RecoveryLeft = len(codes)
	s.renderSecurity(w, r, http.StatusOK, d, "", "Yeni kurtarma kodları oluşturuldu; eskiler geçersiz.")
}

func (s *Server) saveAllowlist(w http.ResponseWriter, r *http.Request) {
	d, _ := s.securityData(r)
	raw := strings.TrimSpace(r.PostFormValue("allowlist"))
	prefixes, err := parseAllowlist(raw)
	if err != nil {
		s.renderSecurity(w, r, http.StatusBadRequest, d, "Geçersiz IP/CIDR: "+err.Error(), "")
		return
	}
	// Refuse a list that would lock out the admin's current connection.
	if !allowed(prefixes, clientIP(r)) {
		s.renderSecurity(w, r, http.StatusBadRequest, d, "Bu liste mevcut IP adresinizi ("+clientIP(r)+") içermiyor; kendinizi kilitlememek için kaydedilmedi.", "")
		return
	}
	old := d.Allowlist
	if err := store.SetSetting(r.Context(), s.DB, "ip_allowlist", raw); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.loadAllowlist(raw)
	s.Activity.Record(r.Context(), logs.Entry{Action: "settings.update", TargetType: "setting", TargetID: "ip_allowlist",
		Summary: "IP izin listesi güncellendi", Diff: simpleDiff(old, raw)}, nil)
	http.Redirect(w, r, "/settings/security", http.StatusSeeOther)
}

// simpleDiff produces a line-based +/- diff, enough for small config values.
func simpleDiff(before, after string) string {
	split := func(s string) []string {
		return strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == ',' })
	}
	a, b := split(before), split(after)
	inB := map[string]bool{}
	for _, l := range b {
		inB[strings.TrimSpace(l)] = true
	}
	inA := map[string]bool{}
	var out []string
	for _, l := range a {
		l = strings.TrimSpace(l)
		inA[l] = true
		if !inB[l] {
			out = append(out, "- "+l)
		} else {
			out = append(out, "  "+l)
		}
	}
	for _, l := range b {
		if l = strings.TrimSpace(l); !inA[l] {
			out = append(out, "+ "+l)
		}
	}
	return strings.Join(out, "\n")
}
