package web

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/notify"
)

type notifyData struct {
	C        notify.Config
	HasToken bool
	HasPass  bool
	Kinds    []struct{ ID, Label string }
}

func (s *Server) renderNotify(w http.ResponseWriter, r *http.Request, status int, errMsg, notice string) {
	c := s.Notify.Load(r.Context())
	d := notifyData{C: c, HasToken: c.TelegramToken != "", HasPass: c.SMTPPass != "", Kinds: notify.Kinds}
	// Secrets are never sent back to the browser.
	d.C.TelegramToken, d.C.SMTPPass = "", ""
	s.render(w, r, status, "settings_notify", "layout", Page{Title: "Bildirimler", Nav: "settings", Data: d, Error: errMsg, Notice: notice})
}

func (s *Server) notifyPage(w http.ResponseWriter, r *http.Request) {
	s.renderNotify(w, r, http.StatusOK, "", "")
}

func (s *Server) notifySave(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	port, _ := strconv.Atoi(strings.TrimSpace(r.PostFormValue("smtp_port")))
	in := notify.Input{
		TelegramOn: r.PostFormValue("telegram_on") == "1", TelegramToken: r.PostFormValue("telegram_token"),
		TelegramChat: r.PostFormValue("telegram_chat"),
		SMTPOn:       r.PostFormValue("smtp_on") == "1", SMTPHost: r.PostFormValue("smtp_host"), SMTPPort: port,
		SMTPUser: r.PostFormValue("smtp_user"), SMTPPass: r.PostFormValue("smtp_pass"),
		SMTPFrom: r.PostFormValue("smtp_from"), SMTPTo: r.PostFormValue("smtp_to"),
		Kinds: r.PostForm["kind"],
	}
	if in.Kinds == nil {
		in.Kinds = []string{}
	}
	entry := logs.Entry{Action: "settings.notify", TargetType: "settings", TargetID: "notify", Summary: "Bildirim ayarları kaydedildi"}
	if err := s.Notify.Save(r.Context(), in); err != nil {
		entry.Status, entry.Error = logs.StatusFailed, err.Error()
		s.Activity.Record(r.Context(), entry, nil)
		s.renderNotify(w, r, http.StatusBadRequest, err.Error(), "")
		return
	}
	s.Activity.Record(r.Context(), entry, map[string]any{"telegram": in.TelegramOn, "email": in.SMTPOn, "kinds": in.Kinds})
	s.renderNotify(w, r, http.StatusOK, "", "Bildirim ayarları kaydedildi.")
}

func (s *Server) notifyTest(w http.ResponseWriter, r *http.Request) {
	if err := s.Notify.Test(r.Context()); err != nil {
		s.renderNotify(w, r, http.StatusBadGateway, "Test bildirimi gönderilemedi: "+err.Error(), "")
		return
	}
	s.renderNotify(w, r, http.StatusOK, "", "Test bildirimi gönderildi.")
}
