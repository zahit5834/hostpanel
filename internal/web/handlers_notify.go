package web

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/metrics"
	"github.com/zahit5834/hostpanel/internal/notify"
)

type notifyData struct {
	C        notify.Config
	HasToken bool
	HasPass  bool
	Kinds    []struct{ ID, Label string }

	Summary   SummarySchedule
	NextSum   time.Time
	Weekdays  []string
	Heartbeat string
	PingAt    time.Time
	PingErr   string
}

var weekdaysTR = []string{"Pazar", "Pazartesi", "Salı", "Çarşamba", "Perşembe", "Cuma", "Cumartesi"}

func (s *Server) renderNotify(w http.ResponseWriter, r *http.Request, status int, errMsg, notice string) {
	c := s.Notify.Load(r.Context())
	d := notifyData{C: c, HasToken: c.TelegramToken != "", HasPass: c.SMTPPass != "", Kinds: notify.Kinds,
		Summary: s.summarySchedule(r.Context()), Weekdays: weekdaysTR}
	d.NextSum = NextSummary(time.Now(), d.Summary)
	if s.Metrics != nil {
		d.Heartbeat = s.Metrics.HeartbeatURL(r.Context())
		d.PingAt, d.PingErr = s.Metrics.PingState()
	}
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
		Kinds: r.PostForm["kind"], Commands: r.PostFormValue("telegram_commands") == "1",
	}
	hour, _ := strconv.Atoi(r.PostFormValue("summary_hour"))
	wd, _ := strconv.Atoi(r.PostFormValue("summary_weekday"))
	sum := SummarySchedule{Mode: r.PostFormValue("summary_mode"), Hour: hour, Weekday: wd}
	if sum.Mode == "" {
		sum.Mode = "off"
	}
	heartbeat := strings.TrimSpace(r.PostFormValue("heartbeat_url"))
	if in.Kinds == nil {
		in.Kinds = []string{}
	}
	entry := logs.Entry{Action: "settings.notify", TargetType: "settings", TargetID: "notify", Summary: "Bildirim ayarları kaydedildi"}
	err := sum.Validate()
	if err == nil && s.Metrics != nil {
		err = metrics.ValidHeartbeat(heartbeat)
	}
	if err == nil {
		err = s.Notify.Save(r.Context(), in)
	}
	if err == nil {
		err = s.saveSummary(r.Context(), sum)
	}
	if err == nil && s.Metrics != nil {
		err = s.Metrics.SaveHeartbeat(r.Context(), heartbeat)
	}
	if err != nil {
		entry.Status, entry.Error = logs.StatusFailed, err.Error()
		s.Activity.Record(r.Context(), entry, nil)
		s.renderNotify(w, r, http.StatusBadRequest, err.Error(), "")
		return
	}
	// The heartbeat URL is the check's secret: only whether it is set is logged.
	s.Activity.Record(r.Context(), entry, map[string]any{"telegram": in.TelegramOn, "email": in.SMTPOn, "kinds": in.Kinds,
		"telegram_commands": in.Commands, "summary": sum.Mode, "heartbeat": heartbeat != ""})
	s.renderNotify(w, r, http.StatusOK, "", "Bildirim ayarları kaydedildi.")
}

func (s *Server) notifyTest(w http.ResponseWriter, r *http.Request) {
	if err := s.Notify.Test(r.Context()); err != nil {
		s.renderNotify(w, r, http.StatusBadGateway, "Test bildirimi gönderilemedi: "+err.Error(), "")
		return
	}
	s.renderNotify(w, r, http.StatusOK, "", "Test bildirimi gönderildi.")
}
