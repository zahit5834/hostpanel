package web

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/mail"
	"github.com/zahit5834/hostpanel/internal/notify"
	"github.com/zahit5834/hostpanel/internal/rbl"
)

func init() {
	funcs["rblList"] = func(id string) rbl.List { l, _ := rbl.ByID(id); return l }
	if _, ok := funcs["join"]; !ok {
		funcs["join"] = strings.Join
	}
}

// Faz 13: E-posta → Teslim edilebilirlik (sending limits, recent senders,
// blocklists, DMARC reports, client set-up). A page of its own so the large
// mail templates do not grow (RAM: one parsed set per cached page).

type mailDelivData struct {
	Installed, Running bool
	Server             mail.Server
	MinRate, MaxRate   int
	RBL                rbl.State
	Lists              []rbl.List
	HasDQS             bool
	ReportAddr         string
	ReportChoices      []string // existing dmarc@ mailboxes
	DMARCLocal         string
	Autoconf           bool
	AutoconfNames      []string
	HostRecords        []mail.Record
	Zone               string // panel zone of the mail host's parent ("" = elsewhere)
	JobID              int64
}

func (s *Server) mailDeliv(w http.ResponseWriter, r *http.Request) {
	s.renderMailDeliv(w, r, http.StatusOK, "", "")
}

func (s *Server) renderMailDeliv(w http.ResponseWriter, r *http.Request, status int, errMsg, notice string) {
	ctx := r.Context()
	d := mailDelivData{MinRate: mail.MinRatePerHour, MaxRate: mail.MaxRatePerHour, Lists: rbl.Lists, DMARCLocal: mail.ReportLocal,
		JobID: parseInt64(r.URL.Query().Get("job"))}
	if srv, err := s.Mail.Store.Server(ctx); err == nil {
		d.Server = srv
		d.Installed = srv.Status == mail.StatusRunning || srv.Status == mail.StatusStopped
		d.Running = srv.Status == mail.StatusRunning
	}
	if s.RBL != nil {
		d.RBL, d.HasDQS = s.RBL.State(ctx), s.RBL.HasKey(ctx)
	}
	d.ReportAddr = s.Mail.ReportAddress(ctx)
	if d.Installed {
		if l, err := s.Mail.Listing(ctx); err == nil {
			for _, m := range l.Mailboxes {
				if lp, _, _ := mail.SplitAddress(m.Address); lp == mail.ReportLocal {
					d.ReportChoices = append(d.ReportChoices, m.Address)
				}
			}
		}
		d.Autoconf = s.Mail.AutoconfReady(ctx)
		d.AutoconfNames = mail.AutoconfNames(d.Server.Hostname)
		ds, _ := s.Mail.Store.Domains(ctx, 0)
		var ips []netip.Addr
		if s.Mail.ServerIPs != nil {
			ips = publicV4(s.Mail.ServerIPs(ctx))
		}
		d.HostRecords = mail.HostRecords(d.Server.Hostname, ips, ds, d.ReportAddr)
		if s.DNS != nil && len(d.AutoconfNames) > 0 {
			d.Zone = s.DNS.ZoneCovering(ctx, d.AutoconfNames[0])
		}
	}
	s.render(w, r, status, "mail_deliv", "layout", Page{Title: "Teslim edilebilirlik · E-posta", Nav: "mail", Data: d, Error: errMsg, Notice: notice})
}

func publicV4(in []netip.Addr) []netip.Addr {
	var out []netip.Addr
	for _, a := range in {
		a = a.Unmap()
		if a.Is4() && a.IsGlobalUnicast() && !a.IsPrivate() {
			out = append(out, a)
		}
	}
	return out
}

// RBLTargets: the server's public IPv4 addresses (mail leaves on IPv4 only)
// and the mail host + mail domains for the domain lists.
func (s *Server) RBLTargets(ctx context.Context) ([]netip.Addr, []string) {
	srv, err := s.Mail.Store.Server(ctx)
	if err != nil || srv.Hostname == "" {
		return nil, nil
	}
	var ips []netip.Addr
	if s.Mail.ServerIPs != nil {
		ips = publicV4(s.Mail.ServerIPs(ctx))
	}
	names := []string{srv.Hostname}
	ds, _ := s.Mail.Store.Domains(ctx, 0)
	for _, d := range ds {
		names = append(names, d.Name)
	}
	return ips, names
}

func (s *Server) mailLimits(w http.ResponseWriter, r *http.Request) {
	rate, alert := formInt(r, "rate_per_hour", -1), formInt(r, "queue_alert", -1)
	act := s.Activity.Begin(r.Context(), logs.Entry{Action: "mail.limits", TargetType: "mail", TargetID: s.Mail.Host(r.Context()),
		Summary: fmt.Sprintf("Posta gönderim sınırı: %s / saat, kuyruk uyarısı %d", rateLabel(rate), alert)}, nil)
	err := s.Mail.SetLimits(r.Context(), rate, alert)
	act.Finish(err)
	if err != nil {
		s.renderMailDeliv(w, r, http.StatusBadRequest, err.Error(), "")
		return
	}
	s.renderMailDeliv(w, r, http.StatusOK, "", "Gönderim sınırı kaydedildi.")
}

func rateLabel(n int) string {
	if n == 0 {
		return "sınırsız"
	}
	return fmt.Sprint(n)
}

// mailSenders is the lazily loaded "senders of the last hour" table.
func (s *Server) mailSenders(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{}
	ss, err := s.Mail.SentStats(r.Context(), 60)
	if err != nil {
		data["Err"] = err.Error()
	}
	data["Senders"] = ss
	if srv, err := s.Mail.Store.Server(r.Context()); err == nil {
		data["Rate"] = srv.RatePerHour
	}
	s.render(w, r, http.StatusOK, "mail_deliv", "mail-senders", Page{Data: data})
}

func (s *Server) mailRBLCheck(w http.ResponseWriter, r *http.Request) {
	_, changes, err := s.RBL.Run(r.Context())
	if err != nil {
		s.renderMailDeliv(w, r, http.StatusBadRequest, err.Error(), "")
		return
	}
	s.rblChanges(r.Context(), changes)
	s.renderMailDeliv(w, r, http.StatusOK, "", "Kara liste kontrolü tamamlandı.")
}

// rblChanges records and notifies listings that appeared or disappeared.
func (s *Server) rblChanges(ctx context.Context, changes []rbl.Change) {
	sys := logs.WithActor(ctx, logs.Actor{Source: logs.SourceSystem})
	for _, c := range changes {
		l, _ := rbl.ByID(c.List)
		var title, text string
		if c.Listed {
			title = "Kara listede: " + c.Target + " (" + l.Name + ")"
			text = "Yanıt: " + strings.Join(c.Codes, ", ") + "\nKaldırma / ayrıntı: " + l.Delist +
				"\nÖnce sebebi giderin (ele geçirilmiş kutu, açık form): E-posta → Teslim edilebilirlik."
		} else {
			title = "Kara listeden çıktı: " + c.Target + " (" + l.Name + ")"
		}
		action := "mail.rbl.listed"
		if !c.Listed {
			action = "mail.rbl.delisted"
		}
		s.Activity.Record(sys, logs.Entry{Action: action, TargetType: "mail", TargetID: c.Target, Summary: title}, nil)
		if s.Notify != nil {
			s.Notify.Send(ctx, notify.Event{Kind: notify.KindMail, Key: "rbl:" + c.List + ":" + c.Target + fmt.Sprint(c.Listed),
				Title: title, Text: text})
		}
	}
}

func (s *Server) mailRBLKey(w http.ResponseWriter, r *http.Request) {
	key := strings.ToLower(strings.TrimSpace(r.PostFormValue("dqs_key")))
	clear := r.PostFormValue("clear") == "1"
	if key == "" && !clear {
		s.renderMailDeliv(w, r, http.StatusBadRequest, "Anahtar girin (silmek için “Anahtarı kaldır”).", "")
		return
	}
	if clear {
		key = ""
	}
	summary := "Spamhaus DQS anahtarı kaydedildi"
	if clear {
		summary = "Spamhaus DQS anahtarı kaldırıldı"
	}
	act := s.Activity.Begin(r.Context(), logs.Entry{Action: "mail.rbl.key", TargetType: "mail", Summary: summary}, nil)
	err := s.RBL.SetKey(r.Context(), key)
	act.Finish(err)
	if err != nil {
		s.renderMailDeliv(w, r, http.StatusBadRequest, err.Error(), "")
		return
	}
	s.renderMailDeliv(w, r, http.StatusOK, "", summary+".")
}

func (s *Server) mailDMARCAddress(w http.ResponseWriter, r *http.Request) {
	addr := mail.NormalizeAddress(r.PostFormValue("address"))
	summary := "DMARC raporları kapatıldı"
	if addr != "" {
		summary = "DMARC rapor kutusu: " + addr
	}
	act := s.Activity.Begin(r.Context(), logs.Entry{Action: "mail.dmarc.address", TargetType: "mail", TargetID: addr, Summary: summary}, nil)
	err := s.Mail.SetReportAddress(r.Context(), addr)
	act.Finish(err)
	if err != nil {
		s.renderMailDeliv(w, r, http.StatusBadRequest, err.Error(), "")
		return
	}
	s.renderMailDeliv(w, r, http.StatusOK, "", summary+". DNS kayıtları yeniden uygulanıyor.")
}

// mailDMARC is the lazily loaded report summary: new report mails are
// copied (root) and parsed first.
func (s *Server) mailDMARC(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	data := map[string]any{"Days": 30}
	if s.Mail.ReportAddress(ctx) != "" {
		res, err := s.Mail.SyncReports(ctx)
		data["Sync"] = res
		if err != nil {
			data["Err"] = err.Error()
		}
	}
	sum, err := s.Mail.DMARCSummaries(ctx, time.Now().AddDate(0, 0, -30))
	if err != nil {
		data["Err"] = err.Error()
	}
	data["Summaries"] = sum
	data["FileErrors"], _ = s.Mail.Store.ReportFileErrors(ctx, 5)
	s.render(w, r, http.StatusOK, "mail_deliv", "mail-dmarc", Page{Data: data})
}

func (s *Server) mailAutoconf(w http.ResponseWriter, r *http.Request) {
	jid, err := s.Mail.StartCertExpand(r.Context())
	if err != nil {
		s.renderMailDeliv(w, r, http.StatusBadRequest, err.Error(), "")
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/mail/deliverability?job=%d", jid), http.StatusSeeOther)
}

func (s *Server) mailDomainDMARC(w http.ResponseWriter, r *http.Request) {
	d, ok := s.mailDomainOK(w, r)
	if !ok {
		return
	}
	p := r.PostFormValue("policy")
	act := s.Activity.Begin(r.Context(), logs.Entry{Action: "mail.dmarc.policy", TargetType: "mail_domain", TargetID: d.Name,
		Summary: "DMARC politikası: " + d.Name + " p=" + p}, nil)
	err := s.Mail.SetDMARCPolicy(r.Context(), d.ID, p)
	act.Finish(err)
	if err != nil {
		s.renderMailDomain(w, r, http.StatusBadRequest, nil, err.Error(), "")
		return
	}
	s.renderMailDomain(w, r, http.StatusOK, nil, "", "DMARC politikası p="+p+" olarak kaydedildi (DNS yeniden uygulanıyor).")
}

// mailMobileConfig downloads an Apple profile for one mailbox (no password
// inside; nothing secret, so no activity record).
func (s *Server) mailMobileConfig(w http.ResponseWriter, r *http.Request) {
	d, ok := s.mailDomainOK(w, r)
	if !ok {
		return
	}
	addr := mail.NormalizeAddress(r.URL.Query().Get("address"))
	host := s.Mail.Host(r.Context())
	if mail.DomainOf(addr) != d.Name || host == "" {
		http.NotFound(w, r)
		return
	}
	l, err := s.Mail.Listing(r.Context())
	if err != nil || !l.HasMailbox(addr) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("Content-Disposition", `attachment; filename="`+strings.ReplaceAll(addr, "@", "_at_")+`.mobileconfig"`)
	w.Write(mail.AppleProfile(addr, host))
}

// MailMaintain is the daily mail step: blocklists (real servers only) and
// new DMARC reports.
func (s *Server) MailMaintain(ctx context.Context) {
	if s.Mail == nil {
		return
	}
	srv, err := s.Mail.Store.Server(ctx)
	if err != nil || srv.Status != mail.StatusRunning {
		return
	}
	if s.RBL != nil && !s.Cfg.DryRun {
		if _, changes, err := s.RBL.Run(ctx); err != nil {
			s.Log.Warn("rbl check failed", "err", err)
		} else {
			s.rblChanges(ctx, changes)
		}
	}
	if s.Mail.ReportAddress(ctx) != "" {
		if _, err := s.Mail.SyncReports(ctx); err != nil {
			s.Log.Warn("dmarc sync failed", "err", err)
		}
	}
}
