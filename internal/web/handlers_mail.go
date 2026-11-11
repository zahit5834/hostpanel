package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/zahit5834/hostpanel/internal/backups"
	"github.com/zahit5834/hostpanel/internal/customers"
	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/mail"
)

// mailDomainRow is one line of the domain table.
type mailDomainRow struct {
	mail.Domain
	Mailboxes int
	Aliases   int
}

type mailPageData struct {
	Server       *mail.Server
	DockerReady  bool
	Domains      []mailDomainRow
	ListErr      string
	Customers    []customers.Customer
	JobID        int64
	DefaultImage string
	DefaultMem   int
	MinMem       int
	ClamAVMin    int
	MaxMsg       int
	MemTotalMB   int
	Form         mail.InstallInput
	Backups      []backups.Backup
	RemoteReady  bool
}

func (s *Server) mailPage(w http.ResponseWriter, r *http.Request) {
	s.renderMail(w, r, http.StatusOK, mail.InstallInput{MemoryMB: mail.DefaultMemoryMB}, "", "")
}

func (s *Server) renderMail(w http.ResponseWriter, r *http.Request, status int, form mail.InstallInput, errMsg, notice string) {
	ctx := r.Context()
	d := mailPageData{JobID: parseInt64(r.URL.Query().Get("job")), DefaultImage: mail.DefaultImage,
		DefaultMem: mail.DefaultMemoryMB, MinMem: mail.MinMemoryMB, ClamAVMin: mail.ClamAVMinMemoryMB, MaxMsg: mail.MaxMsgLimitMB,
		MemTotalMB: s.Mail.MemTotalMB, Form: form, DockerReady: s.Mail.DockerPresent(ctx)}
	if form.MemoryMB == 0 {
		d.Form.MemoryMB = mail.DefaultMemoryMB
	}
	d.Customers, _ = s.Customers.List(ctx, "")
	if srv, err := s.Mail.Store.Server(ctx); err == nil {
		d.Server = &srv
		ds, _ := s.Mail.Store.Domains(ctx, 0)
		var l mail.Listing
		if srv.Status == mail.StatusRunning || srv.Status == mail.StatusStopped {
			var err error
			if l, err = s.Mail.Listing(ctx); err != nil {
				d.ListErr = err.Error()
			}
		}
		for _, dm := range ds {
			own := l.ForDomain(dm.Name)
			d.Domains = append(d.Domains, mailDomainRow{Domain: dm, Mailboxes: len(own.Mailboxes), Aliases: len(own.Aliases)})
		}
		d.Backups, _ = s.Backups.Store.Backups(ctx, backups.Filter{Domain: backups.MailDomain, Limit: 20})
		d.RemoteReady = s.Backups.Remote(ctx).Configured()
	}
	s.render(w, r, status, "mail", "layout", Page{Title: "E-posta", Nav: "mail", Data: d, Error: errMsg, Notice: notice})
}

func (s *Server) mailJobRedirect(w http.ResponseWriter, r *http.Request, id int64, err error) {
	if err != nil {
		s.renderMail(w, r, http.StatusBadRequest, mail.InstallInput{}, err.Error(), "")
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/mail?job=%d", id), http.StatusSeeOther)
}

func (s *Server) mailStatus(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "mail", "mail-status", Page{Data: s.Mail.LiveStatus(r.Context())})
}

type mailOpsData struct {
	Queue    int
	QueueErr string
	Bans     []mail.Ban
	BansErr  string
	Running  bool
}

// mailOps is the lazily loaded queue + ban block (helper calls).
func (s *Server) mailOps(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var d mailOpsData
	if srv, err := s.Mail.Store.Server(ctx); err == nil && srv.Status == mail.StatusRunning {
		d.Running = true
		if n, err := s.Mail.Queue(ctx); err != nil {
			d.QueueErr = err.Error()
		} else {
			d.Queue = n
		}
		if b, err := s.Mail.Bans(ctx); err != nil {
			d.BansErr = err.Error()
		} else {
			d.Bans = b
		}
	}
	s.render(w, r, http.StatusOK, "mail", "mail-ops", Page{Data: d})
}

func (s *Server) mailServerInstall(w http.ResponseWriter, r *http.Request) {
	in := mail.InstallInput{
		Hostname:   r.PostFormValue("hostname"),
		Domain:     r.PostFormValue("domain"),
		CustomerID: parseInt64(r.PostFormValue("customer_id")),
		LEEmail:    r.PostFormValue("le_email"),
		MemoryMB:   formInt(r, "memory_mb", mail.DefaultMemoryMB),
	}
	id, err := s.Mail.StartInstall(r.Context(), in)
	if err != nil {
		s.renderMail(w, r, http.StatusBadRequest, in, err.Error(), "")
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/mail?job=%d", id), http.StatusSeeOther)
}

func (s *Server) mailServerRemove(w http.ResponseWriter, r *http.Request) {
	act := s.Activity.Begin(r.Context(), logs.Entry{Action: "mail.server.remove", TargetType: "mail", TargetID: s.Mail.Host(r.Context()),
		Summary: "Yarım kalan posta sunucusu kurulumu kaldırıldı"}, nil)
	err := s.Mail.RemoveFailed(r.Context(), nil)
	act.Finish(err)
	if err != nil {
		s.renderMail(w, r, http.StatusBadRequest, mail.InstallInput{}, err.Error(), "")
		return
	}
	http.Redirect(w, r, "/mail", http.StatusSeeOther)
}

func (s *Server) mailServerOp(w http.ResponseWriter, r *http.Request) {
	op := r.PathValue("op")
	label, ok := dbOpLabels[op]
	if !ok {
		http.NotFound(w, r)
		return
	}
	act := s.Activity.Begin(r.Context(), logs.Entry{Action: "mail.server." + op, TargetType: "mail", TargetID: s.Mail.Host(r.Context()),
		Summary: "Posta sunucusu " + label}, nil)
	err := s.Mail.Operate(r.Context(), op)
	act.Finish(err)
	if err != nil {
		s.renderMail(w, r, http.StatusBadRequest, mail.InstallInput{}, "İşlem başarısız: "+err.Error(), "")
		return
	}
	http.Redirect(w, r, "/mail", http.StatusSeeOther)
}

func (s *Server) mailServerSettings(w http.ResponseWriter, r *http.Request) {
	in := mail.SettingsInput{
		MemoryMB:   formInt(r, "memory_mb", 0),
		ClamAV:     r.PostFormValue("clamav") == "1",
		MsgLimitMB: formInt(r, "msg_limit_mb", 0),
	}
	id, diff, err := s.Mail.StartSettings(r.Context(), in)
	if err == nil {
		if j, jerr := s.Jobs.Get(r.Context(), id); jerr == nil {
			s.setActivityDiff(j.ActivityID, diff)
		}
	}
	s.mailJobRedirect(w, r, id, err)
}

func (s *Server) mailCheck(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "mail", "mail-checks", Page{Data: s.Mail.CheckServer(r.Context())})
}

func (s *Server) mailFlush(w http.ResponseWriter, r *http.Request) {
	act := s.Activity.Begin(r.Context(), logs.Entry{Action: "mail.queue.flush", TargetType: "mail", TargetID: s.Mail.Host(r.Context()),
		Summary: "Posta kuyruğu yeniden deneniyor"}, nil)
	err := s.Mail.Flush(r.Context())
	act.Finish(err)
	if err != nil {
		s.renderMail(w, r, http.StatusBadRequest, mail.InstallInput{}, "İşlem başarısız: "+err.Error(), "")
		return
	}
	s.renderMail(w, r, http.StatusOK, mail.InstallInput{}, "", "Kuyruktaki iletiler yeniden deneniyor.")
}

func (s *Server) mailUnban(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.PostFormValue("ip"))
	act := s.Activity.Begin(r.Context(), logs.Entry{Action: "mail.unban", TargetType: "mail", TargetID: ip,
		Summary: "Posta sunucusunda engel kaldırıldı: " + ip}, nil)
	err := s.Mail.Unban(r.Context(), ip)
	act.Finish(err)
	if err != nil {
		s.renderMail(w, r, http.StatusBadRequest, mail.InstallInput{}, "İşlem başarısız: "+err.Error(), "")
		return
	}
	s.renderMail(w, r, http.StatusOK, mail.InstallInput{}, "", "Engel kaldırıldı: "+ip)
}

func (s *Server) mailBackup(w http.ResponseWriter, r *http.Request) {
	id, err := s.Backups.StartMailBackup(r.Context(), r.PostFormValue("upload") == "1")
	s.mailJobRedirect(w, r, id, err)
}

func (s *Server) mailRestore(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	b, err := s.Backups.Store.Backup(r.Context(), id)
	if err != nil || !b.IsMail() {
		http.NotFound(w, r)
		return
	}
	if strings.TrimSpace(r.PostFormValue("confirm")) != b.Name {
		s.renderMail(w, r, http.StatusBadRequest, mail.InstallInput{}, "Onay için yedeğin adını tam olarak yazın: "+b.Name, "")
		return
	}
	jid, err := s.Backups.StartMailRestore(r.Context(), b.ID)
	s.mailJobRedirect(w, r, jid, err)
}

func (s *Server) mailDomainAdd(w http.ResponseWriter, r *http.Request) {
	name := r.PostFormValue("name")
	cid := parseInt64(r.PostFormValue("customer_id"))
	act := s.Activity.Begin(r.Context(), logs.Entry{Action: "mail.domain.create", TargetType: "mail_domain", TargetID: strings.ToLower(strings.TrimSpace(name)),
		Summary: "Posta alan adı eklendi: " + strings.ToLower(strings.TrimSpace(name))}, map[string]any{"customer_id": cid})
	d, err := s.Mail.AddDomain(r.Context(), name, cid)
	act.Finish(err)
	if err != nil {
		s.renderMail(w, r, http.StatusBadRequest, mail.InstallInput{}, err.Error(), "")
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/mail/domains/%d", d.ID), http.StatusSeeOther)
}

// --- domain page ---

type mailRevealed struct {
	Address  string
	Password string
	Created  bool
}

type mailDomainData struct {
	Domain     mail.Domain
	Host       string
	Running    bool
	Installed  bool
	Mailboxes  []mail.Mailbox
	Aliases    []mail.Alias
	ListErr    string
	Records    []mail.Record
	Zone       string // panel zone serving the domain ("" = records are added elsewhere)
	DNSReady   bool
	Customers  []customers.Customer
	JobID      int64
	Revealed   *mailRevealed
	MaxTargets int
}

func (s *Server) mailDomainPage(w http.ResponseWriter, r *http.Request) {
	s.renderMailDomain(w, r, http.StatusOK, nil, "", "")
}

func (s *Server) renderMailDomain(w http.ResponseWriter, r *http.Request, status int, rev *mailRevealed, errMsg, notice string) {
	ctx := r.Context()
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	dm, err := s.Mail.Store.Domain(ctx, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	d := mailDomainData{Domain: dm, Host: s.Mail.Host(ctx), JobID: parseInt64(r.URL.Query().Get("job")), Revealed: rev,
		MaxTargets: mail.MaxAliasTargets, Installed: s.Mail.Installed(ctx)}
	if srv, err := s.Mail.Store.Server(ctx); err == nil {
		d.Running = srv.Status == mail.StatusRunning
	}
	if d.Installed {
		l, err := s.Mail.Listing(ctx)
		if err != nil {
			d.ListErr = err.Error()
		}
		own := l.ForDomain(dm.Name)
		if d.Running {
			own = s.Mail.WithUsage(ctx, own)
		}
		d.Mailboxes, d.Aliases = own.Mailboxes, own.Aliases
	}
	d.Records = mail.Records(dm, d.Host)
	if s.DNS != nil {
		d.Zone, d.DNSReady = s.DNS.ZoneCovering(ctx, dm.Name), s.DNS.Installed(ctx)
	}
	d.Customers, _ = s.Customers.List(ctx, "")
	s.render(w, r, status, "mail_domain", "layout", Page{Title: dm.Name + " · E-posta", Nav: "mail", Data: d, Error: errMsg, Notice: notice})
}

// mailDomainOK loads the domain of the path or answers 404.
func (s *Server) mailDomainOK(w http.ResponseWriter, r *http.Request) (mail.Domain, bool) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return mail.Domain{}, false
	}
	d, err := s.Mail.Store.Domain(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return d, false
	}
	return d, true
}

func (s *Server) mailDomainDelete(w http.ResponseWriter, r *http.Request) {
	d, ok := s.mailDomainOK(w, r)
	if !ok {
		return
	}
	if strings.TrimSpace(r.PostFormValue("confirm")) != d.Name {
		s.renderMailDomain(w, r, http.StatusBadRequest, nil, "Onay için alan adını tam olarak yazın: "+d.Name, "")
		return
	}
	act := s.Activity.Begin(r.Context(), logs.Entry{Action: "mail.domain.delete", TargetType: "mail_domain", TargetID: d.Name,
		Summary: "Posta alan adı silindi: " + d.Name}, nil)
	_, err := s.Mail.DeleteDomain(r.Context(), d.ID)
	act.Finish(err)
	if err != nil {
		s.renderMailDomain(w, r, http.StatusBadRequest, nil, err.Error(), "")
		return
	}
	http.Redirect(w, r, "/mail", http.StatusSeeOther)
}

func (s *Server) mailDomainCheck(w http.ResponseWriter, r *http.Request) {
	d, ok := s.mailDomainOK(w, r)
	if !ok {
		return
	}
	s.render(w, r, http.StatusOK, "mail_domain", "mail-checks", Page{Data: s.Mail.CheckDomain(r.Context(), d)})
}

func (s *Server) mailMailboxCreate(w http.ResponseWriter, r *http.Request) {
	d, ok := s.mailDomainOK(w, r)
	if !ok {
		return
	}
	local := strings.ToLower(strings.TrimSpace(r.PostFormValue("local")))
	quota := formInt(r, "quota_mb", 0)
	// The activity never sees the password: only the address and the quota.
	act := s.Activity.Begin(r.Context(), logs.Entry{Action: "mail.mailbox.create", TargetType: "mailbox", TargetID: local + "@" + d.Name,
		Summary: "Posta kutusu oluşturuldu: " + local + "@" + d.Name}, map[string]any{"quota_mb": quota})
	addr, pw, err := s.Mail.CreateMailbox(r.Context(), d.ID, local, r.PostFormValue("password"), quota)
	act.Finish(err)
	if err != nil {
		s.renderMailDomain(w, r, http.StatusBadRequest, nil, err.Error(), "")
		return
	}
	s.renderMailDomain(w, r, http.StatusOK, &mailRevealed{Address: addr, Password: pw, Created: true}, "", "")
}

func (s *Server) mailMailboxPassword(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.mailDomainOK(w, r); !ok {
		return
	}
	addr := mail.NormalizeAddress(r.PostFormValue("address"))
	act := s.Activity.Begin(r.Context(), logs.Entry{Action: "mail.mailbox.password", TargetType: "mailbox", TargetID: addr,
		Summary: "Posta kutusu şifresi değiştirildi: " + addr}, nil)
	pw, err := s.Mail.ResetPassword(r.Context(), addr, r.PostFormValue("password"))
	act.Finish(err)
	if err != nil {
		s.renderMailDomain(w, r, http.StatusBadRequest, nil, err.Error(), "")
		return
	}
	s.renderMailDomain(w, r, http.StatusOK, &mailRevealed{Address: addr, Password: pw}, "", "")
}

func (s *Server) mailMailboxQuota(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.mailDomainOK(w, r); !ok {
		return
	}
	addr := mail.NormalizeAddress(r.PostFormValue("address"))
	mb := formInt(r, "quota_mb", -1)
	act := s.Activity.Begin(r.Context(), logs.Entry{Action: "mail.mailbox.quota", TargetType: "mailbox", TargetID: addr,
		Summary: "Posta kutusu kotası: " + addr + " = " + quotaLabel(mb)}, nil)
	err := s.Mail.SetQuota(r.Context(), addr, mb)
	act.Finish(err)
	if err != nil {
		s.renderMailDomain(w, r, http.StatusBadRequest, nil, err.Error(), "")
		return
	}
	s.renderMailDomain(w, r, http.StatusOK, nil, "", "Kota güncellendi: "+addr+" = "+quotaLabel(mb))
}

func quotaLabel(mb int) string {
	if mb == 0 {
		return "sınırsız"
	}
	return strconv.Itoa(mb) + " MB"
}

func (s *Server) mailMailboxDelete(w http.ResponseWriter, r *http.Request) {
	d, ok := s.mailDomainOK(w, r)
	if !ok {
		return
	}
	addr := mail.NormalizeAddress(r.PostFormValue("address"))
	if strings.TrimSpace(r.PostFormValue("confirm")) != addr {
		s.renderMailDomain(w, r, http.StatusBadRequest, nil, "Onay için adresi tam olarak yazın: "+addr, "")
		return
	}
	jid, err := s.Mail.StartDeleteMailbox(r.Context(), addr)
	if err != nil {
		s.renderMailDomain(w, r, http.StatusBadRequest, nil, err.Error(), "")
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/mail/domains/%d?job=%d", d.ID, jid), http.StatusSeeOther)
}

func (s *Server) mailAliasAdd(w http.ResponseWriter, r *http.Request) {
	d, ok := s.mailDomainOK(w, r)
	if !ok {
		return
	}
	local := strings.ToLower(strings.TrimSpace(r.PostFormValue("local")))
	target := mail.NormalizeAddress(r.PostFormValue("target"))
	act := s.Activity.Begin(r.Context(), logs.Entry{Action: "mail.alias.create", TargetType: "mail_alias", TargetID: local + "@" + d.Name,
		Summary: "Yönlendirme eklendi: " + local + "@" + d.Name + " → " + target}, nil)
	_, err := s.Mail.AddAlias(r.Context(), d.ID, local, target)
	act.Finish(err)
	if err != nil {
		s.renderMailDomain(w, r, http.StatusBadRequest, nil, err.Error(), "")
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/mail/domains/%d", d.ID), http.StatusSeeOther)
}

func (s *Server) mailAliasDelete(w http.ResponseWriter, r *http.Request) {
	d, ok := s.mailDomainOK(w, r)
	if !ok {
		return
	}
	alias := mail.NormalizeAddress(r.PostFormValue("alias"))
	target := mail.NormalizeAddress(r.PostFormValue("target"))
	act := s.Activity.Begin(r.Context(), logs.Entry{Action: "mail.alias.delete", TargetType: "mail_alias", TargetID: alias,
		Summary: "Yönlendirme silindi: " + alias + " → " + target}, nil)
	err := s.Mail.DeleteAlias(r.Context(), alias, target)
	act.Finish(err)
	if err != nil {
		s.renderMailDomain(w, r, http.StatusBadRequest, nil, err.Error(), "")
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/mail/domains/%d", d.ID), http.StatusSeeOther)
}
