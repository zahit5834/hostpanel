package web

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/zahit5834/hostpanel/internal/rbl"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/zahit5834/hostpanel/internal/auth"
	"github.com/zahit5834/hostpanel/internal/exec"
	"github.com/zahit5834/hostpanel/internal/hostsec"
	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/notify"
	"github.com/zahit5834/hostpanel/internal/store"
)

// Settings used by the Faz 11 checks.
const (
	setTransferExported = "transfer_exported_at" // last configuration export (unix)
	setAuditBad         = "security_audit_bad"   // comma list of bad finding ids already notified
	setIntegrityKey     = "security_integrity_key"
	setCLINotified      = "security_notified_id" // newest admin.* activity id already notified
	setSSHWatch         = "ssh_watch_since"      // apply time of a change not yet confirmed/reverted
)

// --- G4: re-authentication for critical actions ---

// requireRecent is requireAuth plus a recent proof of identity (login or
// /reauth within auth.ElevatedFor). A stolen session cookie alone can browse
// but cannot delete, reveal secrets or touch SSH/firewall settings.
func (s *Server) requireRecent(h http.HandlerFunc) http.Handler {
	return s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if se := sessionFrom(r); se != nil && se.Elevated(time.Now()) {
			h(w, r)
			return
		}
		target := "/reauth?next=" + url.QueryEscape(reauthNext(r))
		if isHX(r) {
			w.Header().Set("HX-Redirect", target)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		http.Redirect(w, r, target, http.StatusSeeOther)
	})
}

// reauthNext is where to go after /reauth: the page itself for GET, the page
// the form was on for POST (the action is then repeated by the admin).
func reauthNext(r *http.Request) string {
	if r.Method == http.MethodGet {
		return safeNext(r.URL.RequestURI())
	}
	if u, err := url.Parse(r.Referer()); err == nil && u.Host == r.Host {
		return safeNext(u.RequestURI())
	}
	return "/"
}

// safeNext keeps only local absolute paths ("/x?y"), never "//host" or schemes.
func safeNext(n string) string {
	if n == "" || len(n) > 500 || n[0] != '/' || strings.HasPrefix(n, "//") || strings.HasPrefix(n, "/\\") || strings.ContainsAny(n, "\r\n") {
		return "/"
	}
	u, err := url.Parse(n)
	if err != nil || u.Scheme != "" || u.Host != "" || strings.HasPrefix(u.Path, "/reauth") {
		return "/"
	}
	return n
}

type reauthData struct {
	TOTP bool
	Next string
}

func (s *Server) reauthPage(w http.ResponseWriter, r *http.Request) {
	u, err := s.Auth.Admin(r.Context())
	if err != nil {
		http.Error(w, "Hesap bulunamadı", http.StatusInternalServerError)
		return
	}
	s.render(w, r, http.StatusOK, "reauth", "layout", Page{Title: "Kimlik doğrulama", Nav: "",
		Data: reauthData{TOTP: u.TOTPEnabled, Next: safeNext(r.URL.Query().Get("next"))}})
}

func (s *Server) reauthSubmit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	se := sessionFrom(r)
	u, err := s.Auth.Admin(ctx)
	if err != nil || se == nil {
		http.Error(w, "Hesap bulunamadı", http.StatusInternalServerError)
		return
	}
	d := reauthData{TOTP: u.TOTPEnabled, Next: safeNext(r.PostFormValue("next"))}
	ip := clientIP(r)
	if err := s.Auth.CheckRate(ctx, ip); err != nil {
		s.writeAuthLog("login blocked", ip, "rate_limited")
		s.render(w, r, http.StatusTooManyRequests, "reauth", "layout", Page{Title: "Kimlik doğrulama", Data: d,
			Error: "Çok fazla başarısız deneme. 15 dakika sonra tekrar deneyin."})
		return
	}
	var ok bool
	if u.TOTPEnabled {
		_, ok = s.Auth.VerifySecondFactor(ctx, u, r.PostFormValue("code"))
	} else {
		_, ok = s.Auth.CheckPassword(ctx, u.Username, r.PostFormValue("password"))
	}
	if !ok {
		// Counts toward the login rate limit and the fail2ban jail like a login.
		s.Auth.RecordAttempt(ctx, ip, false)
		s.writeAuthLog("login failed", ip, "reauth")
		s.Activity.Record(ctx, logs.Entry{Action: "auth.reauth", Status: logs.StatusFailed, Summary: "Yeniden doğrulama başarısız"}, nil)
		s.render(w, r, http.StatusUnauthorized, "reauth", "layout", Page{Title: "Kimlik doğrulama", Data: d, Error: "Doğrulama başarısız."})
		return
	}
	if err := s.Auth.Elevate(ctx, se.IDHash); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.Activity.Record(ctx, logs.Entry{Action: "auth.reauth", Summary: "Kritik işlemler için yeniden doğrulandı (10 dk)"}, nil)
	http.Redirect(w, r, d.Next, http.StatusSeeOther)
}

// --- G5: sessions and login history ---

type sessionRow struct {
	auth.Session
	Current bool
	Browser string
}

type attemptRow struct {
	auth.Attempt
	Known bool
}

// shortUA reduces a User-Agent to "Firefox 133 · Linux".
func shortUA(ua string) string {
	browser := ""
	for _, b := range []struct{ key, name string }{{"Edg/", "Edge"}, {"OPR/", "Opera"}, {"Firefox/", "Firefox"}, {"Chrome/", "Chrome"}, {"Version/", "Safari"}, {"curl/", "curl"}} {
		if i := strings.Index(ua, b.key); i >= 0 {
			v := ua[i+len(b.key):]
			if j := strings.IndexAny(v, " .;)"); j >= 0 {
				v = v[:j]
			}
			browser = b.name + " " + v
			break
		}
	}
	osName := ""
	for _, o := range []struct{ key, name string }{{"Android", "Android"}, {"iPhone", "iPhone"}, {"iPad", "iPad"}, {"Windows", "Windows"}, {"Mac OS X", "macOS"}, {"Linux", "Linux"}} {
		if strings.Contains(ua, o.key) {
			osName = o.name
			break
		}
	}
	switch {
	case browser != "" && osName != "":
		return browser + " · " + osName
	case browser != "":
		return browser
	case osName != "":
		return osName
	}
	return truncate(ua, 60)
}

func (s *Server) sessionsData(r *http.Request) ([]sessionRow, []attemptRow) {
	ctx := r.Context()
	cur := sessionFrom(r)
	list, _ := s.Auth.ListSessions(ctx, auth.AdminID)
	rows := make([]sessionRow, 0, len(list))
	for _, se := range list {
		rows = append(rows, sessionRow{Session: se, Current: cur != nil && se.IDHash == cur.IDHash, Browser: shortUA(se.UserAgent)})
	}
	att, _ := s.Auth.RecentAttempts(ctx, 50)
	known := map[string]bool{}
	for _, a := range att {
		if a.Success {
			known[a.IP] = true
		}
	}
	arows := make([]attemptRow, 0, len(att))
	for _, a := range att {
		arows = append(arows, attemptRow{Attempt: a, Known: known[a.IP]})
	}
	return rows, arows
}

func (s *Server) sessionRevoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	h := r.PathValue("hash")
	cur := sessionFrom(r)
	if len(h) != 64 || !s.Auth.RevokeSession(ctx, auth.AdminID, h) {
		d, _ := s.securityData(r)
		s.renderSecurity(w, r, http.StatusNotFound, d, "Oturum bulunamadı (zaten kapanmış olabilir).", "")
		return
	}
	s.Activity.Record(ctx, logs.Entry{Action: "auth.session.revoke", Summary: "Bir oturum kapatıldı"}, nil)
	s.securityAlert(r, "Panel oturumu kapatıldı", "Bir panel oturumu Ayarlar → Güvenlik'ten kapatıldı.")
	if cur != nil && h == cur.IDHash {
		s.setSessionCookie(w, "", -1)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/settings/security#sessions", http.StatusSeeOther)
}

func (s *Server) sessionRevokeOthers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	n := s.Auth.RevokeOthers(ctx, auth.AdminID, sessionFrom(r).IDHash)
	s.Activity.Record(ctx, logs.Entry{Action: "auth.session.revoke", Summary: fmt.Sprintf("Diğer %d oturum kapatıldı", n)}, nil)
	if n > 0 {
		s.securityAlert(r, "Diğer panel oturumları kapatıldı", fmt.Sprintf("%d oturum kapatıldı.", n))
	}
	http.Redirect(w, r, "/settings/security#sessions", http.StatusSeeOther)
}

// --- G6: security notifications ---

// securityAlert sends an immediate "security" notification for a change made
// from the panel (who: the client IP; never secrets).
func (s *Server) securityAlert(r *http.Request, title, text string) {
	if s.Notify == nil {
		return
	}
	s.Notify.Send(r.Context(), notify.Event{Kind: notify.KindSecurity, Key: "security:" + title, NoDedupe: true,
		Title: title, Text: text + "\nKaynak IP: " + clientIP(r)})
}

// CLIWatch notifies "admin …" CLI actions (reset-password, disable-2fa) that
// were recorded while nobody looked (monitor's 10-minute hook).
func (s *Server) CLIWatch(ctx context.Context) {
	last, _ := strconv.ParseInt(store.GetSetting(ctx, s.DB, setCLINotified, "0"), 10, 64)
	entries, err := s.Activity.Query(ctx, logs.Filter{Action: "admin.", Limit: 20})
	if err != nil || len(entries) == 0 {
		return
	}
	if last == 0 { // first run: remember, do not replay history
		store.SetSetting(ctx, s.DB, setCLINotified, strconv.FormatInt(entries[0].ID, 10))
		return
	}
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		if e.ID <= last {
			continue
		}
		if s.Notify != nil {
			s.Notify.Send(ctx, notify.Event{Kind: notify.KindSecurity, Key: fmt.Sprintf("cli:%d", e.ID), NoDedupe: true,
				Title: "Sunucuda yönetici komutu çalıştırıldı", Text: e.Summary + "\n(SSH ile root olarak; panelden yapılmadı)"})
		}
		last = e.ID
	}
	store.SetSetting(ctx, s.DB, setCLINotified, strconv.FormatInt(last, 10))
}

// --- G6: integrity ---

func (s *Server) integrityPaths(ctx context.Context) hostsec.IntegrityPaths {
	p := hostsec.IntegrityPaths{ScriptsDir: s.Cfg.ScriptsDir, TemplatesDir: s.Cfg.TemplatesDir}
	if !s.Cfg.Dev {
		p.Unit = "/etc/systemd/system/hostpanel.service"
		p.CheckOwner = true
		if !s.Cfg.DryRun && s.Sys != nil {
			if sum, err := s.Sys.SudoersSum(ctx); err == nil {
				p.SudoersSum = sum
			}
		}
	}
	return p
}

// IntegrityCheck compares the installed helper scripts, templates, sudoers
// and unit with this binary's release; a new deviation is notified once.
func (s *Server) IntegrityCheck(ctx context.Context) []hostsec.IntegrityIssue {
	issues := hostsec.CheckIntegrity(hostsec.ReleaseManifest(), s.integrityPaths(ctx))
	key := hostsec.IssuesKey(issues)
	if prev := store.GetSetting(ctx, s.DB, setIntegrityKey, ""); key != prev {
		store.SetSetting(ctx, s.DB, setIntegrityKey, key)
		if key != "" {
			var lines []string
			for i, is := range issues {
				if i == 10 {
					lines = append(lines, fmt.Sprintf("… +%d", len(issues)-10))
					break
				}
				lines = append(lines, is.Path+": "+is.Label())
			}
			s.Activity.Record(logs.WithActor(ctx, logs.Actor{Source: logs.SourceSystem}), logs.Entry{Action: "security.integrity",
				Status: logs.StatusFailed, Summary: fmt.Sprintf("Kurulu dosyalar sürümden farklı (%d)", len(issues)),
				Error: strings.Join(lines, "\n")}, nil)
			if s.Notify != nil {
				s.Notify.Send(ctx, notify.Event{Kind: notify.KindSecurity, Key: "integrity:" + key, NoDedupe: true,
					Title: "Script bütünlüğü: kurulu dosyalar bu sürümden farklı",
					Text:  strings.Join(lines, "\n") + "\nPanel dışında değiştirilmiş olabilir. Aynı sürümle update.sh çalıştırmak düzeltir."})
			}
		}
	}
	return issues
}

// --- G3: audit ---

func (s *Server) expectedPorts(ctx context.Context, sshPorts []string) ([]hostsec.PortInfo, []int) {
	exp := []hostsec.PortInfo{{Proto: "tcp", Port: 80, Label: "HTTP"}, {Proto: "tcp", Port: 443, Label: "HTTPS"},
		{Proto: "tcp", Port: s.PanelAddr.Addr.Get().Port, Label: "panel"}, {Proto: "udp", Port: 68, Label: "DHCP"}}
	if p := s.PanelAddr.Addr.Get().IPPort; p != 0 {
		exp = append(exp, hostsec.PortInfo{Proto: "tcp", Port: p, Label: "panel (IP girişi)"})
	}
	if len(sshPorts) == 0 {
		sshPorts = []string{"22"}
	}
	for _, p := range sshPorts {
		if n, err := strconv.Atoi(p); err == nil {
			exp = append(exp, hostsec.PortInfo{Proto: "tcp", Port: n, Label: "SSH"})
		}
	}
	if store.GetSetting(ctx, s.DB, "dns_installed", "") == "1" {
		exp = append(exp, hostsec.PortInfo{Port: 53, Label: "DNS"})
	}
	var docker []int
	if s.Mail != nil {
		if ms, err := s.Mail.Store.Server(ctx); err == nil && ms.ID != 0 {
			for _, p := range []int{25, 465, 587, 993} {
				exp = append(exp, hostsec.PortInfo{Proto: "tcp", Port: p, Label: "posta"})
			}
			docker = []int{25, 465, 587, 993}
		}
	}
	if srv, err := s.DBs.Store.Server(ctx); err == nil && srv.External {
		exp = append(exp, hostsec.PortInfo{Proto: "tcp", Port: 1433, Label: "MSSQL"})
	}
	if s.PG != nil {
		if srv, err := s.PG.Store.Server(ctx); err == nil && srv.External {
			exp = append(exp, hostsec.PortInfo{Proto: "tcp", Port: 5432, Label: "PostgreSQL"})
		}
	}
	return exp, docker
}

const dryRunSS = "tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\ntcp LISTEN 0 511 0.0.0.0:80 0.0.0.0:*\ntcp LISTEN 0 511 0.0.0.0:443 0.0.0.0:*\n" +
	"tcp LISTEN 0 511 0.0.0.0:8443 0.0.0.0:*\ntcp LISTEN 0 4096 127.0.0.1:8090 0.0.0.0:*\ntcp LISTEN 0 128 0.0.0.0:135 0.0.0.0:*\n"

func (s *Server) gatherAudit(ctx context.Context) hostsec.AuditInput {
	in := hostsec.AuditInput{Now: time.Now(), DryRun: s.Cfg.DryRun}
	var sshPorts []string
	if st, err := s.SSH.Status(ctx); err == nil {
		in.SSH, sshPorts = &st, st.Ports
	} else {
		in.SSHErr = helperErr(err)
	}
	if u, err := s.ufwStatus(ctx); err == nil {
		in.UFWInstalled, in.UFWActive = u.Installed, u.Active
	} else {
		in.UFWErr = helperErr(err)
	}
	ssOut := dryRunSS
	if !s.Cfg.DryRun {
		res, err := s.Sites.Probe.Run(ctx, exec.Cmd{Name: "ss", Args: []string{"-ltnuH"}, Timeout: 5 * time.Second})
		ssOut = res.Stdout
		if err != nil {
			in.ListenErr = err.Error()
		}
	}
	in.Listeners = hostsec.ParseSS(ssOut)
	in.Expected, in.DockerPorts = s.expectedPorts(ctx, sshPorts)
	if f, err := s.F2B.Status(ctx); err == nil {
		in.F2B = &f
	} else {
		in.F2BErr = helperErr(err)
	}
	if a := s.Sys.AutoStatus(); a.Known {
		on := a.On
		in.UnattendedOn = &on
	}
	in.SecurityUpdates = s.Sys.Upgradable(ctx, false).Security
	in.RebootRequired = s.Sys.Reboot(ctx).Required
	if u, err := s.Auth.Admin(ctx); err == nil {
		in.TOTP = u.TOTPEnabled
	}
	in.Allowlist = strings.TrimSpace(store.GetSetting(ctx, s.DB, "ip_allowlist", "")) != ""
	if t, _ := strconv.ParseInt(store.GetSetting(ctx, s.DB, setTransferExported, "0"), 10, 64); t > 0 {
		in.LastExport = time.Unix(t, 0)
	}
	rem := s.Backups.Remote(ctx)
	in.RemoteBackups, in.CryptOn = rem.Configured(), rem.Crypt
	if plans, err := s.Backups.Store.Plans(ctx); err == nil {
		for _, p := range plans {
			in.BackupsPlanned = in.BackupsPlanned || p.Enabled
		}
	}
	var last sql.NullInt64
	s.DB.QueryRowContext(ctx, `SELECT MAX(created_at) FROM backups WHERE status='success'`).Scan(&last)
	if last.Valid && last.Int64 > 0 {
		in.LastBackupOK = time.Unix(last.Int64, 0)
	}
	for _, c := range s.SSL.ActiveBySite(ctx) {
		if c.DaysLeft() < 15 {
			in.SSLSoon = append(in.SSLSoon, c.Domain)
		}
	}
	slices.Sort(in.SSLSoon)
	if srv, err := s.DBs.Store.Server(ctx); err == nil && srv.External {
		in.DBExternal = append(in.DBExternal, fmt.Sprintf("MSSQL (%d IP)", len(srv.AllowIPs)))
	}
	if s.PG != nil {
		if srv, err := s.PG.Store.Server(ctx); err == nil && srv.External {
			in.DBExternal = append(in.DBExternal, fmt.Sprintf("PostgreSQL (%d IP)", len(srv.AllowIPs)))
		}
	}
	if s.DBs.AtOldLocation(ctx) {
		in.DBOldLocation = append(in.DBOldLocation, "MSSQL")
	}
	if s.PG != nil && s.PG.AtOldLocation(ctx) {
		in.DBOldLocation = append(in.DBOldLocation, "PostgreSQL")
	}
	if s.RBL != nil && s.Mail != nil && s.Mail.Installed(ctx) {
		st := s.RBL.State(ctx)
		in.MailChecked = st.CheckedAt > 0
		for _, r := range st.Listed() {
			l, _ := rbl.ByID(r.List)
			in.MailListed = append(in.MailListed, r.Target+" ("+l.Name+")")
		}
	}
	in.Integrity, in.IntegrityChecked = s.IntegrityCheck(ctx), true
	return in
}

type auditData struct {
	Findings      []hostsec.Finding
	OK, Warn, Bad int
	Integrity     []hostsec.IntegrityIssue
	Paths         hostsec.IntegrityPaths
	At            time.Time
}

func (s *Server) auditPage(w http.ResponseWriter, r *http.Request) {
	in := s.gatherAudit(r.Context())
	d := auditData{Findings: hostsec.Audit(in), Integrity: in.Integrity, Paths: s.integrityPaths(r.Context()), At: in.Now}
	d.OK, d.Warn, d.Bad = hostsec.Score(d.Findings)
	s.render(w, r, http.StatusOK, "security", "layout", Page{Title: "Güvenlik", Nav: "security", Data: d})
}

// AuditNotify runs the audit (daily maintenance) and notifies new "bad"
// findings once; integrity has its own notification.
func (s *Server) AuditNotify(ctx context.Context) {
	fs := hostsec.Audit(s.gatherAudit(ctx))
	var rest []hostsec.Finding
	for _, f := range fs {
		if f.ID != "integrity" {
			rest = append(rest, f)
		}
	}
	prev := store.GetSetting(ctx, s.DB, setAuditBad, "")
	fresh := hostsec.NewBad(rest, prev)
	store.SetSetting(ctx, s.DB, setAuditBad, hostsec.BadIDs(rest))
	if len(fresh) == 0 || s.Notify == nil {
		return
	}
	var lines []string
	for _, f := range fresh {
		lines = append(lines, "• "+f.Title+": "+f.Detail)
	}
	s.Notify.Send(ctx, notify.Event{Kind: notify.KindSecurity, Key: "audit:" + hostsec.BadIDs(fresh), NoDedupe: true,
		Title: "Güvenlik denetimi: yeni sorun", Text: strings.Join(lines, "\n") + "\nAyrıntı: panel → Güvenlik"})
}

// --- G1: SSH ---

type sshData struct {
	St         hostsec.SSHStatus
	Err        string
	Logins     []hostsec.SSHLogin // newest first, at most 8
	LastKey    hostsec.SSHLogin
	NewSession *hostsec.SSHLogin // key login after the pending apply
	KeySeen    bool
	ClientIP   string
}

func (s *Server) sshData(r *http.Request) sshData {
	d := sshData{ClientIP: clientIP(r)}
	st, err := s.SSH.Status(r.Context())
	if err != nil {
		d.Err = helperErr(err)
		return d
	}
	d.St = st
	logins := s.SSH.Logins()
	d.LastKey = hostsec.LastKeyLogin(logins)
	d.KeySeen = hostsec.CheckApply(st, hostsec.ApplyInput{Root: "no"}, logins) == nil || st.KeyCount() == 0
	if st.Pending && !st.StateAt.IsZero() {
		if l, ok := hostsec.LoginSince(logins, st.StateAt); ok {
			d.NewSession = &l
		}
	}
	for i := len(logins) - 1; i >= 0 && len(d.Logins) < 8; i-- {
		d.Logins = append(d.Logins, logins[i])
	}
	s.sshWatchResolve(r.Context(), st)
	return d
}

// sshWatchResolve records the outcome of an applied change once (the revert
// timer runs in root's systemd unit; the panel only sees the state file).
func (s *Server) sshWatchResolve(ctx context.Context, st hostsec.SSHStatus) {
	since, _ := strconv.ParseInt(store.GetSetting(ctx, s.DB, setSSHWatch, "0"), 10, 64)
	if since == 0 || st.Pending {
		return
	}
	store.SetSetting(ctx, s.DB, setSSHWatch, "0")
	if st.State != "reverted" || st.StateAt.Unix() < since {
		return
	}
	sys := logs.WithActor(ctx, logs.Actor{Source: logs.SourceSystem})
	s.Activity.Record(sys, logs.Entry{Action: "ssh.reverted", TargetType: "server", TargetID: "ssh",
		Summary: "SSH değişikliği onaylanmadığı için geri alındı"}, nil)
	if s.Notify != nil {
		s.Notify.Send(ctx, notify.Event{Kind: notify.KindSecurity, Key: "ssh.reverted", NoDedupe: true,
			Title: "SSH değişikliği geri alındı", Text: "Süre içinde onaylanmadığı için önceki SSH ayarları geri yüklendi."})
	}
}

// SSHWatch is the monitor hook: only while an applied change is unresolved.
func (s *Server) SSHWatch(ctx context.Context) {
	if store.GetSetting(ctx, s.DB, setSSHWatch, "0") == "0" {
		return
	}
	if st, err := s.SSH.Status(ctx); err == nil {
		s.sshWatchResolve(ctx, st)
	}
}

func (s *Server) renderSSH(w http.ResponseWriter, r *http.Request, status int, errMsg, notice string) {
	d := serverData{Tab: "ssh", SSH: s.sshData(r), DryRun: s.Cfg.DryRun}
	if isHX(r) {
		s.render(w, r, status, "server", "ssh", Page{Data: d, Error: errMsg, Notice: notice})
		return
	}
	s.render(w, r, status, "server", "layout", Page{Title: "Sunucu", Nav: "server", Data: d, Error: errMsg, Notice: notice})
}

func (s *Server) sshApply(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	in := hostsec.ApplyInput{Password: r.PostFormValue("password") == "yes", Root: r.PostFormValue("root"),
		KeyTested: r.PostFormValue("key_tested") == "1"}
	st, err := s.SSH.Status(ctx)
	if err != nil {
		s.renderSSH(w, r, http.StatusBadGateway, "SSH durumu okunamadı: "+helperErr(err), "")
		return
	}
	if err := hostsec.CheckApply(st, in, s.SSH.Logins()); err != nil {
		s.renderSSH(w, r, http.StatusBadRequest, err.Error(), "")
		return
	}
	summary := fmt.Sprintf("SSH: parola girişi %s, root %s", onOff(in.Password), hostsec.RootLabel(in.Root))
	start := time.Now()
	deadline, err := s.SSH.Apply(ctx, in)
	s.Activity.Record(ctx, logs.Entry{Action: "ssh.apply", TargetType: "server", TargetID: "ssh", Summary: summary,
		Status: statusOf(err), Error: errText(err), DurationMS: time.Since(start).Milliseconds(),
		Diff: fmt.Sprintf("- PasswordAuthentication %s\n- PermitRootLogin %s\n+ PasswordAuthentication %s\n+ PermitRootLogin %s\n",
			st.Password, st.RootMode(), yesNoStr(in.Password), in.Root)}, map[string]any{"password": in.Password, "root": in.Root})
	if err != nil {
		s.renderSSH(w, r, http.StatusBadGateway, "Uygulanamadı: "+helperErr(err), "")
		return
	}
	store.SetSetting(ctx, s.DB, setSSHWatch, strconv.FormatInt(start.Unix(), 10))
	s.securityAlert(r, "SSH ayarları değiştirildi (onay bekliyor)", summary+fmt.Sprintf("\n%s'e kadar onaylanmazsa geri alınır.", deadline.Format("15:04:05")))
	s.renderSSH(w, r, http.StatusOK, "", "Uygulandı. Bu oturumu kapatmadan yeni bir terminalde SSH ile bağlanıp deneyin; girebiliyorsanız \"Çalışıyor, onayla\".")
}

func onOff(b bool) string {
	if b {
		return "açık"
	}
	return "kapalı"
}

func yesNoStr(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func (s *Server) sshConfirm(w http.ResponseWriter, r *http.Request) {
	err := s.SSH.Confirm(r.Context())
	s.Activity.Record(r.Context(), logs.Entry{Action: "ssh.confirm", TargetType: "server", TargetID: "ssh",
		Summary: "SSH değişikliği onaylandı", Status: statusOf(err), Error: errText(err)}, nil)
	if err != nil {
		s.renderSSH(w, r, http.StatusConflict, helperErr(err), "")
		return
	}
	store.SetSetting(r.Context(), s.DB, setSSHWatch, "0")
	s.securityAlert(r, "SSH değişikliği onaylandı", "Yeni SSH ayarları kalıcı oldu.")
	s.renderSSH(w, r, http.StatusOK, "", "Onaylandı; yeni ayarlar kalıcı.")
}

func (s *Server) sshRevert(w http.ResponseWriter, r *http.Request) {
	err := s.SSH.Revert(r.Context())
	s.Activity.Record(r.Context(), logs.Entry{Action: "ssh.revert", TargetType: "server", TargetID: "ssh",
		Summary: "SSH değişikliği geri alındı", Status: statusOf(err), Error: errText(err)}, nil)
	if err != nil {
		s.renderSSH(w, r, http.StatusBadGateway, helperErr(err), "")
		return
	}
	store.SetSetting(r.Context(), s.DB, setSSHWatch, "0")
	s.securityAlert(r, "SSH değişikliği geri alındı", "Önceki SSH ayarları geri yüklendi.")
	s.renderSSH(w, r, http.StatusOK, "", "Geri alındı; önceki ayarlar geçerli.")
}

func (s *Server) sshKeyAdd(w http.ResponseWriter, r *http.Request) {
	user := r.PostFormValue("user")
	st, err := s.SSH.Status(r.Context())
	if err != nil {
		s.renderSSH(w, r, http.StatusBadGateway, helperErr(err), "")
		return
	}
	if !st.HasUser(user) {
		s.renderSSH(w, r, http.StatusBadRequest, "Yalnızca root ve sudo grubundaki kullanıcılara anahtar eklenebilir.", "")
		return
	}
	if !st.AKFDefault() {
		s.renderSSH(w, r, http.StatusConflict, "AuthorizedKeysFile özelleştirilmiş; anahtarlar panelden yönetilemez.", "")
		return
	}
	fp, err := s.SSH.AddKey(r.Context(), user, r.PostFormValue("key"))
	s.Activity.Record(r.Context(), logs.Entry{Action: "ssh.key.add", TargetType: "server", TargetID: "ssh",
		Summary: "SSH anahtarı eklendi: " + user + " " + fp, Status: statusOf(err), Error: errText(err)}, map[string]any{"user": user, "fingerprint": fp})
	if err != nil {
		s.renderSSH(w, r, http.StatusBadRequest, "Anahtar eklenemedi: "+helperErr(err), "")
		return
	}
	s.securityAlert(r, "SSH anahtarı eklendi", user+" kullanıcısına: "+fp)
	s.renderSSH(w, r, http.StatusOK, "", "Anahtar eklendi: "+fp)
}

func (s *Server) sshKeyDelete(w http.ResponseWriter, r *http.Request) {
	user, fp := r.PostFormValue("user"), r.PostFormValue("fp")
	st, err := s.SSH.Status(r.Context())
	if err != nil {
		s.renderSSH(w, r, http.StatusBadGateway, helperErr(err), "")
		return
	}
	if err := hostsec.CheckDeleteKey(st, user, fp, s.SSH.Logins(), r.PostFormValue("force") == "1"); err != nil {
		s.renderSSH(w, r, http.StatusConflict, err.Error(), "")
		return
	}
	err = s.SSH.DeleteKey(r.Context(), user, fp)
	s.Activity.Record(r.Context(), logs.Entry{Action: "ssh.key.delete", TargetType: "server", TargetID: "ssh",
		Summary: "SSH anahtarı silindi: " + user + " " + fp, Status: statusOf(err), Error: errText(err)}, map[string]any{"user": user, "fingerprint": fp})
	if err != nil {
		s.renderSSH(w, r, http.StatusBadGateway, "Silinemedi: "+helperErr(err), "")
		return
	}
	s.securityAlert(r, "SSH anahtarı silindi", user+": "+fp)
	s.renderSSH(w, r, http.StatusOK, "", "Anahtar silindi.")
}

// --- G2: host fail2ban ---

type f2bData struct {
	St       hostsec.F2BStatus
	Err      string
	ClientIP string
	Ignore   string // textarea
}

func (s *Server) f2bData(r *http.Request) f2bData {
	d := f2bData{ClientIP: clientIP(r)}
	st, err := s.F2B.Status(r.Context())
	if err != nil {
		d.Err = helperErr(err)
	}
	d.St = st
	d.Ignore = strings.Join(st.Ignore, "\n")
	return d
}

func (s *Server) renderF2B(w http.ResponseWriter, r *http.Request, status int, errMsg, notice string) {
	d := serverData{Tab: "fail2ban", F2B: s.f2bData(r), DryRun: s.Cfg.DryRun}
	if isHX(r) {
		s.render(w, r, status, "server", "f2b", Page{Data: d, Error: errMsg, Notice: notice})
		return
	}
	s.render(w, r, status, "server", "layout", Page{Title: "Sunucu", Nav: "server", Data: d, Error: errMsg, Notice: notice})
}

func (s *Server) f2bConfig(w http.ResponseWriter, r *http.Request) {
	atoi := func(k string) int { n, _ := strconv.Atoi(strings.TrimSpace(r.PostFormValue(k))); return n }
	c := hostsec.F2BConfig{MaxRetry: atoi("maxretry"), FindMin: atoi("findtime"), BanMin: atoi("bantime"), Recidive: r.PostFormValue("recidive") == "1"}
	ignore, err := hostsec.ParseIgnoreList(r.PostFormValue("ignore"))
	if err != nil {
		s.renderF2B(w, r, http.StatusBadRequest, err.Error(), "")
		return
	}
	before, _ := s.F2B.Status(r.Context())
	err = s.F2B.Configure(r.Context(), c, ignore, clientIP(r))
	summary := fmt.Sprintf("fail2ban: %d deneme / %d dk → %d dk engel, tekrar edenler %s, %d muaf adres",
		c.MaxRetry, c.FindMin, c.BanMin, onOff(c.Recidive), len(ignore))
	s.Activity.Record(r.Context(), logs.Entry{Action: "f2b.config", TargetType: "server", TargetID: "fail2ban", Summary: summary,
		Status: statusOf(err), Error: errText(err), Diff: simpleDiff(strings.Join(before.Ignore, "\n"), strings.Join(ignore, "\n"))}, nil)
	if err != nil {
		s.renderF2B(w, r, http.StatusBadRequest, helperErr(err), "")
		return
	}
	s.securityAlert(r, "fail2ban ayarları değiştirildi", summary)
	s.renderF2B(w, r, http.StatusOK, "", "Kaydedildi ve fail2ban yeniden yüklendi.")
}

func (s *Server) f2bUnban(w http.ResponseWriter, r *http.Request) {
	jail, ip := r.PostFormValue("jail"), r.PostFormValue("ip")
	err := s.F2B.Unban(r.Context(), jail, ip)
	s.Activity.Record(r.Context(), logs.Entry{Action: "f2b.unban", TargetType: "server", TargetID: "fail2ban",
		Summary: "Engel kaldırıldı: " + ip + " (" + jail + ")", Status: statusOf(err), Error: errText(err)}, nil)
	if err != nil {
		s.renderF2B(w, r, http.StatusBadRequest, helperErr(err), "")
		return
	}
	s.renderF2B(w, r, http.StatusOK, "", "Engel kaldırıldı: "+ip)
}

func init() {
	funcs["rootLabel"] = hostsec.RootLabel
}
