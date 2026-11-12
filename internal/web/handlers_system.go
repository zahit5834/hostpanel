package web

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/zahit5834/hostpanel/internal/exec"
	"github.com/zahit5834/hostpanel/internal/jobs"
	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/monitor"
	"github.com/zahit5834/hostpanel/internal/notify"
	"github.com/zahit5834/hostpanel/internal/sites"
	"github.com/zahit5834/hostpanel/internal/store"
	"github.com/zahit5834/hostpanel/internal/sysmaint"
	"github.com/zahit5834/hostpanel/internal/system"
)

// Settings of the reboot/boot report and OOM watch.
const (
	setLastBoot      = "last_boot_id"
	setPlannedBoot   = "reboot_planned_boot_id" // boot id that was running when a reboot was planned
	setOOMChecked    = "oom_checked_at"
	rebootConfirm    = "YENIDEN-BASLAT"
	bootReportDelay  = 3 * time.Minute
	panelMemoryMaxMB = 256 // hostpanel.service MemoryMax
)

// aptJob is the system.apt job: package upgrades through hp-system.sh.
func (s *Server) aptJob(ctx context.Context, l *jobs.Log, p map[string]any) error {
	mode, _ := p["mode"].(string)
	hold, _ := p["hold"].(bool)
	fmt.Fprintf(l, "Sistem güncellemesi: %s (Docker paketleri %s)\n", map[string]string{"security": "yalnızca güvenlik", "all": "tüm paketler"}[mode],
		map[bool]string{true: "bekletiliyor", false: "dahil"}[hold])
	if s.Cfg.DryRun {
		fmt.Fprintln(l, "[DRY-RUN] hp-system.sh apt-run", mode)
		return nil
	}
	_, err := s.Sys.AptRun(ctx, mode, hold, l)
	if s.Notify != nil {
		title := "Sistem güncellemesi tamamlandı"
		if err != nil {
			title = "Sistem güncellemesi başarısız"
		}
		text := ""
		if ri := s.Sys.Reboot(ctx); ri.Required {
			text = "Yeniden başlatma gerekiyor (" + strings.Join(ri.Pkgs, ", ") + ")."
		}
		s.Notify.Send(ctx, notify.Event{Kind: notify.KindSystem, Key: "apt", NoDedupe: true, Title: title, Text: text})
	}
	return err
}

// --- server page ---

type serviceRow struct {
	Name, Label, Unit, State string
}

type serverData struct {
	Tab      string
	Units    []unitState
	UFW      system.UFWStatus
	UFWErr   string
	Disk     diskInfo
	DryRun   bool
	Hostname string

	Services []serviceRow
	Output   string // nginx -t / service output
	Mem      sysmaint.Mem
	Plan     sysmaint.Plan
	OOM      []oomRow

	Upd     sysmaint.AptInfo
	Auto    sysmaint.AutoUpdates
	Restart sysmaint.Restart
	RErr    string
	Reboot  sysmaint.RebootInfo

	SSH sshData
	F2B f2bData

	Metrics    metricsView
	Clean      []sysmaint.CleanCategory
	CleanErr   string
	CleanTotal int64
}

var serverTabs = []string{"general", "updates", "metrics", "clean", "ssh", "fail2ban", "ufw"}

func (s *Server) serviceRows(ctx context.Context) []serviceRow {
	states := map[string]string{}
	for _, u := range s.unitStates(ctx) {
		states[u.Unit] = u.State
	}
	var out []serviceRow
	for _, m := range sysmaint.ManagedServices {
		out = append(out, serviceRow{Name: m.Name, Label: m.Label, Unit: m.Name + ".service", State: states[m.Name+".service"]})
	}
	return out
}

// memoryPlan sums the memory limits of everything the panel runs.
func (s *Server) memoryPlan(ctx context.Context) sysmaint.Plan {
	var items []sysmaint.Reservation
	if srv, err := s.DBs.Store.Server(ctx); err == nil && srv.ID != 0 {
		items = append(items, sysmaint.Reservation{Label: "MSSQL (container sınırı)", MB: srv.MemoryMB + 256, Link: "/databases"})
	}
	if s.PG != nil {
		if srv, err := s.PG.Store.Server(ctx); err == nil && srv.ID != 0 {
			items = append(items, sysmaint.Reservation{Label: "PostgreSQL (container sınırı)", MB: srv.MemoryMB + 256, Link: "/postgres"})
		}
	}
	if s.Mail != nil {
		if srv, err := s.Mail.Store.Server(ctx); err == nil && srv.ID != 0 {
			items = append(items, sysmaint.Reservation{Label: "Posta sunucusu", MB: srv.MemoryMB, Link: "/mail"})
		}
	}
	list, _ := s.Sites.Store.List(ctx, 0)
	n, sum := 0, 0
	for _, site := range list {
		if p, ok := s.Runtimes.Get(site.RuntimeID); ok && p.Def().HasUnit() && site.Status != sites.StatusDisabled {
			n++
			sum += site.MemoryMaxMB
		}
	}
	if n > 0 {
		items = append(items, sysmaint.Reservation{Label: fmt.Sprintf("Siteler (%d servis, bellek sınırları toplamı)", n), MB: sum, Link: "/sites"})
	}
	items = append(items, sysmaint.Reservation{Label: "Panel", MB: panelMemoryMaxMB})
	return sysmaint.MakePlan(s.Sys.ReadMem(), items)
}

// oomRow is an OOM kill of the last 24 h; Resolved once a later
// system.oom.resolved entry exists for the same unit.
type oomRow struct {
	logs.Entry
	Resolved bool
}

func (s *Server) recentOOM(ctx context.Context) []oomRow {
	from := time.Now().Add(-24 * time.Hour)
	kills, _ := s.Activity.Query(ctx, logs.Filter{Action: "system.oom", From: from, Limit: 50})
	fixed, _ := s.Activity.Query(ctx, logs.Filter{Action: "system.oom.resolved", From: from, Limit: 50})
	out := make([]oomRow, 0, len(kills))
	for _, k := range kills {
		r := oomRow{Entry: k}
		for _, f := range fixed {
			if f.TargetID == k.TargetID && !f.TS.Before(k.TS) {
				r.Resolved = true
				break
			}
		}
		out = append(out, r)
	}
	return out
}

// openOOM is the newest unresolved kill per unit (dashboard alerts).
func (s *Server) openOOM(ctx context.Context) []oomRow {
	var out []oomRow
	seen := map[string]bool{}
	for _, r := range s.recentOOM(ctx) { // newest first
		if seen[r.TargetID] {
			continue
		}
		seen[r.TargetID] = true
		if !r.Resolved {
			out = append(out, r)
		}
	}
	return out
}

func (s *Server) serverDataFor(r *http.Request, tab string) serverData {
	ctx := r.Context()
	d := serverData{Tab: tab, DryRun: s.Cfg.DryRun, Hostname: system.Read().Hostname}
	switch tab {
	case "general":
		d.Units = s.unitStates(ctx)
		d.Services = s.serviceRows(ctx)
		d.Mem = s.Sys.ReadMem()
		d.Plan = s.memoryPlan(ctx)
		d.OOM = s.recentOOM(ctx)
	case "updates":
		d.Auto = s.Sys.AutoStatus()
		d.Reboot = s.Sys.Reboot(ctx)
	case "metrics":
		d.Metrics = s.metricsView(ctx, r.URL.Query().Get("range"))
	case "ssh":
		d.SSH = s.sshData(r)
	case "fail2ban":
		d.F2B = s.f2bData(r)
	case "ufw":
		var err error
		if d.UFW, err = s.ufwStatus(ctx); err != nil {
			d.UFWErr = err.Error()
		}
	}
	return d
}

func (s *Server) renderServerTab(w http.ResponseWriter, r *http.Request, status int, tab, block, errMsg, notice string, edit func(*serverData)) {
	d := s.serverDataFor(r, tab)
	if edit != nil {
		edit(&d)
	}
	if !isHX(r) || block == "" {
		block = "layout"
	}
	s.render(w, r, status, "server", block, Page{Title: "Sunucu", Nav: "server", Data: d, Error: errMsg, Notice: notice})
}

// --- S1 updates ---

func (s *Server) aptRun(w http.ResponseWriter, r *http.Request) {
	mode := r.PostFormValue("mode")
	if mode != "security" && mode != "all" {
		s.renderServerTab(w, r, http.StatusBadRequest, "updates", "", "Geçersiz güncelleme türü.", "", nil)
		return
	}
	hold := r.PostFormValue("docker") != "1"
	if list, err := s.Jobs.List(r.Context(), "running", "system.apt", "", 0, 1); err == nil && len(list) > 0 {
		http.Redirect(w, r, fmt.Sprintf("/logs/jobs/%d", list[0].ID), http.StatusSeeOther)
		return
	}
	id, err := s.Jobs.Submit(r.Context(), jobs.Spec{Kind: "system.apt", TargetType: "server", TargetID: "apt",
		Summary: map[string]string{"security": "Güvenlik güncellemeleri uygulanıyor", "all": "Tüm paket güncellemeleri uygulanıyor"}[mode],
		Params:  map[string]any{"mode": mode, "hold": hold}})
	if err != nil {
		s.renderServerTab(w, r, http.StatusInternalServerError, "updates", "", err.Error(), "", nil)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/logs/jobs/%d", id), http.StatusSeeOther)
}

func (s *Server) aptAuto(w http.ResponseWriter, r *http.Request) {
	on := r.PostFormValue("on") == "1"
	err := s.Sys.SetAuto(r.Context(), on)
	s.Activity.Record(r.Context(), logs.Entry{Action: "system.unattended", TargetType: "server", TargetID: "apt",
		Summary: "Otomatik güvenlik güncellemeleri: " + onOff(on), Status: statusOf(err), Error: errText(err)}, nil)
	if err != nil {
		s.renderServerTab(w, r, http.StatusBadGateway, "updates", "", helperErr(err), "", nil)
		return
	}
	s.renderServerTab(w, r, http.StatusOK, "updates", "", "", "Otomatik güvenlik güncellemeleri "+onOff(on)+".", nil)
}

// --- S2 reboot ---

func (s *Server) rebootSchedule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if strings.TrimSpace(r.PostFormValue("confirm")) != rebootConfirm {
		s.renderServerTab(w, r, http.StatusBadRequest, "updates", "", "Onay için "+rebootConfirm+" yazın.", "", nil)
		return
	}
	when := strings.TrimSpace(r.PostFormValue("when"))
	if when == "now" {
		when = "+1" // one minute: a window to cancel, and the activity row is written first
	}
	at, err := s.Sys.ScheduleReboot(ctx, when)
	s.Activity.Record(ctx, logs.Entry{Action: "system.reboot.schedule", TargetType: "server", TargetID: "reboot",
		Summary: "Yeniden başlatma planlandı: " + at.Format("02.01 15:04"), Status: statusOf(err), Error: errText(err)}, nil)
	if err != nil {
		s.renderServerTab(w, r, http.StatusBadRequest, "updates", "", helperErr(err), "", nil)
		return
	}
	store.SetSetting(ctx, s.DB, setPlannedBoot, s.Sys.BootID())
	if s.Notify != nil {
		s.Notify.Send(ctx, notify.Event{Kind: notify.KindSystem, Key: "reboot.plan", NoDedupe: true,
			Title: "Sunucu yeniden başlatılacak: " + at.Format("02.01 15:04"), Text: "Panelden planlandı (" + clientIP(r) + ")."})
	}
	s.renderServerTab(w, r, http.StatusOK, "updates", "", "", "Yeniden başlatma planlandı: "+at.Format("02.01.2006 15:04")+". Açıldıktan birkaç dakika sonra rapor gelir.", nil)
}

func (s *Server) rebootCancel(w http.ResponseWriter, r *http.Request) {
	err := s.Sys.CancelReboot(r.Context())
	s.Activity.Record(r.Context(), logs.Entry{Action: "system.reboot.cancel", TargetType: "server", TargetID: "reboot",
		Summary: "Planlı yeniden başlatma iptal edildi", Status: statusOf(err), Error: errText(err)}, nil)
	if err != nil {
		s.renderServerTab(w, r, http.StatusBadGateway, "updates", "", helperErr(err), "", nil)
		return
	}
	store.SetSetting(r.Context(), s.DB, setPlannedBoot, "")
	s.renderServerTab(w, r, http.StatusOK, "updates", "", "", "Planlı yeniden başlatma iptal edildi.", nil)
}

// BootReport runs once a few minutes after the panel starts: if the machine
// booted since the last start, it reports what came back (S2).
func (s *Server) BootReport(ctx context.Context) {
	id := s.Sys.BootID()
	if id == "" {
		return
	}
	last := store.GetSetting(ctx, s.DB, setLastBoot, "")
	if last == id {
		return
	}
	store.SetSetting(ctx, s.DB, setLastBoot, id)
	if last == "" {
		return // first start on this machine: nothing to compare with
	}
	planned := store.GetSetting(ctx, s.DB, setPlannedBoot, "") == last
	store.SetSetting(ctx, s.DB, setPlannedBoot, "")
	title := "Sunucu yeniden başladı (beklenmeyen)"
	if planned {
		title = "Sunucu yeniden başladı (planlı)"
	}
	var lines []string
	var down []string
	for _, u := range s.unitStates(ctx) {
		if u.State == "active" {
			continue
		}
		if u.State == "inactive" && (u.Unit == "named.service" || u.Unit == "docker.service") {
			continue // not installed is common; failures still show
		}
		down = append(down, u.Label+": "+u.State)
	}
	if len(down) > 0 {
		lines = append(lines, "Çalışmayan servisler: "+strings.Join(down, ", "))
	} else {
		lines = append(lines, "Servisler çalışıyor (nginx, fail2ban, panel …).")
	}
	list, _ := s.Sites.Store.List(ctx, 0)
	health := map[int64]monitor.Check{}
	if s.Monitor != nil {
		health, _ = s.Monitor.Store.All(ctx)
	}
	running, bad := 0, []string{}
	for _, site := range list {
		if site.Status != sites.StatusRunning {
			continue
		}
		running++
		if h, ok := health[site.ID]; ok && h.State == monitor.StateDown {
			bad = append(bad, site.Domain)
		}
	}
	if len(bad) > 0 {
		lines = append(lines, fmt.Sprintf("Siteler: %d çalışıyor, erişilemeyen: %s", running-len(bad), strings.Join(bad, ", ")))
	} else if running > 0 {
		lines = append(lines, fmt.Sprintf("Siteler: %d çalışıyor (sağlık kontrolleri birkaç dakika içinde tamamlanır).", running))
	}
	if ri := s.Sys.Reboot(ctx); !ri.BootedAt.IsZero() {
		lines = append(lines, "Açılış: "+ri.BootedAt.Format("02.01.2006 15:04"))
	}
	sys := logs.WithActor(ctx, logs.Actor{Source: logs.SourceSystem})
	st := logs.StatusSuccess
	if !planned || len(down) > 0 || len(bad) > 0 {
		st = logs.StatusFailed
	}
	s.Activity.Record(sys, logs.Entry{Action: "system.boot", TargetType: "server", TargetID: "boot", Status: st,
		Summary: title, Diff: strings.Join(lines, "\n")}, nil)
	if s.Notify != nil {
		s.Notify.Send(ctx, notify.Event{Kind: notify.KindSystem, Key: "boot:" + id, NoDedupe: true, Title: title, Text: strings.Join(lines, "\n")})
	}
}

// --- S3 memory / swap / OOM ---

func (s *Server) swapCreate(w http.ResponseWriter, r *http.Request) {
	mb, _ := strconv.Atoi(r.PostFormValue("mb"))
	err := s.Sys.CreateSwap(r.Context(), mb)
	s.Activity.Record(r.Context(), logs.Entry{Action: "system.swap", TargetType: "server", TargetID: "swap",
		Summary: fmt.Sprintf("Swap oluşturuldu: %d MB (/swapfile)", mb), Status: statusOf(err), Error: errText(err)}, nil)
	if err != nil {
		s.renderServerTab(w, r, http.StatusBadRequest, "general", "", helperErr(err), "", nil)
		return
	}
	s.renderServerTab(w, r, http.StatusOK, "general", "", "", fmt.Sprintf("%d MB swap oluşturuldu.", mb), nil)
}

// oomLabel names the victim: a site (hp-site-<short>.service), a container
// (by process name) or the process itself.
func (s *Server) oomLabel(ctx context.Context, o sysmaint.OOM) string {
	if site, part, ok := s.oomSite(ctx, o.Unit()); ok {
		return "site " + site.Domain + part
	}
	switch {
	case o.Process == "sqlservr":
		return "MSSQL"
	case o.Process == "postgres":
		return "PostgreSQL"
	case strings.HasPrefix(o.Unit(), "docker-"):
		return "container (" + o.Process + ")"
	}
	return o.Process
}

// oomSite maps a unit to its site: the service (hp-site-<short>.service),
// a git build (hp-build-<short>) or a cron run (hp-cron-<short>-<id>).
func (s *Server) oomSite(ctx context.Context, unit string) (sites.Site, string, bool) {
	name := strings.TrimSuffix(unit, ".service")
	if !strings.HasPrefix(name, "hp-") {
		return sites.Site{}, "", false
	}
	list, _ := s.Sites.Store.List(ctx, 0)
	for _, site := range list {
		switch {
		case name == site.Unit():
			return site, "", true
		case name == "hp-build-"+site.ShortName:
			return site, " (derleme)", true
		case strings.HasPrefix(name, "hp-cron-"+site.ShortName+"-"):
			return site, " (cron)", true
		}
	}
	return sites.Site{}, "", false
}

// oomQuiet: an OOM counts as resolved after this long without a repeat,
// if the victim is running now.
const oomQuiet = 30 * time.Minute

// oomVictimOK reports whether the killed unit is healthy now.
func (s *Server) oomVictimOK(ctx context.Context, unit string) bool {
	active := func(u string) bool {
		res, _ := s.Sites.Probe.Run(ctx, exec.Cmd{Name: "systemctl", Args: []string{"is-active", u}, Timeout: 5 * time.Second})
		return s.Cfg.DryRun || strings.TrimSpace(string(res.Stdout)) == "active"
	}
	if site, part, ok := s.oomSite(ctx, unit); ok {
		if part != "" || site.Status != sites.StatusRunning {
			return true // build/cron runs are transient; a stopped site is not failing
		}
		if s.Monitor != nil {
			if h, err := s.Monitor.Store.All(ctx); err == nil {
				if c, ok := h[site.ID]; ok && c.Enabled && c.State == monitor.StateDown {
					return false
				}
			}
		}
		return active(site.Unit() + ".service")
	}
	if strings.HasPrefix(unit, "docker-") { // container scopes change id on restart
		return len(s.infraDown(ctx)) == 0
	}
	if strings.HasSuffix(unit, ".service") && !strings.HasPrefix(unit, "hp-") {
		return active(unit)
	}
	return true
}

// resolveOOM closes open OOM alerts whose victim stayed up for oomQuiet:
// activity system.oom.resolved + notification; the dashboard alert goes away.
func (s *Server) resolveOOM(ctx context.Context, now time.Time) {
	sys := logs.WithActor(ctx, logs.Actor{Source: logs.SourceSystem})
	for _, r := range s.openOOM(ctx) {
		if now.Sub(r.TS) < oomQuiet || !s.oomVictimOK(ctx, r.TargetID) {
			continue
		}
		who := strings.TrimPrefix(r.Summary, "Bellek yetersiz: ")
		if i := strings.Index(who, " sonlandırıldı"); i > 0 {
			who = who[:i]
		}
		summary := "Bellek sorunu giderildi: " + who
		s.Activity.Record(sys, logs.Entry{Action: "system.oom.resolved", TargetType: "server", TargetID: r.TargetID,
			Summary: summary, Status: logs.StatusSuccess}, nil)
		if s.Notify != nil {
			s.Notify.Send(ctx, notify.Event{Kind: notify.KindSystem, Key: "oom-ok:" + r.TargetID, NoDedupe: true,
				Title: "✅ " + summary,
				Text: fmt.Sprintf("Son bellek yetersizliği: %s.\n%d dakikadır tekrarlanmadı ve servis çalışıyor.",
					r.TS.Local().Format("02.01 15:04"), int(now.Sub(r.TS).Minutes()))})
		}
	}
}

// OOMCheck reports kernel OOM kills since the last check and closes the ones
// that are resolved (monitor hook, 10 min).
func (s *Server) OOMCheck(ctx context.Context) {
	now := time.Now()
	since, _ := strconv.ParseInt(store.GetSetting(ctx, s.DB, setOOMChecked, "0"), 10, 64)
	store.SetSetting(ctx, s.DB, setOOMChecked, strconv.FormatInt(now.Unix(), 10))
	if since == 0 {
		return
	}
	defer s.resolveOOM(ctx, now)
	events, err := s.Sys.OOMSince(ctx, time.Unix(since, 0))
	if err != nil {
		s.Log.Warn("oom check", "err", err)
		return
	}
	sys := logs.WithActor(ctx, logs.Actor{Source: logs.SourceSystem})
	for _, o := range events {
		who := s.oomLabel(ctx, o)
		why := "sunucunun belleği bitti"
		if o.Limit {
			why = "kendi bellek sınırına ulaştı"
		}
		summary := fmt.Sprintf("Bellek yetersiz: %s sonlandırıldı (%s, pid %d)", who, why, o.PID)
		s.Activity.Record(sys, logs.Entry{Action: "system.oom", TargetType: "server", TargetID: o.Unit(), Status: logs.StatusFailed,
			Summary: summary, Error: o.CGroup}, nil)
		if s.Notify != nil {
			s.Notify.Send(ctx, notify.Event{Kind: notify.KindSystem, Key: "oom:" + o.Unit(), Title: summary,
				Text: "Bellek sınırını artırın ya da Sunucu → Genel'deki bellek planına bakın (swap)."})
		}
	}
}

// --- S5 services ---

func (s *Server) serviceAction(w http.ResponseWriter, r *http.Request) {
	action, name := r.PostFormValue("action"), r.PostFormValue("name")
	if name == "docker" && action == "restart" && r.PostFormValue("docker_ok") != "1" {
		s.renderServerTab(w, r, http.StatusBadRequest, "general", "", "Docker'ı yeniden başlatmak tüm container'ları (MSSQL, PostgreSQL, posta) yeniden başlatır; onay kutusunu işaretleyin.", "", nil)
		return
	}
	start := time.Now()
	out, err := s.Sys.ServiceAction(r.Context(), action, name)
	s.Activity.Record(r.Context(), logs.Entry{Action: "service." + action, TargetType: "service", TargetID: name,
		Summary: name + ": " + map[string]string{"reload": "yeniden yüklendi", "restart": "yeniden başlatıldı"}[action],
		Status:  statusOf(err), Error: errText(err), DurationMS: time.Since(start).Milliseconds()}, nil)
	if err != nil {
		s.renderServerTab(w, r, http.StatusBadGateway, "general", "", helperErr(err), "", func(d *serverData) { d.Output = out })
		return
	}
	s.renderServerTab(w, r, http.StatusOK, "general", "", "", name+": tamam.", func(d *serverData) { d.Output = out })
}

func (s *Server) nginxTest(w http.ResponseWriter, r *http.Request) {
	out, err := s.Sys.NginxTest(r.Context())
	if err != nil && out == "" {
		out = helperErr(err)
	}
	msg, notice := "", "nginx yapılandırması geçerli."
	if err != nil {
		msg, notice = "nginx yapılandırmasında hata var.", ""
	}
	s.renderServerTab(w, r, http.StatusOK, "general", "", msg, notice, func(d *serverData) { d.Output = out })
}

func (s *Server) nginxDump(w http.ResponseWriter, r *http.Request) {
	out, err := s.Sys.NginxDump(r.Context())
	if err != nil {
		http.Error(w, helperErr(err), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(out))
}

// --- lazy parts of the updates tab ---

func (s *Server) serverUpdatesPart(w http.ResponseWriter, r *http.Request, part string) {
	refresh := r.URL.Query().Get("refresh") == "1"
	d := serverData{Tab: "updates", DryRun: s.Cfg.DryRun}
	block := ""
	switch part {
	case "upd":
		d.Upd, block = s.Sys.Upgradable(r.Context(), refresh), "server-upd"
	case "restart":
		var err error
		if d.Restart, err = s.Sys.Needrestart(r.Context()); err != nil {
			d.RErr = helperErr(err)
		}
		block = "server-restart"
	}
	s.render(w, r, http.StatusOK, "server", block, Page{Data: d})
}
