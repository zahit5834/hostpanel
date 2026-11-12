package web

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zahit5834/hostpanel/internal/backups"
	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/monitor"
	"github.com/zahit5834/hostpanel/internal/notify"
	"github.com/zahit5834/hostpanel/internal/sites"
	"github.com/zahit5834/hostpanel/internal/store"
	"github.com/zahit5834/hostpanel/internal/system"
	"github.com/zahit5834/hostpanel/internal/traffic"
)

// --- I3: daily/weekly summary ---

const (
	setSummaryMode = "summary_mode"    // off | daily | weekly
	setSummaryHour = "summary_hour"    // 0–23
	setSummaryDay  = "summary_weekday" // 0 (Sunday) – 6
)

// SummarySchedule is the digest setting.
type SummarySchedule struct {
	Mode    string
	Hour    int
	Weekday int
}

func (s *Server) summarySchedule(ctx context.Context) SummarySchedule {
	sc := SummarySchedule{Mode: store.GetSetting(ctx, s.DB, setSummaryMode, "off")}
	sc.Hour, _ = strconv.Atoi(store.GetSetting(ctx, s.DB, setSummaryHour, "8"))
	sc.Weekday, _ = strconv.Atoi(store.GetSetting(ctx, s.DB, setSummaryDay, "1"))
	return sc
}

// Validate checks the form values.
func (sc SummarySchedule) Validate() error {
	if !slices.Contains([]string{"off", "daily", "weekly"}, sc.Mode) || sc.Hour < 0 || sc.Hour > 23 || sc.Weekday < 0 || sc.Weekday > 6 {
		return fmt.Errorf("geçersiz özet zamanlaması")
	}
	return nil
}

func (s *Server) saveSummary(ctx context.Context, sc SummarySchedule) error {
	if err := sc.Validate(); err != nil {
		return err
	}
	for k, v := range map[string]string{setSummaryMode: sc.Mode, setSummaryHour: strconv.Itoa(sc.Hour), setSummaryDay: strconv.Itoa(sc.Weekday)} {
		if err := store.SetSetting(ctx, s.DB, k, v); err != nil {
			return err
		}
	}
	s.wakeSummary()
	return nil
}

// NextSummary is the next send time after now (zero when off).
func NextSummary(now time.Time, sc SummarySchedule) time.Time {
	if sc.Mode != "daily" && sc.Mode != "weekly" {
		return time.Time{}
	}
	t := time.Date(now.Year(), now.Month(), now.Day(), sc.Hour, 0, 0, 0, now.Location())
	for !t.After(now) || (sc.Mode == "weekly" && int(t.Weekday()) != sc.Weekday) {
		t = t.AddDate(0, 0, 1)
		t = time.Date(t.Year(), t.Month(), t.Day(), sc.Hour, 0, 0, 0, now.Location())
	}
	return t
}

func (s *Server) wakeSummary() {
	if s.summaryWake == nil {
		return
	}
	select {
	case s.summaryWake <- struct{}{}:
	default:
	}
}

// RunSummary sends the digest on schedule: one goroutine, one timer, and no
// timer at all while it is off. A send missed while the panel was down is
// not made up.
func (s *Server) RunSummary(ctx context.Context) {
	for {
		sc := s.summarySchedule(ctx)
		next := NextSummary(time.Now(), sc)
		var tc <-chan time.Time
		var t *time.Timer
		if !next.IsZero() {
			d := min(time.Until(next), 6*time.Hour) // re-evaluated at least every 6 h (clock/DST changes)
			t = time.NewTimer(d)
			tc = t.C
		}
		select {
		case <-ctx.Done():
			if t != nil {
				t.Stop()
			}
			return
		case <-s.summaryWake:
			if t != nil {
				t.Stop()
			}
		case <-tc:
			if now := time.Now(); !next.IsZero() && !now.Before(next.Add(-time.Second)) {
				s.SendSummary(ctx, sc.Mode)
				if s.Idle != nil {
					s.Idle.Touch()
				}
			}
		}
	}
}

// SendSummary queues the digest.
func (s *Server) SendSummary(ctx context.Context, mode string) {
	if s.Notify == nil {
		return
	}
	title, text := s.BuildSummary(ctx, mode, time.Now())
	s.Notify.Send(ctx, notify.Event{Kind: notify.KindSummary, Key: "summary", NoDedupe: true, Title: title, Text: text})
}

func gb(b uint64) string { return strconv.FormatFloat(float64(b)/(1<<30), 'f', 1, 64) + " GB" }

// BuildSummary renders the digest (mode daily = last 24 h, weekly = 7 days).
func (s *Server) BuildSummary(ctx context.Context, mode string, now time.Time) (string, string) {
	days := 1
	label := "Günlük"
	if mode == "weekly" {
		days, label = 7, "Haftalık"
	}
	since := now.AddDate(0, 0, -days)
	snap := system.Read()
	// Sections are "Header:" + "• item" lines separated by a blank line;
	// notify lays them out (bold headers/labels in Telegram).
	var b strings.Builder
	var sec []string
	item := func(format string, a ...any) { sec = append(sec, "• "+fmt.Sprintf(format, a...)) }
	section := func(name string) {
		if len(sec) == 0 {
			return
		}
		if b.Len() > 0 {
			b.WriteString("\n\n")
		}
		b.WriteString(name + ":\n" + strings.Join(sec, "\n"))
		sec = nil
	}
	title := fmt.Sprintf("%s özet — %s (%s)", label, snap.Hostname, now.Format("02.01.2006"))

	item("Disk: %%%d dolu, %s boş", snap.DiskUsedPct(), gb(snap.DiskFree))
	item("RAM: %s / %s (swap %s)", gb(snap.MemTotal-snap.MemAvail), gb(snap.MemTotal), gb(snap.SwapTotal-snap.SwapFree))
	item("Yük: %.2f", snap.Load1)
	section("Sunucu")

	list, _ := s.Sites.Store.List(ctx, 0)
	var health map[int64]monitor.Check
	if s.Monitor != nil {
		health, _ = s.Monitor.Store.All(ctx)
	}
	running := 0
	var down []string
	for _, st := range list {
		if st.Status == sites.StatusRunning {
			running++
		}
		if h, ok := health[st.ID]; ok && h.State == monitor.StateDown {
			down = append(down, st.Domain)
		}
	}
	item("%d site, %d çalışıyor", len(list), running)
	if len(down) > 0 {
		item("Erişilemeyen: %s", strings.Join(down, ", "))
	}
	if bad := s.infraDown(ctx); len(bad) > 0 {
		var n []string
		for _, d := range bad {
			n = append(n, d.Name)
		}
		item("Çalışmayan altyapı: %s", strings.Join(n, ", "))
	}

	if s.Monitor != nil {
		up, _ := s.Monitor.Store.UptimeSummary(ctx, traffic.DayKey(since))
		var checks, fails int64
		worst, worstPct := "", 101.0
		for _, st := range list {
			u, ok := up[st.ID]
			if !ok || u.Checks == 0 {
				continue
			}
			checks += u.Checks
			fails += u.Fails
			if p := u.Pct(); p < worstPct {
				worst, worstPct = st.Domain, p
			}
		}
		if checks > 0 {
			l := fmt.Sprintf("Erişilebilirlik: %%%.2f", 100*float64(checks-fails)/float64(checks))
			if worstPct < 100 {
				l += fmt.Sprintf(" (en düşük: %s %%%.2f)", worst, worstPct)
			}
			item("%s", l)
		}
	}
	section("Siteler")

	all, _ := s.Backups.Store.Backups(ctx, backups.Filter{Limit: 2000})
	okN, failN := 0, 0
	var failed []string
	for _, bk := range all {
		if bk.CreatedAt.Before(since) {
			break
		}
		switch bk.Status {
		case backups.StatusSuccess:
			okN++
		case backups.StatusFailed:
			failN++
			if !slices.Contains(failed, bk.Domain) {
				failed = append(failed, bk.Domain)
			}
		}
	}
	item("%d başarılı, %d başarısız", okN, failN)
	if len(failed) > 0 {
		item("Başarısız: %s", strings.Join(failed, ", "))
	}
	if v, _ := s.Backups.Store.Verifications(ctx, 1); len(v) > 0 {
		mark := "✓"
		if v[0].Status != backups.StatusSuccess {
			mark = "✗"
		}
		item("Son doğrulama: %s %s (%s)", mark, v[0].Domain, v[0].CreatedAt.Format("02.01"))
	}
	section("Yedekler")

	var exp []string
	for _, c := range s.SSL.ActiveBySite(ctx) {
		if c.DaysLeft() <= 30 {
			exp = append(exp, fmt.Sprintf("%s %d gün", c.Domain, c.DaysLeft()))
		}
	}
	sort.Strings(exp)
	if len(exp) > 0 {
		item("SSL: %s", strings.Join(exp, ", "))
	}
	if s.Domains != nil {
		var dn []string
		for _, e := range s.Domains.Expiring(ctx, 30) {
			dn = append(dn, fmt.Sprintf("%s %d gün", e.Name, e.DaysLeft(now)))
		}
		if len(dn) > 0 {
			item("Alan adları: %s", strings.Join(dn, ", "))
		}
	}
	section("30 gün içinde bitecek")

	if s.Traffic != nil {
		tr, _ := s.Traffic.Summary(ctx, traffic.DayKey(since))
		type row struct {
			d string
			t traffic.Totals
		}
		var rows []row
		for _, st := range list {
			if t, ok := tr[st.ID]; ok && t.Requests > 0 {
				rows = append(rows, row{st.Domain, t})
			}
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].t.Requests > rows[j].t.Requests })
		for i, r := range rows {
			if i == 5 {
				break
			}
			item("%s — %d istek, %s", r.d, r.t.Requests, backups.HumanSize(r.t.Bytes))
		}
		section("Trafik (tamamlanmış günler)")
	}

	if s.F2B != nil {
		if st, err := s.F2B.Status(ctx); err == nil && st.Active {
			total := 0
			var per []string
			for _, j := range st.Jails {
				total += j.CurBanned
				per = append(per, fmt.Sprintf("%s %d", j.Name, j.CurBanned))
			}
			item("fail2ban: %d IP engelli (%s)", total, strings.Join(per, ", "))
		}
	}
	if s.RBL != nil {
		var n []string
		for _, r := range s.RBL.State(ctx).Listed() {
			n = append(n, r.Target+" ("+r.List+")")
		}
		if len(n) > 0 {
			item("Posta kara listesi: %s", strings.Join(n, ", "))
		}
	}
	section("Güvenlik")

	if s.Sys != nil {
		if a := s.Sys.Upgradable(ctx, false); a.Err == "" && len(a.Pkgs) > 0 {
			item("Sistem: %d paket (%d güvenlik)", len(a.Pkgs), a.Security)
		}
		if ri := s.Sys.Reboot(ctx); ri.Required {
			item("Yeniden başlatma gerekli")
		}
	}
	if s.Update != nil {
		if inf := s.Update.Info(ctx, false); inf.Available {
			item("Panel: %s", inf.Latest.Tag)
		}
	}
	for _, o := range s.Sites.PatchOffers(ctx) {
		item("%s: %s", o.Name, o.To)
	}
	section("Bekleyen güncellemeler")
	return title, b.String()
}

func (s *Server) summaryTest(w http.ResponseWriter, r *http.Request) {
	c := s.Notify.Load(r.Context())
	if !c.TelegramOn && !c.SMTPOn {
		s.renderNotify(w, r, http.StatusBadRequest, "Etkin bildirim kanalı yok.", "")
		return
	}
	if !c.Enabled(notify.KindSummary) {
		s.renderNotify(w, r, http.StatusBadRequest, "Olaylar listesinde \"Özet raporu\" seçili değil.", "")
		return
	}
	mode := s.summarySchedule(r.Context()).Mode
	if mode == "off" {
		mode = "daily"
	}
	s.SendSummary(r.Context(), mode)
	s.renderNotify(w, r, http.StatusOK, "", "Özet gönderim kuyruğuna alındı.")
}

// --- I5: Telegram commands ---

const botRateKey = "telegram" // login_attempts "ip" of the bot's 2FA codes

const botHelp = `Komutlar:
• /durum — sunucu ve siteler
• /siteler — site listesi (durum, sağlık)
• /disk — disk ve bellek
• /yedekler — son yedekler ve doğrulama
• /yeniden_baslat <site> <2FA kodu> — siteyi yeniden başlat`

// BotCommand answers one Telegram command.
func (s *Server) BotCommand(ctx context.Context, cmd string, args []string) string {
	ctx = logs.WithActor(ctx, logs.Actor{Source: logs.SourceUser, IP: botRateKey})
	switch cmd {
	case "start", "yardim", "help":
		return botHelp
	case "durum":
		return s.botStatus(ctx)
	case "siteler":
		return s.botSites(ctx)
	case "disk":
		snap := system.Read()
		return fmt.Sprintf("Disk: %%%d dolu, %s boş (toplam %s)\nRAM: %s / %s kullanımda\nSwap: %s / %s",
			snap.DiskUsedPct(), gb(snap.DiskFree), gb(snap.DiskTotal), gb(snap.MemTotal-snap.MemAvail), gb(snap.MemTotal),
			gb(snap.SwapTotal-snap.SwapFree), gb(snap.SwapTotal))
	case "yedekler":
		return s.botBackups(ctx)
	case "yeniden_baslat":
		return s.botRestart(ctx, args)
	}
	return "Bilinmeyen komut.\n\n" + botHelp
}

func (s *Server) botStatus(ctx context.Context) string {
	snap := system.Read()
	var b strings.Builder
	fmt.Fprintf(&b, "Sunucu: %s\nÇalışma süresi: %s\nYük: %.2f · RAM %%%d · disk %%%d\n\n", snap.Hostname,
		upFor(snap.Uptime), snap.Load1, snap.MemUsedPct(), snap.DiskUsedPct())
	list, _ := s.Sites.Store.List(ctx, 0)
	health, _ := s.Monitor.Store.All(ctx)
	running, down := 0, []string{}
	for _, st := range list {
		if st.Status == sites.StatusRunning {
			running++
		}
		if h, ok := health[st.ID]; ok && h.State == monitor.StateDown {
			down = append(down, st.Domain)
		}
	}
	fmt.Fprintf(&b, "Siteler: %d / %d çalışıyor\n", running, len(list))
	if len(down) > 0 {
		fmt.Fprintf(&b, "🔴 Erişilemeyen: %s\n", strings.Join(down, ", "))
	}
	b.WriteString("\n")
	if bad := s.infraDown(ctx); len(bad) > 0 {
		b.WriteString("Altyapı:\n")
		for _, d := range bad {
			fmt.Fprintf(&b, "• ✗ %s — %s\n", d.Name, d.Why)
		}
	} else {
		b.WriteString("Altyapı: ✓ sorun yok\n")
	}
	return strings.TrimSpace(b.String())
}

func (s *Server) botSites(ctx context.Context) string {
	list, _ := s.Sites.Store.List(ctx, 0)
	if len(list) == 0 {
		return "Site yok."
	}
	health, _ := s.Monitor.Store.All(ctx)
	var b strings.Builder
	for _, st := range list {
		h := "—"
		if c, ok := health[st.ID]; ok && c.Enabled {
			h = c.State
		}
		dot := "🟡"
		switch {
		case h == monitor.StateDown || st.Status == sites.StatusError:
			dot = "🔴"
		case st.Status == sites.StatusRunning:
			dot = "🟢"
		case st.Status == sites.StatusStopped || st.Status == sites.StatusDisabled:
			dot = "⚪"
		}
		fmt.Fprintf(&b, "%s %s\n    %s · sağlık: %s\n", dot, st.Domain, st.Status, h)
	}
	return strings.TrimSpace(b.String())
}

func (s *Server) botBackups(ctx context.Context) string {
	latest, _ := s.Backups.Store.LatestBySite(ctx)
	list, _ := s.Sites.Store.List(ctx, 0)
	var b strings.Builder
	for _, st := range list {
		bk, ok := latest[st.ID]
		if !ok {
			fmt.Fprintf(&b, "⚪ %s\n    yedek yok\n", st.Domain)
			continue
		}
		where := "yerel"
		if bk.Remote {
			where = "Drive"
			if bk.Local {
				where = "yerel+Drive"
			}
		}
		mark := "✅"
		if bk.Status != backups.StatusSuccess {
			mark = "❌"
		}
		fmt.Fprintf(&b, "%s %s\n    %s · %s · %s\n", mark, st.Domain, bk.CreatedAt.Format("02.01 15:04"), bk.Status, where)
	}
	if v, _ := s.Backups.Store.Verifications(ctx, 1); len(v) > 0 {
		fmt.Fprintf(&b, "\nSon doğrulama: %s %s / %s (%s)\n", map[bool]string{true: "✓", false: "✗"}[v[0].Status == backups.StatusSuccess],
			v[0].Domain, v[0].Name, v[0].CreatedAt.Format("02.01 15:04"))
	}
	if b.Len() == 0 {
		return "Site yok."
	}
	return strings.TrimSpace(b.String())
}

// botRestart restarts a site after a TOTP code (2FA must be on). Failed codes
// count against the login rate limit (key "telegram").
func (s *Server) botRestart(ctx context.Context, args []string) string {
	if len(args) != 2 {
		return "Kullanım: /yeniden_baslat <site> <2FA kodu>"
	}
	u, err := s.Auth.Admin(ctx)
	if err != nil || !u.TOTPEnabled {
		return "Bu komut için panelde iki adımlı doğrulama (2FA) açık olmalı."
	}
	if err := s.Auth.CheckRate(ctx, botRateKey); err != nil {
		return "Çok fazla hatalı kod; 15 dk sonra deneyin."
	}
	code := args[1]
	ok := len(code) == 6
	if ok {
		var rec bool
		rec, ok = s.Auth.VerifySecondFactor(ctx, u, code)
		ok = ok && !rec
	}
	s.Auth.RecordAttempt(ctx, botRateKey, ok)
	if !ok {
		s.writeAuthLog("login failed", botRateKey, "telegram")
		s.Activity.Record(ctx, logs.Entry{Action: "telegram.command", TargetType: "site", TargetID: args[0], Status: logs.StatusFailed,
			Summary: "Telegram: yeniden başlatma reddedildi (hatalı 2FA kodu)"}, nil)
		return "Kod hatalı."
	}
	site, err := s.Sites.Store.GetByDomain(ctx, strings.ToLower(args[0]))
	if err != nil {
		return "Site bulunamadı: " + args[0]
	}
	id, err := s.Sites.SubmitOp(ctx, site, sites.OpRestart)
	if err != nil {
		return "Başlatılamadı: " + err.Error()
	}
	s.Activity.Record(ctx, logs.Entry{Action: "telegram.command", TargetType: "site", TargetID: site.Domain,
		Summary: "Telegram: " + site.Domain + " yeniden başlatılıyor"}, map[string]any{"job_id": id})
	return fmt.Sprintf("%s yeniden başlatılıyor (iş #%d). Sonuç için /siteler.", site.Domain, id)
}

// upFor renders an uptime as "3 gün 4 sa" (Telegram /durum).
func upFor(d time.Duration) string {
	h := int(d.Hours())
	if h < 24 {
		return fmt.Sprintf("%d sa", h)
	}
	return fmt.Sprintf("%d gün %d sa", h/24, h%24)
}
