package web

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zahit5834/hostpanel/internal/backups"
	"github.com/zahit5834/hostpanel/internal/domains"
	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/metrics"
	"github.com/zahit5834/hostpanel/internal/notify"
	"github.com/zahit5834/hostpanel/internal/sites"
	"github.com/zahit5834/hostpanel/internal/store"
	"github.com/zahit5834/hostpanel/internal/sysmaint"
)

// --- I4: domain registration expiry ---

// domainUse is where a registrable name is used.
type domainUse struct {
	Entry    domains.Entry
	Days     int
	Uses     []string
	Customer string
	Class    string // ok | warn | bad | muted
}

// domainHosts collects every host name the panel serves.
func (s *Server) domainHosts(ctx context.Context) map[string][]string {
	uses := map[string][]string{}
	add := func(host, use string) {
		if n := domains.Registrable(host); n != "" && !slices.Contains(uses[n], use) {
			uses[n] = append(uses[n], use)
		}
	}
	list, _ := s.Sites.Store.List(ctx, 0)
	for _, st := range list {
		for _, h := range st.HostNames() {
			add(h, "site "+st.Domain)
		}
	}
	if s.DNS != nil {
		zones, _ := s.DNS.Store.Zones(ctx, 0)
		for _, z := range zones {
			add(z.Name, "DNS zone")
		}
	}
	if s.Mail != nil {
		ds, _ := s.Mail.Store.Domains(ctx, 0)
		for _, d := range ds {
			add(d.Name, "posta alan adı")
		}
		if srv, err := s.Mail.Store.Server(ctx); err == nil && srv.Hostname != "" {
			add(srv.Hostname, "posta sunucusu adı")
		}
	}
	if d := s.PanelAddr.Addr.Domain(); d != "" {
		add(d, "panel adresi")
	}
	return uses
}

// DomainsMaintain (daily maintenance) syncs the list and looks up the dates.
func (s *Server) DomainsMaintain(ctx context.Context) {
	if s.Domains == nil {
		return
	}
	uses := s.domainHosts(ctx)
	names := make([]string, 0, len(uses))
	for n := range uses {
		names = append(names, n)
	}
	if err := s.Domains.Sync(ctx, names); err != nil {
		s.Log.Warn("domain expiry sync", "err", err)
		return
	}
	if s.Cfg.DryRun {
		return // no lookups from a development box
	}
	if err := s.Domains.Refresh(ctx, false); err != nil {
		s.Log.Info("domain expiry lookup", "err", err)
	}
}

func domainClass(e domains.Entry, days int) string {
	switch {
	case e.ExpiresAt.IsZero():
		return ""
	case days <= 7:
		return "failed"
	case days <= 30:
		return "warn"
	}
	return "success"
}

func (s *Server) domainRows(ctx context.Context, customerID int64) []domainUse {
	uses := s.domainHosts(ctx)
	owner := map[string]string{}
	mine := map[string]bool{}
	list, _ := s.Sites.Store.List(ctx, 0)
	for _, st := range list {
		for _, h := range st.HostNames() {
			n := domains.Registrable(h)
			if owner[n] == "" {
				owner[n] = st.CustomerName
			}
			if st.CustomerID == customerID {
				mine[n] = true
			}
		}
	}
	if customerID > 0 {
		if s.DNS != nil {
			zones, _ := s.DNS.Store.Zones(ctx, customerID)
			for _, z := range zones {
				mine[domains.Registrable(z.Name)] = true
			}
		}
		if s.Mail != nil {
			ds, _ := s.Mail.Store.Domains(ctx, customerID)
			for _, d := range ds {
				mine[domains.Registrable(d.Name)] = true
			}
		}
	}
	entries, _ := s.Domains.List(ctx)
	have := map[string]bool{}
	now := time.Now()
	var out []domainUse
	for _, e := range entries {
		have[e.Name] = true
		if customerID > 0 && !mine[e.Name] {
			continue
		}
		d := domainUse{Entry: e, Days: e.DaysLeft(now), Uses: uses[e.Name], Customer: owner[e.Name]}
		d.Class = domainClass(e, d.Days)
		out = append(out, d)
	}
	// Names not synced yet (new site since the last maintenance).
	for n, u := range uses {
		if !have[n] && (customerID == 0 || mine[n]) {
			out = append(out, domainUse{Entry: domains.Entry{Name: n, Source: domains.SourceRDAP}, Uses: u, Customer: owner[n]})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Entry.ExpiresAt.IsZero() != b.Entry.ExpiresAt.IsZero() {
			return !a.Entry.ExpiresAt.IsZero()
		}
		if !a.Entry.ExpiresAt.Equal(b.Entry.ExpiresAt) {
			return a.Entry.ExpiresAt.Before(b.Entry.ExpiresAt)
		}
		return a.Entry.Name < b.Entry.Name
	})
	return out
}

func (s *Server) renderDomains(w http.ResponseWriter, r *http.Request, status int, errMsg, notice string) {
	d := map[string]any{"Rows": s.domainRows(r.Context(), 0), "DryRun": s.Cfg.DryRun}
	s.render(w, r, status, "domains", "layout", Page{Title: "Alan adları", Nav: "domains", Data: d, Error: errMsg, Notice: notice})
}

func (s *Server) domainsPage(w http.ResponseWriter, r *http.Request) {
	s.renderDomains(w, r, http.StatusOK, "", "")
}

func (s *Server) domainManual(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	raw := strings.TrimSpace(r.PostFormValue("date"))
	var date time.Time
	if raw != "" {
		var err error
		if date, err = time.ParseInLocation("2006-01-02", raw, time.Local); err != nil {
			s.renderDomains(w, r, http.StatusBadRequest, "Geçersiz tarih", "")
			return
		}
	}
	if _, err := s.Domains.Get(r.Context(), name); err != nil {
		s.DomainsMaintainSync(r.Context()) // a name the daily sync has not seen yet
	}
	if err := s.Domains.SetManual(r.Context(), name, date); err != nil {
		s.renderDomains(w, r, http.StatusBadRequest, err.Error(), "")
		return
	}
	sum := name + " bitiş tarihi elle girildi: " + raw
	if raw == "" {
		sum = name + " bitiş tarihi yeniden otomatik (RDAP) sorgulanacak"
	}
	s.Activity.Record(r.Context(), logs.Entry{Action: "domain.expiry", TargetType: "domain", TargetID: name, Summary: sum}, nil)
	s.renderDomains(w, r, http.StatusOK, "", "Kaydedildi.")
}

// DomainsMaintainSync only syncs the list (no lookups).
func (s *Server) DomainsMaintainSync(ctx context.Context) {
	uses := s.domainHosts(ctx)
	names := make([]string, 0, len(uses))
	for n := range uses {
		names = append(names, n)
	}
	s.Domains.Sync(ctx, names)
}

func (s *Server) domainRefresh(w http.ResponseWriter, r *http.Request) {
	s.DomainsMaintainSync(r.Context())
	if s.Cfg.DryRun {
		s.renderDomains(w, r, http.StatusOK, "", "Dry-run: RDAP sorgusu yapılmadı.")
		return
	}
	if !s.domainBusy.CompareAndSwap(false, true) {
		s.renderDomains(w, r, http.StatusConflict, "Sorgu zaten sürüyor.", "")
		return
	}
	go func() {
		defer s.domainBusy.Store(false)
		ctx, cancel := context.WithTimeout(s.BaseCtx, 10*time.Minute)
		defer cancel()
		s.Domains.Refresh(ctx, true)
	}()
	s.renderDomains(w, r, http.StatusOK, "", "Sorgu başlatıldı; alan adı başına yaklaşık 1–2 sn sürer, birazdan sayfayı yenileyin.")
}

// --- D1: runtime patches ---

const setPatchNotified = "runtime_patch_notified" // JSON list of "id@version" already announced

// RuntimePatchCheck (daily maintenance) announces new patches once.
func (s *Server) RuntimePatchCheck(ctx context.Context) {
	var seen []string
	json.Unmarshal([]byte(store.GetSetting(ctx, s.DB, setPatchNotified, "[]")), &seen)
	var keep []string
	for _, o := range s.Sites.PatchOffers(ctx) {
		key := o.Runtime + "@" + o.To
		if !slices.Contains(keep, key) {
			keep = append(keep, key)
		}
		if slices.Contains(seen, key) {
			continue
		}
		seen = append(seen, key)
		if s.Notify != nil {
			text := fmt.Sprintf("Kurulu: %s. Altyapılar sayfasından kurup siteleri tek tek taşıyabilirsiniz.", o.From)
			if len(o.Sites) > 0 {
				text += fmt.Sprintf(" Bu sürümü kullanan site: %d.", len(o.Sites))
			}
			s.Notify.Send(ctx, notify.Event{Kind: notify.KindUpdate, Key: "runtime:" + key,
				Title: o.Name + " " + o.To + " yaması mevcut", Text: text})
		}
	}
	// Remember only current offers (an old key would otherwise grow forever),
	// plus the ones announced this round.
	var out []string
	for _, k := range seen {
		if slices.Contains(keep, k) {
			out = append(out, k)
		}
	}
	b, _ := json.Marshal(out)
	store.SetSetting(ctx, s.DB, setPatchNotified, string(b))
}

func (s *Server) runtimePatch(w http.ResponseWriter, r *http.Request) {
	id, err := s.Sites.SubmitPatch(r.Context(), r.PathValue("id"), r.PostFormValue("from"), r.PostFormValue("to"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/logs/jobs/%d", id), http.StatusSeeOther)
}

// --- K2: bulk site operations ---

func (s *Server) siteBulk(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	op := r.PostFormValue("op")
	var ids []int64
	for _, v := range r.PostForm["site"] {
		if id, err := strconv.ParseInt(v, 10, 64); err == nil && !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		s.renderSiteList(w, r, http.StatusBadRequest, "Site seçilmedi.", "")
		return
	}
	if len(ids) > 200 {
		s.renderSiteList(w, r, http.StatusBadRequest, "En fazla 200 site seçilebilir.", "")
		return
	}
	var ok, failed []string
	for _, id := range ids {
		site, err := s.Sites.Store.Get(r.Context(), id)
		if err != nil {
			continue
		}
		switch op {
		case "backup":
			_, err = s.Backups.StartManual(r.Context(), backups.ManualInput{SiteID: id, Components: backups.AllComponents,
				Upload: r.PostFormValue("upload") == "1"})
		default:
			if !slices.Contains(sites.BulkOps, op) {
				s.renderSiteList(w, r, http.StatusBadRequest, "Geçersiz işlem.", "")
				return
			}
			_, err = s.Sites.SubmitOp(r.Context(), site, op)
		}
		if err != nil {
			failed = append(failed, site.Domain+": "+err.Error())
		} else {
			ok = append(ok, site.Domain)
		}
	}
	label := sites.BulkOpLabel(op)
	if op == "backup" {
		label = "yedekle"
	}
	s.Activity.Record(r.Context(), logs.Entry{Action: "site.bulk", TargetType: "site", TargetID: op,
		Summary: fmt.Sprintf("Toplu işlem (%s): %d site", label, len(ok)), Status: statusOf(nil)},
		map[string]any{"op": op, "sites": ok})
	notice := fmt.Sprintf("%d site için iş kuyruğa alındı (%s). İlerleme: İş Logları.", len(ok), label)
	errMsg := ""
	if len(failed) > 0 {
		errMsg = "Kuyruğa alınamayanlar: " + strings.Join(failed, "; ")
	}
	s.renderSiteList(w, r, http.StatusOK, errMsg, notice)
}

// --- Y1: backup verification ---

func (s *Server) backupVerify(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PostFormValue("backup_id"), 10, 64)
	job, err := s.Backups.StartVerify(r.Context(), id)
	if err != nil {
		s.renderBackups(w, r, http.StatusBadRequest, "verify", defaultPlanForm(), nil, err.Error(), "")
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/logs/jobs/%d", job), http.StatusSeeOther)
}

func (s *Server) backupVerifySettings(w http.ResponseWriter, r *http.Request) {
	on := r.PostFormValue("weekly") == "1"
	if err := s.Backups.SetVerifyWeeklyOn(r.Context(), on); err != nil {
		s.renderBackups(w, r, http.StatusInternalServerError, "verify", defaultPlanForm(), nil, err.Error(), "")
		return
	}
	s.Activity.Record(r.Context(), logs.Entry{Action: "backup.verify.settings", TargetType: "backup", TargetID: "verify",
		Summary: map[bool]string{true: "Haftalık yedek doğrulaması açıldı", false: "Haftalık yedek doğrulaması kapatıldı"}[on]}, nil)
	s.renderBackups(w, r, http.StatusOK, "verify", defaultPlanForm(), nil, "", "Kaydedildi.")
}

// lastVerifyFailed is the newest drill when it failed (dashboard).
func (s *Server) lastVerifyFailed(ctx context.Context) *backups.Verification {
	v, err := s.Backups.Store.Verifications(ctx, 1)
	if err != nil || len(v) == 0 || v[0].Status != backups.StatusFailed {
		return nil
	}
	return &v[0]
}

// --- S4: disk assistant ---

func (s *Server) cleanDelete(w http.ResponseWriter, r *http.Request) {
	cat, id := r.PostFormValue("cat"), r.PostFormValue("id")
	start := time.Now()
	err := s.Sys.CleanDelete(r.Context(), s.Sites.UploadDir, cat, id)
	s.Activity.Record(r.Context(), logs.Entry{Action: "server.clean", TargetType: "server", TargetID: cat,
		Summary: "Disk temizliği: " + cat + " " + id, Status: statusOf(err), Error: errText(err),
		DurationMS: time.Since(start).Milliseconds()}, map[string]any{"cat": cat, "id": id})
	if err != nil {
		s.renderServerTab(w, r, http.StatusBadGateway, "clean", "", "Silinemedi: "+helperErr(err), "", nil)
		return
	}
	s.renderServerTab(w, r, http.StatusOK, "clean", "", "", "Silindi: "+id, nil)
}

func cleanTotal(cats []sysmaint.CleanCategory) (n int64) {
	for _, c := range cats {
		if c.Deletable {
			n += c.Bytes
		}
	}
	return n
}

// --- S6: metric history ---

const (
	chartW, chartH = 600.0, 120.0
	chartBuckets   = 300 // points per chart at most
)

type chartLine struct{ Class, Points string }

type chart struct {
	Title  string
	Now    string // latest value
	Max    string // y-axis top label
	Legend []struct{ Class, Label string }
	Lines  []chartLine
}

type metricsView struct {
	Range    string
	Enabled  bool
	Charts   []chart
	Samples  int
	From, To string
	Mid      string
	Interval string
}

type series struct {
	class, label string
	v            func(metrics.Point) float64
}

// buildChart turns points into SVG polylines (viewBox chartW×chartH); a gap of
// more than three buckets starts a new line.
func buildChart(title string, pts []metrics.Point, from, to time.Time, max float64, fmtv func(float64) string, ss ...series) chart {
	c := chart{Title: title}
	if max <= 0 {
		for _, p := range pts {
			for _, sr := range ss {
				max = math.Max(max, sr.v(p))
			}
		}
		max = niceMax(max)
	}
	c.Max = fmtv(max)
	span := to.Sub(from).Seconds()
	gap := 3 * math.Max(span/chartBuckets, metrics.Interval.Seconds()) // more than three empty buckets: new line
	for _, sr := range ss {
		c.Legend = append(c.Legend, struct{ Class, Label string }{sr.class, sr.label})
		var b strings.Builder
		var prev time.Time
		flush := func() {
			if b.Len() > 0 {
				c.Lines = append(c.Lines, chartLine{Class: sr.class, Points: b.String()})
				b.Reset()
			}
		}
		for _, p := range pts {
			if !prev.IsZero() && p.TS.Sub(prev).Seconds() > gap {
				flush()
			}
			prev = p.TS
			x := p.TS.Sub(from).Seconds() / span * chartW
			y := chartH - math.Min(sr.v(p)/max, 1)*chartH
			if b.Len() > 0 {
				b.WriteByte(' ')
			}
			fmt.Fprintf(&b, "%.1f,%.1f", x, y)
		}
		flush()
	}
	if len(pts) > 0 {
		last := pts[len(pts)-1]
		var parts []string
		for _, sr := range ss {
			parts = append(parts, sr.label+" "+fmtv(sr.v(last)))
		}
		c.Now = strings.Join(parts, " · ")
	}
	return c
}

// niceMax rounds up to 1/2/5 × 10ⁿ.
func niceMax(v float64) float64 {
	if v <= 0 {
		return 1
	}
	e := math.Pow(10, math.Floor(math.Log10(v)))
	for _, m := range []float64{1, 2, 5, 10} {
		if v <= m*e {
			return m * e
		}
	}
	return 10 * e
}

func fmtPct(v float64) string { return strconv.FormatFloat(v, 'f', 0, 64) + "%" }

func fmtBytes(v float64) string { return backups.HumanSize(int64(v)) }

func fmtRate(v float64) string { return backups.HumanSize(int64(v)) + "/sn" }

func fmtLoad(v float64) string { return strconv.FormatFloat(v, 'f', 2, 64) }

func (s *Server) metricsView(ctx context.Context, rng string) metricsView {
	v := metricsView{Range: rng}
	dur := map[string]time.Duration{"24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour}[rng]
	if dur == 0 {
		v.Range, dur = "24h", 24*time.Hour
	}
	if s.Metrics == nil {
		return v
	}
	v.Enabled = s.Metrics.Enabled(ctx)
	to := time.Now()
	from := to.Add(-dur)
	pts, _ := s.Metrics.Query(ctx, from, to, chartBuckets)
	v.Samples = len(pts)
	layout := "02.01 15:04"
	v.From, v.Mid, v.To = from.Format(layout), from.Add(dur/2).Format(layout), to.Format(layout)
	step := dur / chartBuckets
	if step < metrics.Interval {
		step = metrics.Interval
	}
	v.Interval = step.Round(time.Minute).String()
	if len(pts) == 0 {
		return v
	}
	var memTotal float64
	for _, p := range pts {
		memTotal = math.Max(memTotal, p.MemTotal)
	}
	v.Charts = []chart{
		buildChart("CPU", pts, from, to, 100, fmtPct, series{"s1", "kullanım", func(p metrics.Point) float64 { return p.CPU }}),
		buildChart("Bellek", pts, from, to, memTotal, fmtBytes,
			series{"s1", "RAM", func(p metrics.Point) float64 { return p.MemUsed }},
			series{"s2", "swap", func(p metrics.Point) float64 { return p.SwapUsed }}),
		buildChart("Disk (/)", pts, from, to, 100, fmtPct, series{"s1", "dolu", func(p metrics.Point) float64 { return p.DiskPct }}),
		buildChart("Yük (1 dk)", pts, from, to, 0, fmtLoad, series{"s1", "load", func(p metrics.Point) float64 { return p.Load1 }}),
		buildChart("Ağ", pts, from, to, 0, fmtRate,
			series{"s1", "gelen", func(p metrics.Point) float64 { return p.RXps }},
			series{"s2", "giden", func(p metrics.Point) float64 { return p.TXps }}),
	}
	return v
}

func (s *Server) metricsToggle(w http.ResponseWriter, r *http.Request) {
	on := r.PostFormValue("enabled") == "1"
	if err := s.Metrics.SetEnabledTo(r.Context(), on); err != nil {
		s.renderServerTab(w, r, http.StatusInternalServerError, "metrics", "", err.Error(), "", nil)
		return
	}
	s.Activity.Record(r.Context(), logs.Entry{Action: "settings.metrics", TargetType: "settings", TargetID: "metrics",
		Summary: map[bool]string{true: "Metrik geçmişi açıldı", false: "Metrik geçmişi kapatıldı"}[on]}, nil)
	s.renderServerTab(w, r, http.StatusOK, "metrics", "", "", "Kaydedildi.", nil)
}

func init() {
	funcs["seq"] = func(a, b int) []int {
		var out []int
		for i := a; i <= b; i++ {
			out = append(out, i)
		}
		return out
	}
}

// --- I2: heartbeat ---

func (s *Server) heartbeatTest(w http.ResponseWriter, r *http.Request) {
	if err := s.Metrics.TestPing(r.Context()); err != nil {
		s.renderNotify(w, r, http.StatusBadGateway, "Heartbeat gönderilemedi: "+err.Error(), "")
		return
	}
	s.renderNotify(w, r, http.StatusOK, "", "Heartbeat gönderildi.")
}
