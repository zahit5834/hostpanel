package web

import (
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/zahit5834/hostpanel/internal/images"
	"github.com/zahit5834/hostpanel/internal/monitor"
	"github.com/zahit5834/hostpanel/internal/sites"
	"github.com/zahit5834/hostpanel/internal/traffic"
)

// --- container image updates ---

func (s *Server) imageInfo(r *http.Request, id string) *images.Info {
	if s.Images == nil {
		return nil
	}
	i, ok := s.Images.Info(r.Context(), id)
	if !ok {
		return nil
	}
	return &i
}

func (s *Server) dbServerUpdate(w http.ResponseWriter, r *http.Request) {
	id, err := s.DBs.StartImageUpdate(r.Context(), r.PostFormValue("image"))
	s.dbJobRedirect(w, r, id, err)
}

func (s *Server) mailServerUpdate(w http.ResponseWriter, r *http.Request) {
	id, err := s.Mail.StartImageUpdate(r.Context(), r.PostFormValue("image"))
	s.mailJobRedirect(w, r, id, err)
}

func (s *Server) imagesCheck(w http.ResponseWriter, r *http.Request) {
	s.Images.Check(r.Context())
	http.Redirect(w, r, "/settings/update#images", http.StatusSeeOther)
}

// --- traffic + uptime ---

// statRange is the selectable periods (days).
var statRanges = []int{7, 30, 90}

func statDays(r *http.Request) int {
	n := parseInt64(r.URL.Query().Get("days"))
	for _, d := range statRanges {
		if int64(d) == n {
			return d
		}
	}
	return 30
}

type statDay struct {
	Day        string
	Label      string // 02.01
	Today      bool
	Traffic    traffic.Day
	Uptime     monitor.UptimeDay
	HasUptime  bool
	BarX       int
	BarY, BarH int // request bar (SVG, 0–100)
	UpClass    string
}

type incidentRow struct {
	Start    time.Time
	End      time.Time
	Open     bool
	Duration string
	Reason   string
	EndNote  string
}

type siteStatsData struct {
	Site      sites.Site
	Days      int
	Ranges    []int
	Rows      []statDay
	BarW      int // SVG width of one bar
	BarInner  int
	ChartW    int
	Totals    traffic.Totals
	Top       []traffic.PathCount
	MaxReq    int64
	Uptime    monitor.UptimeDay // whole period
	Incidents []incidentRow
	Down      string // total down time in the period
	Health    monitor.Check
	ScanErr   string
}

// humanDuration is a short Turkish duration ("2 sa 5 dk").
func humanDuration(d time.Duration) string {
	d = d.Round(time.Minute)
	switch {
	case d < time.Minute:
		return "1 dk'dan kısa"
	case d < time.Hour:
		return fmt.Sprintf("%d dk", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d sa %d dk", int(d.Hours()), int(d.Minutes())%60)
	default:
		return fmt.Sprintf("%d gün %d sa", int(d.Hours())/24, int(d.Hours())%24)
	}
}

func upClass(u monitor.UptimeDay) string {
	switch p := u.Pct(); {
	case p >= 99.9:
		return "up-ok"
	case p >= 98:
		return "up-warn"
	default:
		return "up-bad"
	}
}

// siteStats is the lazily loaded body of the site's İstatistik tab: it
// stores missing complete days from the rotated logs first (the first open
// can scan up to two weeks of logs), then scans today's lines.
func (s *Server) siteStats(w http.ResponseWriter, r *http.Request) {
	site, ok := s.loadSite(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	days := statDays(r)
	now := time.Now()
	from := now.AddDate(0, 0, -(days - 1))
	d := siteStatsData{Site: site, Days: days, Ranges: statRanges}
	var errs []string
	if err := s.Traffic.Collect(ctx, site); err != nil {
		errs = append(errs, err.Error())
	}
	stored, _ := s.Traffic.Range(ctx, site.ID, traffic.DayKey(from))
	today, err := s.Traffic.Today(site)
	if err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		d.ScanErr = errs[0]
	}
	up, _ := s.Monitor.Store.UptimeDays(ctx, site.ID, traffic.DayKey(from))
	byDay := map[string]traffic.Day{}
	for _, t := range stored {
		byDay[t.Day] = t
	}
	byDay[today.Day] = today
	upDay := map[string]monitor.UptimeDay{}
	for _, u := range up {
		upDay[u.Day] = u
		d.Uptime.Checks += u.Checks
		d.Uptime.Fails += u.Fails
		d.Uptime.MSSum += u.MSSum
		d.Uptime.MSMax = max(d.Uptime.MSMax, u.MSMax)
	}
	all := make([]traffic.Day, 0, days)
	for t := from; !t.After(now); t = t.AddDate(0, 0, 1) {
		k := traffic.DayKey(t)
		row := statDay{Day: k, Label: t.Format("02.01"), Today: k == today.Day, Traffic: byDay[k]}
		row.Traffic.Day = k
		row.Uptime, row.HasUptime = upDay[k]
		if row.HasUptime {
			row.UpClass = upClass(row.Uptime)
		}
		d.MaxReq = max(d.MaxReq, row.Traffic.Requests)
		all = append(all, row.Traffic)
		d.Rows = append(d.Rows, row)
	}
	d.Totals, d.Top = traffic.Sum(all)
	d.BarW, d.BarInner = 10, 8
	d.ChartW = d.BarW * len(d.Rows)
	for i := range d.Rows {
		d.Rows[i].BarX = i * d.BarW
		if d.MaxReq > 0 {
			d.Rows[i].BarH = int(d.Rows[i].Traffic.Requests * 100 / d.MaxReq)
		}
		if d.Rows[i].BarH == 0 && d.Rows[i].Traffic.Requests > 0 {
			d.Rows[i].BarH = 1
		}
		d.Rows[i].BarY = 100 - d.Rows[i].BarH
	}
	inc, _ := s.Monitor.Store.Incidents(ctx, site.ID, from, 50)
	var down time.Duration
	for _, i := range inc {
		dur := i.Duration(now)
		down += dur
		d.Incidents = append(d.Incidents, incidentRow{Start: i.StartedAt, End: i.EndedAt, Open: i.Open(),
			Duration: humanDuration(dur), Reason: i.Reason, EndNote: i.EndNote})
	}
	if down > 0 {
		d.Down = humanDuration(down)
	}
	d.Health, _ = s.Monitor.Store.Get(ctx, site.ID)
	s.render(w, r, http.StatusOK, "site", "site-stats", Page{Data: d})
}

type statsRow struct {
	Site      sites.Site
	Traffic   traffic.Totals
	Uptime    monitor.UptimeDay
	HasUptime bool
	Health    monitor.Check
	HasHealth bool
	UpClass   string
	Err5xx    float64
}

type statsPageData struct {
	Rows []statsRow
	Days int
}

// statsPage is the all-sites overview: stored days only (complete days are
// added by the daily maintenance or when a site's tab is opened).
func (s *Server) statsPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	days := 7
	if r.URL.Query().Get("days") == "30" {
		days = 30
	}
	from := traffic.DayKey(time.Now().AddDate(0, 0, -days))
	list, _ := s.Sites.Store.List(ctx, 0)
	tr, _ := s.Traffic.Summary(ctx, from)
	up, _ := s.Monitor.Store.UptimeSummary(ctx, traffic.DayKey(time.Now().AddDate(0, 0, -29)))
	checks, _ := s.Monitor.Store.All(ctx)
	d := statsPageData{Days: days}
	for _, site := range list {
		row := statsRow{Site: site, Traffic: tr[site.ID]}
		row.Uptime, row.HasUptime = up[site.ID]
		if row.HasUptime {
			row.UpClass = upClass(row.Uptime)
		}
		row.Health, row.HasHealth = checks[site.ID]
		if row.Traffic.Requests > 0 {
			row.Err5xx = float64(row.Traffic.S5) * 100 / float64(row.Traffic.Requests)
		}
		d.Rows = append(d.Rows, row)
	}
	sort.SliceStable(d.Rows, func(i, j int) bool { return d.Rows[i].Traffic.Requests > d.Rows[j].Traffic.Requests })
	s.render(w, r, http.StatusOK, "stats", "layout", Page{Title: "İstatistikler", Nav: "stats", Data: d})
}
