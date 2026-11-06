package web

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"sort"
	"sync"
	"time"

	"hostpanel/internal/backups"
	"hostpanel/internal/logs"
	"hostpanel/internal/monitor"
	"hostpanel/internal/sites"
	"hostpanel/internal/ssl"
	"hostpanel/internal/system"
)

// metricsState keeps the previous CPU samples so a percentage can be derived
// from two consecutive dashboard polls; nothing is sampled in the background.
type metricsState struct {
	mu      sync.Mutex
	cpu     system.CPUTimes
	cpuOK   bool
	units   map[string]system.UnitUsage
	unitsAt time.Time
}

// hostCPU returns the busy % since the previous call (-1 on the first call).
func (m *metricsState) hostCPU() int {
	cur, ok := system.ReadCPU()
	m.mu.Lock()
	defer m.mu.Unlock()
	pct := -1
	if ok && m.cpuOK {
		pct = system.CPUPercent(m.cpu, cur)
	}
	m.cpu, m.cpuOK = cur, ok
	return pct
}

// unitUsage samples the cgroups of units and returns memory + CPU % per unit.
func (m *metricsState) unitUsage(units []string) map[string]unitStat {
	out := make(map[string]unitStat, len(units))
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.units == nil || time.Since(m.unitsAt) > 10*time.Minute {
		m.units = map[string]system.UnitUsage{} // forget sites that were deleted
	}
	m.unitsAt = time.Now()
	for _, u := range units {
		cur := system.ReadUnit(u)
		st := unitStat{OK: cur.OK, Mem: cur.MemBytes, CPU: -1}
		if prev, ok := m.units[u]; ok {
			st.CPU = system.UnitCPUPercent(prev, cur)
		}
		m.units[u] = cur
		out[u] = st
	}
	return out
}

type unitStat struct {
	OK  bool
	Mem uint64
	CPU int // % of one core, -1 = unknown (first sample)
}

// siteRow is one line of the dashboard site table.
type siteRow struct {
	Site   sites.Site
	Proxy  bool
	Usage  unitStat
	Cert   *ssl.Certificate
	Backup *backups.Backup
	Health monitor.Check
}

// alert is one dashboard warning card entry.
type alert struct {
	Text, Link, Detail string
}

func (s *Server) dashboardRows(ctx context.Context) []siteRow {
	list, _ := s.Sites.Store.List(ctx, 0)
	certs := s.SSL.ActiveBySite(ctx)
	latest, _ := s.Backups.Store.LatestBySite(ctx)
	var health map[int64]monitor.Check
	if s.Monitor != nil {
		health, _ = s.Monitor.Store.All(ctx)
	}
	var units []string
	rows := make([]siteRow, 0, len(list))
	for _, site := range list {
		r := siteRow{Site: site, Cert: certs[site.ID], Health: health[site.ID]}
		if p, ok := s.Runtimes.Get(site.RuntimeID); ok && p.Def().HasUnit() {
			r.Proxy = true
			units = append(units, site.Unit())
		}
		if b, ok := latest[site.ID]; ok {
			r.Backup = &b
		}
		rows = append(rows, r)
	}
	usage := s.metrics.unitUsage(units)
	for i := range rows {
		if rows[i].Proxy {
			rows[i].Usage = usage[rows[i].Site.Unit()]
		}
	}
	return rows
}

func (s *Server) dashboardAlerts(ctx context.Context, snap system.Snapshot, rows []siteRow) []alert {
	var out []alert
	if snap.DiskUsedPct() >= monitor.DiskThreshold {
		out = append(out, alert{Text: fmt.Sprintf("Disk kullanımı %%%d (eşik %%%d)", snap.DiskUsedPct(), monitor.DiskThreshold),
			Link: "/server", Detail: "Disk dağılımına bakın; eski yedekler ve loglar en sık sebeptir."})
	}
	for _, r := range rows {
		link := fmt.Sprintf("/sites/%d", r.Site.ID)
		switch {
		case r.Site.Status == sites.StatusError:
			out = append(out, alert{Text: r.Site.Domain + ": site hata durumunda", Link: link})
		case r.Health.State == monitor.StateDown:
			out = append(out, alert{Text: r.Site.Domain + ": sağlık kontrolü başarısız", Link: link,
				Detail: r.Health.LastError})
		case r.Health.RecentRestarts(time.Now()) >= monitor.RestartLimit:
			out = append(out, alert{Text: r.Site.Domain + ": servis sık sık yeniden başlıyor", Link: link + "?tab=logs&source=journal"})
		}
	}
	var expiring []*ssl.Certificate
	for _, c := range s.SSL.ActiveBySite(ctx) {
		if c.DaysLeft() < 15 {
			expiring = append(expiring, c)
		}
	}
	sort.Slice(expiring, func(i, j int) bool { return expiring[i].NotAfter.Before(expiring[j].NotAfter) })
	for _, c := range expiring {
		d := fmt.Sprintf("%d gün kaldı (%s)", c.DaysLeft(), c.NotAfter.Format("2006-01-02"))
		if c.DaysLeft() < 0 {
			d = "süresi doldu"
		}
		if c.Kind == "letsencrypt" {
			d += " · otomatik yenileme başarısız olmuş olabilir"
		}
		out = append(out, alert{Text: c.Domain + ": SSL sertifikası", Link: fmt.Sprintf("/sites/%d?tab=ssl", c.SiteID), Detail: d})
	}
	failed, _ := s.Backups.Store.FailedSince(ctx, time.Now().Add(-24*time.Hour))
	for _, b := range failed {
		out = append(out, alert{Text: b.Domain + ": yedek başarısız (" + b.CreatedAt.Format("02.01 15:04") + ")",
			Link: "/backups", Detail: b.Error})
	}
	return out
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	snap := system.Read()
	snap.Goroutines = runtime.NumGoroutine()
	rows := s.dashboardRows(ctx)
	data := map[string]any{"Sys": snap, "CPU": s.metrics.hostCPU(), "Sites": rows}
	block := "layout"
	// The live part polls only while the page is open (hx-trigger="every 5s");
	// nothing is collected when no browser is looking.
	if isHX(r) && r.URL.Query().Get("part") == "metrics" {
		block = "live"
	} else {
		data["Recent"], _ = s.Activity.Query(ctx, logs.Filter{Limit: 10})
		data["Alerts"] = s.dashboardAlerts(ctx, snap, rows)
	}
	s.render(w, r, http.StatusOK, "dashboard", block, Page{Title: "Genel Bakış", Nav: "dashboard", Data: data})
}

func init() {
	// page re-wraps a Page around other data so a block that expects a Page
	// (CSRF, Data) can be included from a page with a different Data.
	funcs["page"] = func(p Page, data any) Page {
		p.Data = data
		return p
	}
	funcs["div"] = func(a, b int) int { return a / b }
	funcs["bytes"] = func(b uint64) string {
		const unit = 1024
		if b < unit {
			return fmt.Sprintf("%d B", b)
		}
		div, exp := uint64(unit), 0
		for n := b / unit; n >= unit; n /= unit {
			div *= unit
			exp++
		}
		return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
	}
	funcs["uptime"] = func(d time.Duration) string {
		days := int(d.Hours()) / 24
		h := int(d.Hours()) % 24
		m := int(d.Minutes()) % 60
		if days > 0 {
			return fmt.Sprintf("%d gün %d sa", days, h)
		}
		return fmt.Sprintf("%d sa %d dk", h, m)
	}
	funcs["meterClass"] = func(p int) string {
		switch {
		case p >= 90:
			return "crit"
		case p >= 75:
			return "warn"
		}
		return "ok"
	}
	funcs["healthLabel"] = func(st string) string {
		switch st {
		case monitor.StateUp:
			return "ayakta"
		case monitor.StateDown:
			return "yanıt yok"
		}
		return "bilinmiyor"
	}
}
