package web

import (
	"fmt"
	"net/http"
	"runtime"
	"sort"
	"time"

	"hostpanel/internal/logs"
	"hostpanel/internal/ssl"
	"hostpanel/internal/system"
)

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	snap := system.Read()
	snap.Goroutines = runtime.NumGoroutine()
	recent, _ := s.Activity.Query(r.Context(), logs.Filter{Limit: 10})
	data := map[string]any{"Sys": snap, "Recent": recent}
	if s.SSL != nil {
		var expiring []*ssl.Certificate
		for _, c := range s.SSL.ActiveBySite(r.Context()) {
			if c.DaysLeft() < 15 {
				expiring = append(expiring, c)
			}
		}
		sort.Slice(expiring, func(i, j int) bool { return expiring[i].NotAfter.Before(expiring[j].NotAfter) })
		data["Expiring"] = expiring
	}
	block := "layout"
	// The metrics card polls only while the page is open (hx-trigger="every 5s");
	// nothing is collected when no browser is looking.
	if isHX(r) && r.URL.Query().Get("part") == "metrics" {
		block = "metrics"
	}
	s.render(w, r, http.StatusOK, "dashboard", block, Page{Title: "Genel Bakış", Nav: "dashboard", Data: data})
}

func init() {
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
}
