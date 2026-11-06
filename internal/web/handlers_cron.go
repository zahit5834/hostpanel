package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"hostpanel/internal/crons"
	"hostpanel/internal/sites"
)

// Schedule presets offered in the cron form (datalist).
var cronPresets = []struct{ Expr, Label string }{
	{"* * * * *", "Her dakika"},
	{"*/5 * * * *", "5 dakikada bir"},
	{"*/15 * * * *", "15 dakikada bir"},
	{"0 * * * *", "Her saat başı"},
	{"0 3 * * *", "Her gün 03:00"},
	{"0 4 * * 0", "Her Pazar 04:00"},
	{"0 5 1 * *", "Her ayın 1'i 05:00"},
}

func init() {
	funcs["int64"] = func(n int) int64 { return int64(n) }
	funcs["cronStatus"] = func(st string) string {
		return map[string]string{crons.StatusOK: "Başarılı", crons.StatusFailed: "Başarısız", crons.StatusTimeout: "Zaman aşımı",
			crons.StatusSkipped: "Atlandı", "": "Hiç çalışmadı"}[st]
	}
	funcs["cronClass"] = func(st string) string {
		switch st {
		case crons.StatusOK:
			return "success"
		case crons.StatusFailed, crons.StatusTimeout:
			return "failed"
		}
		return ""
	}
}

// cronTabData fills the site Cron tab.
func (s *Server) cronTabData(r *http.Request, d *siteData) {
	ctx := r.Context()
	d.Crons, _ = s.Crons.Store.BySite(ctx, d.Site.ID)
	d.CronRunning = map[int64]bool{}
	for _, c := range d.Crons {
		d.CronRunning[c.ID] = s.Crons.Running(c.ID)
	}
	d.CronRuns, _ = s.Crons.Store.Runs(ctx, crons.RunFilter{SiteID: d.Site.ID, Limit: 20})
	d.CronPresets = cronPresets
	if d.CronEdit.ID == 0 && d.CronEdit.Name == "" {
		d.CronEdit = crons.Cron{Enabled: true, TimeoutSec: crons.DefaultTimeout, Schedule: "*/5 * * * *"}
		if id := parseInt64(r.URL.Query().Get("edit")); id > 0 {
			for _, c := range d.Crons {
				if c.ID == id {
					d.CronEdit = c
				}
			}
		}
	}
	d.CronEligible = crons.Eligible(d.Site, d.Active)
}

func (s *Server) siteCronSave(w http.ResponseWriter, r *http.Request) {
	site, ok := s.loadSite(w, r)
	if !ok {
		return
	}
	c := crons.Cron{ID: parseInt64(r.PostFormValue("cron_id")), Name: r.PostFormValue("name"),
		Schedule: r.PostFormValue("schedule"), Command: strings.TrimSpace(r.PostFormValue("command")),
		TimeoutSec: formInt(r, "timeout_sec", crons.DefaultTimeout), Enabled: r.PostFormValue("enabled") == "1"}
	if _, err := s.Crons.Save(r.Context(), site, c); err != nil {
		s.renderSiteWith(w, r, http.StatusBadRequest, site, "cron", err.Error(), func(d *siteData) { d.CronEdit = c })
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/sites/%d?tab=cron", site.ID), http.StatusSeeOther)
}

func (s *Server) siteCronDelete(w http.ResponseWriter, r *http.Request) {
	site, ok := s.loadSite(w, r)
	if !ok {
		return
	}
	if err := s.Crons.Delete(r.Context(), site, parseInt64(r.PathValue("cid"))); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/sites/%d?tab=cron", site.ID), http.StatusSeeOther)
}

func (s *Server) siteCronRun(w http.ResponseWriter, r *http.Request) {
	site, ok := s.loadSite(w, r)
	if !ok {
		return
	}
	base := s.BaseCtx
	if base == nil {
		base = r.Context()
	}
	if err := s.Crons.RunNow(r.Context(), base, site, parseInt64(r.PathValue("cid"))); err != nil {
		s.renderSite(w, r, http.StatusBadRequest, site, "cron", err.Error(), "")
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/sites/%d?tab=cron&started=1", site.ID), http.StatusSeeOther)
}

// --- Log Merkezi → Cron çalışmaları ---

type cronLogData struct {
	Runs     []crons.Run
	Sites    []sites.Site
	SiteID   int64
	Status   string
	Since    string
	Until    string
	Statuses []string
}

func parseLocalTime(v string) time.Time {
	t, err := time.ParseInLocation("2006-01-02T15:04", v, time.Local)
	if err != nil {
		return time.Time{}
	}
	return t
}

func (s *Server) cronLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	d := cronLogData{SiteID: parseInt64(q.Get("site")), Status: q.Get("status"), Since: q.Get("since"), Until: q.Get("until"),
		Statuses: []string{crons.StatusOK, crons.StatusFailed, crons.StatusSkipped}}
	if d.Status != "" && d.Status != crons.StatusOK && d.Status != crons.StatusFailed && d.Status != crons.StatusSkipped {
		d.Status = ""
	}
	limit, _ := strconv.Atoi(q.Get("n"))
	if limit != 200 && limit != 500 {
		limit = 100
	}
	d.Runs, _ = s.Crons.Store.Runs(r.Context(), crons.RunFilter{SiteID: d.SiteID, Status: d.Status,
		Since: parseLocalTime(d.Since), Until: parseLocalTime(d.Until), Limit: limit})
	d.Sites, _ = s.Sites.Store.List(r.Context(), 0)
	s.render(w, r, http.StatusOK, "logs_cron", "layout", Page{Title: "Cron çalışmaları", Nav: "logs", Data: d})
}
