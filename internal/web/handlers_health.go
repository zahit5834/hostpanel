package web

import (
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/monitor"
	"github.com/zahit5834/hostpanel/internal/sites"
)

type healthData struct {
	Site      sites.Site
	Check     monitor.Check
	Intervals []int
	Restarts  int
	Error     string
	Notice    string
}

func (s *Server) healthData(r *http.Request, site sites.Site) healthData {
	s.Monitor.Store.Ensure(r.Context(), site)
	c, _ := s.Monitor.Store.Get(r.Context(), site.ID)
	return healthData{Site: site, Check: c, Intervals: monitor.Intervals, Restarts: c.RecentRestarts(s.Monitor.Clock())}
}

func (s *Server) renderHealth(w http.ResponseWriter, r *http.Request, status int, d healthData) {
	s.render(w, r, status, "site", "site-health", Page{Data: d})
}

func (s *Server) siteHealthSave(w http.ResponseWriter, r *http.Request) {
	site, ok := s.loadSite(w, r)
	if !ok {
		return
	}
	d := s.healthData(r, site)
	before := d.Check
	c := before
	c.Enabled = r.PostFormValue("enabled") == "1"
	c.Path = strings.TrimSpace(r.PostFormValue("path"))
	c.Expect, _ = strconv.Atoi(strings.TrimSpace(r.PostFormValue("expect")))
	c.Interval, _ = strconv.Atoi(r.PostFormValue("interval"))
	switch {
	case !monitor.ValidPath(c.Path):
		d.Error = "Geçersiz yol (/ ile başlamalı; boşluk, ?, # içeremez)."
	case c.Expect != 0 && (c.Expect < 100 || c.Expect > 599):
		d.Error = "Beklenen durum kodu 100-599 arasında olmalı (0 = 500'den küçük her kod)."
	case !slices.Contains(monitor.Intervals, c.Interval):
		d.Error = "Geçersiz aralık."
	}
	if d.Error != "" {
		d.Check = c
		s.renderHealth(w, r, http.StatusBadRequest, d)
		return
	}
	err := s.Monitor.Store.SaveSettings(r.Context(), c)
	s.Activity.Record(r.Context(), logs.Entry{Action: "site.health.settings", TargetType: "site", TargetID: site.Domain,
		Summary: "Sağlık kontrolü ayarları kaydedildi", Status: statusOf(err), Error: errText(err),
		Diff: logs.LineDiff(healthText(before), healthText(c))}, nil)
	s.Monitor.Reschedule()
	d = s.healthData(r, site)
	if err != nil {
		d.Error = err.Error()
	} else {
		d.Notice = "Kaydedildi."
	}
	s.renderHealth(w, r, http.StatusOK, d)
}

func healthText(c monitor.Check) string {
	return "enabled=" + strconv.FormatBool(c.Enabled) + "\npath=" + c.Path + "\nexpect=" + strconv.Itoa(c.Expect) +
		"\ninterval=" + strconv.Itoa(c.Interval) + "\n"
}

func (s *Server) siteHealthCheck(w http.ResponseWriter, r *http.Request) {
	site, ok := s.loadSite(w, r)
	if !ok {
		return
	}
	_, err := s.Monitor.CheckNow(r.Context(), site)
	d := s.healthData(r, site)
	if err != nil {
		d.Error = err.Error()
	}
	s.renderHealth(w, r, http.StatusOK, d)
}
