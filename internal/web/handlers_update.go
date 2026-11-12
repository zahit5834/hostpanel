package web

import (
	"bytes"
	"fmt"
	"github.com/zahit5834/hostpanel/internal/images"
	"net/http"
	"strconv"
	"time"

	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/panelcfg"
	"github.com/zahit5834/hostpanel/internal/store"
	"github.com/zahit5834/hostpanel/internal/update"
)

// --- Ayarlar → Güncelleme ---

type updateData struct {
	update.Info
	Started bool // just started: poll the status block
	Images  []images.Info
}

func (s *Server) updateData(r *http.Request, refresh bool) updateData {
	d := updateData{Info: s.Update.Info(r.Context(), refresh)}
	if s.Images != nil {
		d.Images = s.Images.Infos(r.Context())
	}
	d.Started = r.URL.Query().Get("started") == "1"
	return d
}

func (s *Server) updatePage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "settings_update", "layout", Page{Title: "Güncelleme", Nav: "settings", Data: s.updateData(r, true)})
}

func (s *Server) updateCheck(w http.ResponseWriter, r *http.Request) {
	if _, err := s.Update.Check(r.Context()); err != nil {
		s.render(w, r, http.StatusOK, "settings_update", "layout", Page{Title: "Güncelleme", Nav: "settings",
			Error: "Sürüm kontrolü başarısız: " + err.Error(), Data: s.updateData(r, false)})
		return
	}
	http.Redirect(w, r, "/settings/update", http.StatusSeeOther)
}

func (s *Server) updateStart(w http.ResponseWriter, r *http.Request) {
	if err := s.Update.Start(r.Context(), r.PostFormValue("version")); err != nil {
		s.render(w, r, http.StatusBadRequest, "settings_update", "layout", Page{Title: "Güncelleme", Nav: "settings",
			Error: err.Error(), Data: s.updateData(r, false)})
		return
	}
	http.Redirect(w, r, "/settings/update?started=1", http.StatusSeeOther)
}

// updateStatus is polled by the update page while an update runs. During the
// restart the request fails (nginx 502) and HTMX simply polls again.
func (s *Server) updateStatus(w http.ResponseWriter, r *http.Request) {
	d := s.updateData(r, false)
	d.Started = r.URL.Query().Get("started") == "1" && !d.Status.Done()
	s.render(w, r, http.StatusOK, "settings_update", "update-status", Page{Data: d})
}

// --- Ayarlar → Taşıma (panel yapılandırması) ---

func (s *Server) transferPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "settings_transfer", "layout", Page{Title: "Taşıma", Nav: "settings",
		Data: map[string]any{"Min": panelcfg.MinPassphrase}})
}

func (s *Server) transferExport(w http.ResponseWriter, r *http.Request) {
	fail := func(msg string) {
		s.render(w, r, http.StatusBadRequest, "settings_transfer", "layout", Page{Title: "Taşıma", Nav: "settings", Error: msg,
			Data: map[string]any{"Min": panelcfg.MinPassphrase}})
	}
	pass, again := r.PostFormValue("passphrase"), r.PostFormValue("passphrase2")
	if pass != again {
		fail("Parolalar aynı değil.")
		return
	}
	if len([]rune(pass)) < panelcfg.MinPassphrase {
		fail(fmt.Sprintf("Parola en az %d karakter olmalı.", panelcfg.MinPassphrase))
		return
	}
	var buf bytes.Buffer
	man, err := s.ExportConfig(r.Context(), pass, &buf)
	if err != nil {
		fail("Dışa aktarma başarısız: " + err.Error())
		return
	}
	s.Activity.Record(r.Context(), logs.Entry{Action: "panel.export", TargetType: "panel",
		Summary: fmt.Sprintf("Panel yapılandırması dışa aktarıldı (%d müşteri, %d plan)", man.Customers, man.Plans)},
		map[string]any{"customers": man.Customers, "plans": man.Plans, "runtimes": man.Runtimes, "bytes": buf.Len()})
	store.SetSetting(r.Context(), s.DB, setTransferExported, strconv.FormatInt(time.Now().Unix(), 10)) // security audit
	name := fmt.Sprintf("hostpanel-config-%s-%s.hpcfg", safeFileName(man.Server), time.Now().Format("20060102-1504"))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Content-Length", strconv.Itoa(buf.Len()))
	w.Header().Set("Cache-Control", "no-store")
	w.Write(buf.Bytes())
}

// safeFileName keeps [A-Za-z0-9._-] for a download name.
func safeFileName(s string) string {
	b := []byte(s)
	out := b[:0]
	for _, c := range b {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_' {
			out = append(out, c)
		}
	}
	if len(out) == 0 || len(out) > 60 {
		return "panel"
	}
	return string(out)
}
