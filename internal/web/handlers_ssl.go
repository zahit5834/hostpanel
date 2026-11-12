package web

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/sites"
	"github.com/zahit5834/hostpanel/internal/ssl"
	"github.com/zahit5834/hostpanel/internal/store"
)

func init() {
	// daysClass colours the days-left figure of a certificate.
	funcs["daysClass"] = func(d int) string {
		switch {
		case d < 7:
			return "failed"
		case d < 30:
			return "canceled"
		}
		return "success"
	}
}

// --- list ---

func (s *Server) sslList(w http.ResponseWriter, r *http.Request) {
	certs, _ := s.SSL.Store.All(r.Context())
	csrs, _ := s.SSL.Store.CSRs(r.Context())
	s.render(w, r, http.StatusOK, "ssl", "layout", Page{Title: "SSL", Nav: "ssl",
		Data: map[string]any{"Certs": certs, "CSRs": csrs}})
}

func (s *Server) loadCert(w http.ResponseWriter, r *http.Request) (ssl.Certificate, bool) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return ssl.Certificate{}, false
	}
	c, err := s.SSL.Store.Get(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return c, false
	}
	return c, true
}

// sslExport sends the certificate + key as a zip (POST: it releases a secret).
func (s *Server) sslExport(w http.ResponseWriter, r *http.Request) {
	c, ok := s.loadCert(w, r)
	if !ok {
		return
	}
	b, err := s.SSL.Export(r.Context(), c)
	s.Activity.Record(r.Context(), logs.Entry{Action: "ssl.export", TargetType: "site", TargetID: c.Domain,
		Summary: "Sertifika ve private key dışa aktarıldı", Status: statusOf(err), Error: errText(err)}, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-ssl-%d.zip"`, c.Domain, c.ID))
	w.Header().Set("Cache-Control", "no-store")
	w.Write(b)
}

func statusOf(err error) string {
	if err != nil {
		return logs.StatusFailed
	}
	return logs.StatusSuccess
}

func errText(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}

// --- CSR ---

type csrFormData struct {
	In       ssl.CSRInput
	SANs     string
	SiteID   int64
	Sites    []sites.Site
	KeyTypes any
}

func (s *Server) csrNew(w http.ResponseWriter, r *http.Request) {
	d := csrFormData{In: ssl.CSRInput{KeyType: ssl.KeyRSA2048, Subject: ssl.Subject{Country: "TR"}}}
	if site, err := s.Sites.Store.Get(r.Context(), parseInt64(r.URL.Query().Get("site"))); err == nil {
		d.SiteID = site.ID
		d.In.CommonName = site.Domain
		d.SANs = strings.Join(ssl.SiteNames(site)[1:], ", ")
	}
	s.renderCSRForm(w, r, http.StatusOK, d, "")
}

func (s *Server) renderCSRForm(w http.ResponseWriter, r *http.Request, status int, d csrFormData, errMsg string) {
	d.Sites, _ = s.Sites.Store.List(r.Context(), 0)
	d.KeyTypes = ssl.KeyTypes
	s.render(w, r, status, "ssl_csr_new", "layout", Page{Title: "CSR oluştur", Nav: "ssl", Data: d, Error: errMsg})
}

func (s *Server) csrCreate(w http.ResponseWriter, r *http.Request) {
	d := csrFormData{
		In: ssl.CSRInput{CommonName: r.PostFormValue("cn"), KeyType: r.PostFormValue("key_type"), Subject: ssl.Subject{
			Country: r.PostFormValue("c"), State: r.PostFormValue("st"), Locality: r.PostFormValue("l"),
			Org: r.PostFormValue("o"), OrgUnit: r.PostFormValue("ou"), Email: r.PostFormValue("email"),
		}},
		SANs:   r.PostFormValue("sans"),
		SiteID: parseInt64(r.PostFormValue("site_id")),
	}
	d.In.SANs = strings.FieldsFunc(d.SANs, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' })
	if d.SiteID != 0 {
		if _, err := s.Sites.Store.Get(r.Context(), d.SiteID); err != nil {
			d.SiteID = 0
		}
	}
	c, err := s.SSL.CreateCSR(r.Context(), d.In, d.SiteID)
	s.Activity.Record(r.Context(), logs.Entry{Action: "ssl.csr", TargetType: "site", TargetID: d.In.CommonName,
		Summary: "CSR oluşturuldu (" + d.In.KeyType + ")", Status: statusOf(err), Error: errText(err)},
		map[string]any{"cn": d.In.CommonName, "sans": d.In.SANs, "key_type": d.In.KeyType})
	if err != nil {
		s.renderCSRForm(w, r, http.StatusBadRequest, d, err.Error())
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/ssl/csr/%d", c.ID), http.StatusSeeOther)
}

func (s *Server) loadCSR(w http.ResponseWriter, r *http.Request) (ssl.CSR, bool) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return ssl.CSR{}, false
	}
	c, err := s.SSL.Store.GetCSR(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return c, false
	}
	return c, true
}

func (s *Server) csrDetail(w http.ResponseWriter, r *http.Request) {
	c, ok := s.loadCSR(w, r)
	if !ok {
		return
	}
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Type", "application/pkcs10")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.csr"`, strings.ReplaceAll(c.CommonName, "*", "wildcard")))
		w.Write([]byte(c.PEM))
		return
	}
	s.render(w, r, http.StatusOK, "ssl_csr", "layout", Page{Title: "CSR · " + c.CommonName, Nav: "ssl", Data: c})
}

func (s *Server) csrDelete(w http.ResponseWriter, r *http.Request) {
	c, ok := s.loadCSR(w, r)
	if !ok {
		return
	}
	if err := s.SSL.Store.DeleteCSR(r.Context(), c.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.Activity.Record(r.Context(), logs.Entry{Action: "ssl.csr.delete", TargetType: "site", TargetID: c.CommonName,
		Summary: "CSR ve private key'i silindi"}, nil)
	http.Redirect(w, r, "/ssl", http.StatusSeeOther)
}

// --- purchased certificate install ---

type installData struct {
	Sites   []sites.Site
	CSRs    []ssl.CSR
	SiteID  int64
	CSRID   int64
	KeyPEM  string
	CertPEM string
	Chain   string
	Report  *ssl.Report
}

func installInput(r *http.Request) (installData, ssl.InstallInput) {
	d := installData{
		SiteID: parseInt64(r.PostFormValue("site_id")), CSRID: parseInt64(r.PostFormValue("csr_id")),
		KeyPEM: r.PostFormValue("key"), CertPEM: r.PostFormValue("cert"), Chain: r.PostFormValue("chain"),
	}
	in := ssl.InstallInput{CertPEM: d.CertPEM, ChainPEM: d.Chain}
	if d.CSRID != 0 {
		in.CSRID = d.CSRID
		d.KeyPEM = "" // never echo a stored key back into the page
	} else {
		in.KeyPEM = d.KeyPEM
	}
	return d, in
}

func (s *Server) renderInstall(w http.ResponseWriter, r *http.Request, status int, d installData, errMsg string) {
	d.Sites, _ = s.Sites.Store.List(r.Context(), 0)
	d.CSRs, _ = s.SSL.Store.CSRs(r.Context())
	d.KeyPEM = "" // pasted keys are not rendered back either; the user re-pastes on error
	s.render(w, r, status, "ssl_install", "layout", Page{Title: "Ücretli sertifika kur", Nav: "ssl", Data: d, Error: errMsg})
}

func (s *Server) sslInstallPage(w http.ResponseWriter, r *http.Request) {
	d := installData{SiteID: parseInt64(r.URL.Query().Get("site")), CSRID: parseInt64(r.URL.Query().Get("csr"))}
	if d.CSRID != 0 && d.SiteID == 0 {
		if c, err := s.SSL.Store.GetCSR(r.Context(), d.CSRID); err == nil {
			d.SiteID = c.SiteID
		}
	}
	s.renderInstall(w, r, http.StatusOK, d, "")
}

func (s *Server) sslVerify(w http.ResponseWriter, r *http.Request) {
	d, in := installInput(r)
	site, err := s.Sites.Store.Get(r.Context(), d.SiteID)
	var rep ssl.Report
	if err != nil {
		rep = ssl.Report{Checks: []ssl.Check{{Level: ssl.LevelErr, Text: "Site seçin"}}}
	} else {
		rep = s.SSL.Verify(r.Context(), site, in)
	}
	d.Report = &rep
	s.render(w, r, http.StatusOK, "ssl_install", "verify-report", Page{Data: d})
}

func (s *Server) sslInstall(w http.ResponseWriter, r *http.Request) {
	d, in := installInput(r)
	site, err := s.Sites.Store.Get(r.Context(), d.SiteID)
	if err != nil {
		s.renderInstall(w, r, http.StatusBadRequest, d, "Site seçin.")
		return
	}
	jobID, rep, err := s.SSL.StartCustom(r.Context(), site, in)
	if err != nil {
		d.Report = &rep
		s.renderInstall(w, r, http.StatusBadRequest, d, "Sertifika kurulamadı: "+err.Error())
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/sites/%d?tab=ssl&job=%d", site.ID, jobID), http.StatusSeeOther)
}

// --- site SSL tab actions ---

type sslCheckData struct {
	Site     sites.Site
	Checks   []ssl.NameCheck
	ServerIP string
	AnyBad   bool
	DNSErr   string // why DNS-01 is unavailable ("" = usable)
}

func (s *Server) siteSSLCheck(w http.ResponseWriter, r *http.Request) {
	site, ok := s.loadSite(w, r)
	if !ok {
		return
	}
	d := sslCheckData{Site: site, Checks: s.SSL.Precheck(r.Context(), site)}
	if err := s.SSL.DNSReady(r.Context(), ssl.SiteNames(site)); err != nil {
		d.DNSErr = err.Error()
	}
	for _, ip := range s.SSL.ServerIPs(r.Context()) {
		if ip.Is4() && !ip.IsPrivate() {
			d.ServerIP = ip.String()
			break
		}
	}
	for _, c := range d.Checks {
		d.AnyBad = d.AnyBad || !c.OK()
	}
	s.render(w, r, http.StatusOK, "site", "ssl-check", Page{Data: d})
}

func (s *Server) siteSSLLetsEncrypt(w http.ResponseWriter, r *http.Request) {
	site, ok := s.loadSite(w, r)
	if !ok {
		return
	}
	r.ParseForm()
	jobID, err := s.SSL.StartLE(r.Context(), site, ssl.LEInput{Names: r.PostForm["names"], Email: r.PostFormValue("email"),
		Staging: r.PostFormValue("staging") == "1", Method: r.PostFormValue("method")})
	if err != nil {
		s.renderSite(w, r, http.StatusBadRequest, site, "ssl", err.Error(), "")
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/sites/%d?tab=ssl&job=%d", site.ID, jobID), http.StatusSeeOther)
}

func (s *Server) siteSSLRenew(w http.ResponseWriter, r *http.Request) {
	site, ok := s.loadSite(w, r)
	if !ok {
		return
	}
	c, err := s.SSL.Store.Active(r.Context(), site.ID)
	if err != nil {
		s.renderSite(w, r, http.StatusBadRequest, site, "ssl", "Etkin sertifika yok.", "")
		return
	}
	jobID, err := s.SSL.StartRenew(r.Context(), c, r.PostFormValue("force") == "1")
	if err != nil {
		s.renderSite(w, r, http.StatusBadRequest, site, "ssl", err.Error(), "")
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/sites/%d?tab=ssl&job=%d", site.ID, jobID), http.StatusSeeOther)
}

func (s *Server) siteSSLRemove(w http.ResponseWriter, r *http.Request) {
	site, ok := s.loadSite(w, r)
	if !ok {
		return
	}
	jobID, err := s.SSL.StartRemove(r.Context(), site)
	if err != nil {
		s.renderSite(w, r, http.StatusBadRequest, site, "ssl", err.Error(), "")
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/sites/%d?tab=ssl&job=%d", site.ID, jobID), http.StatusSeeOther)
}

// sslTabData fills the SSL tab of the site page.
func (s *Server) sslTabData(r *http.Request, d *siteData) {
	if c, err := s.SSL.Store.Active(r.Context(), d.Site.ID); err == nil {
		d.Cert = &c
	} else if !errors.Is(err, sql.ErrNoRows) {
		s.Log.Warn("ssl active", "err", err)
	}
	d.CertHistory, _ = s.SSL.Store.ForSite(r.Context(), d.Site.ID)
	if s.DNS != nil {
		if zn := s.DNS.ZoneCovering(r.Context(), d.Site.Domain); zn != "" {
			if z, err := s.DNS.Store.ZoneByName(r.Context(), zn); err == nil {
				d.DNSZone = &z
			}
		}
	}
	d.ACMEEmail = store.GetSetting(r.Context(), s.DB, ssl.SettingACMEEmail, "")
}

// --- general settings ---

func (s *Server) generalPage(w http.ResponseWriter, r *http.Request) {
	s.renderGeneral(w, r, http.StatusOK, "", "")
}

func (s *Server) renderGeneral(w http.ResponseWriter, r *http.Request, status int, errMsg, notice string) {
	var local []string
	for _, ip := range ssl.LocalIPs() {
		local = append(local, ip.String())
	}
	s.render(w, r, status, "settings_general", "layout", Page{Title: "Genel ayarlar", Nav: "settings", Error: errMsg, Notice: notice,
		Data: map[string]any{
			"Email":    store.GetSetting(r.Context(), s.DB, ssl.SettingACMEEmail, ""),
			"IPs":      store.GetSetting(r.Context(), s.DB, ssl.SettingServerIPs, ""),
			"LocalIPs": strings.Join(local, ", "),
			"Defaults": s.panelDefaults(r.Context()),
		}})
}

func (s *Server) saveGeneral(w http.ResponseWriter, r *http.Request) {
	email := strings.TrimSpace(r.PostFormValue("acme_email"))
	if email != "" && !ssl.ValidEmail(email) {
		s.renderGeneral(w, r, http.StatusBadRequest, "Geçersiz e-posta adresi.", "")
		return
	}
	ips, err := ssl.ParseIPList(r.PostFormValue("server_ips"))
	if err != nil {
		s.renderGeneral(w, r, http.StatusBadRequest, err.Error(), "")
		return
	}
	cur := s.panelDefaults(r.Context())
	def := panelDefaults{
		ActivityDays: formInt(r, setRetentionActivity, cur.ActivityDays), JobDays: formInt(r, setRetentionJobs, cur.JobDays),
		MemoryMB: formInt(r, setDefaultMemory, cur.MemoryMB), CPUPct: formInt(r, setDefaultCPU, cur.CPUPct)}
	if err := def.validate(); err != nil {
		s.renderGeneral(w, r, http.StatusBadRequest, err.Error(), "")
		return
	}
	def.save(r.Context(), s.DB)
	store.SetSetting(r.Context(), s.DB, ssl.SettingACMEEmail, email)
	store.SetSetting(r.Context(), s.DB, ssl.SettingServerIPs, ips)
	s.Activity.Record(r.Context(), logs.Entry{Action: "settings.update", Summary: "Genel ayarlar güncellendi"},
		map[string]any{"acme_email": email, "server_ips": ips, "retention_activity_days": def.ActivityDays,
			"retention_job_days": def.JobDays, "default_memory_mb": def.MemoryMB, "default_cpu_pct": def.CPUPct})
	s.renderGeneral(w, r, http.StatusOK, "", "Kaydedildi.")
}
