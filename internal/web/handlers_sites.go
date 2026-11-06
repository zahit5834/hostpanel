package web

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zahit5834/hostpanel/internal/backups"
	"github.com/zahit5834/hostpanel/internal/crons"
	"github.com/zahit5834/hostpanel/internal/customers"
	"github.com/zahit5834/hostpanel/internal/databases"
	"github.com/zahit5834/hostpanel/internal/exec"
	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/runtimes"
	"github.com/zahit5834/hostpanel/internal/sites"
	"github.com/zahit5834/hostpanel/internal/ssl"
)

// MaxUploadBytes caps a deploy zip.
const MaxUploadBytes = 1 << 30

func (s *Server) siteList(w http.ResponseWriter, r *http.Request) {
	list, err := s.Sites.Store.List(r.Context(), 0)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.render(w, r, http.StatusOK, "sites", "layout", Page{Title: "Siteler", Nav: "sites", Data: map[string]any{"List": list, "Certs": s.SSL.ActiveBySite(r.Context())}})
}

type runtimeOption struct {
	ID, Name, Type string
}

func (s *Server) runtimeOptions() []runtimeOption {
	var out []runtimeOption
	for _, p := range s.Runtimes.All() {
		d := p.Def()
		out = append(out, runtimeOption{ID: d.ID, Name: d.DisplayName, Type: d.Type})
	}
	return out
}

type wizardData struct {
	Customers []customers.Customer
	Runtimes  []runtimeOption
	In        sites.CreateInput
	Fields    *runtimeFieldsData // preloaded when re-rendering after an error

	DBAvailable bool // MSSQL running: offer "create a database"
	CreateDB    bool
	Import      bool // "Mevcut siteyi taşı": continue on the Taşıma tab
}

func (s *Server) siteNew(w http.ResponseWriter, r *http.Request) {
	def := s.panelDefaults(r.Context())
	s.renderWizard(w, r, http.StatusOK, sites.CreateInput{
		CustomerID: parseInt64(r.URL.Query().Get("customer")), MemoryMaxMB: def.MemoryMB, CPUQuotaPct: def.CPUPct, WWWMode: sites.WWWNone,
	}, "")
}

func (s *Server) renderWizard(w http.ResponseWriter, r *http.Request, status int, in sites.CreateInput, errMsg string) {
	cs, _ := s.Customers.List(r.Context(), "")
	d := wizardData{Customers: cs, Runtimes: s.runtimeOptions(), In: in,
		DBAvailable: s.DBs.Available(r.Context()), CreateDB: r.PostFormValue("create_db") == "1",
		Import: r.FormValue("import") == "1"}
	if p, ok := s.Runtimes.Get(in.RuntimeID); ok {
		f := s.runtimeFieldsData(r, p, in.RuntimeVersion, in.Fields)
		d.Fields = &f
	}
	s.render(w, r, status, "site_new", "layout", Page{Title: "Yeni site", Nav: "sites", Error: errMsg, Data: d})
}

// siteRuntimeFields renders the runtime-specific part of the wizard/settings (HTMX).
func (s *Server) siteRuntimeFields(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("runtime")
	p, ok := s.Runtimes.Get(id)
	if !ok {
		w.Write([]byte(`<p class="muted">Bir altyapı seçin.</p>`))
		return
	}
	s.render(w, r, http.StatusOK, "site_new", "runtime-fields", Page{Data: s.runtimeFieldsData(r, p, r.URL.Query().Get("version"), nil)})
}

type runtimeFieldsData struct {
	Def       *runtimes.Definition
	Installed []string
	Version   string
	Values    map[string]string
}

func (s *Server) runtimeFieldsData(r *http.Request, p runtimes.Provider, version string, values map[string]string) runtimeFieldsData {
	installed, _ := p.InstalledVersions(r.Context())
	if values == nil {
		values = map[string]string{}
	}
	return runtimeFieldsData{Def: p.Def(), Installed: installed, Version: version, Values: values}
}

func fieldValues(r *http.Request) map[string]string {
	out := map[string]string{}
	for k, v := range r.PostForm {
		if strings.HasPrefix(k, "field_") && len(v) > 0 {
			out[strings.TrimPrefix(k, "field_")] = v[0]
		}
	}
	return out
}

func parseInt64(s string) int64 {
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}

func formInt(r *http.Request, key string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue(key)))
	if err != nil {
		return def
	}
	return n
}

func (s *Server) siteCreate(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	in := sites.CreateInput{
		CustomerID:     parseInt64(r.PostFormValue("customer_id")),
		Domain:         r.PostFormValue("domain"),
		Aliases:        r.PostFormValue("aliases"),
		WWWMode:        r.PostFormValue("www_mode"),
		RuntimeID:      r.PostFormValue("runtime"),
		RuntimeVersion: r.PostFormValue("version"),
		Fields:         fieldValues(r),
		MemoryMaxMB:    formInt(r, "memory_max_mb", 512),
		CPUQuotaPct:    formInt(r, "cpu_quota_pct", 100),
		PersistentDirs: r.PostFormValue("persistent_dirs"),
	}
	site, jobID, err := s.Sites.Create(r.Context(), in)
	if err != nil {
		s.Activity.Record(r.Context(), logs.Entry{Action: "site.create", TargetType: "site", TargetID: sites.NormalizeDomain(in.Domain),
			Status: logs.StatusFailed, Error: err.Error(), Summary: "Site oluşturulamadı"}, nil)
		s.renderWizard(w, r, http.StatusBadRequest, in, err.Error())
		return
	}
	if r.PostFormValue("create_db") == "1" {
		s.wizardDatabase(r, site)
	}
	tab := ""
	if r.PostFormValue("import") == "1" {
		tab = "&tab=import"
	}
	http.Redirect(w, r, fmt.Sprintf("/sites/%d?job=%d%s", site.ID, jobID, tab), http.StatusSeeOther)
}

// wizardDatabase queues a database for a new site (named after its short
// name) and, for proxy runtimes, writes the connection string into its env.
// The db.create job runs after site.create (one worker; the env write also
// waits for the site lock). Failures are logged; the site is already created.
func (s *Server) wizardDatabase(r *http.Request, site sites.Site) {
	base := databases.DBBase(site.ShortName)
	name := base
	for i := 2; s.DBs.Store.DBNameTaken(r.Context(), name); i++ {
		name = base + "_" + strconv.Itoa(i)
	}
	p, ok := s.Runtimes.Get(site.RuntimeID)
	in := databases.CreateInput{CustomerID: site.CustomerID, Name: name, SiteID: site.ID,
		WriteEnv: ok && p.Def().HasUnit()}
	if _, _, err := s.DBs.StartCreate(r.Context(), in); err != nil {
		s.Activity.Record(r.Context(), logs.Entry{Action: "db.create", TargetType: "database", TargetID: name,
			Status: logs.StatusFailed, Error: err.Error(), Summary: "Site için veritabanı oluşturulamadı: " + site.Domain}, nil)
	}
}

func (s *Server) loadSite(w http.ResponseWriter, r *http.Request) (sites.Site, bool) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return sites.Site{}, false
	}
	site, err := s.Sites.Store.Get(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return site, false
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return site, false
	}
	return site, true
}

type siteData struct {
	Site       sites.Site
	Def        *runtimes.Definition
	Tab        string
	Unit       string // systemctl is-active result
	Releases   []sites.Release
	Active     string
	Env        []envRow
	Nginx      string
	Runtime    runtimeFieldsData
	JobID      int64
	LogSource  string
	LogN       int
	LogLines   []string
	LogEntries []logs.Entry
	DryRun     bool

	Cert        *ssl.Certificate
	CertHistory []ssl.Certificate
	ACMEEmail   string

	DBs         []databases.Database
	DBAvailable bool
	Health      healthData

	Backups    []backups.Backup
	Remote     backups.RemoteSettings
	Components []string
	ServerIPs  []string
	EnvKeyHint string
	DBNameHint string
	MaxBakMB   int64

	Crons        []crons.Cron
	CronRuns     []crons.Run
	CronEdit     crons.Cron
	CronRunning  map[int64]bool
	CronPresets  []struct{ Expr, Label string }
	CronEligible bool

	Git         sites.GitSettings
	GitSet      bool
	GitInfo     sites.GitInfo
	GitDefaults sites.GitSettings
}

type envRow struct{ Key, Value string }

var siteTabs = map[string]bool{"overview": true, "deploy": true, "env": true, "ssl": true, "settings": true, "logs": true,
	"backups": true, "import": true, "cron": true}

func (s *Server) siteDetail(w http.ResponseWriter, r *http.Request) {
	site, ok := s.loadSite(w, r)
	if !ok {
		return
	}
	tab := r.URL.Query().Get("tab")
	if !siteTabs[tab] {
		tab = "overview"
	}
	notice := ""
	if tab == "cron" && r.URL.Query().Get("started") == "1" {
		notice = "Cron başlatıldı; sonucu “Son çalışmalar” listesinde görünür (sayfayı yenileyin)."
	}
	s.renderSite(w, r, http.StatusOK, site, tab, "", notice)
}

func (s *Server) renderSite(w http.ResponseWriter, r *http.Request, status int, site sites.Site, tab, errMsg, notice string) {
	s.renderSiteWith(w, r, status, site, tab, errMsg, nil, notice)
}

// renderSiteWith lets a failed form keep its values (pre fills siteData
// before the tab data is loaded).
func (s *Server) renderSiteWith(w http.ResponseWriter, r *http.Request, status int, site sites.Site, tab, errMsg string, pre func(*siteData), notice ...string) {
	ctx := r.Context()
	p, ok := s.Runtimes.Get(site.RuntimeID)
	d := siteData{Site: site, Tab: tab, JobID: parseInt64(r.URL.Query().Get("job")), DryRun: s.Cfg.DryRun}
	if ok {
		d.Def = p.Def()
	} else {
		d.Def = &runtimes.Definition{ID: site.RuntimeID, DisplayName: site.RuntimeID + " (tanım yok)"}
	}
	if d.Def.HasUnit() {
		res, _ := s.Sites.Probe.Run(ctx, exec.Cmd{Name: "systemctl", Args: []string{"is-active", site.Unit() + ".service"}, Timeout: 5 * time.Second})
		d.Unit = strings.TrimSpace(res.Stdout)
	}
	d.Releases, _ = s.Sites.Store.Releases(ctx, site.ID)
	d.Active = s.Sites.Store.ActiveRelease(ctx, site.ID)
	d.DBs, _ = s.DBs.Store.Databases(ctx, databases.DBFilter{SiteID: site.ID})
	d.DBAvailable = s.DBs.Available(ctx)
	if pre != nil {
		pre(&d)
	}
	switch tab {
	case "cron":
		s.cronTabData(r, &d)
	case "deploy":
		s.gitTabData(r, &d)
	case "overview":
		d.Health = s.healthData(r, site)
	case "ssl":
		s.sslTabData(r, &d)
	case "backups", "import":
		s.siteBackupData(r, &d)
	case "env":
		env, err := s.Sites.Env(ctx, site.ID)
		if err != nil {
			errMsg = err.Error()
		}
		keys := make([]string, 0, len(env))
		for k := range env {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			d.Env = append(d.Env, envRow{k, env[k]})
		}
	case "settings":
		d.Nginx, _ = s.Sites.RenderNginxFor(site)
		s.sslTabData(r, &d)
		if ok {
			d.Runtime = s.runtimeFieldsData(r, p, site.RuntimeVersion, site.Fields)
		}
	case "logs":
		q := r.URL.Query()
		d.LogSource = q.Get("source")
		d.LogN, _ = strconv.Atoi(q.Get("n"))
		if d.LogN != 500 && d.LogN != 1000 {
			d.LogN = 100
		}
		switch d.LogSource {
		case "journal":
			d.LogLines = s.Sites.JournalTail(ctx, site, d.LogN)
		case "access", "error":
			lines, err := logs.TailLines(sites.NginxLogPath(site, d.LogSource), d.LogN)
			if err != nil {
				lines = []string{"(log okunamadı: " + err.Error() + ")"}
			}
			d.LogLines = lines
		default:
			d.LogSource = "activity"
			d.LogEntries, _ = s.Activity.Query(ctx, logs.Filter{TargetID: site.Domain, Limit: d.LogN})
		}
		if isHX(r) && r.URL.Query().Get("part") == "logs" {
			s.render(w, r, status, "site", "site-logs", Page{Data: d})
			return
		}
	}
	s.render(w, r, status, "site", "layout", Page{Title: site.Domain, Nav: "sites", Data: d, Error: errMsg, Notice: strings.Join(notice, "")})
}

var opLabels = map[string]string{
	sites.OpStart: "başlatıldı", sites.OpStop: "durduruldu", sites.OpRestart: "yeniden başlatıldı",
	sites.OpMaintenanceOn: "bakım modu açıldı", sites.OpMaintenanceOff: "bakım modu kapatıldı",
	sites.OpDisable: "devre dışı bırakıldı", sites.OpEnable: "etkinleştirildi",
	sites.OpReapplyNginx: "nginx yapılandırması yeniden uygulandı", sites.OpReinstallService: "servis yeniden oluşturuldu",
}

func (s *Server) siteOperate(w http.ResponseWriter, r *http.Request) {
	site, ok := s.loadSite(w, r)
	if !ok {
		return
	}
	op := r.PathValue("op")
	label, known := opLabels[op]
	if !known {
		http.NotFound(w, r)
		return
	}
	act := s.Activity.Begin(r.Context(), logs.Entry{Action: "site." + op, TargetType: "site", TargetID: site.Domain,
		Summary: site.Domain + " " + label}, nil)
	status, err := s.Sites.Operate(r.Context(), site, op)
	act.Finish(err)
	site.Status = status
	if err != nil {
		s.renderSite(w, r, http.StatusBadRequest, site, "overview", "İşlem başarısız: "+err.Error(), "")
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/sites/%d", site.ID), http.StatusSeeOther)
}

// siteUpload streams a multipart zip upload straight to disk and starts the deploy job.
func (s *Server) siteUpload(w http.ResponseWriter, r *http.Request) {
	site, ok := s.loadSite(w, r)
	if !ok {
		return
	}
	// Large uploads over slow links outlive the server's 60 s ReadTimeout.
	rc := http.NewResponseController(w)
	rc.SetReadDeadline(time.Now().Add(time.Hour))
	r.Body = http.MaxBytesReader(w, r.Body, MaxUploadBytes+1<<20)
	mr, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "multipart form bekleniyor", http.StatusBadRequest)
		return
	}
	var name string
	var size int64
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, "yükleme okunamadı: "+err.Error(), http.StatusBadRequest)
			return
		}
		if part.FormName() != "zip" {
			part.Close()
			continue
		}
		if _, params, _ := mime.ParseMediaType(part.Header.Get("Content-Disposition")); !strings.HasSuffix(strings.ToLower(params["filename"]), ".zip") {
			http.Error(w, "yalnızca .zip dosyası yüklenebilir", http.StatusBadRequest)
			return
		}
		name, size, err = s.Sites.SaveUpload(part, MaxUploadBytes)
		part.Close()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		break
	}
	if name == "" {
		http.Error(w, "zip dosyası seçilmedi", http.StatusBadRequest)
		return
	}
	jobID, err := s.Sites.StartDeploy(r.Context(), site, name, size, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("HX-Redirect", fmt.Sprintf("/sites/%d?tab=deploy&job=%d", site.ID, jobID))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) siteRollback(w http.ResponseWriter, r *http.Request) {
	site, ok := s.loadSite(w, r)
	if !ok {
		return
	}
	rel := r.PostFormValue("release")
	found := false
	rels, _ := s.Sites.Store.Releases(r.Context(), site.ID)
	for _, x := range rels {
		if x.Name == rel && x.Status != sites.ReleasePruned && x.Status != sites.ReleaseActive {
			found = true
		}
	}
	if !found {
		http.Error(w, "sürüm bulunamadı veya zaten aktif", http.StatusBadRequest)
		return
	}
	jobID, err := s.Sites.StartDeploy(r.Context(), site, "", 0, rel)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/sites/%d?tab=deploy&job=%d", site.ID, jobID), http.StatusSeeOther)
}

func (s *Server) siteSaveEnv(w http.ResponseWriter, r *http.Request) {
	site, ok := s.loadSite(w, r)
	if !ok {
		return
	}
	r.ParseForm()
	keys, vals := r.PostForm["key"], r.PostForm["value"]
	values := map[string]string{}
	for i, k := range keys {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		v := ""
		if i < len(vals) {
			v = vals[i]
		}
		if _, dup := values[k]; dup {
			s.renderSite(w, r, http.StatusBadRequest, site, "env", "Aynı değişken iki kez girildi: "+k, "")
			return
		}
		values[k] = v
	}
	// Bulk paste: KEY=VALUE per line.
	for _, line := range strings.Split(r.PostFormValue("bulk"), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			s.renderSite(w, r, http.StatusBadRequest, site, "env", "Toplu girişte geçersiz satır: "+line, "")
			return
		}
		values[strings.TrimSpace(k)] = v
	}
	op := s.Activity.Begin(r.Context(), logs.Entry{Action: "site.env.update", TargetType: "site", TargetID: site.Domain,
		Summary: "Ortam değişkenleri güncellendi"}, nil)
	diff, err := s.Sites.SaveEnv(r.Context(), site, values)
	op.Finish(err)
	if err != nil {
		s.renderSite(w, r, http.StatusBadRequest, site, "env", err.Error(), "")
		return
	}
	s.setActivityDiff(op.ID(), diff)
	notice := "Kaydedildi."
	if site.Status == sites.StatusRunning {
		notice += " Değişikliklerin geçerli olması için siteyi yeniden başlatın."
	}
	s.renderSite(w, r, http.StatusOK, site, "env", "", notice)
}

func (s *Server) setActivityDiff(id int64, diff string) {
	if diff != "" {
		s.DB.Exec(`UPDATE activity_log SET diff=? WHERE id=?`, diff, id)
	}
}

func (s *Server) siteSaveSettings(w http.ResponseWriter, r *http.Request) {
	site, ok := s.loadSite(w, r)
	if !ok {
		return
	}
	r.ParseForm()
	in := sites.SettingsInput{
		Aliases:        r.PostFormValue("aliases"),
		WWWMode:        r.PostFormValue("www_mode"),
		RuntimeVersion: r.PostFormValue("version"),
		Fields:         fieldValues(r),
		MemoryMaxMB:    formInt(r, "memory_max_mb", site.MemoryMaxMB),
		CPUQuotaPct:    formInt(r, "cpu_quota_pct", site.CPUQuotaPct),
		PersistentDirs: r.PostFormValue("persistent_dirs"),
		HealthPath:     strings.TrimSpace(r.PostFormValue("health_path")),
		MaxUploadMB:    formInt(r, "max_upload_mb", site.MaxUploadMB),
		Gzip:           r.PostFormValue("gzip") == "1",
		HSTS:           r.PostFormValue("hsts") == "1",
		ForceHTTPS:     r.PostFormValue("force_https") == "1",
		CustomSnippet:  r.PostFormValue("custom_snippet"),
	}
	if in.RuntimeVersion == "" {
		in.RuntimeVersion = site.RuntimeVersion
	}
	op := s.Activity.Begin(r.Context(), logs.Entry{Action: "site.settings.update", TargetType: "site", TargetID: site.Domain,
		Summary: "Site ayarları güncellendi"}, map[string]any{"memory_max_mb": in.MemoryMaxMB, "cpu_quota_pct": in.CPUQuotaPct,
		"max_upload_mb": in.MaxUploadMB, "www_mode": in.WWWMode, "aliases": in.Aliases})
	res, err := s.Sites.UpdateSettings(r.Context(), site, in)
	op.Finish(err)
	if err != nil {
		s.renderSite(w, r, http.StatusBadRequest, site, "settings", err.Error(), "")
		return
	}
	s.setActivityDiff(op.ID(), res.NginxDiff)
	site, _ = s.Sites.Store.Get(r.Context(), site.ID)
	notice := "Ayarlar kaydedildi."
	if res.NginxDiff != "" {
		notice += " nginx yapılandırması güncellendi."
	}
	if res.RestartAdvised {
		notice += " Servis ayarları değişti; geçerli olması için siteyi yeniden başlatın."
	}
	s.renderSite(w, r, http.StatusOK, site, "settings", "", notice)
}

func (s *Server) siteDelete(w http.ResponseWriter, r *http.Request) {
	site, ok := s.loadSite(w, r)
	if !ok {
		return
	}
	if strings.TrimSpace(strings.ToLower(r.PostFormValue("confirm"))) != site.Domain {
		s.renderSite(w, r, http.StatusBadRequest, site, "overview", "Onay için domain adını tam olarak yazın.", "")
		return
	}
	jobID, err := s.Sites.StartDelete(r.Context(), site, r.PostFormValue("drop_dbs") == "1")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/logs/jobs/%d", jobID), http.StatusSeeOther)
}

// --- runtimes page ---

type runtimeRow struct {
	Def         *runtimes.Definition
	Installed   []installedVersion
	Available   []runtimes.Available
	RemoteErr   string
	SDKs        []string // installed SDK versions (runtimes with an SDK definition)
	SDKChannels []string // X.Y channels of installed runtimes without an SDK
}

type installedVersion struct {
	Version string
	Sites   int
}

func (s *Server) runtimesPage(w http.ResponseWriter, r *http.Request) {
	var rows []runtimeRow
	for _, p := range s.Runtimes.All() {
		row := runtimeRow{Def: p.Def()}
		inst, _ := p.InstalledVersions(r.Context())
		have := map[string]bool{}
		for _, v := range inst {
			have[v] = true
			row.Installed = append(row.Installed, installedVersion{v, s.Sites.Store.CountByRuntimeVersion(r.Context(), p.Def().ID, v)})
		}
		av, err := p.AvailableVersions(r.Context())
		if err != nil {
			row.RemoteErr = err.Error()
		}
		for _, a := range av {
			if !have[a.Version] {
				row.Available = append(row.Available, a)
			}
		}
		if p.Def().SDK != nil {
			row.SDKs = p.InstalledSDKs(r.Context())
			for _, v := range inst {
				f := strings.Split(v, ".")
				if len(f) == 3 && !runtimes.HasSDKFor(row.SDKs, v) && !slices.Contains(row.SDKChannels, f[0]+"."+f[1]) {
					row.SDKChannels = append(row.SDKChannels, f[0]+"."+f[1])
				}
			}
		}
		rows = append(rows, row)
	}
	var loadErrs []string
	for _, e := range s.Runtimes.Errors() {
		loadErrs = append(loadErrs, e.Error())
	}
	s.render(w, r, http.StatusOK, "runtimes", "layout", Page{Title: "Altyapılar", Nav: "runtimes",
		Data: map[string]any{"Rows": rows, "LoadErrors": loadErrs, "Dir": s.Cfg.RuntimesDir}})
}

func (s *Server) runtimeAction(w http.ResponseWriter, r *http.Request) {
	action := r.PathValue("action")
	switch action {
	case "install", "remove", "install-sdk", "remove-sdk":
	default:
		http.NotFound(w, r)
		return
	}
	id, version := r.PathValue("id"), r.PostFormValue("version")
	if _, ok := s.Runtimes.Get(id); !ok || !runtimes.ValidInstallVersion(version) {
		http.Error(w, "geçersiz altyapı veya sürüm", http.StatusBadRequest)
		return
	}
	jobID, err := s.Sites.SubmitRuntime(r.Context(), action, id, version)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/logs/jobs/%d", jobID), http.StatusSeeOther)
}
