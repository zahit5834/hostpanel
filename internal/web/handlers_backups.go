package web

import (
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/zahit5834/hostpanel/internal/backups"
	"github.com/zahit5834/hostpanel/internal/databases"
	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/sites"
)

// MaxBakBytes caps an uploaded .bak (Express databases are ≤ 10 GB).
const MaxBakBytes = 10 << 30

func init() {
	funcs["schedule"] = backups.Describe
	funcs["compLabel"] = func(c string) string {
		return map[string]string{backups.CompFiles: "Dosyalar", backups.CompDB: "Veritabanı", backups.CompConfig: "Ayarlar",
			backups.CompSSL: "SSL"}[c]
	}
	funcs["kindLabel"] = func(k string) string {
		return map[string]string{backups.KindManual: "elle", backups.KindScheduled: "plan", backups.KindPreRestore: "geri yükleme öncesi",
			backups.KindImported: "Drive'dan"}[k]
	}
	funcs["destLabel"] = func(d string) string {
		return map[string]string{backups.DestLocal: "Yerel", backups.DestRemote: "Google Drive", backups.DestBoth: "Yerel + Drive"}[d]
	}
	funcs["hasInt"] = func(list []int64, v int64) bool { return slices.Contains(list, v) }
	funcs["hasStr"] = func(list []string, v string) bool { return slices.Contains(list, v) }
}

type planForm struct {
	Plan     backups.Plan
	Schedule backups.Schedule
	Time     string // HH:MM
}

type backupsPageData struct {
	Tab        string
	JobID      int64
	Backups    []backups.Backup
	Plans      []backups.Plan
	Sites      []sites.Site
	SiteFilter int64
	LocalSize  int64
	Remote     backups.RemoteSettings
	Form       planForm
	Weekdays   []string
	Components []string
	Keys       *backups.CryptSecret // shown once after generation / on reveal
	Rclone     string
	DryRun     bool
}

var backupTabs = map[string]bool{"list": true, "plans": true, "settings": true}

func defaultPlanForm() planForm {
	return planForm{Plan: backups.Plan{Scope: "all", Components: []string{backups.CompFiles, backups.CompDB, backups.CompConfig},
		Destination: backups.DestLocal, KeepLocal: 7, Enabled: true}, Schedule: backups.Schedule{Kind: "daily", Hour: 3}, Time: "03:00"}
}

func (s *Server) backupsPage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	tab := q.Get("tab")
	if !backupTabs[tab] {
		tab = "list"
	}
	form := defaultPlanForm()
	if id := parseInt64(q.Get("edit")); id > 0 {
		if p, err := s.Backups.Store.Plan(r.Context(), id); err == nil {
			sc := backups.ScheduleOf(p.Schedule)
			form = planForm{Plan: p, Schedule: sc, Time: fmt.Sprintf("%02d:%02d", sc.Hour, sc.Minute)}
			tab = "plans"
		}
	}
	s.renderBackups(w, r, http.StatusOK, tab, form, nil, "", "")
}

func (s *Server) renderBackups(w http.ResponseWriter, r *http.Request, status int, tab string, form planForm, keys *backups.CryptSecret, errMsg, notice string) {
	ctx := r.Context()
	d := backupsPageData{Tab: tab, JobID: parseInt64(r.URL.Query().Get("job")), Form: form, Weekdays: backups.Weekdays,
		Components: backups.AllComponents, Keys: keys, SiteFilter: parseInt64(r.URL.Query().Get("site")), DryRun: s.Cfg.DryRun,
		Rclone: backups.RcloneVersion}
	d.Sites, _ = s.Sites.Store.List(ctx, 0)
	d.Remote = s.Backups.Remote(ctx)
	switch tab {
	case "list":
		d.Backups, _ = s.Backups.Store.Backups(ctx, backups.Filter{SiteID: d.SiteFilter, Limit: 500})
		d.LocalSize = s.Backups.Store.LocalSize(ctx)
	case "plans":
		d.Plans, _ = s.Backups.Store.Plans(ctx)
	}
	s.render(w, r, status, "backups", "layout", Page{Title: "Yedekler", Nav: "backups", Data: d, Error: errMsg, Notice: notice})
}

func (s *Server) backupJobRedirect(w http.ResponseWriter, r *http.Request, tab string, id int64, err error) {
	if err != nil {
		s.renderBackups(w, r, http.StatusBadRequest, tab, defaultPlanForm(), nil, err.Error(), "")
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/backups?tab=%s&job=%d", tab, id), http.StatusSeeOther)
}

// --- settings tab ---

func (s *Server) backupRcloneInstall(w http.ResponseWriter, r *http.Request) {
	id, err := s.Backups.StartRcloneInstall(r.Context())
	s.backupJobRedirect(w, r, "settings", id, err)
}

func (s *Server) backupRemoteSave(w http.ResponseWriter, r *http.Request) {
	in := backups.RemoteInput{
		Type:         r.PostFormValue("type"),
		Token:        r.PostFormValue("token"),
		ClientID:     r.PostFormValue("client_id"),
		ClientSecret: r.PostFormValue("client_secret"),
		SAJSON:       r.PostFormValue("sa_json"),
		SharedDrive:  r.PostFormValue("shared_drive"),
		RootFolder:   r.PostFormValue("root_folder"),
		ServerName:   r.PostFormValue("server_name"),
		Crypt:        r.PostFormValue("crypt") == "1",
	}
	act := s.Activity.Begin(r.Context(), logs.Entry{Action: "backup.remote.config", TargetType: "backup", TargetID: "remote",
		Summary: "Google Drive bağlantısı yapılandırıldı"},
		map[string]any{"type": in.Type, "root_folder": in.RootFolder, "server_name": in.ServerName, "crypt": in.Crypt, "shared_drive": in.SharedDrive})
	keys, err := s.Backups.ConfigureRemote(r.Context(), in)
	act.Finish(err)
	if err != nil {
		s.renderBackups(w, r, http.StatusBadRequest, "settings", defaultPlanForm(), nil, err.Error(), "")
		return
	}
	notice := "Bağlantı kaydedildi. “Bağlantıyı test et” ile doğrulayın."
	if keys != nil {
		notice = "Bağlantı kaydedildi. Şifreleme anahtarları oluşturuldu — aşağıdan bir kopyasını güvenli bir yere kaydedin."
	}
	s.renderBackups(w, r, http.StatusOK, "settings", defaultPlanForm(), keys, "", notice)
}

func (s *Server) backupOptions(w http.ResponseWriter, r *http.Request) {
	bw, srv := r.PostFormValue("bwlimit"), r.PostFormValue("server_name")
	act := s.Activity.Begin(r.Context(), logs.Entry{Action: "backup.options", TargetType: "backup", TargetID: "remote",
		Summary: "Yedekleme seçenekleri güncellendi"}, map[string]any{"bwlimit": bw, "server_name": srv})
	err := s.Backups.SaveOptions(r.Context(), bw, srv)
	act.Finish(err)
	if err != nil {
		s.renderBackups(w, r, http.StatusBadRequest, "settings", defaultPlanForm(), nil, err.Error(), "")
		return
	}
	s.renderBackups(w, r, http.StatusOK, "settings", defaultPlanForm(), nil, "", "Seçenekler kaydedildi.")
}

func (s *Server) backupRemoteTest(w http.ResponseWriter, r *http.Request) {
	id, err := s.Backups.StartRemoteTest(r.Context())
	s.backupJobRedirect(w, r, "settings", id, err)
}

func (s *Server) backupRemoteScan(w http.ResponseWriter, r *http.Request) {
	id, err := s.Backups.StartScan(r.Context())
	s.backupJobRedirect(w, r, "list", id, err)
}

// backupCryptReveal shows the crypt keys (POST + CSRF, logged).
func (s *Server) backupCryptReveal(w http.ResponseWriter, r *http.Request) {
	keys, err := s.Backups.CryptKeys(r.Context())
	if err == nil && keys == nil {
		err = errors.New("şifreleme anahtarı yok")
	}
	s.Activity.Record(r.Context(), logs.Entry{Action: "backup.crypt.reveal", TargetType: "backup", TargetID: "remote",
		Summary: "Yedek şifreleme anahtarı görüntülendi", Status: statusOf(err), Error: errText(err)}, nil)
	if err != nil {
		s.renderBackups(w, r, http.StatusBadRequest, "settings", defaultPlanForm(), nil, err.Error(), "")
		return
	}
	s.renderBackups(w, r, http.StatusOK, "settings", defaultPlanForm(), keys, "", "")
}

// --- plans ---

func (s *Server) backupPlanSave(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	id := parseInt64(r.PostFormValue("id"))
	p := backups.Plan{ID: id, Name: r.PostFormValue("name"), Scope: r.PostFormValue("scope"), Components: r.PostForm["components"],
		Destination: r.PostFormValue("destination"), KeepLocal: formInt(r, "keep_local", 7), KeepRemote: formInt(r, "keep_remote", 0),
		KeepRemoteDays: formInt(r, "keep_remote_days", 0), Enabled: r.PostFormValue("enabled") == "1"}
	for _, v := range r.PostForm["site_ids"] {
		if n := parseInt64(v); n > 0 {
			p.SiteIDs = append(p.SiteIDs, n)
		}
	}
	tm := r.PostFormValue("time")
	sc := backups.Schedule{Kind: r.PostFormValue("kind"), Weekday: formInt(r, "weekday", 0), Day: formInt(r, "day", 1),
		Expr: r.PostFormValue("expr")}
	hh, mm, ok := strings.Cut(tm, ":")
	sc.Hour, _ = strconv.Atoi(hh)
	sc.Minute, _ = strconv.Atoi(mm)
	form := planForm{Plan: p, Schedule: sc, Time: tm}
	expr, err := sc.Cron()
	if err == nil && !ok && sc.Kind != "custom" {
		err = errors.New("saat SS:DD biçiminde olmalı")
	}
	if err != nil {
		s.renderBackups(w, r, http.StatusBadRequest, "plans", form, nil, err.Error(), "")
		return
	}
	p.Schedule = expr
	var old string
	if id > 0 {
		if prev, err := s.Backups.Store.Plan(r.Context(), id); err == nil {
			old = planText(prev)
		} else {
			http.NotFound(w, r)
			return
		}
	}
	err = s.Backups.SavePlan(r.Context(), &p)
	verb := "oluşturuldu"
	if id > 0 {
		verb = "güncellendi"
	}
	s.Activity.Record(r.Context(), logs.Entry{Action: "backup.plan.save", TargetType: "backup", TargetID: p.Name,
		Summary: "Yedekleme planı " + verb + ": " + p.Name, Status: statusOf(err), Error: errText(err), Diff: logs.LineDiff(old, planText(p))}, nil)
	if err != nil {
		form.Plan = p
		s.renderBackups(w, r, http.StatusBadRequest, "plans", form, nil, err.Error(), "")
		return
	}
	http.Redirect(w, r, "/backups?tab=plans", http.StatusSeeOther)
}

func planText(p backups.Plan) string {
	return fmt.Sprintf("name: %s\nscope: %s %v\ncomponents: %s\nschedule: %s\ndestination: %s\nkeep_local: %d\nkeep_remote: %d\nkeep_remote_days: %d\nenabled: %v\n",
		p.Name, p.Scope, p.SiteIDs, strings.Join(p.Components, ","), p.Schedule, p.Destination, p.KeepLocal, p.KeepRemote, p.KeepRemoteDays, p.Enabled)
}

func (s *Server) backupPlanDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	p, err := s.Backups.Store.Plan(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	act := s.Activity.Begin(r.Context(), logs.Entry{Action: "backup.plan.delete", TargetType: "backup", TargetID: p.Name,
		Summary: "Yedekleme planı silindi: " + p.Name}, nil)
	err = s.Backups.DeletePlan(r.Context(), id)
	act.Finish(err)
	http.Redirect(w, r, "/backups?tab=plans", http.StatusSeeOther)
}

func (s *Server) backupPlanRun(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	jobID, err := s.Backups.RunPlanNow(r.Context(), id)
	s.backupJobRedirect(w, r, "plans", jobID, err)
}

// --- backups ---

func (s *Server) loadBackup(w http.ResponseWriter, r *http.Request) (backups.Backup, bool) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return backups.Backup{}, false
	}
	b, err := s.Backups.Store.Backup(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return b, false
	}
	return b, true
}

func (s *Server) backupUpload(w http.ResponseWriter, r *http.Request) {
	b, ok := s.loadBackup(w, r)
	if !ok {
		return
	}
	id, err := s.Backups.StartUpload(r.Context(), b)
	s.backupJobRedirect(w, r, "list", id, err)
}

func (s *Server) backupDelete(w http.ResponseWriter, r *http.Request) {
	b, ok := s.loadBackup(w, r)
	if !ok {
		return
	}
	id, err := s.Backups.StartDelete(r.Context(), b, r.PostFormValue("where"))
	s.backupJobRedirect(w, r, "list", id, err)
}

type restorePageData struct {
	Backup   backups.Backup
	Targets  []sites.Site
	TargetID int64
	Source   *sites.Site
}

func (s *Server) backupRestorePage(w http.ResponseWriter, r *http.Request) {
	b, ok := s.loadBackup(w, r)
	if !ok {
		return
	}
	s.renderRestore(w, r, http.StatusOK, b, "")
}

func (s *Server) renderRestore(w http.ResponseWriter, r *http.Request, status int, b backups.Backup, errMsg string) {
	ctx := r.Context()
	d := restorePageData{Backup: b}
	runtime := ""
	if src, err := s.Sites.Store.GetByDomain(ctx, b.Domain); err == nil {
		d.Source, d.TargetID, runtime = &src, src.ID, src.RuntimeID
	}
	d.Targets = s.Backups.RestoreTargets(ctx, b, runtime)
	if t := parseInt64(r.FormValue("target")); t > 0 {
		d.TargetID = t
	}
	s.render(w, r, status, "backup_restore", "layout", Page{Title: "Geri yükle", Nav: "backups", Data: d, Error: errMsg})
}

func (s *Server) backupRestore(w http.ResponseWriter, r *http.Request) {
	b, ok := s.loadBackup(w, r)
	if !ok {
		return
	}
	r.ParseForm()
	target, err := s.Sites.Store.Get(r.Context(), parseInt64(r.PostFormValue("target")))
	if err != nil {
		s.renderRestore(w, r, http.StatusBadRequest, b, "Hedef site seçin")
		return
	}
	if strings.TrimSpace(r.PostFormValue("confirm")) != target.Domain {
		s.renderRestore(w, r, http.StatusBadRequest, b, "Onay için hedef domaini aynen yazın: "+target.Domain)
		return
	}
	id, err := s.Backups.StartRestore(r.Context(), backups.RestoreInput{BackupID: b.ID, TargetID: target.ID, Components: r.PostForm["components"]})
	if err != nil {
		s.renderRestore(w, r, http.StatusBadRequest, b, err.Error())
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/sites/%d?tab=backups&job=%d", target.ID, id), http.StatusSeeOther)
}

// --- site tabs ---

func (s *Server) siteBackupData(r *http.Request, d *siteData) {
	ctx := r.Context()
	d.Backups, _ = s.Backups.Store.Backups(ctx, backups.Filter{Domain: d.Site.Domain, Limit: 200})
	d.Remote = s.Backups.Remote(ctx)
	d.Components = backups.AllComponents
	for _, ip := range s.SSL.ServerIPs(ctx) {
		d.ServerIPs = append(d.ServerIPs, ip.String())
	}
	d.EnvKeyHint = databases.DefaultEnvKey(d.Site.RuntimeID)
	d.DBNameHint = databases.DBBase(d.Site.ShortName)
	for i := 2; s.DBs.Store.DBNameTaken(ctx, d.DBNameHint); i++ {
		d.DBNameHint = databases.DBBase(d.Site.ShortName) + "_" + strconv.Itoa(i)
	}
	d.MaxBakMB = MaxBakBytes >> 20
}

func (s *Server) siteBackupNow(w http.ResponseWriter, r *http.Request) {
	site, ok := s.loadSite(w, r)
	if !ok {
		return
	}
	r.ParseForm()
	id, err := s.Backups.StartManual(r.Context(), backups.ManualInput{SiteID: site.ID, Components: r.PostForm["components"],
		Upload: r.PostFormValue("upload") == "1"})
	if err != nil {
		s.renderSite(w, r, http.StatusBadRequest, site, "backups", err.Error(), "")
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/sites/%d?tab=backups&job=%d", site.ID, id), http.StatusSeeOther)
}

// siteImportDB streams an uploaded .bak to disk (the multipart body is not
// parsed for _csrf: the X-CSRF-Token header is required) and queues the restore.
func (s *Server) siteImportDB(w http.ResponseWriter, r *http.Request) {
	site, ok := s.loadSite(w, r)
	if !ok {
		return
	}
	rc := http.NewResponseController(w)
	rc.SetReadDeadline(time.Now().Add(time.Hour))
	r.Body = http.MaxBytesReader(w, r.Body, MaxBakBytes+1<<20)
	mr, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "multipart form bekleniyor", http.StatusBadRequest)
		return
	}
	in := backups.ImportDBInput{SiteID: site.ID}
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, "yükleme okunamadı: "+err.Error(), http.StatusBadRequest)
			return
		}
		switch part.FormName() {
		case "name", "env_key", "write_env":
			b, _ := io.ReadAll(io.LimitReader(part, 256))
			v := strings.TrimSpace(string(b))
			switch part.FormName() {
			case "name":
				in.Name = v
			case "env_key":
				in.EnvKey = v
			case "write_env":
				in.WriteEnv = v == "1"
			}
		case "bak":
			if _, params, _ := mime.ParseMediaType(part.Header.Get("Content-Disposition")); !strings.HasSuffix(strings.ToLower(params["filename"]), ".bak") {
				part.Close()
				http.Error(w, "yalnızca .bak dosyası yüklenebilir", http.StatusBadRequest)
				return
			}
			if in.Name == "" {
				part.Close()
				http.Error(w, "veritabanı adı dosyadan önce gönderilmeli", http.StatusBadRequest)
				return
			}
			in.Upload, _, err = s.Backups.SaveBakUpload(part, MaxBakBytes)
			part.Close()
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		part.Close()
	}
	if in.Upload == "" {
		http.Error(w, ".bak dosyası seçilmedi", http.StatusBadRequest)
		return
	}
	jobID, err := s.Backups.StartImportDB(r.Context(), in)
	if err != nil {
		s.Backups.DiscardUpload(in.Upload)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("HX-Redirect", fmt.Sprintf("/sites/%d?tab=import&job=%d", site.ID, jobID))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) siteImportEnv(w http.ResponseWriter, r *http.Request) {
	site, ok := s.loadSite(w, r)
	if !ok {
		return
	}
	act := s.Activity.Begin(r.Context(), logs.Entry{Action: "site.env", TargetType: "site", TargetID: site.Domain,
		Summary: "Ortam değişkenleri içe aktarıldı: " + site.Domain}, nil)
	diff, n, err := s.Backups.ImportEnv(r.Context(), site, r.PostFormValue("dotenv"))
	act.Finish(err)
	if err != nil {
		s.renderSite(w, r, http.StatusBadRequest, site, "import", "Ortam değişkenleri alınamadı: "+err.Error(), "")
		return
	}
	s.setActivityDiff(act.ID(), diff)
	s.renderSite(w, r, http.StatusOK, site, "import", "", fmt.Sprintf("%d değişken kaydedildi; site yeniden başlatılınca geçerli olur.", n))
}
