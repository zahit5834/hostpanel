// Command hostpanel is a lightweight single-admin hosting control panel.
package main

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/zahit5834/hostpanel/internal/auth"
	"github.com/zahit5834/hostpanel/internal/backups"
	"github.com/zahit5834/hostpanel/internal/config"
	"github.com/zahit5834/hostpanel/internal/crons"
	"github.com/zahit5834/hostpanel/internal/crypto"
	"github.com/zahit5834/hostpanel/internal/customers"
	"github.com/zahit5834/hostpanel/internal/databases"
	"github.com/zahit5834/hostpanel/internal/dns"
	"github.com/zahit5834/hostpanel/internal/domains"
	"github.com/zahit5834/hostpanel/internal/exec"
	"github.com/zahit5834/hostpanel/internal/hostsec"
	"github.com/zahit5834/hostpanel/internal/images"
	"github.com/zahit5834/hostpanel/internal/jobs"
	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/mail"
	"github.com/zahit5834/hostpanel/internal/metrics"
	"github.com/zahit5834/hostpanel/internal/monitor"
	"github.com/zahit5834/hostpanel/internal/notify"
	"github.com/zahit5834/hostpanel/internal/panelcfg"
	"github.com/zahit5834/hostpanel/internal/pgsql"
	"github.com/zahit5834/hostpanel/internal/runtimes"
	"github.com/zahit5834/hostpanel/internal/sites"
	"github.com/zahit5834/hostpanel/internal/ssl"
	"github.com/zahit5834/hostpanel/internal/store"
	"github.com/zahit5834/hostpanel/internal/sysmaint"
	"github.com/zahit5834/hostpanel/internal/system"
	"github.com/zahit5834/hostpanel/internal/traffic"
	"github.com/zahit5834/hostpanel/internal/update"
	"github.com/zahit5834/hostpanel/internal/web"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `Kullanım:
  hostpanel [serve] [--dev] [--config PATH]   Paneli başlat
  hostpanel admin reset-password [--username admin] [--config PATH]
                                              Admin şifresini sıfırla (yeni şifre ekrana basılır)
  hostpanel admin disable-2fa [--config PATH] İki adımlı doğrulamayı kapat (kurtarma)
  hostpanel admin init [--config PATH]        Admin yoksa oluştur ve şifresini bas (install.sh)
  hostpanel admin import-config --file F [--force] [--config PATH]
                                              Dışa aktarılmış panel yapılandırmasını içe al
                                              (root, panel durdurulmuşken; parola: HP_IMPORT_PASS ya da stdin)
  hostpanel version
`

func main() {
	args := os.Args[1:]
	cmd := "serve"
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve(args)
	case "admin":
		err = admin(args)
	case "version":
		fmt.Println(version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "hata:", err)
		os.Exit(1)
	}
}

func loadConfig(fs *flag.FlagSet, args []string) (config.Config, error) {
	dev := fs.Bool("dev", false, "geliştirme modu (./data, dry-run, şablonlar diskten)")
	path := fs.String("config", config.DefaultPath, "yapılandırma dosyası")
	if err := fs.Parse(args); err != nil {
		return config.Config{}, err
	}
	base := config.Defaults()
	if *dev {
		base = config.DevDefaults()
		if *path == config.DefaultPath {
			*path = "data/config.yaml"
		}
	}
	return config.Load(*path, base)
}

// app bundles the shared dependencies used by both serve and admin commands.
type app struct {
	cfg  config.Config
	db   *sql.DB
	box  *crypto.Box
	auth *auth.Service
	key  []byte
}

func openApp(ctx context.Context, cfg config.Config) (*app, error) {
	key, err := crypto.LoadKey(cfg.MasterKeyPath, cfg.Dev, !cfg.Dev)
	if err != nil {
		return nil, err
	}
	box, err := crypto.New(key)
	if err != nil {
		return nil, err
	}
	db, err := store.Open(cfg.DBPath())
	if err != nil {
		return nil, err
	}
	if err := store.Migrate(ctx, db); err != nil {
		db.Close()
		return nil, err
	}
	return &app{cfg: cfg, db: db, box: box, auth: auth.New(db, box, key), key: key}, nil
}

func serve(args []string) error {
	cfg, err := loadConfig(flag.NewFlagSet("serve", flag.ExitOnError), args)
	if err != nil {
		return err
	}
	// Soft memory limit unless systemd/env sets GOMEMLIMIT: GC works harder
	// before the heap grows past it, keeping idle RSS small.
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(64 << 20)
	}
	for _, d := range []string{cfg.LogDir, cfg.JobLogDir()} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return err
		}
	}
	logFile, err := os.OpenFile(cfg.PanelLogPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	defer logFile.Close()
	var logOut io.Writer = logFile
	if cfg.Dev {
		logOut = io.MultiWriter(logFile, os.Stderr)
	}
	log := slog.New(slog.NewJSONHandler(logOut, &slog.HandlerOptions{ReplaceAttr: logs.SlogReplaceAttr}))
	slog.SetDefault(log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	a, err := openApp(ctx, cfg)
	if err != nil {
		return err
	}
	defer a.db.Close()

	if cfg.Dev {
		if _, err := a.auth.Admin(ctx); errors.Is(err, sql.ErrNoRows) {
			pw := auth.RandomPassword(16)
			if err := a.auth.SetAdminPassword(ctx, "admin", pw); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "\n  DEV admin oluşturuldu → kullanıcı: admin  şifre: %s\n\n", pw)
		}
	}

	activity := logs.NewActivity(a.db)
	var runner exec.Runner = &exec.Real{Log: log}
	if cfg.DryRun {
		runner = &exec.DryRun{Log: log, Activity: activity}
	}
	jm := jobs.NewManager(a.db, cfg.JobLogDir(), activity, jobs.NewBroker(), log)
	// probe runs read-only, unprivileged commands (dotnet --list-runtimes,
	// systemctl is-active, journalctl) even in dry-run mode.
	probe := &exec.Real{Log: log}
	reg, err := runtimes.Load(cfg.RuntimesDir, probe, cfg.DryRun)
	if err != nil {
		return err
	}
	for _, e := range reg.Errors() {
		log.Warn("runtime definition skipped", "err", e)
	}
	siteSvc := &sites.Service{Store: sites.NewStore(a.db), Box: a.box, Runner: runner, Probe: probe, Runtimes: reg,
		Jobs: jm, Activity: activity, Log: log, ScriptsDir: cfg.ScriptsDir, TemplatesDir: cfg.TemplatesDir,
		UploadDir: filepath.Join(cfg.DataDir, "uploads"), DryRun: cfg.DryRun}
	siteSvc.ProbeToken = ssl.EnsureServerID(ctx, a.db)
	siteSvc.PanelDomain = cfg.PanelDomain
	siteSvc.Register()
	sslSvc := &ssl.Service{Store: ssl.NewStore(a.db), Sites: siteSvc, DB: a.db, Box: a.box, Runner: runner, Probe: probe,
		Jobs: jm, Activity: activity, Log: log, ScriptsDir: cfg.ScriptsDir,
		RenewLog: cfg.RenewLogPath(), DryRun: cfg.DryRun}
	sslSvc.Register()
	dbSvc := &databases.Service{Store: databases.NewStore(a.db), DB: a.db, Box: a.box, Runner: runner, Jobs: jm,
		Activity: activity, Log: log, Sites: siteSvc, ScriptsDir: cfg.ScriptsDir, DryRun: cfg.DryRun,
		MemTotalMB: int(system.Read().MemTotal >> 20)}
	if cfg.DryRun {
		// No SQL Server in dry-run: an in-memory stand-in with the same isolation rules.
		dbSvc.Fake = databases.NewFakeServer("")
	}
	dbSvc.Register()
	pgSvc := &pgsql.Service{Store: pgsql.NewStore(a.db), DB: a.db, Box: a.box, Runner: runner, Jobs: jm,
		Activity: activity, Log: log, Sites: siteSvc, ScriptsDir: cfg.ScriptsDir, UploadDir: siteSvc.UploadDir,
		DryRun: cfg.DryRun, MemTotalMB: dbSvc.MemTotalMB}
	pgSvc.Register() // after dbSvc: chains the site delete hook
	dnsSvc := &dns.Service{Store: dns.NewStore(a.db), DB: a.db, Runner: runner, Jobs: jm, Activity: activity, Log: log,
		Sites: siteSvc, ScriptsDir: cfg.ScriptsDir, DryRun: cfg.DryRun, DefaultIPs: sslSvc.ServerIPs}
	dnsSvc.Register()
	mailSvc := &mail.Service{Store: mail.NewStore(a.db), DB: a.db, Runner: runner, Jobs: jm, Activity: activity, Log: log,
		ScriptsDir: cfg.ScriptsDir, DryRun: cfg.DryRun, MemTotalMB: dbSvc.MemTotalMB, ServerIPs: sslSvc.ServerIPs,
		Changed: dnsSvc.MailChanged, NameTaken: mailNameTaken(siteSvc, cfg.PanelDomain)}
	if cfg.DryRun {
		mailSvc.Fake = mail.NewFake() // hp-mail.sh is only logged: accounts live in memory
	}
	mailSvc.Register()
	siteSvc.MailHost = mailSvc.Host
	dnsSvc.Mail = func(ctx context.Context) (string, []dns.MailDomain) {
		host, ds := mailSvc.DNSInfo(ctx)
		out := make([]dns.MailDomain, 0, len(ds))
		for _, d := range ds {
			out = append(out, dns.MailDomain{Name: d.Name, DKIMSelector: d.DKIMSelector, DKIMTXT: d.DKIMTXT})
		}
		return host, out
	}
	bkSvc := &backups.Service{Store: backups.NewStore(a.db), DB: a.db, Box: a.box, Runner: runner, Probe: probe, Jobs: jm,
		Activity: activity, Log: log, Sites: siteSvc, DBs: dbSvc, PG: pgSvc, ScriptsDir: cfg.ScriptsDir,
		UploadDir: siteSvc.UploadDir, DryRun: cfg.DryRun, Mail: mailSvc}
	bkSvc.Register()
	bkSvc.Recover(ctx)
	notifySvc := &notify.Service{DB: a.db, Box: a.box, Activity: activity, Log: log}
	sslSvc.Notify, bkSvc.Notify = notifySvc.Send, notifySvc.Send
	monSvc := &monitor.Service{Store: monitor.NewStore(a.db), Sites: siteSvc, Probe: probe, Activity: activity, Log: log,
		Notify: notifySvc.Send, DryRun: cfg.DryRun}
	cronSvc := &crons.Service{Store: crons.NewStore(a.db), Sites: siteSvc, Runner: runner, Activity: activity, Log: log,
		ScriptsDir: cfg.ScriptsDir, DryRun: cfg.DryRun, Notify: notifySvc.Send}
	bkSvc.Crons = cronSvc
	statusPath := update.DefaultStatusPath
	if cfg.Dev {
		statusPath = filepath.Join(cfg.DataDir, "update-status.json")
	}
	updSvc := &update.Service{DB: a.db, Runner: runner, ScriptsDir: cfg.ScriptsDir, Activity: activity, Log: log,
		Notify: notifySvc.Send, Version: version, Repo: cfg.UpdateRepo, StatusPath: statusPath,
		LogPath: cfg.UpdateLogPath(), Dev: cfg.Dev}
	updSvc.RecordFinished(ctx)
	// After 30 s without requests or jobs, freed memory goes back to the OS.
	idle := &system.IdleGC{Delay: 30 * time.Second}
	defer idle.Stop()
	jm.AfterJob = idle.Touch
	trafficSvc := &traffic.Service{DB: a.db, Sites: siteSvc, Log: log}
	imgSvc := &images.Service{DB: a.db, Notify: notifySvc.Send, Log: log, Version: version, Engines: []images.Engine{
		{ID: images.MSSQL, Label: "MSSQL", Current: func(ctx context.Context) string {
			if srv, err := dbSvc.Store.Server(ctx); err == nil && srv.Status != databases.StatusInstalling {
				return srv.Image
			}
			return ""
		}},
		{ID: images.Mail, Label: "Posta sunucusu", Current: func(ctx context.Context) string {
			if srv, err := mailSvc.Store.Server(ctx); err == nil && srv.Status != mail.StatusInstalling {
				return srv.Image
			}
			return ""
		}},
	}}
	srv := &web.Server{Cfg: cfg, DB: a.db, Auth: a.auth, Activity: activity, Jobs: jm, Runner: runner, Log: log, Version: version,
		Customers: customers.New(a.db), Sites: siteSvc, Runtimes: reg, SSL: sslSvc, DBs: dbSvc, PG: pgSvc, Backups: bkSvc,
		Monitor: monSvc, Notify: notifySvc, Crons: cronSvc, Update: updSvc, DNS: dnsSvc, Mail: mailSvc,
		Traffic: trafficSvc, Images: imgSvc, Idle: idle,
		SSH: &hostsec.SSH{Runner: runner, ScriptsDir: cfg.ScriptsDir, DryRun: cfg.DryRun},
		F2B: &hostsec.Fail2ban{Runner: runner, ScriptsDir: cfg.ScriptsDir, DryRun: cfg.DryRun},
		Sys: &sysmaint.Service{Runner: runner, Probe: probe, ScriptsDir: cfg.ScriptsDir, DryRun: cfg.DryRun}}
	metricsSvc := &metrics.Service{DB: a.db, Log: log, AfterTick: idle.Touch}
	metricsSvc.Init()
	srv.Metrics = metricsSvc
	srv.Domains = &domains.Service{DB: a.db, Log: log, Notify: func(ctx context.Context, title, text, key string) {
		notifySvc.Send(ctx, notify.Event{Kind: notify.KindDomain, Key: key, Title: title, Text: text})
	}}
	// Cheap checks that ride on the monitor's 10-minute step (no new timer).
	monSvc.Periodic = []func(context.Context){srv.OOMCheck, srv.SSHWatch, srv.CLIWatch, srv.InfraCheck}
	srv.ExportConfig = func(ctx context.Context, pass string, w io.Writer) (panelcfg.Manifest, error) {
		server := store.GetSetting(ctx, a.db, "backup_server_name", "")
		if server == "" {
			server, _ = os.Hostname()
		}
		return panelcfg.Export(ctx, a.db, panelcfg.ExportOptions{DataDir: cfg.DataDir, MasterKey: a.key,
			RuntimesDir: cfg.RuntimesDir, Version: version, Server: server}, pass, w)
	}
	srv.RegisterJobs()
	if err := srv.Init(ctx); err != nil {
		return err
	}
	defer srv.Close()

	jobCtx, cancelJobs := context.WithCancel(context.Background())
	if err := jm.Start(jobCtx, cfg.Workers); err != nil {
		cancelJobs()
		return err
	}
	daily := []func(context.Context){
		trafficSvc.CollectAll,
		func(ctx context.Context) {
			cut := time.Now().AddDate(0, 0, -statsKeepDays)
			trafficSvc.Purge(ctx, traffic.DayKey(cut))
			monSvc.Store.PurgeUptime(ctx, cut)
		},
	}
	if !cfg.DryRun { // dry-run has no real containers to compare with
		daily = append(daily, func(ctx context.Context) { imgSvc.Check(ctx) })
	}
	if !cfg.Dev { // dev reads deploy/ straight from the repo (test files, no unit)
		daily = append(daily, func(ctx context.Context) { srv.IntegrityCheck(ctx) })
	}
	daily = append(daily, srv.AuditNotify, srv.DomainsMaintain, srv.RuntimePatchCheck, bkSvc.MaintainVerify,
		func(ctx context.Context) { metricsSvc.Purge(ctx, time.Now()) },
		// Maintenance is neither a request nor a job: hand its garbage back too.
		func(context.Context) { idle.Touch() })
	// The boot report waits until sites and containers had time to come up.
	bootTimer := time.AfterFunc(3*time.Minute, func() { srv.BootReport(jobCtx) })
	defer bootTimer.Stop()
	go maintenance(ctx, a, activity, jm, sslSvc, dbSvc, pgSvc, cronSvc, updSvc, log, daily)
	go bkSvc.RunScheduler(jobCtx)
	go notifySvc.Run(jobCtx)
	go monSvc.Run(jobCtx)
	go metricsSvc.Run(jobCtx)                   // 5-minute samples / heartbeat (sleeps without a timer when both are off)
	go srv.RunSummary(jobCtx)                   // daily/weekly digest (no timer while off)
	go notifySvc.RunBot(jobCtx, srv.BotCommand) // Telegram commands (no connection while off)
	go mailSvc.EnsureVhost(jobCtx)              // one-shot: a panel update runs the old hp-update.sh
	cronDone := make(chan struct{})
	go func() { cronSvc.Run(jobCtx); close(cronDone) }()
	srv.BaseCtx = jobCtx

	hs := srv.HTTPServer()
	errc := make(chan error, 1)
	go func() { errc <- hs.ListenAndServe() }()
	log.Info("hostpanel started", "version", version, "listen", cfg.Listen, "dev", cfg.Dev, "dry_run", cfg.DryRun)
	activity.Record(ctx, logs.Entry{Action: "system.start", Summary: "Panel başlatıldı (" + version + ")"}, nil)

	select {
	case err := <-errc:
		cancelJobs()
		jm.Wait()
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
	}
	log.Info("shutting down")
	shutCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	hs.Shutdown(shutCtx) // SSE handlers end via their request context
	cancelJobs()
	jm.Wait()
	<-cronDone // running crons are stopped with their context
	activity.Record(context.Background(), logs.Entry{Action: "system.stop", Summary: "Panel durduruldu"}, nil)
	return nil
}

// statsKeepDays is how long daily traffic and uptime history is kept.
const statsKeepDays = 400

// maintenance runs the daily cleanup: one timer, no polling.
func maintenance(ctx context.Context, a *app, activity *logs.Activity, jm *jobs.Manager, sslSvc *ssl.Service, dbSvc *databases.Service,
	pgSvc *pgsql.Service, cronSvc *crons.Service, updSvc *update.Service, log *slog.Logger, daily []func(context.Context)) {
	t := time.NewTimer(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		days := func(key string, def int) time.Time {
			n, err := strconv.Atoi(store.GetSetting(ctx, a.db, key, strconv.Itoa(def)))
			if err != nil || n < 1 {
				n = def
			}
			return time.Now().AddDate(0, 0, -n)
		}
		a.auth.PurgeExpired(ctx)
		nAct, _ := activity.Purge(ctx, days("retention_activity_days", 180))
		nJobs, _ := jm.Purge(ctx, days("retention_job_days", 30))
		sslSvc.Maintain(ctx)
		dbSvc.Maintain(ctx)
		pgSvc.Maintain(ctx)
		cronSvc.Maintain(ctx)
		if update.ValidTag(updSvc.Version) {
			if _, err := updSvc.Check(ctx); err != nil {
				log.Warn("update check failed", "err", err)
			}
		}
		for _, f := range daily {
			f(ctx)
		}
		a.db.ExecContext(ctx, `PRAGMA optimize`)
		if nAct+int64(nJobs) > 0 {
			activity.Record(ctx, logs.Entry{Action: "system.cleanup",
				Summary: fmt.Sprintf("Eski kayıtlar silindi: %d işlem, %d iş", nAct, nJobs)}, nil)
		}
		log.Info("maintenance done", "activity_purged", nAct, "jobs_purged", nJobs)
		t.Reset(24 * time.Hour)
	}
}

func admin(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	sub, args := args[0], args[1:]
	fs := flag.NewFlagSet("admin "+sub, flag.ExitOnError)
	username := fs.String("username", "admin", "admin kullanıcı adı")
	file := fs.String("file", "", "içe aktarılacak .hpcfg dosyası (import-config)")
	force := fs.Bool("force", false, "dolu bir panelin üzerine yaz (import-config)")
	cfg, err := loadConfig(fs, args)
	if err != nil {
		return err
	}
	ctx := context.Background()
	if sub == "import-config" {
		return importConfig(ctx, cfg, *file, *force)
	}
	a, err := openApp(ctx, cfg)
	if err != nil {
		return err
	}
	defer a.db.Close()
	activity := logs.NewActivity(a.db)
	switch sub {
	case "reset-password":
		pw := auth.RandomPassword(20)
		if err := a.auth.SetAdminPassword(ctx, *username, pw); err != nil {
			return err
		}
		activity.Record(ctx, logs.Entry{Action: "admin.reset-password", Summary: "Admin şifresi CLI ile sıfırlandı (" + *username + ")"}, nil)
		fmt.Printf("Kullanıcı: %s\nŞifre:     %s\n", *username, pw)
	case "init":
		if _, err := a.auth.Admin(ctx); err == nil {
			fmt.Println("Admin hesabı zaten var (şifreyi sıfırlamak için: hostpanel admin reset-password).")
			return nil
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		pw := auth.RandomPassword(20)
		if err := a.auth.SetAdminPassword(ctx, *username, pw); err != nil {
			return err
		}
		activity.Record(ctx, logs.Entry{Action: "settings.password", Summary: "Admin hesabı kurulumda oluşturuldu"}, nil)
		fmt.Printf("Kullanıcı: %s\nŞifre:     %s\n", *username, pw)
	case "disable-2fa":
		if err := a.auth.DisableTOTP(ctx); err != nil {
			return err
		}
		activity.Record(ctx, logs.Entry{Action: "admin.disable-2fa", Summary: "2FA CLI ile kapatıldı"}, nil)
		fmt.Println("İki adımlı doğrulama kapatıldı.")
	default:
		return fmt.Errorf("bilinmeyen admin komutu: %s", sub)
	}
	return nil
}

// importConfig restores an exported panel configuration (run as root by
// install.sh --import, with the panel stopped).
func importConfig(ctx context.Context, cfg config.Config, file string, force bool) error {
	if file == "" {
		return errors.New("--file gerekli")
	}
	pass := os.Getenv("HP_IMPORT_PASS")
	if pass == "" {
		fmt.Fprint(os.Stderr, "Parola: ")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return errors.New("parola okunamadı")
		}
		pass = strings.TrimRight(line, "\r\n")
	}
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	arc, err := panelcfg.Open(f, pass)
	if err != nil {
		return err
	}
	uid, gid := -1, -1
	if os.Geteuid() == 0 && !cfg.Dev {
		u, err := user.Lookup("hostpanel")
		if err != nil {
			return fmt.Errorf("hostpanel kullanıcısı yok: %w", err)
		}
		uid, _ = strconv.Atoi(u.Uid)
		gid, _ = strconv.Atoi(u.Gid)
	}
	if err := panelcfg.Import(ctx, arc, panelcfg.ImportOptions{DBPath: cfg.DBPath(), MasterKeyPath: cfg.MasterKeyPath,
		RuntimesDir: cfg.RuntimesDir, Force: force, UID: uid, GID: gid}); err != nil {
		return err
	}
	a, err := openApp(ctx, cfg)
	if err != nil {
		return err
	}
	defer a.db.Close()
	m := arc.Manifest
	logs.NewActivity(a.db).Record(ctx, logs.Entry{Action: "panel.import", Source: logs.SourceSystem,
		Summary: fmt.Sprintf("Panel yapılandırması içe aktarıldı (%s, %s, %s)", m.Server, m.Version, m.Created.Format("2006-01-02"))},
		map[string]any{"server": m.Server, "version": m.Version, "customers": m.Customers, "plans": m.Plans, "zones": m.Zones, "runtimes": m.Runtimes})
	fmt.Printf(`Yapılandırma içe aktarıldı: %s (%s, %s) — %d müşteri, %d yedek planı, %d DNS zone'u.

Sıradaki adımlar:
  1. Yedekler → Ayarlar: Google Drive token'ını (ya da service account'u) yeniden girin;
     crypt anahtarları dosyayla geldi, eski yedekler açılabilir.
  2. Yedekler → "Drive'ı tara": eski sunucunun yedekleri listeye gelir.
  3. Siteleri sihirbazla aynı domain'lerle oluşturun ve yedekten geri yükleyin.
  4. MSSQL kullanılıyorsa: sunucuyu kurun, müşteri login'lerini yeniden oluşturun.
  5. Git deploy kullanan siteler için yeni deploy key üretip repo'ya ekleyin.
  6. Site kapsamlı yedek planları devre dışı geldi; siteleri seçip yeniden açın.
  7. DNS zone'ları geldiyse: DNS → IP'leri kontrol edip kaydedin → "DNS sunucusunu kur";
     registrar'da glue IP'lerini değiştirin. DNSSEC'li zone'lar yeni anahtarla imzalanır:
     yeni DS kaydını registrar'a girin (eskisini kaldırın).
`, m.Server, m.Version, m.Created.Format("2006-01-02 15:04"), m.Customers, m.Plans, m.Zones)
	return nil
}

// mailNameTaken rejects a mail server name that a site or the panel uses
// (their nginx vhosts own the name on port 80).
func mailNameTaken(siteSvc *sites.Service, panelDomain string) func(ctx context.Context, host string) error {
	return func(ctx context.Context, host string) error {
		if panelDomain != "" && host == panelDomain {
			return fmt.Errorf("%s panelin kendi adresi; posta sunucusu adı olarak kullanılamaz", host)
		}
		list, err := siteSvc.Store.List(ctx, 0)
		if err != nil {
			return err
		}
		for _, st := range list {
			if slices.Contains(st.HostNames(), host) {
				return fmt.Errorf("%s bir sitenin adı (%s); posta sunucusu için ayrı bir ad seçin (ör. mail.%s)", host, st.Domain, st.Domain)
			}
		}
		return nil
	}
}
