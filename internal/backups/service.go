package backups

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zahit5834/hostpanel/internal/crons"
	"github.com/zahit5834/hostpanel/internal/crypto"
	"github.com/zahit5834/hostpanel/internal/databases"
	"github.com/zahit5834/hostpanel/internal/exec"
	"github.com/zahit5834/hostpanel/internal/jobs"
	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/notify"
	"github.com/zahit5834/hostpanel/internal/pgsql"
	"github.com/zahit5834/hostpanel/internal/sites"
	"github.com/zahit5834/hostpanel/internal/store"
)

// Root is where local backups live (root only, 0700).
const Root = "/var/backups/hostpanel"

// maxConfigBytes keeps config.json well under the runner's 256 KB stdout
// capture (read-config returns it on stdout).
const maxConfigBytes = 200 << 10

// mssqlBackupDir is the container's backup volume as seen by SQL Server.
const mssqlBackupDir = "/var/opt/mssql/backup"

var (
	nameRe     = regexp.MustCompile(`^[0-9]{8}-[0-9]{6}-[0-9a-f]{4}$`)
	importRe   = regexp.MustCompile(`^import-[0-9]+\.bak$`)
	sizeLineRe = regexp.MustCompile(`(?m)^size=([0-9]+)$`)
)

// ValidName checks a backup directory name.
func ValidName(n string) bool { return nameRe.MatchString(n) }

// Service takes, ships, prunes and restores backups.
type Service struct {
	Store      *Store
	DB         *sql.DB
	Box        *crypto.Box
	Runner     exec.Runner    // privileged helpers (dry-run in dev)
	Probe      exec.Runner    // unprivileged reads (rclone version)
	Crons      *crons.Service // optional: crons go into config.json
	Jobs       *jobs.Manager
	Activity   *logs.Activity
	Log        *slog.Logger
	Sites      *sites.Service
	DBs        *databases.Service
	PG         *pgsql.Service
	Mail       MailBackend // optional: mail server backups
	ScriptsDir string
	UploadDir  string
	DryRun     bool

	// Now is the clock (tests); nil = time.Now.
	Now func() time.Time
	// Notify receives backup.failed events (nil: none).
	Notify func(ctx context.Context, e notify.Event)

	wake    chan struct{}
	mu      sync.Mutex
	planJob map[int64]int64 // plan id → running job id
}

// Register binds the job kinds and prepares the scheduler.
func (s *Service) Register() {
	s.wake = make(chan struct{}, 1)
	s.planJob = map[int64]int64{}
	s.Jobs.Register("backup.rclone.install", s.jobRcloneInstall)
	s.Jobs.Register("backup.remote.test", s.jobRemoteTest)
	s.Jobs.Register("backup.remote.scan", s.jobRemoteScan)
	s.Jobs.Register("backup.run", s.jobRun)
	s.Jobs.Register("backup.plan", s.jobPlan)
	s.Jobs.Register("backup.upload", s.jobUpload)
	s.Jobs.Register("backup.delete", s.jobDelete)
	s.Jobs.Register("backup.restore", s.jobRestore)
	s.Jobs.Register("backup.import-db", s.jobImportDB)
	s.Jobs.Register("backup.mail", s.jobMailBackup)
	s.Jobs.Register("backup.mail.restore", s.jobMailRestore)
	s.Jobs.Register("backup.verify", s.jobVerify)
}

// Recover marks backups left "running" by a crash as failed.
func (s *Service) Recover(ctx context.Context) {
	s.DB.ExecContext(ctx, `UPDATE backups SET status=?, error=?, finished_at=? WHERE status=?`,
		StatusFailed, "panel yeniden başladı", time.Now().Unix(), StatusRunning)
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) helper(ctx context.Context, w io.Writer, stdin io.Reader, secrets []string, timeout time.Duration, args ...string) (exec.Result, error) {
	c := exec.Helper(s.ScriptsDir, "hp-backup.sh", args...)
	c.Output, c.Stdin, c.Secrets, c.Timeout = w, stdin, secrets, timeout
	if c.Timeout == 0 {
		c.Timeout = 6 * time.Hour // large sites over a throttled uplink
	}
	return s.Runner.Run(ctx, c)
}

func (s *Service) setting(ctx context.Context, key, def string) string {
	return store.GetSetting(ctx, s.DB, key, def)
}

func paramID(p map[string]any, key string) int64 {
	switch v := p[key].(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case int:
		return int64(v)
	}
	return 0
}

func paramStrings(p map[string]any, key string) []string {
	var out []string
	switch v := p[key].(type) {
	case []string:
		out = v
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

// --- remote settings ---

// RemoteSettings is the Ayarlar tab.
type RemoteSettings struct {
	Type          string // "" = not configured
	RootFolder    string
	ServerName    string
	Bwlimit       string
	Crypt         bool
	SharedDrive   string
	RcloneVersion string // "" = not installed
}

// Configured reports a usable remote.
func (r RemoteSettings) Configured() bool { return r.Type != "" && r.RcloneVersion != "" }

// Remote returns the current remote settings.
func (s *Service) Remote(ctx context.Context) RemoteSettings {
	return RemoteSettings{
		Type:          s.setting(ctx, setRemoteType, ""),
		RootFolder:    s.setting(ctx, setRootFolder, DefaultRootFolder),
		ServerName:    s.serverName(ctx),
		Bwlimit:       s.setting(ctx, setBwlimit, ""),
		Crypt:         s.setting(ctx, setCrypt, "") == "1",
		SharedDrive:   s.setting(ctx, setSharedID, ""),
		RcloneVersion: s.RcloneInstalled(ctx),
	}
}

func (s *Service) serverName(ctx context.Context) string {
	return s.setting(ctx, setServerName, DefaultServerName())
}

// RcloneInstalled returns the installed rclone version ("" = none).
func (s *Service) RcloneInstalled(ctx context.Context) string {
	if s.DryRun {
		return s.setting(ctx, setRcloneOK, "")
	}
	if _, err := os.Stat(RcloneBin); err != nil {
		return ""
	}
	res, err := s.Probe.Run(ctx, exec.Cmd{Name: RcloneBin, Args: []string{"version"}, Timeout: 10 * time.Second})
	if err != nil {
		return "?"
	}
	first, _, _ := strings.Cut(res.Stdout, "\n")
	return strings.TrimPrefix(strings.TrimSpace(first), "rclone ")
}

// SaveOptions stores the non-secret options (bandwidth limit, server name).
func (s *Service) SaveOptions(ctx context.Context, bwlimit, server string) error {
	bwlimit = strings.TrimSpace(bwlimit)
	server = strings.TrimSpace(server)
	if bwlimit != "" && !bwlimitRe.MatchString(bwlimit) {
		return errors.New("bant genişliği sınırı örn. 512K, 2M ya da 10M olmalı")
	}
	if !serverRe.MatchString(server) {
		return errors.New("sunucu adı yalnızca harf, rakam, . _ - içerebilir")
	}
	if err := store.SetSetting(ctx, s.DB, setBwlimit, bwlimit); err != nil {
		return err
	}
	return store.SetSetting(ctx, s.DB, setServerName, server)
}

// StartRcloneInstall queues the pinned rclone install.
func (s *Service) StartRcloneInstall(ctx context.Context) (int64, error) {
	return s.Jobs.Submit(ctx, jobs.Spec{Kind: "backup.rclone.install", TargetType: "backup", TargetID: "rclone",
		Summary: "rclone kurulumu (" + RcloneVersion + ")", Retryable: true})
}

func (s *Service) jobRcloneInstall(ctx context.Context, l *jobs.Log, _ map[string]any) error {
	l.Printf("rclone %s indiriliyor (resmi zip, SHA-256 doğrulanır)…", RcloneVersion)
	if _, err := s.helper(ctx, l, nil, nil, 15*time.Minute, "rclone-install"); err != nil {
		return err
	}
	if s.DryRun {
		store.SetSetting(ctx, s.DB, setRcloneOK, RcloneVersion+" (dry-run)")
	}
	l.Printf("Kurulu: %s", s.RcloneInstalled(ctx))
	return nil
}

func randomString(n int) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

// ConfigureRemote validates the Drive connection, writes rclone.conf through
// the helper and stores the settings. When crypt is on and no keys exist yet,
// new keys are generated and returned (shown once); existing keys are reused
// so older backups stay readable.
func (s *Service) ConfigureRemote(ctx context.Context, in RemoteInput) (*CryptSecret, error) {
	if s.RcloneInstalled(ctx) == "" {
		return nil, errors.New("önce rclone'u kurun")
	}
	in.RootFolder = strings.Trim(strings.TrimSpace(in.RootFolder), "/")
	if in.RootFolder == "" {
		in.RootFolder = DefaultRootFolder
	}
	if !ValidFolder(in.RootFolder) {
		return nil, errors.New("kök klasör yalnızca harf, rakam, . _ - ve / içerebilir")
	}
	in.ServerName = strings.TrimSpace(in.ServerName)
	if in.ServerName == "" {
		in.ServerName = DefaultServerName()
	}
	if !serverRe.MatchString(in.ServerName) {
		return nil, errors.New("sunucu adı yalnızca harf, rakam, . _ - içerebilir")
	}
	in.SharedDrive = strings.TrimSpace(in.SharedDrive)
	if in.SharedDrive != "" && !sharedRe.MatchString(in.SharedDrive) {
		return nil, errors.New("geçersiz Shared Drive ID")
	}
	clientID, clientSecret := strings.TrimSpace(in.ClientID), strings.TrimSpace(in.ClientSecret)
	var mode, payload string
	switch in.Type {
	case RemoteOAuth:
		mode = "drive-oauth"
		tok, err := ExtractToken(in.Token)
		if err != nil {
			return nil, err
		}
		payload = tok
		if (clientID == "") != (clientSecret == "") {
			return nil, errors.New("kendi OAuth istemcinizi kullanıyorsanız client ID ve secret birlikte girilmeli")
		}
		if clientID != "" && (!clientIDRe.MatchString(clientID) || !secretRe.MatchString(clientSecret)) {
			return nil, errors.New("geçersiz OAuth client ID/secret")
		}
	case RemoteSA:
		mode = "drive-sa"
		js, _, err := CheckServiceAccount(in.SAJSON)
		if err != nil {
			return nil, err
		}
		if in.SharedDrive == "" {
			return nil, errors.New("service account'ların kendi depolama kotası yok: bir Shared Drive ID girin ve hesabı o drive'a üye yapın")
		}
		payload = js
		clientID, clientSecret = "", ""
	default:
		return nil, errors.New("geçersiz bağlantı türü")
	}

	var keys *CryptSecret
	var fresh bool
	if in.Crypt {
		k, err := s.CryptKeys(ctx)
		if err != nil {
			return nil, err
		}
		if k == nil {
			k = &CryptSecret{Password: randomString(32), Salt: randomString(32)}
			fresh = true
		}
		keys = k
	}
	dash := func(v string) string {
		if v == "" {
			return "-"
		}
		return v
	}
	var pw, salt string
	if keys != nil {
		pw, salt = keys.Password, keys.Salt
	}
	stdin := strings.Join([]string{dash(pw), dash(salt), dash(clientID), dash(clientSecret), payload}, "\n") + "\n"
	cryptArg := "0"
	if in.Crypt {
		cryptArg = "1"
	}
	secrets := []string{payload}
	for _, v := range []string{pw, salt, clientSecret} {
		if v != "" {
			secrets = append(secrets, v)
		}
	}
	if _, err := s.helper(ctx, nil, strings.NewReader(stdin), secrets, time.Minute,
		"remote-config", mode, in.RootFolder, cryptArg, dash(in.SharedDrive)); err != nil {
		return nil, err
	}
	if fresh {
		b, _ := json.Marshal(keys)
		sealed, err := s.Box.Seal(b)
		if err != nil {
			return nil, err
		}
		if err := store.SetSetting(ctx, s.DB, setCryptKey, sealed); err != nil {
			return nil, err
		}
	}
	for k, v := range map[string]string{setRemoteType: in.Type, setRootFolder: in.RootFolder, setServerName: in.ServerName,
		setSharedID: in.SharedDrive, setCrypt: cryptArg} {
		if err := store.SetSetting(ctx, s.DB, k, v); err != nil {
			return nil, err
		}
	}
	if fresh {
		return keys, nil
	}
	return nil, nil
}

// CryptKeys returns the stored crypt keys (nil = none yet).
func (s *Service) CryptKeys(ctx context.Context) (*CryptSecret, error) {
	sealed := s.setting(ctx, setCryptKey, "")
	if sealed == "" {
		return nil, nil
	}
	b, err := s.Box.Open(sealed)
	if err != nil {
		return nil, fmt.Errorf("crypt anahtarı açılamadı: %w", err)
	}
	var k CryptSecret
	if err := json.Unmarshal(b, &k); err != nil {
		return nil, err
	}
	return &k, nil
}

// StartRemoteTest queues a write/read/delete round trip on the remote.
func (s *Service) StartRemoteTest(ctx context.Context) (int64, error) {
	if !s.Remote(ctx).Configured() {
		return 0, errors.New("uzak hedef yapılandırılmamış")
	}
	return s.Jobs.Submit(ctx, jobs.Spec{Kind: "backup.remote.test", TargetType: "backup", TargetID: "remote",
		Summary: "Google Drive bağlantı testi", Retryable: true})
}

func (s *Service) jobRemoteTest(ctx context.Context, l *jobs.Log, _ map[string]any) error {
	_, err := s.helper(ctx, l, nil, nil, 5*time.Minute, "remote-test", s.serverName(ctx))
	if err == nil {
		l.Printf("Bağlantı testi başarılı")
	}
	return err
}

// --- taking backups ---

func (s *Service) newName() string {
	var b [2]byte
	rand.Read(b[:])
	return s.now().Format("20060102-150405") + "-" + hex.EncodeToString(b[:])
}

// ManualInput is the "Şimdi yedekle" form.
type ManualInput struct {
	SiteID     int64
	Components []string
	Upload     bool // also send to the remote
}

func cleanComponents(in []string) ([]string, error) {
	var out []string
	for _, c := range AllComponents {
		if slices.Contains(in, c) {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("en az bir bileşen seçin")
	}
	return out, nil
}

// StartManual queues a manual backup of one site.
func (s *Service) StartManual(ctx context.Context, in ManualInput) (int64, error) {
	site, err := s.Sites.Store.Get(ctx, in.SiteID)
	if err != nil {
		return 0, errors.New("site bulunamadı")
	}
	comps, err := cleanComponents(in.Components)
	if err != nil {
		return 0, err
	}
	if in.Upload && !s.Remote(ctx).Configured() {
		return 0, errors.New("uzak hedef (Google Drive) yapılandırılmamış")
	}
	summary := "Yedek: " + site.Domain + " (" + strings.Join(comps, ", ") + ")"
	if in.Upload {
		summary += " → Drive"
	}
	return s.Jobs.Submit(ctx, jobs.Spec{Kind: "backup.run", TargetType: "site", TargetID: site.Domain, Summary: summary,
		Params: map[string]any{"site_id": site.ID, "components": comps, "upload": in.Upload}})
}

func (s *Service) jobRun(ctx context.Context, l *jobs.Log, p map[string]any) error {
	site, err := s.Sites.Store.Get(ctx, paramID(p, "site_id"))
	if err != nil {
		return fmt.Errorf("site bulunamadı: %w", err)
	}
	b, err := s.runBackup(ctx, l, site, KindManual, 0, paramStrings(p, "components"))
	if err != nil {
		return err
	}
	if up, _ := p["upload"].(bool); up {
		l.Progress(70)
		return s.upload(ctx, l, &b)
	}
	return nil
}

// siteDBs lists the site's databases that can be backed up (MSSQL first,
// then PostgreSQL).
func (s *Service) siteDBs(ctx context.Context, siteID int64) []ConfigDB {
	var out []ConfigDB
	if s.DBs != nil {
		list, _ := s.DBs.Store.Databases(ctx, databases.DBFilter{SiteID: siteID})
		for _, d := range list {
			if d.Status == databases.DBReady {
				out = append(out, ConfigDB{Name: d.Name, EnvKey: d.EnvKey})
			}
		}
	}
	if s.PG != nil {
		list, _ := s.PG.Store.Databases(ctx, pgsql.DBFilter{SiteID: siteID})
		for _, d := range list {
			if d.Status == pgsql.DBReady {
				out = append(out, ConfigDB{Name: d.Name, EnvKey: d.EnvKey, Engine: EnginePostgres})
			}
		}
	}
	return out
}

// runBackup takes one backup of site and records it.
func (s *Service) runBackup(ctx context.Context, l *jobs.Log, site sites.Site, kind string, planID int64, comps []string) (Backup, error) {
	comps, err := cleanComponents(comps)
	if err != nil {
		return Backup{}, err
	}
	active := s.Sites.Store.ActiveRelease(ctx, site.ID)
	if slices.Contains(comps, CompFiles) && (active == "" || active == sites.PlaceholderRelease) {
		l.Printf("%s: henüz deploy edilmiş sürüm yok, dosyalar atlandı", site.Domain)
		comps = slices.DeleteFunc(comps, func(c string) bool { return c == CompFiles })
	}
	var dbs []ConfigDB
	if slices.Contains(comps, CompDB) {
		if dbs = s.siteDBs(ctx, site.ID); len(dbs) == 0 {
			l.Printf("%s: siteye bağlı veritabanı yok, DB bileşeni atlandı", site.Domain)
			comps = slices.DeleteFunc(comps, func(c string) bool { return c == CompDB })
		}
	}
	if !slices.Contains(comps, CompConfig) {
		// config.json is always written (restore needs runtime + DB list), only
		// the env values and settings are left out.
		l.Printf("%s: ayarlar bileşeni seçilmedi; config.json yalnızca meta bilgiyle yazılır", site.Domain)
	}
	b := Backup{PlanID: planID, SiteID: site.ID, Domain: site.Domain, Name: s.newName(), Kind: kind,
		Components: comps, Status: StatusRunning, CreatedAt: s.now()}
	if err := s.Store.Insert(ctx, &b); err != nil {
		return b, err
	}
	s.Store.SetJob(ctx, b.ID, l.ID())
	l.Printf("Yedek başlıyor: %s/%s [%s]", site.Domain, b.Name, strings.Join(comps, ", "))

	size, err := s.create(ctx, l, site, b, active, dbs)
	if err != nil {
		rctx := context.WithoutCancel(ctx)
		s.helper(rctx, l, nil, nil, time.Minute, "delete", site.Domain, b.Name)
		s.Store.Finish(rctx, b.ID, StatusFailed, 0, false, err.Error())
		return b, fmt.Errorf("%s yedeği başarısız: %w", site.Domain, err)
	}
	b.Status, b.SizeBytes, b.Local = StatusSuccess, size, true
	s.Store.Finish(ctx, b.ID, StatusSuccess, size, true, "")
	l.Printf("Yedek tamam: %s/%s (%s)", site.Domain, b.Name, HumanSize(size))
	return b, nil
}

func (s *Service) create(ctx context.Context, l *jobs.Log, site sites.Site, b Backup, active string, dbs []ConfigDB) (int64, error) {
	var cfgDBs []ConfigDB
	var dbNames []string
	for _, d := range dbs {
		if d.IsPG() {
			l.Printf("PostgreSQL veritabanı yedekleniyor (pg_dump): %s", d.Name)
			if err := s.PG.DumpTo(ctx, l, d.Name, "hpbk-"+b.Name+"-"+d.Name); err != nil {
				return 0, fmt.Errorf("veritabanı %s: %w", d.Name, err)
			}
			dbNames = append(dbNames, "pg:"+d.Name)
		} else {
			path := mssqlBackupDir + "/hpbk-" + b.Name + "-" + d.Name + ".bak"
			l.Printf("Veritabanı yedekleniyor: %s", d.Name)
			if err := s.DBs.BackupTo(ctx, l, d.Name, path); err != nil {
				return 0, fmt.Errorf("veritabanı %s: %w", d.Name, err)
			}
			dbNames = append(dbNames, d.Name)
		}
		cfgDBs = append(cfgDBs, d)
	}
	var env map[string]string
	if b.Has(CompConfig) {
		var err error
		if env, err = s.Sites.Store.EnvSealed(ctx, site.ID); err != nil {
			return 0, err
		}
	}
	cfg := ConfigFor(site, active, env, cfgDBs)
	cfg.Crons, cfg.Git = s.configExtras(ctx, site.ID)
	if !b.Has(CompConfig) {
		cfg = SiteConfig{Version: 1, CreatedAt: cfg.CreatedAt, Domain: site.Domain, ShortName: site.ShortName,
			RuntimeID: site.RuntimeID, RuntimeVersion: site.RuntimeVersion, ActiveRelease: active, Databases: cfgDBs}
	}
	js, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return 0, err
	}
	if len(js) > maxConfigBytes {
		return 0, errors.New("site ayarları/ortam değişkenleri yedek için çok büyük (en fazla 200 KB)")
	}
	release := active
	if !b.Has(CompFiles) {
		release = "-"
	}
	args := append([]string{"create", site.Domain, b.Name, strings.Join(b.Components, ","), release}, dbNames...)
	res, err := s.helper(ctx, l, strings.NewReader(string(js)+"\n"), nil, 0, args...)
	if err != nil {
		return 0, err
	}
	var size int64
	if m := sizeLineRe.FindStringSubmatch(res.Stdout); m != nil {
		size, _ = strconv.ParseInt(m[1], 10, 64)
	}
	return size, nil
}

// --- upload / delete ---

// StartUpload queues sending a local backup to the remote.
func (s *Service) StartUpload(ctx context.Context, b Backup) (int64, error) {
	if !b.Local || b.Status != StatusSuccess {
		return 0, errors.New("yalnızca başarılı yerel yedekler gönderilebilir")
	}
	if !s.Remote(ctx).Configured() {
		return 0, errors.New("uzak hedef yapılandırılmamış")
	}
	return s.Jobs.Submit(ctx, jobs.Spec{Kind: "backup.upload", TargetType: "site", TargetID: b.Domain,
		Summary: "Drive'a gönder: " + b.Domain + "/" + b.Name, Params: map[string]any{"backup_id": b.ID}, Retryable: true})
}

func (s *Service) jobUpload(ctx context.Context, l *jobs.Log, p map[string]any) error {
	b, err := s.Store.Backup(ctx, paramID(p, "backup_id"))
	if err != nil {
		return errors.New("yedek bulunamadı")
	}
	return s.upload(ctx, l, &b)
}

func (s *Service) upload(ctx context.Context, l *jobs.Log, b *Backup) error {
	srv := s.serverName(ctx)
	bw := s.setting(ctx, setBwlimit, "")
	if bw == "" {
		bw = "0"
	}
	l.Printf("Drive'a gönderiliyor: %s/%s/%s", srv, b.Domain, b.Name)
	if _, err := s.helper(ctx, l, nil, nil, 0, "upload", srv, b.Domain, b.Name, bw); err != nil {
		return fmt.Errorf("%s yüklenemedi: %w", b.Domain, err)
	}
	b.Remote, b.RemoteSrv = true, srv
	return s.Store.SetUploaded(ctx, b.ID, srv)
}

// Where to delete.
const (
	WhereLocal  = "local"
	WhereRemote = "remote"
	WhereBoth   = "both"
)

// StartDelete queues deleting copies of a backup.
func (s *Service) StartDelete(ctx context.Context, b Backup, where string) (int64, error) {
	if b.Status == StatusRunning {
		return 0, errors.New("yedek hâlâ alınıyor")
	}
	switch where {
	case WhereLocal, WhereRemote, WhereBoth:
	default:
		return 0, errors.New("geçersiz seçim")
	}
	label := map[string]string{WhereLocal: "yerel kopya", WhereRemote: "Drive kopyası", WhereBoth: "tüm kopyalar"}[where]
	return s.Jobs.Submit(ctx, jobs.Spec{Kind: "backup.delete", TargetType: "site", TargetID: b.Domain,
		Summary: "Yedek siliniyor (" + label + "): " + b.Domain + "/" + b.Name, Params: map[string]any{"backup_id": b.ID, "where": where}})
}

func (s *Service) jobDelete(ctx context.Context, l *jobs.Log, p map[string]any) error {
	b, err := s.Store.Backup(ctx, paramID(p, "backup_id"))
	if err != nil {
		return errors.New("yedek bulunamadı")
	}
	where, _ := p["where"].(string)
	return s.deleteCopies(ctx, l, b, where == WhereLocal || where == WhereBoth, where == WhereRemote || where == WhereBoth)
}

// deleteCopies removes the local and/or remote copy; the row goes when no copy is left.
func (s *Service) deleteCopies(ctx context.Context, l *jobs.Log, b Backup, local, remote bool) error {
	if local && (b.Local || b.Status == StatusFailed) {
		if _, err := s.helper(ctx, l, nil, nil, 10*time.Minute, "delete", b.Domain, b.Name); err != nil {
			return err
		}
		b.Local = false
	}
	if remote && b.Remote {
		srv := b.RemoteSrv
		if srv == "" {
			srv = s.serverName(ctx)
		}
		if _, err := s.helper(ctx, l, nil, nil, 10*time.Minute, "remote-delete", srv, b.Domain, b.Name); err != nil {
			return err
		}
		b.Remote = false
	}
	l.Printf("Silindi: %s/%s (yerel: %v, Drive: %v kaldı)", b.Domain, b.Name, b.Local, b.Remote)
	return s.Store.SetLocation(ctx, b.ID, b.Local, b.Remote)
}

// --- plans ---

// ValidatePlan normalises p and computes its next run.
func (s *Service) ValidatePlan(ctx context.Context, p *Plan) error {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" || len(p.Name) > 100 {
		return errors.New("plan adı gerekli (en fazla 100 karakter)")
	}
	switch p.Scope {
	case ScopeMail:
		if err := s.mailReady(ctx); err != nil {
			return err
		}
		p.SiteIDs, p.Components = nil, []string{CompMail}
	case "all":
		p.SiteIDs = nil
	case "sites":
		if len(p.SiteIDs) == 0 {
			return errors.New("en az bir site seçin")
		}
		for _, id := range p.SiteIDs {
			if _, err := s.Sites.Store.Get(ctx, id); err != nil {
				return errors.New("seçilen site bulunamadı")
			}
		}
	default:
		return errors.New("geçersiz kapsam")
	}
	var err error
	if p.Scope != ScopeMail {
		if p.Components, err = cleanComponents(p.Components); err != nil {
			return err
		}
	}
	switch p.Destination {
	case DestLocal:
	case DestRemote, DestBoth:
		if s.setting(ctx, setRemoteType, "") == "" {
			return errors.New("önce Ayarlar sekmesinden Google Drive bağlantısını yapılandırın")
		}
	default:
		return errors.New("geçersiz hedef")
	}
	if p.KeepLocal < 0 || p.KeepLocal > 365 || p.KeepRemote < 0 || p.KeepRemote > 1000 || p.KeepRemoteDays < 0 || p.KeepRemoteDays > 3650 {
		return errors.New("saklama değerleri aralık dışında")
	}
	if p.Destination != DestRemote && p.KeepLocal < 1 {
		return errors.New("yerel hedefte en az 1 yedek saklanmalı")
	}
	next, err := NextRun(p.Schedule, s.now())
	if err != nil {
		return err
	}
	p.NextRunAt = next
	return nil
}

// SavePlan validates and stores p, then wakes the scheduler.
func (s *Service) SavePlan(ctx context.Context, p *Plan) error {
	if err := s.ValidatePlan(ctx, p); err != nil {
		return err
	}
	if err := s.Store.SavePlan(ctx, p); err != nil {
		return err
	}
	s.Reschedule()
	return nil
}

// DeletePlan removes a plan.
func (s *Service) DeletePlan(ctx context.Context, id int64) error {
	if err := s.Store.DeletePlan(ctx, id); err != nil {
		return err
	}
	s.Reschedule()
	return nil
}

// RunPlanNow queues a plan immediately (does not move its schedule).
func (s *Service) RunPlanNow(ctx context.Context, id int64) (int64, error) {
	p, err := s.Store.Plan(ctx, id)
	if err != nil {
		return 0, errors.New("plan bulunamadı")
	}
	return s.submitPlan(ctx, p, "elle")
}

// submitPlan queues a plan run unless one is already running.
func (s *Service) submitPlan(ctx context.Context, p Plan, why string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id, ok := s.planJob[p.ID]; ok && s.Jobs.IsActive(id) {
		return 0, errors.New("bu plan zaten çalışıyor")
	}
	id, err := s.Jobs.Submit(ctx, jobs.Spec{Kind: "backup.plan", TargetType: "backup", TargetID: p.Name,
		Summary: "Yedekleme planı (" + why + "): " + p.Name, Params: map[string]any{"plan_id": p.ID}})
	if err == nil {
		s.planJob[p.ID] = id
	}
	return id, err
}

func (s *Service) planSites(ctx context.Context, p Plan) ([]sites.Site, error) {
	all, err := s.Sites.Store.List(ctx, 0)
	if err != nil {
		return nil, err
	}
	var out []sites.Site
	for _, site := range all {
		if site.Status == sites.StatusProvisioning {
			continue
		}
		if p.Scope == "all" || slices.Contains(p.SiteIDs, site.ID) {
			out = append(out, site)
		}
	}
	return out, nil
}

func (s *Service) jobPlan(ctx context.Context, l *jobs.Log, params map[string]any) error {
	p, err := s.Store.Plan(ctx, paramID(params, "plan_id"))
	if err != nil {
		return errors.New("plan bulunamadı")
	}
	if p.Scope == ScopeMail {
		return s.jobMailPlan(ctx, l, p)
	}
	list, err := s.planSites(ctx, p)
	if err != nil {
		return err
	}
	l.Printf("Plan: %s — %d site, bileşenler: %s, hedef: %s", p.Name, len(list), strings.Join(p.Components, ", "), p.Destination)
	remote := p.Destination == DestRemote || p.Destination == DestBoth
	if remote && !s.Remote(ctx).Configured() {
		return errors.New("uzak hedef yapılandırılmamış (rclone/Drive)")
	}
	var failures []string
	for i, site := range list {
		if err := ctx.Err(); err != nil {
			return err
		}
		b, err := s.runBackup(ctx, l, site, KindScheduled, p.ID, p.Components)
		if err == nil && remote {
			err = s.upload(ctx, l, &b)
		}
		if err != nil {
			l.Printf("HATA: %v", err)
			failures = append(failures, site.Domain)
		}
		s.applyRetention(ctx, l, p, site.Domain)
		l.Progress((i + 1) * 100 / max(len(list), 1))
	}
	s.Store.SetPlanRun(ctx, p.ID, s.now(), p.NextRunAt)
	if len(failures) > 0 {
		return s.planFailed(ctx, l, p, fmt.Sprintf("%d/%d site yedeklenemedi: %s", len(failures), len(list), strings.Join(failures, ", ")))
	}
	return nil
}

// jobMailPlan runs a plan whose scope is the mail server.
func (s *Service) jobMailPlan(ctx context.Context, l *jobs.Log, p Plan) error {
	l.Printf("Plan: %s — posta sunucusu, hedef: %s", p.Name, p.Destination)
	remote := p.Destination == DestRemote || p.Destination == DestBoth
	if remote && !s.Remote(ctx).Configured() {
		return errors.New("uzak hedef yapılandırılmamış (rclone/Drive)")
	}
	b, err := s.runMailBackup(ctx, l, KindScheduled, p.ID)
	if err == nil && remote {
		l.Progress(60)
		err = s.upload(ctx, l, &b)
	}
	s.applyRetention(ctx, l, p, MailDomain)
	s.Store.SetPlanRun(ctx, p.ID, s.now(), p.NextRunAt)
	l.Progress(100)
	if err != nil {
		return s.planFailed(ctx, l, p, "posta sunucusu yedeklenemedi: "+err.Error())
	}
	return nil
}

// planFailed records and reports a failed plan run.
func (s *Service) planFailed(ctx context.Context, l *jobs.Log, p Plan, msg string) error {
	s.Activity.Record(ctx, logs.Entry{Action: "backup.failed", TargetType: "backup", TargetID: p.Name,
		Summary: "Yedekleme planı başarısız: " + p.Name, Status: logs.StatusFailed, Error: msg}, map[string]any{"job_id": l.ID()})
	if s.Notify != nil {
		s.Notify(ctx, notify.Event{Kind: notify.KindBackup, Key: fmt.Sprintf("backup:%d", p.ID),
			Title: "Yedekleme planı başarısız: " + p.Name, Text: msg})
	}
	return errors.New(msg)
}

// applyRetention deletes the plan's surplus copies of one site.
func (s *Service) applyRetention(ctx context.Context, l *jobs.Log, p Plan, domain string) {
	all, err := s.Store.Backups(ctx, Filter{PlanID: p.ID, Domain: domain, Limit: 5000})
	if err != nil {
		return
	}
	var ok []Backup
	for _, b := range all {
		if b.Status == StatusSuccess {
			ok = append(ok, b)
		}
	}
	keepLocal := p.KeepLocal
	if p.Destination == DestRemote {
		keepLocal = 0
	}
	local, remote := Prune(ok, keepLocal, p.KeepRemote, p.KeepRemoteDays, s.now())
	byID := map[int64]Backup{}
	for _, b := range ok {
		byID[b.ID] = b
	}
	del := map[int64][2]bool{}
	for _, id := range local {
		// Remote-only plans: a copy that never reached Drive stays local.
		if p.Destination == DestRemote && !byID[id].Remote {
			continue
		}
		v := del[id]
		v[0] = true
		del[id] = v
	}
	for _, id := range remote {
		v := del[id]
		v[1] = true
		del[id] = v
	}
	for _, b := range ok {
		v, hit := del[b.ID]
		if !hit {
			continue
		}
		l.Printf("Saklama: %s/%s siliniyor (yerel: %v, Drive: %v)", b.Domain, b.Name, v[0], v[1])
		if err := s.deleteCopies(ctx, l, b, v[0], v[1]); err != nil {
			l.Printf("Uyarı: silinemedi: %v", err)
		}
	}
}

// --- remote scan ---

// StartScan queues importing the remote's backup list.
func (s *Service) StartScan(ctx context.Context) (int64, error) {
	if !s.Remote(ctx).Configured() {
		return 0, errors.New("uzak hedef yapılandırılmamış")
	}
	return s.Jobs.Submit(ctx, jobs.Spec{Kind: "backup.remote.scan", TargetType: "backup", TargetID: "remote",
		Summary: "Drive'daki yedekler taranıyor", Retryable: true})
}

// manifest is the helper-written manifest.json.
type manifest struct {
	Domain     string   `json:"domain"`
	Name       string   `json:"name"`
	Components []string `json:"components"`
	Size       int64    `json:"size"`
}

func (s *Service) jobRemoteScan(ctx context.Context, l *jobs.Log, _ map[string]any) error {
	srv := s.serverName(ctx)
	res, err := s.helper(ctx, l, nil, nil, 10*time.Minute, "remote-list", srv)
	if err != nil {
		return err
	}
	added := 0
	for _, line := range strings.Split(res.Stdout, "\n") {
		domain, name, ok := strings.Cut(strings.Trim(strings.TrimSpace(line), "/"), "/")
		if !ok || !(sites.ValidDomain(domain) || domain == MailDomain) || !ValidName(name) || s.Store.Exists(ctx, domain, name) {
			continue
		}
		created, err := time.ParseInLocation("20060102-150405", name[:15], time.Local)
		if err != nil {
			continue
		}
		b := Backup{Domain: domain, Name: name, Kind: KindImported, Status: StatusSuccess, Remote: true, RemoteSrv: srv, CreatedAt: created}
		if mres, err := s.helper(ctx, nil, nil, nil, 2*time.Minute, "remote-manifest", srv, domain, name); err == nil {
			var m manifest
			if json.Unmarshal([]byte(mres.Stdout), &m) == nil {
				b.Components, b.SizeBytes = m.Components, m.Size
			}
		}
		if site, err := s.Sites.Store.GetByDomain(ctx, domain); err == nil {
			b.SiteID = site.ID
		}
		if err := s.Store.Insert(ctx, &b); err != nil {
			return err
		}
		s.Store.Finish(ctx, b.ID, StatusSuccess, b.SizeBytes, false, "")
		added++
		l.Printf("Kayda alındı: %s/%s", domain, name)
	}
	l.Printf("Tarama bitti: %d yeni yedek", added)
	return nil
}

// HumanSize formats bytes.
func HumanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

// --- import (.bak upload) ---

// SaveBakUpload streams an uploaded .bak into the upload dir.
func (s *Service) SaveBakUpload(r io.Reader, limit int64) (string, int64, error) {
	if err := os.MkdirAll(s.UploadDir, 0o750); err != nil {
		return "", 0, err
	}
	name := fmt.Sprintf("import-%d.bak", time.Now().UnixNano())
	path := filepath.Join(s.UploadDir, name)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return "", 0, err
	}
	n, err := io.Copy(f, io.LimitReader(r, limit+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > limit {
		err = fmt.Errorf("dosya çok büyük (en fazla %d MB)", limit>>20)
	}
	if err == nil && n == 0 {
		err = errors.New("dosya boş")
	}
	if err != nil {
		os.Remove(path)
		return "", 0, err
	}
	return name, n, nil
}

// DiscardUpload removes an upload that was not queued.
func (s *Service) DiscardUpload(name string) {
	if importRe.MatchString(name) {
		os.Remove(filepath.Join(s.UploadDir, name))
	}
}

// ImportDBInput is the Taşıma tab's .bak form.
type ImportDBInput struct {
	SiteID   int64
	Upload   string
	Name     string
	WriteEnv bool
	EnvKey   string
}

// StartImportDB queues restoring an uploaded .bak for the site's customer.
func (s *Service) StartImportDB(ctx context.Context, in ImportDBInput) (int64, error) {
	site, err := s.Sites.Store.Get(ctx, in.SiteID)
	if err != nil {
		return 0, errors.New("site bulunamadı")
	}
	in.Name = strings.TrimSpace(strings.ToLower(in.Name))
	if !databases.ValidName(in.Name) {
		return 0, databases.ErrName
	}
	if !importRe.MatchString(in.Upload) {
		return 0, errors.New("geçersiz yükleme")
	}
	if in.EnvKey != "" && !sites.ValidEnvKey(in.EnvKey) {
		return 0, errors.New("geçersiz değişken adı")
	}
	if s.DBs == nil || !s.DBs.Available(ctx) {
		return 0, errors.New("MSSQL sunucusu çalışmıyor")
	}
	return s.Jobs.Submit(ctx, jobs.Spec{Kind: "backup.import-db", TargetType: "site", TargetID: site.Domain,
		Summary: "Veritabanı içe aktarma (.bak): " + in.Name + " → " + site.Domain,
		Params:  map[string]any{"site_id": site.ID, "upload": in.Upload, "name": in.Name, "write_env": in.WriteEnv, "env_key": in.EnvKey}})
}

func (s *Service) jobImportDB(ctx context.Context, l *jobs.Log, p map[string]any) error {
	site, err := s.Sites.Store.Get(ctx, paramID(p, "site_id"))
	if err != nil {
		return errors.New("site bulunamadı")
	}
	upload, _ := p["upload"].(string)
	if !importRe.MatchString(upload) {
		return errors.New("geçersiz yükleme")
	}
	defer os.Remove(filepath.Join(s.UploadDir, upload))
	name, _ := p["name"].(string)
	writeEnv, _ := p["write_env"].(bool)
	envKey, _ := p["env_key"].(string)
	staged := "hpim-" + strconv.FormatInt(l.ID(), 10) + ".bak"
	if _, err := s.helper(ctx, l, nil, nil, 30*time.Minute, "stage-upload", filepath.Join(s.UploadDir, upload), staged); err != nil {
		return err
	}
	defer s.helper(context.WithoutCancel(ctx), l, nil, nil, time.Minute, "unstage", staged)
	d, err := s.DBs.RestoreFrom(ctx, l, mssqlBackupDir+"/"+staged, databases.CreateInput{CustomerID: site.CustomerID,
		Name: name, SiteID: site.ID, WriteEnv: writeEnv, EnvKey: envKey})
	if err != nil {
		return err
	}
	l.Printf("Veritabanı hazır: %s (sahibi %s)", d.Name, d.LoginName)
	if writeEnv && d.EnvKey != "" {
		l.Printf("Bağlantı dizesi %s değişkenine yazıldı; site yeniden başlatılınca geçerli olur", d.EnvKey)
	}
	return nil
}

// ImportEnv merges pasted KEY=VALUE lines into the site's env.
func (s *Service) ImportEnv(ctx context.Context, site sites.Site, text string) (string, int, error) {
	vals, err := ParseDotenv(text)
	if err != nil {
		return "", 0, err
	}
	cur, err := s.Sites.Env(ctx, site.ID)
	if err != nil {
		return "", 0, err
	}
	for k, v := range vals {
		cur[k] = v
	}
	diff, err := s.Sites.SaveEnv(ctx, site, cur)
	return diff, len(vals), err
}

// --- restore ---

// RestoreInput is the restore form.
type RestoreInput struct {
	BackupID   int64
	TargetID   int64
	Components []string // files, db, config
}

// RestoreTargets lists sites a backup can be restored into (same runtime).
func (s *Service) RestoreTargets(ctx context.Context, b Backup, runtimeID string) []sites.Site {
	all, _ := s.Sites.Store.List(ctx, 0)
	var out []sites.Site
	for _, site := range all {
		if site.Status == sites.StatusProvisioning {
			continue
		}
		if runtimeID == "" || site.RuntimeID == runtimeID || site.Domain == b.Domain {
			out = append(out, site)
		}
	}
	return out
}

// StartRestore validates and queues a restore.
func (s *Service) StartRestore(ctx context.Context, in RestoreInput) (int64, error) {
	b, err := s.Store.Backup(ctx, in.BackupID)
	if err != nil {
		return 0, errors.New("yedek bulunamadı")
	}
	if b.IsMail() {
		return 0, errors.New("posta sunucusu yedeği E-posta sayfasından geri yüklenir")
	}
	if b.Status != StatusSuccess || (!b.Local && !b.Remote) {
		return 0, errors.New("bu yedek geri yüklenemez")
	}
	if !b.Local && !s.Remote(ctx).Configured() {
		return 0, errors.New("yedek yalnızca Drive'da; önce uzak hedefi yapılandırın")
	}
	target, err := s.Sites.Store.Get(ctx, in.TargetID)
	if err != nil {
		return 0, errors.New("hedef site bulunamadı")
	}
	if target.Status == sites.StatusProvisioning {
		return 0, errors.New("hedef site hâlâ hazırlanıyor")
	}
	var comps []string
	for _, c := range []string{CompFiles, CompDB, CompConfig} {
		if slices.Contains(in.Components, c) && (b.Has(c) || len(b.Components) == 0) {
			comps = append(comps, c)
		}
	}
	if len(comps) == 0 {
		return 0, errors.New("geri yüklenecek bileşen seçin")
	}
	summary := "Geri yükleme: " + b.Domain + "/" + b.Name + " → " + target.Domain + " (" + strings.Join(comps, ", ") + ")"
	return s.Jobs.Submit(ctx, jobs.Spec{Kind: "backup.restore", TargetType: "site", TargetID: target.Domain, Summary: summary,
		Params: map[string]any{"backup_id": b.ID, "target_id": target.ID, "components": comps}})
}

// readConfig returns config.json of a local backup.
func (s *Service) readConfig(ctx context.Context, l *jobs.Log, b Backup) (SiteConfig, error) {
	res, err := s.helper(ctx, nil, nil, nil, time.Minute, "read-config", b.Domain, b.Name)
	if err != nil {
		return SiteConfig{}, err
	}
	if res.DryRun {
		// Dev: nothing on disk; describe the source site as it is now.
		src, err := s.Sites.Store.GetByDomain(ctx, b.Domain)
		if err != nil {
			return SiteConfig{}, errors.New("[DRY-RUN] kaynak site yok, config.json okunamadı")
		}
		env, _ := s.Sites.Store.EnvSealed(ctx, src.ID)
		dbs := s.siteDBs(ctx, src.ID)
		l.Printf("[DRY-RUN] config.json yerine kaynak sitenin güncel ayarları kullanılıyor")
		cfg := ConfigFor(src, s.Sites.Store.ActiveRelease(ctx, src.ID), env, dbs)
		cfg.Crons, cfg.Git = s.configExtras(ctx, src.ID)
		return cfg, nil
	}
	if res.Truncated {
		return SiteConfig{}, errors.New("config.json çok büyük")
	}
	return ParseConfig([]byte(res.Stdout))
}

func (s *Service) jobRestore(ctx context.Context, l *jobs.Log, p map[string]any) error {
	b, err := s.Store.Backup(ctx, paramID(p, "backup_id"))
	if err != nil {
		return errors.New("yedek bulunamadı")
	}
	target, err := s.Sites.Store.Get(ctx, paramID(p, "target_id"))
	if err != nil {
		return errors.New("hedef site bulunamadı")
	}
	comps := paramStrings(p, "components")
	clone := target.Domain != b.Domain
	if clone {
		l.Printf("Farklı siteye geri yükleme (klon): %s → %s", b.Domain, target.Domain)
	}

	// 1. Bring the backup here if it is only on the remote.
	if !b.Local {
		srv := b.RemoteSrv
		if srv == "" {
			srv = s.serverName(ctx)
		}
		l.Printf("Drive'dan indiriliyor: %s/%s/%s", srv, b.Domain, b.Name)
		if _, err := s.helper(ctx, l, nil, nil, 0, "download", srv, b.Domain, b.Name); err != nil {
			return err
		}
		b.Local = true
		s.Store.SetLocation(ctx, b.ID, true, b.Remote)
	} else if _, err := s.helper(ctx, l, nil, nil, 30*time.Minute, "verify", b.Domain, b.Name); err != nil {
		return err
	}
	l.Progress(10)

	cfg, err := s.readConfig(ctx, l, b)
	if err != nil {
		return err
	}
	if cfg.RuntimeID != target.RuntimeID {
		return fmt.Errorf("yedek %s altyapısında, hedef site %s: yalnızca aynı altyapıya geri yüklenebilir", cfg.RuntimeID, target.RuntimeID)
	}

	// 2. Safety net: back up the target as it is now.
	l.Printf("Hedefin mevcut hali yedekleniyor (geri yükleme öncesi)…")
	if _, err := s.runBackup(ctx, l, target, KindPreRestore, 0, []string{CompFiles, CompDB, CompConfig}); err != nil {
		return fmt.Errorf("geri yükleme öncesi yedek alınamadı, işlem durduruldu: %w", err)
	}
	l.Progress(30)

	// 3. Settings + env (before the DBs: their connection strings win).
	if slices.Contains(comps, CompConfig) {
		if err := s.restoreConfig(ctx, l, cfg, target); err != nil {
			return err
		}
	}
	l.Progress(45)

	// 4. Databases.
	if slices.Contains(comps, CompDB) && len(cfg.Databases) > 0 {
		if err := s.restoreDBs(ctx, l, b, cfg, target, clone); err != nil {
			return err
		}
	}
	l.Progress(60)

	// 5. Files: a new release through the deploy path (health check + fallback).
	target, _ = s.Sites.Store.Get(ctx, target.ID)
	if slices.Contains(comps, CompFiles) && b.Has(CompFiles) {
		err := s.Sites.RestoreRelease(ctx, l, target, func(ctx context.Context, release string) error {
			args := append([]string{"restore-files", b.Domain, b.Name, target.Domain, target.User(), release}, target.PersistentDirs...)
			_, err := s.helper(ctx, l, nil, nil, 0, args...)
			return err
		})
		if err != nil {
			return err
		}
	} else if target.Status == sites.StatusRunning {
		if _, err := s.Sites.Operate(ctx, target, sites.OpRestart); err != nil {
			l.Printf("Uyarı: yeniden başlatılamadı: %v", err)
		} else {
			l.Printf("Site yeniden başlatıldı")
		}
	}
	l.Printf("Geri yükleme tamamlandı: %s", target.Domain)
	return nil
}

// configExtras collects the site's crons and git settings for config.json.
func (s *Service) configExtras(ctx context.Context, siteID int64) ([]ConfigCron, *ConfigGit) {
	var out []ConfigCron
	if s.Crons != nil {
		list, _ := s.Crons.Store.BySite(ctx, siteID)
		for _, c := range list {
			out = append(out, ConfigCron{Name: c.Name, Schedule: c.Schedule, Command: c.Command, Enabled: c.Enabled, TimeoutSec: c.TimeoutSec})
		}
	}
	var g *ConfigGit
	if gs, err := s.Sites.Store.Git(ctx, siteID); err == nil {
		g = &ConfigGit{RepoURL: gs.RepoURL, Branch: gs.Branch, BuildCommand: gs.BuildCommand, OutputDir: gs.OutputDir, BuildTimeout: gs.BuildTimeout}
	}
	return out, g
}

// restoreExtras re-creates crons (missing ones, by name) and git settings
// (when the target has none). A clone gets its crons disabled so two sites
// don't run the same job. Problems are logged, not fatal.
func (s *Service) restoreExtras(ctx context.Context, l *jobs.Log, cfg SiteConfig, target sites.Site) {
	clone := cfg.Domain != target.Domain
	if s.Crons != nil && len(cfg.Crons) > 0 {
		existing, _ := s.Crons.Store.BySite(ctx, target.ID)
		have := map[string]bool{}
		for _, c := range existing {
			have[c.Name] = true
		}
		n := 0
		for _, c := range cfg.Crons {
			if have[c.Name] {
				continue
			}
			cr := crons.Cron{Name: c.Name, Schedule: c.Schedule, Command: c.Command, Enabled: c.Enabled && !clone, TimeoutSec: c.TimeoutSec}
			if _, err := s.Crons.Save(ctx, target, cr); err != nil {
				l.Printf("Uyarı: cron %q geri yüklenemedi: %v", c.Name, err)
				continue
			}
			n++
		}
		if n > 0 {
			msg := "Cron görevleri geri yüklendi (%d)"
			if clone {
				msg += " — klonda devre dışı; kontrol edip açın"
			}
			l.Printf(msg, n)
		}
	}
	if cfg.Git != nil {
		if _, err := s.Sites.Store.Git(ctx, target.ID); err == nil {
			return // target keeps its own git settings
		}
		g := sites.GitSettings{RepoURL: cfg.Git.RepoURL, Branch: cfg.Git.Branch, BuildCommand: cfg.Git.BuildCommand,
			OutputDir: cfg.Git.OutputDir, BuildTimeout: cfg.Git.BuildTimeout}
		if saved, err := s.Sites.SaveGit(ctx, target, g); err != nil {
			l.Printf("Uyarı: git ayarları geri yüklenemedi: %v", err)
		} else if saved.PublicKey != "" {
			l.Printf("Git ayarları geri yüklendi; yeni deploy key üretildi (repo'ya eklenmeli): %s", saved.PublicKey)
		} else {
			l.Printf("Git ayarları geri yüklendi")
		}
	}
}

func (s *Service) restoreConfig(ctx context.Context, l *jobs.Log, cfg SiteConfig, target sites.Site) error {
	in := cfg.SettingsFor(target)
	if prov, ok := s.Sites.Runtimes.Get(target.RuntimeID); ok && prov.Def().HasUnit() {
		installed, _ := prov.InstalledVersions(ctx)
		if !slices.Contains(installed, in.RuntimeVersion) {
			l.Printf("Uyarı: %s sürümü kurulu değil, hedefin sürümü (%s) korunuyor", in.RuntimeVersion, target.RuntimeVersion)
			in.RuntimeVersion = target.RuntimeVersion
		}
	}
	if _, err := s.Sites.UpdateSettings(ctx, target, in); err != nil {
		return fmt.Errorf("ayarlar uygulanamadı: %w", err)
	}
	l.Printf("Site ayarları uygulandı")
	s.restoreExtras(ctx, l, cfg, target)
	if cfg.EnvSealed == nil {
		return nil
	}
	env := make(map[string]string, len(cfg.EnvSealed))
	for k, v := range cfg.EnvSealed {
		plain, err := s.Box.OpenString(v)
		if err != nil {
			return errors.New("ortam değişkenleri açılamadı: yedek başka bir panelin master.key'i ile mühürlenmiş (aynı master.key'i kullanın ya da değişkenleri Taşıma sekmesinden girin)")
		}
		env[k] = plain
	}
	target, _ = s.Sites.Store.Get(ctx, target.ID)
	if _, err := s.Sites.SaveEnv(ctx, target, env); err != nil {
		return fmt.Errorf("ortam değişkenleri yazılamadı: %w", err)
	}
	l.Printf("Ortam değişkenleri geri yüklendi (%d)", len(env))
	return nil
}

// restoreDBs restores each backed-up database. Same site: under its own
// name. Clone: onto the target site's databases of the same engine in order,
// extra ones as new databases named after the target; connection strings are
// rewritten for the target.
func (s *Service) restoreDBs(ctx context.Context, l *jobs.Log, b Backup, cfg SiteConfig, target sites.Site, clone bool) error {
	var existMS, existPG []ConfigDB
	for _, d := range s.siteDBs(ctx, target.ID) {
		if d.IsPG() {
			existPG = append(existPG, d)
		} else {
			existMS = append(existMS, d)
		}
	}
	nMS, nPG := 0, 0
	for _, src := range cfg.Databases {
		pg := src.IsPG()
		if pg && (s.PG == nil || !s.PG.Available(ctx)) {
			return errors.New("PostgreSQL sunucusu çalışmıyor, veritabanları geri yüklenemedi")
		}
		if !pg && (s.DBs == nil || !s.DBs.Available(ctx)) {
			return errors.New("MSSQL sunucusu çalışmıyor, veritabanları geri yüklenemedi")
		}
		name := src.Name
		if clone {
			if pg {
				if nPG < len(existPG) {
					name = existPG[nPG].Name
				} else {
					name = s.freePGName(ctx, pgsql.DBBase(target.ShortName))
				}
				nPG++
			} else {
				if nMS < len(existMS) {
					name = existMS[nMS].Name
				} else {
					name = s.freeDBName(ctx, databases.DBBase(target.ShortName))
				}
				nMS++
			}
		}
		l.Printf("Veritabanı geri yükleniyor: %s → %s", src.Name, name)
		if pg {
			_, err := s.PG.RestoreFrom(ctx, l, pgsql.Source{Domain: b.Domain, Backup: b.Name, DB: src.Name},
				pgsql.CreateInput{CustomerID: target.CustomerID, Name: name, SiteID: target.ID, WriteEnv: true, EnvKey: src.EnvKey})
			if err != nil {
				return fmt.Errorf("veritabanı %s: %w", name, err)
			}
			continue
		}
		staged := "hprs-" + b.Name + "-" + src.Name + ".bak"
		if _, err := s.helper(ctx, l, nil, nil, 30*time.Minute, "stage-db", b.Domain, b.Name, src.Name, staged); err != nil {
			return err
		}
		_, err := s.DBs.RestoreFrom(ctx, l, mssqlBackupDir+"/"+staged, databases.CreateInput{CustomerID: target.CustomerID,
			Name: name, SiteID: target.ID, WriteEnv: true, EnvKey: src.EnvKey})
		s.helper(context.WithoutCancel(ctx), l, nil, nil, time.Minute, "unstage", staged)
		if err != nil {
			return fmt.Errorf("veritabanı %s: %w", name, err)
		}
	}
	return nil
}

func (s *Service) freePGName(ctx context.Context, base string) string {
	name := base
	for i := 2; s.PG.Store.DBNameTaken(ctx, name); i++ {
		name = fmt.Sprintf("%s_%d", base, i)
	}
	return name
}

func (s *Service) freeDBName(ctx context.Context, base string) string {
	name := base
	for i := 2; s.DBs.Store.DBNameTaken(ctx, name); i++ {
		name = fmt.Sprintf("%s_%d", base, i)
	}
	return name
}
