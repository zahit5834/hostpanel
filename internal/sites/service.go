package sites

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"hostpanel/internal/crypto"
	"hostpanel/internal/exec"
	"hostpanel/internal/jobs"
	"hostpanel/internal/logs"
	"hostpanel/internal/runtimes"
)

// KeepReleases is how many releases stay on disk (plus the active one).
const KeepReleases = 5

// Service provisions and operates sites. Every privileged action goes through
// Runner + exec.Helper; the service itself never touches system files.
type Service struct {
	Store        *Store
	Box          *crypto.Box
	Runner       exec.Runner // privileged helpers (dry-run in dev)
	Probe        exec.Runner // unprivileged read-only commands (journalctl)
	Runtimes     *runtimes.Registry
	Jobs         *jobs.Manager
	Activity     *logs.Activity
	Log          *slog.Logger
	ScriptsDir   string
	TemplatesDir string
	UploadDir    string
	DryRun       bool

	// CertFor returns the site's active certificate for nginx (nil: none).
	// Injected by the ssl package so sites does not depend on it.
	CertFor func(ctx context.Context, siteID int64) *TLSPaths
	// ProbeToken is served at /.well-known/hostpanel-probe for SSL pre-checks.
	ProbeToken string
	// DeleteHook runs inside the site delete job before the site row is
	// removed (databases inject "drop the site's databases"). The site lock is
	// held: the hook must not call SaveEnv/Operate.
	DeleteHook func(ctx context.Context, l *jobs.Log, site Site, params map[string]any) error

	locks sync.Map // site id → *sync.Mutex: one mutating operation per site at a time
}

// Register binds the site job kinds.
func (s *Service) Register() {
	s.Jobs.Register("site.create", s.jobCreate)
	s.Jobs.Register("site.deploy", s.jobDeploy)
	s.Jobs.Register("site.delete", s.jobDelete)
	s.Jobs.Register("runtime.install", s.jobRuntime("install"))
	s.Jobs.Register("runtime.remove", s.jobRuntime("remove"))
}

// Lock serialises mutating operations on one site (also used by the ssl package).
func (s *Service) Lock(id int64) func() { return s.lock(id) }

func (s *Service) lock(id int64) func() {
	m, _ := s.locks.LoadOrStore(id, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// helper runs a root helper script, streaming output to w (may be nil).
func (s *Service) helper(ctx context.Context, w io.Writer, stdin io.Reader, secrets []string, name string, args ...string) error {
	c := exec.Helper(s.ScriptsDir, name, args...)
	c.Output, c.Stdin, c.Secrets = w, stdin, secrets
	c.Timeout = 5 * time.Minute
	_, err := s.Runner.Run(ctx, c)
	return err
}

func (s *Service) provider(site Site) (runtimes.Provider, error) {
	p, ok := s.Runtimes.Get(site.RuntimeID)
	if !ok {
		return nil, fmt.Errorf("altyapı tanımı bulunamadı: %s", site.RuntimeID)
	}
	return p, nil
}

func (s *Service) vars(site Site) runtimes.Vars {
	return runtimes.Vars{Domain: site.Domain, Port: site.Port, Version: site.RuntimeVersion, SiteDir: site.Dir(), Fields: site.Fields}
}

// --- create ---

// CreateInput is what the wizard submits.
type CreateInput struct {
	CustomerID     int64
	Domain         string
	Aliases        string
	WWWMode        string
	RuntimeID      string
	RuntimeVersion string
	Fields         map[string]string
	MemoryMaxMB    int
	CPUQuotaPct    int
	PersistentDirs string
}

// Prepare validates input and builds the Site (without saving it).
func (s *Service) Prepare(ctx context.Context, in CreateInput) (Site, error) {
	site := Site{
		CustomerID:  in.CustomerID,
		Domain:      NormalizeDomain(in.Domain),
		WWWMode:     in.WWWMode,
		RuntimeID:   in.RuntimeID,
		MemoryMaxMB: in.MemoryMaxMB,
		CPUQuotaPct: in.CPUQuotaPct,
		Status:      StatusProvisioning,
		HealthPath:  "/",
		MaxUploadMB: 50,
		Gzip:        true,
	}
	if site.CustomerID <= 0 {
		return site, errors.New("müşteri seçin")
	}
	if !ValidDomain(site.Domain) {
		return site, errors.New("geçersiz domain")
	}
	if strings.HasPrefix(site.Domain, "www.") {
		return site, errors.New("domain'i www. olmadan girin; www otomatik eklenir")
	}
	if _, err := s.Store.GetByDomain(ctx, site.Domain); err == nil {
		return site, errors.New("bu domain zaten kayıtlı")
	}
	var err error
	if site.Aliases, err = ParseAliases(in.Aliases, site.Domain); err != nil {
		return site, err
	}
	switch site.WWWMode {
	case WWWNone, WWWToWWW, WWWToApex:
	case "":
		site.WWWMode = WWWNone
	default:
		return site, errors.New("geçersiz www seçeneği")
	}
	p, ok := s.Runtimes.Get(in.RuntimeID)
	if !ok {
		return site, errors.New("altyapı seçin")
	}
	def := p.Def()
	if def.Type == runtimes.TypeFastCGI {
		return site, errors.New("bu altyapı henüz desteklenmiyor")
	}
	if def.Type == runtimes.TypeProxy {
		installed, _ := p.InstalledVersions(ctx)
		if !contains(installed, in.RuntimeVersion) {
			return site, errors.New("seçilen sürüm sunucuda kurulu değil; önce Altyapılar sayfasından kurun")
		}
		site.RuntimeVersion = in.RuntimeVersion
	}
	if site.Fields, err = p.ValidateFields(in.Fields); err != nil {
		return site, err
	}
	if site.MemoryMaxMB < 64 || site.MemoryMaxMB > 65536 {
		return site, errors.New("bellek limiti 64–65536 MB olmalı")
	}
	if site.CPUQuotaPct < 5 || site.CPUQuotaPct > 1600 {
		return site, errors.New("CPU kotası %5–%1600 olmalı")
	}
	if site.PersistentDirs, err = ParsePersistentDirs(in.PersistentDirs); err != nil {
		return site, err
	}
	site.ShortName = UniqueShortName(site.Domain, func(n string) bool { return s.Store.ShortNameTaken(ctx, n) })
	if def.Type == runtimes.TypeProxy {
		used, err := s.Store.UsedPorts(ctx)
		if err != nil {
			return site, err
		}
		if site.Port, err = FreePort(used); err != nil {
			return site, err
		}
		if _, err := p.StartArgs(s.vars(site)); err != nil {
			return site, err
		}
	}
	return site, nil
}

// Create validates, stores the site and starts the provisioning job.
func (s *Service) Create(ctx context.Context, in CreateInput) (Site, int64, error) {
	site, err := s.Prepare(ctx, in)
	if err != nil {
		return site, 0, err
	}
	if err := s.Store.Insert(ctx, &site); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return site, 0, errors.New("domain, kısa ad veya port çakıştı; tekrar deneyin")
		}
		return site, 0, err
	}
	jobID, err := s.Jobs.Submit(ctx, jobs.Spec{
		Kind: "site.create", TargetType: "site", TargetID: site.Domain,
		Summary: "Site oluşturuluyor: " + site.Domain + " (" + site.RuntimeID + ")",
		Params:  map[string]any{"site_id": site.ID},
	})
	if err != nil {
		s.Store.Delete(ctx, site.ID)
		return site, 0, err
	}
	return site, jobID, nil
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

func (s *Service) jobCreate(ctx context.Context, l *jobs.Log, p map[string]any) error {
	site, err := s.Store.Get(ctx, paramID(p, "site_id"))
	if err != nil {
		return fmt.Errorf("site bulunamadı: %w", err)
	}
	defer s.lock(site.ID)()
	prov, err := s.provider(site)
	if err != nil {
		return err
	}
	def := prov.Def()
	sg := &saga{log: l}
	fail := func(err error) error {
		sg.rollback()
		s.Store.Delete(context.Background(), site.ID)
		l.Printf("Site kaydı silindi.")
		return err
	}
	if err := sg.step("Linux kullanıcısı: "+site.User(), func() error {
		return s.helper(ctx, l, nil, nil, "hp-site-user.sh", "create", site.User(), site.Domain)
	}, func(c context.Context) error {
		return s.helper(c, l, nil, nil, "hp-site-user.sh", "delete", site.User(), site.Domain)
	}); err != nil {
		return fail(err)
	}
	l.Progress(20)
	if err := sg.step("Dizin yapısı: "+site.Dir(), func() error {
		return s.helper(ctx, l, nil, nil, "hp-site-dirs.sh", "create", site.Domain, site.User())
	}, func(c context.Context) error {
		return s.helper(c, l, nil, nil, "hp-site-dirs.sh", "delete", site.Domain)
	}); err != nil {
		return fail(err)
	}
	s.Store.AddRelease(ctx, &Release{SiteID: site.ID, Name: PlaceholderRelease, Status: ReleaseActive})
	l.Progress(40)
	if def.Type == runtimes.TypeProxy {
		if err := sg.step("Ortam değişkenleri dosyası", func() error {
			return s.writeEnv(ctx, l, site, nil)
		}, func(c context.Context) error {
			return s.helper(c, l, nil, nil, "hp-site-env.sh", "delete", site.Domain)
		}); err != nil {
			return fail(err)
		}
		if err := sg.step("systemd servisi: "+site.Unit(), func() error {
			return s.installUnit(ctx, l, site)
		}, func(c context.Context) error {
			return s.helper(c, l, nil, nil, "hp-site-unit.sh", "remove", site.ShortName)
		}); err != nil {
			return fail(err)
		}
	}
	l.Progress(70)
	if err := sg.step("nginx yapılandırması", func() error {
		return s.applyNginx(ctx, l, site, ModePlaceholder)
	}, nil); err != nil {
		return fail(err)
	}
	s.Store.SetStatus(ctx, site.ID, StatusAwaitingDeploy)
	l.Printf("Site hazır. İlk deploy'a kadar \"yakında\" sayfası gösterilir.")
	if def.Type == runtimes.TypeProxy {
		l.Printf("Uygulama portu: 127.0.0.1:%d", site.Port)
	}
	return nil
}

// installUnit asks the root helper to render the systemd unit from validated arguments.
func (s *Service) installUnit(ctx context.Context, w io.Writer, site Site) error {
	prov, err := s.provider(site)
	if err != nil {
		return err
	}
	argv, err := prov.StartArgs(s.vars(site))
	if err != nil {
		return err
	}
	args := []string{"install", site.Domain, site.ShortName, prov.Def().SystemdTemplate,
		strconv.Itoa(site.MemoryMaxMB), strconv.Itoa(site.CPUQuotaPct), "--"}
	return s.helper(ctx, w, nil, nil, "hp-site-unit.sh", append(args, argv...)...)
}

// applyNginx renders and installs the site's nginx config for mode.
// The helper validates it, runs nginx -t and restores the old file on failure.
func (s *Service) applyNginx(ctx context.Context, w io.Writer, site Site, mode string) error {
	prov, err := s.provider(site)
	if err != nil {
		return err
	}
	conf, err := RenderNginx(s.TemplatesDir, prov.Def().NginxTemplate, s.nginxData(ctx, site, prov.Def(), mode))
	if err != nil {
		return err
	}
	return s.helper(ctx, w, strings.NewReader(conf), nil, "hp-nginx-site.sh", "install", site.Domain)
}

// ApplyNginx re-renders and installs the config for the site's current status
// (after a certificate change). The caller holds Lock(site.ID).
func (s *Service) ApplyNginx(ctx context.Context, w io.Writer, site Site) error {
	return s.applyNginx(ctx, w, site, ModeFor(site.Status))
}

func (s *Service) nginxData(ctx context.Context, site Site, def *runtimes.Definition, mode string) NginxData {
	d := NginxDataFor(site, def, mode, s.TemplatesDir)
	if probeTokenRe.MatchString(s.ProbeToken) {
		d.ProbeToken = s.ProbeToken
	}
	if s.CertFor != nil {
		d.TLS = s.CertFor(ctx, site.ID)
	}
	return d
}

var probeTokenRe = regexp.MustCompile(`^[a-f0-9]{16,64}$`)

// RenderNginxFor returns the config that would be installed (for the UI preview / diff).
func (s *Service) RenderNginxFor(site Site) (string, error) {
	prov, err := s.provider(site)
	if err != nil {
		return "", err
	}
	return RenderNginx(s.TemplatesDir, prov.Def().NginxTemplate, s.nginxData(context.Background(), site, prov.Def(), ModeFor(site.Status)))
}

// --- env ---

// Env returns decrypted user-defined env values.
func (s *Service) Env(ctx context.Context, siteID int64) (map[string]string, error) {
	sealed, err := s.Store.EnvSealed(ctx, siteID)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(sealed))
	for k, v := range sealed {
		pt, err := s.Box.OpenString(v)
		if err != nil {
			return nil, fmt.Errorf("%s çözülemedi: %w", k, err)
		}
		out[k] = pt
	}
	return out, nil
}

// writeEnv writes runtime env + user env (user wins, except the runtime's own
// keys like ASPNETCORE_URLS/PORT that the panel must control).
func (s *Service) writeEnv(ctx context.Context, w io.Writer, site Site, user map[string]string) error {
	prov, err := s.provider(site)
	if err != nil {
		return err
	}
	runtimeEnv := prov.Env(s.vars(site))
	merged := map[string]string{}
	for k, v := range user {
		merged[k] = v
	}
	for k, v := range runtimeEnv {
		merged[k] = v
	}
	keys := make([]string, 0, len(merged))
	for k := range merged {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	secrets := make([]string, 0, len(user))
	for _, k := range keys {
		b.WriteString(k + "=" + merged[k] + "\n")
	}
	for _, v := range user {
		secrets = append(secrets, v)
	}
	return s.helper(ctx, w, strings.NewReader(b.String()), secrets, "hp-site-env.sh", "write", site.Domain)
}

// SaveEnv validates, stores (sealed) and writes the env file. It returns the
// key-level diff for the activity log (values are never logged).
func (s *Service) SaveEnv(ctx context.Context, site Site, values map[string]string) (string, error) {
	defer s.lock(site.ID)()
	prov, err := s.provider(site)
	if err != nil {
		return "", err
	}
	reserved := prov.Env(s.vars(site))
	for k, v := range values {
		if !ValidEnvKey(k) {
			return "", fmt.Errorf("geçersiz değişken adı: %s", k)
		}
		if !ValidEnvValue(v) {
			return "", fmt.Errorf("%s: değer tek satır olmalı (en fazla 8 KB)", k)
		}
		if _, ok := reserved[k]; ok {
			return "", fmt.Errorf("%s panel tarafından yönetiliyor, değiştirilemez", k)
		}
	}
	old, err := s.Env(ctx, site.ID)
	if err != nil {
		return "", err
	}
	sealed := make(map[string]string, len(values))
	for k, v := range values {
		if sealed[k], err = s.Box.SealString(v); err != nil {
			return "", err
		}
	}
	if prov.Def().Type == runtimes.TypeProxy {
		if err := s.writeEnv(ctx, nil, site, values); err != nil {
			return "", err
		}
	}
	if err := s.Store.ReplaceEnv(ctx, site.ID, sealed); err != nil {
		return "", err
	}
	return envDiff(old, values), nil
}

func envDiff(old, cur map[string]string) string {
	var keys []string
	seen := map[string]bool{}
	for k := range old {
		keys, seen[k] = append(keys, k), true
	}
	for k := range cur {
		if !seen[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var out []string
	for _, k := range keys {
		ov, inOld := old[k]
		nv, inNew := cur[k]
		switch {
		case !inOld:
			out = append(out, "+ "+k+"=***")
		case !inNew:
			out = append(out, "- "+k)
		case ov != nv:
			out = append(out, "- "+k+"=*** (eski)", "+ "+k+"=*** (yeni)")
		}
	}
	return strings.Join(out, "\n")
}

// --- lifecycle operations (fast, run synchronously) ---

// Op names accepted by Operate.
const (
	OpStart            = "start"
	OpStop             = "stop"
	OpRestart          = "restart"
	OpMaintenanceOn    = "maintenance-on"
	OpMaintenanceOff   = "maintenance-off"
	OpDisable          = "disable"
	OpEnable           = "enable"
	OpReapplyNginx     = "nginx"
	OpReinstallService = "service"
)

// Operate performs a lifecycle action and returns the new status.
func (s *Service) Operate(ctx context.Context, site Site, op string) (string, error) {
	defer s.lock(site.ID)()
	prov, err := s.provider(site)
	if err != nil {
		return site.Status, err
	}
	proxy := prov.Def().Type == runtimes.TypeProxy
	hasRelease := s.Store.ActiveRelease(ctx, site.ID) != PlaceholderRelease
	svc := func(action string) error {
		if !proxy {
			return nil
		}
		return s.helper(ctx, nil, nil, nil, "hp-site-service.sh", action, site.ShortName)
	}
	next := site.Status
	switch op {
	case OpStart, OpEnable, OpMaintenanceOff:
		if !hasRelease {
			return site.Status, errors.New("önce bir sürüm deploy edin")
		}
		if op == OpEnable {
			if err := svc("enable"); err != nil {
				return site.Status, err
			}
		}
		// start is idempotent; it also covers leaving maintenance while the app was stopped.
		if err := svc("start"); err != nil {
			return site.Status, err
		}
		next = StatusRunning
	case OpStop:
		if err := svc("stop"); err != nil {
			return site.Status, err
		}
		next = StatusStopped
	case OpRestart:
		if !hasRelease {
			return site.Status, errors.New("önce bir sürüm deploy edin")
		}
		if err := svc("restart"); err != nil {
			return site.Status, err
		}
		next = StatusRunning
	case OpMaintenanceOn:
		next = StatusMaintenance
	case OpDisable:
		if err := svc("stop"); err != nil {
			return site.Status, err
		}
		if err := svc("disable"); err != nil {
			return site.Status, err
		}
		next = StatusDisabled
	case OpReapplyNginx:
	case OpReinstallService:
		if !proxy {
			return site.Status, errors.New("statik sitede servis yok")
		}
		if err := s.installUnit(ctx, nil, site); err != nil {
			return site.Status, err
		}
		if site.Status == StatusRunning {
			if err := svc("restart"); err != nil {
				return site.Status, err
			}
		}
	default:
		return site.Status, fmt.Errorf("bilinmeyen işlem: %s", op)
	}
	site.Status = next
	if err := s.applyNginx(ctx, nil, site, ModeFor(next)); err != nil {
		return next, err
	}
	return next, s.Store.SetStatus(ctx, site.ID, next)
}

// --- deploy ---

// SaveUpload streams an uploaded zip to the upload dir without buffering it in
// memory. It returns the stored file name and its size.
func (s *Service) SaveUpload(r io.Reader, limit int64) (string, int64, error) {
	if err := os.MkdirAll(s.UploadDir, 0o750); err != nil {
		return "", 0, err
	}
	f, err := os.CreateTemp(s.UploadDir, "upload-*.zip")
	if err != nil {
		return "", 0, err
	}
	name := filepath.Base(f.Name())
	n, err := io.Copy(f, io.LimitReader(r, limit+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > limit {
		err = fmt.Errorf("dosya çok büyük (en fazla %d MB)", limit>>20)
	}
	if err == nil {
		err = checkZipMagic(f.Name())
	}
	if err != nil {
		os.Remove(f.Name())
		return "", 0, err
	}
	return name, n, nil
}

func checkZipMagic(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var b [4]byte
	if _, err := io.ReadFull(f, b[:]); err != nil || string(b[:]) != "PK\x03\x04" {
		return errors.New("dosya geçerli bir zip değil")
	}
	return nil
}

// StartDeploy queues a deploy (from an uploaded zip) or a rollback (release != "").
func (s *Service) StartDeploy(ctx context.Context, site Site, upload string, size int64, rollbackTo string) (int64, error) {
	summary := "Zip deploy: " + site.Domain
	params := map[string]any{"site_id": site.ID}
	if rollbackTo != "" {
		summary = "Geri dönüş: " + site.Domain + " → " + rollbackTo
		params["rollback"] = rollbackTo
	} else {
		params["upload"] = upload
		params["size"] = size
	}
	return s.Jobs.Submit(ctx, jobs.Spec{Kind: "site.deploy", TargetType: "site", TargetID: site.Domain, Summary: summary, Params: params})
}

var uploadNameOK = func(n string) bool {
	return strings.HasPrefix(n, "upload-") && strings.HasSuffix(n, ".zip") && !strings.ContainsAny(n, "/\\") && !strings.Contains(n, "..")
}

func (s *Service) jobDeploy(ctx context.Context, l *jobs.Log, p map[string]any) error {
	site, err := s.Store.Get(ctx, paramID(p, "site_id"))
	if err != nil {
		return fmt.Errorf("site bulunamadı: %w", err)
	}
	defer s.lock(site.ID)()
	prov, err := s.provider(site)
	if err != nil {
		return err
	}
	proxy := prov.Def().Type == runtimes.TypeProxy
	previous := s.Store.ActiveRelease(ctx, site.ID)
	rollbackTo, _ := p["rollback"].(string)
	release := rollbackTo

	if rollbackTo == "" {
		upload, _ := p["upload"].(string)
		if !uploadNameOK(upload) {
			return errors.New("geçersiz yükleme dosyası")
		}
		uploadPath := filepath.Join(s.UploadDir, upload)
		defer os.Remove(uploadPath)
		release = time.Now().Format("20060102-150405")
		size, _ := p["size"].(float64)
		rel := &Release{SiteID: site.ID, Name: release, Size: int64(size), Status: ReleasePrevious, JobID: l.ID()}
		if err := s.Store.AddRelease(ctx, rel); err != nil {
			return err
		}
		l.Printf("Yeni sürüm: %s (%d KB)", release, int64(size)/1024)
		args := append([]string{"extract", site.Domain, site.User(), uploadPath, release}, site.PersistentDirs...)
		if err := s.helper(ctx, l, nil, nil, "hp-site-deploy.sh", args...); err != nil {
			s.Store.SetReleaseStatus(ctx, site.ID, release, ReleaseFailed)
			return err
		}
		l.Progress(40)
	} else {
		l.Printf("Önceki sürüme dönülüyor: %s", rollbackTo)
	}

	activate := func(name string) error {
		if err := s.helper(ctx, l, nil, nil, "hp-site-deploy.sh", "activate", site.Domain, name); err != nil {
			return err
		}
		return s.Store.MarkActive(ctx, site.ID, name)
	}
	if err := activate(release); err != nil {
		return err
	}
	l.Progress(60)

	if proxy {
		if err := s.helper(ctx, l, nil, nil, "hp-site-service.sh", "restart", site.ShortName); err != nil {
			return s.revert(ctx, l, site, release, previous, err)
		}
		l.Progress(70)
		if err := s.healthCheck(ctx, l, site); err != nil {
			return s.revert(ctx, l, site, release, previous, err)
		}
	}
	l.Progress(85)
	newStatus := site.Status
	if site.Status == StatusAwaitingDeploy || site.Status == StatusError || site.Status == StatusStopped {
		newStatus = StatusRunning
	}
	site.Status = newStatus
	if err := s.applyNginx(ctx, l, site, ModeFor(newStatus)); err != nil {
		return err
	}
	s.Store.SetStatus(ctx, site.ID, newStatus)
	if err := s.helper(ctx, l, nil, nil, "hp-site-deploy.sh", "prune", site.Domain, strconv.Itoa(KeepReleases)); err != nil {
		l.Printf("Uyarı: eski sürümler temizlenemedi: %v", err)
	} else {
		s.markPruned(ctx, site.ID)
	}
	l.Printf("Yayında: %s", release)
	return nil
}

// markPruned mirrors the helper's prune policy in the DB.
func (s *Service) markPruned(ctx context.Context, siteID int64) {
	rels, _ := s.Store.Releases(ctx, siteID)
	kept := 0
	for _, r := range rels {
		if r.Name == PlaceholderRelease || r.Status == ReleasePruned || r.Status == ReleaseActive {
			continue
		}
		if kept++; kept > KeepReleases {
			s.Store.SetReleaseStatus(ctx, siteID, r.Name, ReleasePruned)
		}
	}
}

// revert switches back to the previous release after a failed deploy.
func (s *Service) revert(ctx context.Context, l *jobs.Log, site Site, failed, previous string, cause error) error {
	l.Printf("HATA: %v", cause)
	s.Store.SetReleaseStatus(ctx, site.ID, failed, ReleaseFailed)
	if previous == "" || previous == failed {
		s.Store.SetStatus(ctx, site.ID, StatusError)
		return cause
	}
	l.Printf("Otomatik geri dönüş: %s", previous)
	rctx := context.WithoutCancel(ctx)
	if err := s.helper(rctx, l, nil, nil, "hp-site-deploy.sh", "activate", site.Domain, previous); err != nil {
		l.Printf("Geri dönüş başarısız: %v", err)
		s.Store.SetStatus(rctx, site.ID, StatusError)
		return cause
	}
	s.Store.MarkActive(rctx, site.ID, previous)
	if previous != PlaceholderRelease {
		s.helper(rctx, l, nil, nil, "hp-site-service.sh", "restart", site.ShortName)
	} else {
		s.helper(rctx, l, nil, nil, "hp-site-service.sh", "stop", site.ShortName)
		s.Store.SetStatus(rctx, site.ID, StatusAwaitingDeploy)
	}
	return fmt.Errorf("deploy başarısız, %s sürümüne geri dönüldü: %w", previous, cause)
}

// healthCheck polls the app until it answers with a status < 500.
func (s *Service) healthCheck(ctx context.Context, l *jobs.Log, site Site) error {
	url := fmt.Sprintf("http://127.0.0.1:%d%s", site.Port, site.HealthPath)
	if s.DryRun {
		l.Printf("[DRY-RUN] health check atlandı: %s", url)
		return nil
	}
	l.Printf("Health check: %s", url)
	client := &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	deadline := time.Now().Add(30 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		res, err := client.Do(req)
		if err == nil {
			res.Body.Close()
			if res.StatusCode < 500 {
				l.Printf("Health check başarılı: HTTP %d", res.StatusCode)
				return nil
			}
			last = fmt.Sprintf("HTTP %d", res.StatusCode)
		} else {
			last = err.Error()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return fmt.Errorf("health check 30 sn içinde başarılı olmadı (son sonuç: %s)", last)
}

// --- delete ---

// StartDelete queues deletion after the domain confirmation matched.
// dropDBs is passed to DeleteHook.
func (s *Service) StartDelete(ctx context.Context, site Site, dropDBs bool) (int64, error) {
	summary := "Site siliniyor: " + site.Domain
	if dropDBs {
		summary += " (veritabanlarıyla birlikte)"
	}
	return s.Jobs.Submit(ctx, jobs.Spec{Kind: "site.delete", TargetType: "site", TargetID: site.Domain,
		Summary: summary, Params: map[string]any{"site_id": site.ID, "drop_dbs": dropDBs}})
}

func (s *Service) jobDelete(ctx context.Context, l *jobs.Log, p map[string]any) error {
	site, err := s.Store.Get(ctx, paramID(p, "site_id"))
	if err != nil {
		return fmt.Errorf("site bulunamadı: %w", err)
	}
	defer s.lock(site.ID)()
	prev := site.Status
	s.Store.SetStatus(ctx, site.ID, StatusDeleting)
	l.Printf("Son yedek alınıyor…")
	if err := s.helper(ctx, l, nil, nil, "hp-site-archive.sh", site.Domain); err != nil {
		s.Store.SetStatus(context.WithoutCancel(ctx), site.ID, prev)
		return fmt.Errorf("yedek alınamadı, silme iptal edildi: %w", err)
	}
	l.Progress(30)
	// From here on, continue past individual failures so nothing is left half-registered.
	var errs []string
	try := func(name string, fn func() error) {
		l.Printf("→ %s", name)
		if err := fn(); err != nil {
			l.Printf("✗ %s: %v", name, err)
			errs = append(errs, name)
		}
	}
	dctx := context.WithoutCancel(ctx)
	prov, _ := s.provider(site)
	if prov == nil || prov.Def().Type == runtimes.TypeProxy {
		try("systemd servisi kaldırılıyor", func() error { return s.helper(dctx, l, nil, nil, "hp-site-unit.sh", "remove", site.ShortName) })
		try("ortam değişkenleri siliniyor", func() error { return s.helper(dctx, l, nil, nil, "hp-site-env.sh", "delete", site.Domain) })
	}
	try("nginx yapılandırması kaldırılıyor", func() error { return s.helper(dctx, l, nil, nil, "hp-nginx-site.sh", "remove", site.Domain) })
	try("SSL sertifikaları siliniyor", func() error { return s.helper(dctx, l, nil, nil, "hp-ssl.sh", "delete", site.Domain, "all") })
	l.Progress(60)
	try("site dizini siliniyor", func() error { return s.helper(dctx, l, nil, nil, "hp-site-dirs.sh", "delete", site.Domain) })
	try("Linux kullanıcısı siliniyor", func() error {
		return s.helper(dctx, l, nil, nil, "hp-site-user.sh", "delete", site.User(), site.Domain)
	})
	if s.DeleteHook != nil {
		try("veritabanları", func() error { return s.DeleteHook(dctx, l, site, p) })
	}
	if err := s.Store.Delete(dctx, site.ID); err != nil {
		return err
	}
	l.Progress(100)
	if len(errs) > 0 {
		return fmt.Errorf("site kaydı silindi ama şu adımlar başarısız oldu (elle kontrol edin): %s", strings.Join(errs, ", "))
	}
	return nil
}

// --- runtimes ---

func (s *Service) jobRuntime(action string) jobs.Handler {
	return func(ctx context.Context, l *jobs.Log, p map[string]any) error {
		id, _ := p["runtime"].(string)
		version, _ := p["version"].(string)
		prov, ok := s.Runtimes.Get(id)
		if !ok || prov.Def().Versions.InstallScript == "" {
			return errors.New("bu altyapı için kurulum desteklenmiyor")
		}
		if !runtimes.IsSemver(version) {
			return errors.New("geçersiz sürüm")
		}
		if action == "remove" && s.Store.CountByRuntimeVersion(ctx, id, version) > 0 {
			return errors.New("bu sürümü kullanan siteler var")
		}
		c := exec.Helper(s.ScriptsDir, "hp-runtime.sh", action, strings.TrimSuffix(prov.Def().Versions.InstallScript, ".sh"), version)
		c.Output, c.Timeout = l, 20*time.Minute
		_, err := s.Runner.Run(ctx, c)
		return err
	}
}

// SubmitRuntime queues install/remove of a runtime version.
func (s *Service) SubmitRuntime(ctx context.Context, action, id, version string) (int64, error) {
	if action == "remove" && s.Store.CountByRuntimeVersion(ctx, id, version) > 0 {
		return 0, errors.New("bu sürümü kullanan siteler var; kaldırılamaz")
	}
	label := map[string]string{"install": "kuruluyor", "remove": "kaldırılıyor"}[action]
	return s.Jobs.Submit(ctx, jobs.Spec{Kind: "runtime." + action, TargetType: "runtime", TargetID: id + "@" + version,
		Summary: id + " " + version + " " + label, Params: map[string]any{"runtime": id, "version": version}, Retryable: true})
}

// --- logs ---

// JournalTail returns the last n journal lines of the site's unit (no sudo:
// the panel user is in the systemd-journal group).
func (s *Service) JournalTail(ctx context.Context, site Site, n int) []string {
	res, err := s.Probe.Run(ctx, exec.Cmd{Name: "journalctl", Args: []string{"-u", site.Unit() + ".service", "-n", strconv.Itoa(n),
		"--no-pager", "-o", "short-iso"}, Timeout: 10 * time.Second})
	if err != nil && res.Stdout == "" {
		return []string{"(journal okunamadı: " + err.Error() + ")"}
	}
	return strings.Split(strings.TrimRight(res.Stdout, "\n"), "\n")
}

// NginxLogPath returns the access or error log path of a site.
func NginxLogPath(site Site, kind string) string {
	if kind != "error" {
		kind = "access"
	}
	return "/var/log/nginx/hp-" + site.Domain + "." + kind + ".log"
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// ErrNotFound is returned for unknown sites.
var ErrNotFound = sql.ErrNoRows
