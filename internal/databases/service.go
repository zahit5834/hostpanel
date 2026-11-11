package databases

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zahit5834/hostpanel/internal/crypto"
	"github.com/zahit5834/hostpanel/internal/exec"
	"github.com/zahit5834/hostpanel/internal/jobs"
	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/sites"
	"github.com/zahit5834/hostpanel/internal/store"
)

// Defaults chosen with the admin (Faz 3): pinned image tag, never "latest".
const (
	DefaultImage    = "mcr.microsoft.com/mssql/server:2025-CU10-ubuntu-24.04"
	DefaultMemoryMB = 2048
	MinMemoryMB     = 2048 // SQL Server on Linux refuses to start with less than 2 GB
	MaxMemoryMB     = 65536
	Port            = 1433
	ContainerName   = "hostpanel-mssql"
	DataDir         = "/var/lib/hostpanel/mssql" // host path mounted at /var/opt/mssql

	settingDockerInstalled = "docker_installed"
)

// Editions offered at install time. "key" means a purchased product key.
var Editions = []string{"Express", "Developer", "key"}

var (
	imageRe      = regexp.MustCompile(`^mcr\.microsoft\.com/mssql/server:20(22|25)-[A-Za-z0-9.-]{1,64}$`)
	productKeyRe = regexp.MustCompile(`^[A-Z0-9]{5}(-[A-Z0-9]{5}){4}$`)
)

// Service manages the MSSQL container, logins and databases.
type Service struct {
	Store      *Store
	DB         *sql.DB
	Box        *crypto.Box
	Runner     exec.Runner // privileged helpers (dry-run in dev)
	Jobs       *jobs.Manager
	Activity   *logs.Activity
	Log        *slog.Logger
	Sites      *sites.Service
	ScriptsDir string
	DryRun     bool
	Addr       string // 127.0.0.1:1433

	// Fake replaces the SQL server (dry-run and tests).
	Fake *FakeServer
	// ReadyTimeout bounds waiting for a fresh container (default 3 min).
	ReadyTimeout time.Duration
	// MemTotalMB caps the memory setting (0 = no cap).
	MemTotalMB int

	mu sync.Mutex // serializes container-level operations
}

// Register binds job kinds and the site deletion hook.
func (s *Service) Register() {
	s.Jobs.Register("db.docker.install", s.jobDockerInstall)
	s.Jobs.Register("db.server.install", s.jobInstall)
	s.Jobs.Register("db.server.recreate", s.jobRecreate)
	s.Jobs.Register("db.create", s.jobCreate)
	s.Jobs.Register("db.drop", s.jobDrop)
	s.Jobs.Register("db.isolation-test", s.jobIsolation)
	s.Jobs.Register("db.server.update", s.jobImageUpdate)
	s.Sites.DeleteHook = s.siteDeleted
}

func (s *Service) addr() string {
	if s.Addr == "" {
		return "127.0.0.1:" + strconv.Itoa(Port)
	}
	return s.Addr
}

func (s *Service) helper(ctx context.Context, w io.Writer, stdin io.Reader, secrets []string, timeout time.Duration, args ...string) (exec.Result, error) {
	c := exec.Helper(s.ScriptsDir, "hp-mssql.sh", args...)
	c.Output, c.Stdin, c.Secrets, c.Timeout = w, stdin, secrets, timeout
	return s.Runner.Run(ctx, c)
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

// provider returns an sa connection with the given password.
func (s *Service) provider(w io.Writer, pw string) DatabaseProvider {
	if s.Fake != nil {
		return s.Fake.Admin(w, pw)
	}
	return &MSSQL{Addr: s.addr(), User: "sa", Password: pw}
}

// ErrNoServer means MSSQL has not been installed yet.
var ErrNoServer = errors.New("MSSQL sunucusu kurulu değil")

// admin connects as sa. If the stored password fails but a rotation was
// interrupted (pending password set), the pending one is tried and promoted.
func (s *Service) admin(ctx context.Context, w io.Writer) (DatabaseProvider, error) {
	srv, err := s.Store.Server(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoServer
	}
	if err != nil {
		return nil, err
	}
	pw, err := s.Box.OpenString(srv.SASealed)
	if err != nil {
		return nil, err
	}
	p := s.provider(w, pw)
	perr := p.Ping(ctx)
	if perr == nil {
		return p, nil
	}
	if srv.SAPendingSealed != "" {
		if pending, err := s.Box.OpenString(srv.SAPendingSealed); err == nil {
			pp := s.provider(w, pending)
			if pp.Ping(ctx) == nil {
				s.Store.PromoteSA(ctx, srv.ID)
				return pp, nil
			}
		}
	}
	return nil, fmt.Errorf("MSSQL sunucusuna bağlanılamadı: %w", perr)
}

func (s *Service) connect(ctx context.Context, login, pw, db string) (LoginSession, error) {
	if s.Fake != nil {
		return s.Fake.Session(login, pw, db)
	}
	m := &MSSQL{Addr: s.addr(), User: login, Password: pw, Database: db}
	if err := m.Ping(ctx); err != nil {
		return nil, err
	}
	return m, nil
}

// --- container status ---

// Status is the live state of Docker and the container.
type Status struct {
	Docker    string // absent | inactive | active
	Container string // absent | running | exited | restarting | created | …
	StartedAt string
	Restarts  string
	OOM       bool
	Image     string
	CPU       string
	Mem       string
	MemPct    string
	Err       string
}

// DockerInstalled reports whether Docker looks installed.
func (st Status) DockerInstalled() bool { return st.Docker == "active" || st.Docker == "inactive" }

// Running reports a running container.
func (st Status) Running() bool { return st.Container == "running" }

// ParseStatus parses `hp-mssql.sh status` (key=value lines).
func ParseStatus(out string) Status {
	var st Status
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "docker":
			st.Docker = v
		case "container":
			st.Container = v
		case "started_at":
			st.StartedAt = v
		case "restarts":
			st.Restarts = v
		case "oom":
			st.OOM = v == "true"
		case "image":
			st.Image = v
		case "cpu":
			st.CPU = v
		case "mem":
			st.Mem = v
		case "mem_pct":
			st.MemPct = v
		}
	}
	return st
}

// LiveStatus asks Docker (root helper). In dry-run it is derived from the DB.
func (s *Service) LiveStatus(ctx context.Context) Status {
	if s.DryRun {
		st := Status{Docker: "absent", Container: "absent"}
		if store.GetSetting(ctx, s.DB, settingDockerInstalled, "") == "1" {
			st.Docker = "active"
		}
		if srv, err := s.Store.Server(ctx); err == nil {
			switch srv.Status {
			case StatusRunning:
				st.Container, st.CPU, st.Mem, st.MemPct = "running", "0.40%", "812MiB / 2.25GiB", "35.2%"
				st.StartedAt, st.Image = srv.UpdatedAt.UTC().Format(time.RFC3339), srv.Image
			case StatusStopped:
				st.Container = "exited"
			}
		}
		return st
	}
	res, err := s.helper(ctx, nil, nil, nil, 30*time.Second, "status")
	st := ParseStatus(res.Stdout)
	if err != nil {
		st.Err = err.Error()
	}
	return st
}

// ContainerLogs returns the last n container log lines (Log Merkezi).
func (s *Service) ContainerLogs(ctx context.Context, n int) []string {
	if s.DryRun {
		return []string{"(dry-run: container çalışmıyor, log yok)"}
	}
	res, err := s.helper(ctx, nil, nil, nil, 30*time.Second, "logs", strconv.Itoa(n))
	out := strings.TrimRight(res.Stdout, "\n")
	if err != nil && out == "" {
		return []string{"(container logu okunamadı: " + err.Error() + ")"}
	}
	if out == "" {
		return nil
	}
	return strings.Split(out, "\n")
}

// DockerPresent is a cheap, unprivileged check that picks the page state
// (the live status needs the root helper).
func (s *Service) DockerPresent(ctx context.Context) bool {
	if s.DryRun {
		return store.GetSetting(ctx, s.DB, settingDockerInstalled, "") == "1"
	}
	_, err := os.Stat("/usr/bin/docker")
	return err == nil
}

// Available reports a running server (forms that create databases/logins).
func (s *Service) Available(ctx context.Context) bool {
	_, err := s.runningServer(ctx)
	return err == nil
}

// --- Docker + server install ---

// StartDockerInstall queues `apt-get install docker.io`.
func (s *Service) StartDockerInstall(ctx context.Context) (int64, error) {
	return s.Jobs.Submit(ctx, jobs.Spec{Kind: "db.docker.install", TargetType: "db_server", TargetID: "docker",
		Summary: "Docker kuruluyor (docker.io)", Retryable: true})
}

func (s *Service) jobDockerInstall(ctx context.Context, l *jobs.Log, _ map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	l.Printf("Ubuntu deposundan docker.io kuruluyor…")
	if _, err := s.helper(ctx, l, nil, nil, 20*time.Minute, "install-docker"); err != nil {
		return err
	}
	store.SetSetting(ctx, s.DB, settingDockerInstalled, "1")
	l.Progress(100)
	l.Printf("Docker hazır. Panel kullanıcısı docker grubuna eklenmez; Docker yalnızca root helper üzerinden yönetilir.")
	return nil
}

// InstallInput is the MSSQL install form.
type InstallInput struct {
	Edition    string
	ProductKey string
	MemoryMB   int
	AcceptEULA bool
}

func (s *Service) checkMemory(mb int) error {
	if mb < MinMemoryMB || mb > MaxMemoryMB {
		return fmt.Errorf("bellek %d–%d MB arasında olmalı (SQL Server en az 2 GB ister)", MinMemoryMB, MaxMemoryMB)
	}
	if s.MemTotalMB > 0 && mb > s.MemTotalMB-512 {
		return fmt.Errorf("bellek sunucudaki toplam RAM'in (%d MB) en az 512 MB altında olmalı", s.MemTotalMB)
	}
	return nil
}

// StartInstall validates the form, stores the server and queues the install job.
func (s *Service) StartInstall(ctx context.Context, in InstallInput) (int64, error) {
	if !in.AcceptEULA {
		return 0, errors.New("kurulum için Microsoft SQL Server lisans koşullarını kabul etmelisiniz")
	}
	if err := s.checkMemory(in.MemoryMB); err != nil {
		return 0, err
	}
	srv := Server{Engine: "mssql", Image: DefaultImage, Edition: in.Edition, MemoryMB: in.MemoryMB, Status: StatusInstalling}
	switch in.Edition {
	case "Express", "Developer":
	case "key":
		k := strings.ToUpper(strings.TrimSpace(in.ProductKey))
		if !productKeyRe.MatchString(k) {
			return 0, errors.New("ürün anahtarı XXXXX-XXXXX-XXXXX-XXXXX-XXXXX biçiminde olmalı")
		}
		sealed, err := s.Box.SealString(k)
		if err != nil {
			return 0, err
		}
		srv.ProductKeySealed = sealed
	default:
		return 0, errors.New("geçersiz sürüm")
	}
	if _, err := s.Store.Server(ctx); err == nil {
		return 0, errors.New("MSSQL sunucusu zaten kurulu")
	}
	if !s.DryRun && !s.LiveStatus(ctx).DockerInstalled() {
		return 0, errors.New("önce Docker'ı kurun")
	}
	sealed, err := s.Box.SealString(GeneratePassword())
	if err != nil {
		return 0, err
	}
	srv.SASealed = sealed
	if err := s.Store.InsertServer(ctx, &srv); err != nil {
		return 0, err
	}
	id, err := s.Jobs.Submit(ctx, jobs.Spec{Kind: "db.server.install", TargetType: "db_server", TargetID: "mssql",
		Summary: fmt.Sprintf("MSSQL kuruluyor (%s, %d MB)", editionLabel(srv.Edition), srv.MemoryMB),
		Params:  map[string]any{"server_id": srv.ID}, Retryable: true})
	if err != nil {
		s.Store.DeleteServer(ctx, srv.ID)
	}
	return id, err
}

func editionLabel(e string) string {
	if e == "key" {
		return "ürün anahtarı"
	}
	return e
}

// pid is MSSQL_PID: the edition name or the product key.
func (s *Service) pid(srv Server) (string, error) {
	if srv.Edition != "key" {
		return srv.Edition, nil
	}
	return s.Box.OpenString(srv.ProductKeySealed)
}

func bindAddr(srv Server) string {
	if srv.External {
		return "0.0.0.0"
	}
	return "127.0.0.1"
}

// createContainer runs `hp-mssql.sh create`; secrets go through stdin
// (the script writes a 600 env-file for docker, never argv).
func (s *Service) createContainer(ctx context.Context, l *jobs.Log, srv Server, saPW string) error {
	if !imageRe.MatchString(srv.Image) {
		return fmt.Errorf("izin verilmeyen imaj: %s", srv.Image)
	}
	pid, err := s.pid(srv)
	if err != nil {
		return err
	}
	stdin := strings.NewReader(saPW + "\n" + pid + "\n")
	_, err = s.helper(ctx, l, stdin, []string{saPW, pid}, 30*time.Minute,
		"create", srv.Image, strconv.Itoa(srv.MemoryMB), bindAddr(srv))
	if err == nil && s.Fake != nil {
		s.Fake.SetSA(saPW) // dry-run: the "container" was set up with this password
	}
	return err
}

// waitReady polls until sa can log in (a fresh container needs ~20–60 s).
func (s *Service) waitReady(ctx context.Context, l *jobs.Log) error {
	timeout := s.ReadyTimeout
	if timeout == 0 {
		timeout = 3 * time.Minute
	}
	return s.waitReadyFor(ctx, l, timeout)
}

// waitReadyFor is waitReady with an explicit limit (a cumulative update
// upgrades the system databases on its first start).
func (s *Service) waitReadyFor(ctx context.Context, l *jobs.Log, timeout time.Duration) error {
	if s.ReadyTimeout != 0 && s.ReadyTimeout < timeout {
		timeout = s.ReadyTimeout // tests
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	l.Printf("SQL Server'ın açılması bekleniyor (en fazla %s)…", timeout)
	t := time.NewTimer(0)
	defer t.Stop()
	var last error
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("SQL Server zamanında hazır olmadı: %v", last)
		case <-t.C:
		}
		pctx, pcancel := context.WithTimeout(ctx, 10*time.Second)
		_, last = s.admin(pctx, nil)
		pcancel()
		if last == nil {
			l.Printf("SQL Server hazır.")
			return nil
		}
		t.Reset(3 * time.Second)
	}
}

// rotateSA replaces the sa password. The initial password was passed to the
// container's environment and stays visible in `docker inspect`; after this
// it no longer works. The pending column makes the rotation crash-safe.
func (s *Service) rotateSA(ctx context.Context, l *jobs.Log, srv Server) error {
	p, err := s.admin(ctx, l)
	if err != nil {
		return err
	}
	pw := GeneratePassword()
	sealed, err := s.Box.SealString(pw)
	if err != nil {
		return err
	}
	if err := s.Store.SetSAPending(ctx, srv.ID, sealed); err != nil {
		return err
	}
	if err := p.ChangeSA(ctx, pw); err != nil {
		s.Store.ClearSAPending(context.WithoutCancel(ctx), srv.ID)
		return fmt.Errorf("sa şifresi değiştirilemedi: %w", err)
	}
	if err := s.Store.PromoteSA(ctx, srv.ID); err != nil {
		return err
	}
	l.Printf("sa şifresi yenilendi (container ortamındaki ilk şifre artık geçersiz).")
	return nil
}

// maxServerMemory leaves room for the non-buffer-pool parts of SQL Server
// inside MSSQL_MEMORY_LIMIT_MB.
func maxServerMemory(memMB int) int {
	if m := memMB - 512; m > 1024 {
		return m
	}
	return 1024
}

func (s *Service) configure(ctx context.Context, l *jobs.Log, srv Server) error {
	p, err := s.admin(ctx, l)
	if err != nil {
		return err
	}
	if err := p.SetMaxMemory(ctx, maxServerMemory(srv.MemoryMB)); err != nil {
		return fmt.Errorf("max server memory ayarlanamadı: %w", err)
	}
	return nil
}

func (s *Service) failServer(ctx context.Context, id int64, err error) error {
	s.Store.SetServerStatus(context.WithoutCancel(ctx), id, StatusError, err.Error())
	return err
}

func (s *Service) jobInstall(ctx context.Context, l *jobs.Log, p map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	srv, err := s.Store.Server(ctx)
	if err != nil || srv.ID != paramID(p, "server_id") {
		return errors.New("sunucu kaydı bulunamadı")
	}
	s.Store.SetServerStatus(ctx, srv.ID, StatusInstalling, "")
	saPW, err := s.Box.OpenString(srv.SASealed)
	if err != nil {
		return s.failServer(ctx, srv.ID, err)
	}
	if st := s.LiveStatus(ctx); s.DryRun || st.Container == "absent" {
		l.Printf("İmaj: %s · sürüm: %s · bellek: %d MB · dinleme: 127.0.0.1:%d", srv.Image, editionLabel(srv.Edition), srv.MemoryMB, Port)
		l.Printf("İmaj indiriliyor (~1.5 GB) ve container oluşturuluyor…")
		if err := s.createContainer(ctx, l, srv, saPW); err != nil {
			l.Printf("Kurulum başarısız; yarım kalan container kaldırılıyor…")
			s.helper(context.WithoutCancel(ctx), l, nil, nil, 2*time.Minute, "remove-container")
			return s.failServer(ctx, srv.ID, err)
		}
	} else {
		l.Printf("Container zaten var (%s); oluşturma adımı atlandı.", st.Container)
	}
	l.Progress(60)
	if err := s.waitReady(ctx, l); err != nil {
		return s.failServer(ctx, srv.ID, err)
	}
	l.Progress(80)
	if err := s.rotateSA(ctx, l, srv); err != nil {
		return s.failServer(ctx, srv.ID, err)
	}
	if err := s.configure(ctx, l, srv); err != nil {
		return s.failServer(ctx, srv.ID, err)
	}
	s.Store.SetServerStatus(ctx, srv.ID, StatusRunning, "")
	l.Progress(100)
	l.Printf("MSSQL hazır: 127.0.0.1:%d (yalnızca yerel). Veri: %s", Port, DataDir)
	return nil
}

// RemoveFailed removes a server that never finished installing (no
// logins yet): container removed, data directory moved aside.
func (s *Service) RemoveFailed(ctx context.Context, w io.Writer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	srv, err := s.Store.Server(ctx)
	if err != nil {
		return ErrNoServer
	}
	if srv.Status == StatusRunning || srv.Status == StatusStopped {
		return errors.New("çalışan bir sunucu bu yolla kaldırılamaz")
	}
	if n := len(s.mustLogins(ctx)); n > 0 {
		return errors.New("sunucuda login'ler var")
	}
	if _, err := s.helper(ctx, w, nil, nil, 2*time.Minute, "purge"); err != nil {
		return err
	}
	return s.Store.DeleteServer(ctx, srv.ID)
}

func (s *Service) mustLogins(ctx context.Context) []Login {
	l, _ := s.Store.Logins(ctx)
	return l
}

// --- container operations ---

// Container operations accepted by Operate.
var containerOps = map[string]string{"start": StatusRunning, "stop": StatusStopped, "restart": StatusRunning}

// Operate starts/stops/restarts the container.
func (s *Service) Operate(ctx context.Context, op string) error {
	status, ok := containerOps[op]
	if !ok {
		return errors.New("geçersiz işlem")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	srv, err := s.Store.Server(ctx)
	if err != nil {
		return ErrNoServer
	}
	if srv.Status == StatusInstalling {
		return errors.New("kurulum sürüyor")
	}
	if _, err := s.helper(ctx, nil, nil, nil, 2*time.Minute, op); err != nil {
		return err
	}
	return s.Store.SetServerStatus(ctx, srv.ID, status, "")
}

// SettingsInput is the server settings form.
type SettingsInput struct {
	MemoryMB int
	External bool
	AllowIPs string
}

// ParseAllowIPs validates and normalizes IPs/CIDRs (one per line or comma separated).
func ParseAllowIPs(raw string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, f := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' }) {
		var norm string
		if strings.Contains(f, "/") {
			p, err := netip.ParsePrefix(f)
			if err != nil {
				return nil, fmt.Errorf("geçersiz IP/CIDR: %s", f)
			}
			p = p.Masked()
			if p.Bits() == 0 {
				return nil, fmt.Errorf("%s tüm interneti açar; belirli IP'ler girin", f)
			}
			norm = p.String()
		} else {
			a, err := netip.ParseAddr(f)
			if err != nil {
				return nil, fmt.Errorf("geçersiz IP: %s", f)
			}
			a = a.Unmap()
			norm = a.String()
		}
		// 0.0.0.0 / :: as a source matches no client in UFW: someone typing
		// it to "open everything" would silently get no access at all.
		base, _ := netip.ParseAddr(strings.Split(norm, "/")[0])
		if base.IsUnspecified() {
			return nil, fmt.Errorf("%s bir istemci adresi değil; tüm interneti açmak desteklenmez. Bağlanacak bilgisayarların IP'lerini girin ya da SSH tüneli kullanın", f)
		}
		if base.IsLoopback() || base.IsMulticast() {
			return nil, fmt.Errorf("%s dış erişim için geçerli değil (yerel erişim zaten açık)", f)
		}
		if !seen[norm] {
			seen[norm] = true
			out = append(out, norm)
		}
	}
	if len(out) > 50 {
		return nil, errors.New("en fazla 50 IP/CIDR girilebilir")
	}
	return out, nil
}

// StartSettings stores memory/external access and queues a container
// recreate (data volume is kept). It returns the job id and the settings diff.
func (s *Service) StartSettings(ctx context.Context, in SettingsInput) (int64, string, error) {
	srv, err := s.Store.Server(ctx)
	if err != nil {
		return 0, "", ErrNoServer
	}
	if srv.Status == StatusInstalling {
		return 0, "", errors.New("kurulum sürüyor")
	}
	if err := s.checkMemory(in.MemoryMB); err != nil {
		return 0, "", err
	}
	ips, err := ParseAllowIPs(in.AllowIPs)
	if err != nil {
		return 0, "", err
	}
	if in.External && len(ips) == 0 {
		return 0, "", errors.New("dış erişim için en az bir izinli IP girin")
	}
	before := settingsText(srv)
	srv.MemoryMB, srv.External, srv.AllowIPs = in.MemoryMB, in.External, ips
	after := settingsText(srv)
	if before == after {
		return 0, "", errors.New("değişiklik yok")
	}
	if err := s.Store.UpdateServerSettings(ctx, srv); err != nil {
		return 0, "", err
	}
	id, err := s.Jobs.Submit(ctx, jobs.Spec{Kind: "db.server.recreate", TargetType: "db_server", TargetID: "mssql",
		Summary: "MSSQL ayarları uygulanıyor (container yeniden oluşturuluyor)", Params: map[string]any{"server_id": srv.ID}, Retryable: true})
	return id, logs.LineDiff(before, after), err
}

func settingsText(srv Server) string {
	ext := "kapalı (yalnızca 127.0.0.1)"
	if srv.External {
		ext = "açık (0.0.0.0:1433, UFW ile kısıtlı)"
	}
	return fmt.Sprintf("bellek: %d MB\ndış erişim: %s\nizinli IP'ler: %s", srv.MemoryMB, ext, strings.Join(srv.AllowIPs, ", "))
}

// jobRecreate applies settings: firewall first (refuses when UFW is inactive,
// before anything is torn down), then container remove + create on the same
// data directory, then the sa password is rotated again.
func (s *Service) jobRecreate(ctx context.Context, l *jobs.Log, p map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	srv, err := s.Store.Server(ctx)
	if err != nil || srv.ID != paramID(p, "server_id") {
		return errors.New("sunucu kaydı bulunamadı")
	}
	if srv.External {
		l.Printf("UFW kuralları güncelleniyor (yalnızca 1433/tcp, izinli IP'ler: %s)…", strings.Join(srv.AllowIPs, ", "))
		if _, err := s.helper(ctx, l, nil, nil, 2*time.Minute, append([]string{"firewall"}, srv.AllowIPs...)...); err != nil {
			return fmt.Errorf("güvenlik duvarı kuralları uygulanamadı, container'a dokunulmadı: %w", err)
		}
	} else {
		l.Printf("Panelin eklediği 1433 UFW kuralları (varsa) kaldırılıyor…")
		if _, err := s.helper(ctx, l, nil, nil, 2*time.Minute, "firewall-clear"); err != nil {
			return err
		}
	}
	l.Progress(20)
	saPW, err := s.Box.OpenString(srv.SASealed)
	if err != nil {
		return err
	}
	l.Printf("Container yeniden oluşturuluyor (veri dizini %s korunur)…", DataDir)
	if _, err := s.helper(ctx, l, nil, nil, 2*time.Minute, "remove-container"); err != nil {
		return s.failServer(ctx, srv.ID, err)
	}
	// The current sa password is passed so the container is consistent
	// whether or not the image re-applies MSSQL_SA_PASSWORD to existing data;
	// it is rotated right after, so `docker inspect` never shows a live one.
	if err := s.createContainer(ctx, l, srv, saPW); err != nil {
		return s.failServer(ctx, srv.ID, err)
	}
	l.Progress(50)
	if err := s.waitReady(ctx, l); err != nil {
		return s.failServer(ctx, srv.ID, err)
	}
	if err := s.rotateSA(ctx, l, srv); err != nil {
		return s.failServer(ctx, srv.ID, err)
	}
	if err := s.configure(ctx, l, srv); err != nil {
		return s.failServer(ctx, srv.ID, err)
	}
	s.Store.SetServerStatus(ctx, srv.ID, StatusRunning, "")
	l.Progress(100)
	l.Printf("Ayarlar uygulandı: %s", strings.ReplaceAll(settingsText(srv), "\n", " · "))
	return nil
}

// --- logins ---

func (s *Service) customerName(ctx context.Context, id int64) (string, error) {
	var name string
	err := s.DB.QueryRowContext(ctx, `SELECT name FROM customers WHERE id=?`, id).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return "", errors.New("müşteri bulunamadı")
	}
	return name, err
}

func (s *Service) runningServer(ctx context.Context) (Server, error) {
	srv, err := s.Store.Server(ctx)
	if err != nil {
		return srv, ErrNoServer
	}
	if srv.Status != StatusRunning {
		return srv, errors.New("MSSQL sunucusu çalışmıyor")
	}
	return srv, nil
}

// EnsureLogin returns the customer's login, creating it (on the server and
// in the panel DB) if needed. created reports a new login.
func (s *Service) EnsureLogin(ctx context.Context, customerID int64) (Login, bool, error) {
	if l, err := s.Store.LoginForCustomer(ctx, customerID); err == nil {
		return l, false, nil
	}
	srv, err := s.runningServer(ctx)
	if err != nil {
		return Login{}, false, err
	}
	cname, err := s.customerName(ctx, customerID)
	if err != nil {
		return Login{}, false, err
	}
	base := LoginBase(cname)
	name := base
	for i := 2; s.Store.LoginNameTaken(ctx, name); i++ {
		name = base + "_" + strconv.Itoa(i)
	}
	if !ValidName(name) {
		return Login{}, false, ErrName
	}
	pw := GeneratePassword()
	sealed, err := s.Box.SealString(pw)
	if err != nil {
		return Login{}, false, err
	}
	p, err := s.admin(ctx, nil)
	if err != nil {
		return Login{}, false, err
	}
	if err := p.CreateLogin(ctx, name, pw); err != nil {
		return Login{}, false, fmt.Errorf("login oluşturulamadı: %w", err)
	}
	l := Login{ServerID: srv.ID, CustomerID: customerID, CustomerName: cname, Name: name, PasswordSealed: sealed}
	if err := s.Store.InsertLogin(ctx, &l); err != nil {
		p.DropLogin(context.WithoutCancel(ctx), name)
		return Login{}, false, err
	}
	s.Activity.Record(ctx, logs.Entry{Action: "db.login.create", TargetType: "customer", TargetID: strconv.FormatInt(customerID, 10),
		Summary: "MSSQL login'i oluşturuldu: " + name + " (" + cname + ")"}, nil)
	return l, true, nil
}

// ResetPassword sets a new random password. Connection strings written to
// site env files are updated; the returned sites need a restart to use it.
func (s *Service) ResetPassword(ctx context.Context, loginID int64) ([]string, error) {
	l, err := s.Store.Login(ctx, loginID)
	if err != nil {
		return nil, err
	}
	p, err := s.admin(ctx, nil)
	if err != nil {
		return nil, err
	}
	pw := GeneratePassword()
	sealed, err := s.Box.SealString(pw)
	if err != nil {
		return nil, err
	}
	if err := p.SetPassword(ctx, l.Name, pw); err != nil {
		return nil, err
	}
	if err := s.Store.SetLoginPassword(ctx, l.ID, sealed); err != nil {
		return nil, err
	}
	dbs, _ := s.Store.Databases(ctx, DBFilter{LoginID: l.ID})
	var updated []string
	for _, d := range dbs {
		if d.SiteID == 0 || d.EnvKey == "" {
			continue
		}
		if err := s.writeSiteEnv(ctx, d, false); err != nil {
			return updated, fmt.Errorf("şifre değişti ama %s ortam değişkeni güncellenemedi: %w", d.SiteDomain, err)
		}
		updated = append(updated, d.SiteDomain)
	}
	return updated, nil
}

// SetLoginEnabled enables/disables a login (disabling ends its sessions).
func (s *Service) SetLoginEnabled(ctx context.Context, loginID int64, enabled bool) error {
	l, err := s.Store.Login(ctx, loginID)
	if err != nil {
		return err
	}
	p, err := s.admin(ctx, nil)
	if err != nil {
		return err
	}
	if err := p.SetLoginEnabled(ctx, l.Name, enabled); err != nil {
		return err
	}
	return s.Store.SetLoginDisabled(ctx, l.ID, !enabled)
}

// DropLogin removes a login that owns no databases.
func (s *Service) DropLogin(ctx context.Context, loginID int64) (Login, error) {
	l, err := s.Store.Login(ctx, loginID)
	if err != nil {
		return l, err
	}
	if l.DBCount > 0 {
		return l, ErrLoginHasDatabases
	}
	p, err := s.admin(ctx, nil)
	if err != nil {
		return l, err
	}
	if err := p.DropLogin(ctx, l.Name); err != nil {
		return l, err
	}
	return l, s.Store.DeleteLogin(ctx, l.ID)
}

// PrepareCustomerDelete drops the customer's login before the customer row
// is deleted; databases must be deleted first.
func (s *Service) PrepareCustomerDelete(ctx context.Context, customerID int64) error {
	if s.Store.CountForCustomer(ctx, customerID) > 0 {
		return errors.New("müşterinin veritabanları var; önce veritabanlarını silin")
	}
	l, err := s.Store.LoginForCustomer(ctx, customerID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = s.DropLogin(ctx, l.ID)
	return err
}

// --- databases ---

// CreateInput is the new database form.
type CreateInput struct {
	CustomerID int64
	Name       string
	SiteID     int64
	WriteEnv   bool
	EnvKey     string
}

// StartCreate validates, stores the database row and queues db.create.
func (s *Service) StartCreate(ctx context.Context, in CreateInput) (Database, int64, error) {
	in.Name = strings.TrimSpace(strings.ToLower(in.Name))
	if !ValidName(in.Name) {
		return Database{}, 0, ErrName
	}
	if s.Store.DBNameTaken(ctx, in.Name) {
		return Database{}, 0, errors.New("bu adda bir veritabanı zaten var")
	}
	srv, err := s.runningServer(ctx)
	if err != nil {
		return Database{}, 0, err
	}
	d := Database{ServerID: srv.ID, CustomerID: in.CustomerID, Name: in.Name, SiteID: in.SiteID, Status: DBCreating}
	if in.SiteID > 0 {
		site, err := s.Sites.Store.Get(ctx, in.SiteID)
		if err != nil {
			return d, 0, errors.New("site bulunamadı")
		}
		if site.CustomerID != in.CustomerID {
			return d, 0, errors.New("site bu müşteriye ait değil")
		}
		if in.WriteEnv {
			if !s.siteHasEnv(site) {
				return d, 0, errors.New("bu sitenin ortam değişkeni yok (statik site)")
			}
			key := strings.TrimSpace(in.EnvKey)
			if key == "" {
				key = DefaultEnvKey(site.RuntimeID)
			}
			if !sites.ValidEnvKey(key) {
				return d, 0, fmt.Errorf("geçersiz değişken adı: %s", key)
			}
			d.EnvKey = key
		}
	} else if in.WriteEnv {
		return d, 0, errors.New("ortam değişkenine yazmak için bir site seçin")
	}
	login, _, err := s.EnsureLogin(ctx, in.CustomerID)
	if err != nil {
		return d, 0, err
	}
	if login.Disabled {
		return d, 0, errors.New("müşterinin login'i devre dışı")
	}
	d.LoginID, d.LoginName = login.ID, login.Name
	if err := s.Store.InsertDatabase(ctx, &d); err != nil {
		return d, 0, err
	}
	id, err := s.Jobs.Submit(ctx, jobs.Spec{Kind: "db.create", TargetType: "database", TargetID: d.Name,
		Summary: "Veritabanı oluşturuluyor: " + d.Name + " (sahip: " + login.Name + ")",
		Params:  map[string]any{"database_id": d.ID}, Retryable: true})
	if err != nil {
		s.Store.DeleteDatabase(ctx, d.ID)
	}
	return d, id, err
}

func (s *Service) siteHasEnv(site sites.Site) bool {
	p, ok := s.Sites.Runtimes.Get(site.RuntimeID)
	return ok && p.Def().HasUnit()
}

func (s *Service) jobCreate(ctx context.Context, l *jobs.Log, p map[string]any) error {
	d, err := s.Store.Database(ctx, paramID(p, "database_id"))
	if err != nil {
		return errors.New("veritabanı kaydı bulunamadı")
	}
	prov, err := s.admin(ctx, l)
	if err != nil {
		s.Store.SetDBStatus(ctx, d.ID, DBError)
		return err
	}
	l.Printf("%s oluşturuluyor, sahibi %s yapılıyor…", d.Name, d.LoginName)
	if err := prov.CreateDatabase(ctx, d.Name, d.LoginName); err != nil {
		s.Store.SetDBStatus(context.WithoutCancel(ctx), d.ID, DBError)
		return err
	}
	s.Store.SetDBStatus(ctx, d.ID, DBReady)
	l.Progress(70)
	if sizes, err := prov.GetSize(ctx); err == nil {
		s.Store.SetSizes(ctx, sizes)
	}
	if d.SiteID > 0 && d.EnvKey != "" {
		l.Printf("Connection string %s sitesinin %s değişkenine yazılıyor…", d.SiteDomain, d.EnvKey)
		if err := s.writeSiteEnv(ctx, d, true); err != nil {
			return fmt.Errorf("veritabanı oluşturuldu ama ortam değişkeni yazılamadı: %w", err)
		}
		l.Printf("Yazıldı. Uygulamanın yeni değeri okuması için siteyi yeniden başlatın.")
	}
	l.Progress(100)
	return nil
}

// Connection returns the connection details of a database (password decrypted).
func (s *Service) Connection(ctx context.Context, dbID int64) (ConnInfo, Database, error) {
	d, err := s.Store.Database(ctx, dbID)
	if err != nil {
		return ConnInfo{}, d, err
	}
	l, err := s.Store.Login(ctx, d.LoginID)
	if err != nil {
		return ConnInfo{}, d, err
	}
	pw, err := s.Box.OpenString(l.PasswordSealed)
	if err != nil {
		return ConnInfo{}, d, err
	}
	host, _, _ := strings.Cut(s.addr(), ":")
	return ConnInfo{Host: host, Port: Port, Database: d.Name, User: l.Name, Password: pw}, d, nil
}

// writeSiteEnv puts the connection string into the site's env (merged with
// the existing values) and records the key-level diff.
func (s *Service) writeSiteEnv(ctx context.Context, d Database, setKey bool) error {
	site, err := s.Sites.Store.Get(ctx, d.SiteID)
	if err != nil {
		return err
	}
	ci, _, err := s.Connection(ctx, d.ID)
	if err != nil {
		return err
	}
	env, err := s.Sites.Env(ctx, site.ID)
	if err != nil {
		return err
	}
	env[d.EnvKey] = ci.ForRuntime(site.RuntimeID)
	diff, err := s.Sites.SaveEnv(ctx, site, env)
	if err != nil {
		return err
	}
	if setKey {
		s.Store.SetDBEnvKey(ctx, d.ID, d.EnvKey)
	}
	s.Activity.Record(ctx, logs.Entry{Action: "site.env", TargetType: "site", TargetID: site.Domain,
		Summary: "Veritabanı bağlantısı ortam değişkenine yazıldı: " + d.EnvKey, Diff: diff}, nil)
	return nil
}

// StartDrop queues db.drop (backup first).
func (s *Service) StartDrop(ctx context.Context, d Database) (int64, error) {
	if d.Status == DBDropping {
		return 0, errors.New("silme zaten sürüyor")
	}
	s.Store.SetDBStatus(ctx, d.ID, DBDropping)
	id, err := s.Jobs.Submit(ctx, jobs.Spec{Kind: "db.drop", TargetType: "database", TargetID: d.Name,
		Summary: "Veritabanı siliniyor: " + d.Name, Params: map[string]any{"database_id": d.ID, "prev_status": d.Status}})
	if err != nil {
		s.Store.SetDBStatus(ctx, d.ID, d.Status)
	}
	return id, err
}

func backupPath(db string) string {
	return BackupDir + "/pre-drop-" + db + "-" + time.Now().Format("20060102-150405") + ".bak"
}

func (s *Service) dropOne(ctx context.Context, l *jobs.Log, prov DatabaseProvider, d Database) error {
	path := ""
	if d.Status != DBError && d.Status != DBCreating {
		path = backupPath(d.Name)
		l.Printf("Son yedek: %s%s", DataDir, strings.TrimPrefix(path, "/var/opt/mssql"))
	}
	if err := prov.Drop(ctx, d.Name, path); err != nil {
		return err
	}
	return s.Store.DeleteDatabase(context.WithoutCancel(ctx), d.ID)
}

func (s *Service) jobDrop(ctx context.Context, l *jobs.Log, p map[string]any) error {
	d, err := s.Store.Database(ctx, paramID(p, "database_id"))
	if err != nil {
		return errors.New("veritabanı kaydı bulunamadı")
	}
	prev, _ := p["prev_status"].(string)
	if prev == "" {
		prev = DBReady
	}
	d.Status = prev
	restore := func(err error) error {
		s.Store.SetDBStatus(context.WithoutCancel(ctx), d.ID, prev)
		return err
	}
	prov, err := s.admin(ctx, l)
	if err != nil {
		return restore(err)
	}
	if err := s.dropOne(ctx, l, prov, d); err != nil {
		return restore(fmt.Errorf("silinemedi (yedek alınamadıysa silme yapılmaz): %w", err))
	}
	l.Progress(80)
	if d.SiteID > 0 && d.EnvKey != "" {
		if site, err := s.Sites.Store.Get(ctx, d.SiteID); err == nil {
			if env, err := s.Sites.Env(ctx, site.ID); err == nil {
				if _, ok := env[d.EnvKey]; ok {
					delete(env, d.EnvKey)
					if diff, err := s.Sites.SaveEnv(ctx, site, env); err == nil {
						l.Printf("%s sitesinden %s değişkeni kaldırıldı.", site.Domain, d.EnvKey)
						s.Activity.Record(ctx, logs.Entry{Action: "site.env", TargetType: "site", TargetID: site.Domain,
							Summary: "Silinen veritabanının değişkeni kaldırıldı: " + d.EnvKey, Diff: diff}, nil)
					} else {
						l.Printf("! %s değişkeni kaldırılamadı: %v", d.EnvKey, err)
					}
				}
			}
		}
	}
	l.Progress(100)
	return nil
}

// siteDeleted is sites.Service.DeleteHook: runs inside the site delete job
// (site lock held — must not call SaveEnv). Without drop_dbs the databases
// stay and are just unlinked (ON DELETE SET NULL).
func (s *Service) siteDeleted(ctx context.Context, l *jobs.Log, site sites.Site, p map[string]any) error {
	dbs, err := s.Store.Databases(ctx, DBFilter{SiteID: site.ID})
	if err != nil || len(dbs) == 0 {
		return err
	}
	if drop, _ := p["drop_dbs"].(bool); !drop {
		l.Printf("Veritabanları korunuyor (siteden ayrılıyor): %s", dbNames(dbs))
		return nil
	}
	prov, err := s.admin(ctx, l)
	if err != nil {
		return err
	}
	var failed []string
	for _, d := range dbs {
		l.Printf("→ veritabanı siliniyor: %s", d.Name)
		if err := s.dropOne(ctx, l, prov, d); err != nil {
			l.Printf("✗ %s: %v", d.Name, err)
			failed = append(failed, d.Name)
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("silinemeyen veritabanları: %s", strings.Join(failed, ", "))
	}
	return nil
}

func dbNames(dbs []Database) string {
	n := make([]string, len(dbs))
	for i, d := range dbs {
		n[i] = d.Name
	}
	return strings.Join(n, ", ")
}

// RefreshSizes reads database sizes from the server.
func (s *Service) RefreshSizes(ctx context.Context) error {
	prov, err := s.admin(ctx, nil)
	if err != nil {
		return err
	}
	sizes, err := prov.GetSize(ctx)
	if err != nil {
		return err
	}
	return s.Store.SetSizes(ctx, sizes)
}

// Maintain is part of the daily maintenance: refresh sizes.
func (s *Service) Maintain(ctx context.Context) {
	if srv, err := s.Store.Server(ctx); err != nil || srv.Status != StatusRunning {
		return
	}
	if err := s.RefreshSizes(ctx); err != nil && s.Log != nil {
		s.Log.Warn("db size refresh failed", "err", err)
	}
}

// --- isolation test ---

// StartIsolationTest queues the two-customer isolation test.
func (s *Service) StartIsolationTest(ctx context.Context) (int64, error) {
	if _, err := s.runningServer(ctx); err != nil {
		return 0, err
	}
	return s.Jobs.Submit(ctx, jobs.Spec{Kind: "db.isolation-test", TargetType: "db_server", TargetID: "mssql",
		Summary: "MSSQL müşteri izolasyon testi", Retryable: true})
}

func (s *Service) jobIsolation(ctx context.Context, l *jobs.Log, _ map[string]any) error {
	prov, err := s.admin(ctx, l)
	if err != nil {
		return err
	}
	return IsolationTest(ctx, l, prov, s.connect)
}

// --- backup / restore (used by the backups package) ---

// BackupTo writes a COPY_ONLY full backup of db to path (inside the server).
func (s *Service) BackupTo(ctx context.Context, w io.Writer, db, path string) error {
	p, err := s.admin(ctx, w)
	if err != nil {
		return err
	}
	return p.Backup(ctx, db, path)
}

// RestoreFrom restores the server-side .bak at path as in.Name. An existing
// panel database of the same name is replaced (it must belong to the same
// customer); otherwise a new one is created, owned by the customer's login.
// With in.SiteID + in.WriteEnv the connection string goes into the site env.
func (s *Service) RestoreFrom(ctx context.Context, w io.Writer, path string, in CreateInput) (Database, error) {
	in.Name = strings.TrimSpace(strings.ToLower(in.Name))
	if !ValidName(in.Name) {
		return Database{}, ErrName
	}
	srv, err := s.runningServer(ctx)
	if err != nil {
		return Database{}, err
	}
	prov, err := s.admin(ctx, w)
	if err != nil {
		return Database{}, err
	}
	var d Database
	created := false
	if existing, ok := s.byName(ctx, in.Name); ok {
		if existing.CustomerID != in.CustomerID {
			return d, errors.New("bu adda başka bir müşteriye ait veritabanı var")
		}
		d = existing
	} else {
		login, _, err := s.EnsureLogin(ctx, in.CustomerID)
		if err != nil {
			return d, err
		}
		d = Database{ServerID: srv.ID, CustomerID: in.CustomerID, LoginID: login.ID, LoginName: login.Name,
			SiteID: in.SiteID, Name: in.Name, Status: DBCreating}
		if err := s.Store.InsertDatabase(ctx, &d); err != nil {
			return d, err
		}
		created = true
	}
	if err := prov.Restore(ctx, d.Name, path, d.LoginName); err != nil {
		if created {
			s.Store.DeleteDatabase(context.WithoutCancel(ctx), d.ID)
		}
		return d, err
	}
	s.Store.SetDBStatus(ctx, d.ID, DBReady)
	if sizes, err := prov.GetSize(ctx); err == nil {
		s.Store.SetSizes(ctx, sizes)
	}
	if in.WriteEnv && in.SiteID > 0 {
		site, err := s.Sites.Store.Get(ctx, in.SiteID)
		if err != nil {
			return d, err
		}
		if d.SiteID != in.SiteID {
			s.Store.SetDBSite(ctx, d.ID, in.SiteID)
		}
		if s.siteHasEnv(site) {
			d.SiteID = in.SiteID
			d.EnvKey = strings.TrimSpace(in.EnvKey)
			if d.EnvKey == "" {
				d.EnvKey = DefaultEnvKey(site.RuntimeID)
			}
			if !sites.ValidEnvKey(d.EnvKey) {
				return d, fmt.Errorf("geçersiz değişken adı: %s", d.EnvKey)
			}
			if err := s.writeSiteEnv(ctx, d, true); err != nil {
				return d, fmt.Errorf("veritabanı geri yüklendi ama ortam değişkeni yazılamadı: %w", err)
			}
		}
	}
	return d, nil
}

func (s *Service) byName(ctx context.Context, name string) (Database, bool) {
	var id int64
	if s.DB.QueryRowContext(ctx, `SELECT id FROM databases WHERE name=?`, name).Scan(&id) != nil {
		return Database{}, false
	}
	d, err := s.Store.Database(ctx, id)
	return d, err == nil
}
