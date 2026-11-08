package pgsql

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zahit5834/hostpanel/internal/crypto"
	"github.com/zahit5834/hostpanel/internal/databases"
	"github.com/zahit5834/hostpanel/internal/exec"
	"github.com/zahit5834/hostpanel/internal/jobs"
	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/sites"
	"github.com/zahit5834/hostpanel/internal/store"
)

// Defaults chosen with the admin (Faz 8): pinned tag, never "latest".
const (
	DefaultImage    = "postgres:18.6-trixie"
	DefaultMemoryMB = 2048
	MinMemoryMB     = 512
	MaxMemoryMB     = 65536
	Port            = 5432
	Host            = "127.0.0.1"
	ContainerName   = "hostpanel-postgres"
	DataDir         = "/var/lib/hostpanel/postgres"
	BackupDir       = "/var/lib/hostpanel/postgres-backup"

	settingDockerInstalled = "docker_installed" // shared with the MSSQL service
)

var (
	imageRe = regexp.MustCompile(`^postgres:1[6-9]\.[0-9]{1,2}-(trixie|bookworm)$`)
	// ImportRe is an uploaded pg_dump file in the panel's upload dir.
	ImportRe = regexp.MustCompile(`^pgimport-[0-9]+\.dump$`)
	sizeRe   = regexp.MustCompile(`^([a-z][a-z0-9_]{0,62})=([0-9]+)$`)
)

// Service manages the PostgreSQL container, roles and databases.
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
	UploadDir  string
	DryRun     bool
	// MemTotalMB caps the memory setting (0 = no cap).
	MemTotalMB int

	mu sync.Mutex // serializes container-level operations
}

// Register adds the job handlers and chains the site delete hook (after the
// MSSQL one, if any).
func (s *Service) Register() {
	s.Jobs.Register("pg.server.install", s.jobInstall)
	s.Jobs.Register("pg.server.recreate", s.jobRecreate)
	s.Jobs.Register("pg.create", s.jobCreate)
	s.Jobs.Register("pg.drop", s.jobDrop)
	s.Jobs.Register("pg.isolation-test", s.jobIsolation)
	s.Jobs.Register("pg.import", s.jobImport)
	prev := s.Sites.DeleteHook
	s.Sites.DeleteHook = func(ctx context.Context, l *jobs.Log, site sites.Site, p map[string]any) error {
		var err error
		if prev != nil {
			err = prev(ctx, l, site, p)
		}
		return errors.Join(err, s.siteDeleted(ctx, l, site, p))
	}
}

func (s *Service) helper(ctx context.Context, w io.Writer, stdin io.Reader, secrets []string, timeout time.Duration, args ...string) (exec.Result, error) {
	c := exec.Helper(s.ScriptsDir, "hp-pg.sh", args...)
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

// ErrNoServer means PostgreSQL has not been installed yet.
var ErrNoServer = errors.New("PostgreSQL sunucusu kurulu değil")

// --- status ---

// Status is the live state of Docker and the container (same format as MSSQL).
type Status = databases.Status

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
				st.Container, st.CPU, st.Mem, st.MemPct = "running", "0.02%", "24MiB / 2.25GiB", "1.0%"
				st.StartedAt, st.Image = srv.UpdatedAt.UTC().Format(time.RFC3339), srv.Image
			case StatusStopped:
				st.Container = "exited"
			}
		}
		return st
	}
	res, err := s.helper(ctx, nil, nil, nil, 30*time.Second, "status")
	st := databases.ParseStatus(res.Stdout)
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

// DockerPresent is a cheap, unprivileged check that picks the page state.
func (s *Service) DockerPresent(ctx context.Context) bool {
	if s.DryRun {
		return store.GetSetting(ctx, s.DB, settingDockerInstalled, "") == "1"
	}
	_, err := os.Stat("/usr/bin/docker")
	return err == nil
}

// Available reports a running server (forms that create databases/roles).
func (s *Service) Available(ctx context.Context) bool {
	_, err := s.runningServer(ctx)
	return err == nil
}

func (s *Service) runningServer(ctx context.Context) (Server, error) {
	srv, err := s.Store.Server(ctx)
	if err != nil {
		return srv, ErrNoServer
	}
	if srv.Status != StatusRunning {
		return srv, errors.New("PostgreSQL sunucusu çalışmıyor")
	}
	return srv, nil
}

// --- install / recreate ---

func (s *Service) checkMemory(mb int) error {
	if mb < MinMemoryMB || mb > MaxMemoryMB {
		return fmt.Errorf("bellek %d–%d MB arasında olmalı", MinMemoryMB, MaxMemoryMB)
	}
	if s.MemTotalMB > 0 && mb > s.MemTotalMB-512 {
		return fmt.Errorf("bellek sunucudaki toplam RAM'in (%d MB) en az 512 MB altında olmalı", s.MemTotalMB)
	}
	return nil
}

// SuggestMemory is the install form's default: a quarter of the RAM, at
// least the default, leaving room for sites and the panel.
func (s *Service) SuggestMemory() int {
	m := DefaultMemoryMB
	if s.MemTotalMB > 0 {
		if q := s.MemTotalMB / 4 / 256 * 256; q > m {
			m = q
		}
		if m > s.MemTotalMB-1024 {
			m = max(MinMemoryMB, (s.MemTotalMB-1024)/256*256)
		}
	}
	return m
}

// StartInstall stores the server and queues the install job.
func (s *Service) StartInstall(ctx context.Context, memoryMB int) (int64, error) {
	if err := s.checkMemory(memoryMB); err != nil {
		return 0, err
	}
	if _, err := s.Store.Server(ctx); err == nil {
		return 0, errors.New("PostgreSQL sunucusu zaten kurulu")
	}
	if !s.DryRun && !s.LiveStatus(ctx).DockerInstalled() {
		return 0, errors.New("önce Docker'ı kurun")
	}
	srv := Server{Image: DefaultImage, MemoryMB: memoryMB, Status: StatusInstalling}
	if err := s.Store.InsertServer(ctx, &srv); err != nil {
		return 0, err
	}
	id, err := s.Jobs.Submit(ctx, jobs.Spec{Kind: "pg.server.install", TargetType: "db_server", TargetID: "postgres",
		Summary: fmt.Sprintf("PostgreSQL kuruluyor (%s, %d MB)", srv.Image, srv.MemoryMB),
		Params:  map[string]any{"server_id": srv.ID}, Retryable: true})
	if err != nil {
		s.Store.DeleteServer(ctx, srv.ID)
	}
	return id, err
}

func bindAddr(srv Server) string {
	if srv.External {
		return "*"
	}
	return "127.0.0.1"
}

func (s *Service) failServer(ctx context.Context, id int64, err error) error {
	s.Store.SetServerStatus(context.WithoutCancel(ctx), id, StatusError, err.Error())
	return err
}

// createContainer runs `hp-pg.sh create` and, with external access, writes
// the allow list into pg_hba (create itself allows loopback only).
func (s *Service) createContainer(ctx context.Context, l *jobs.Log, srv Server) error {
	if !imageRe.MatchString(srv.Image) {
		return fmt.Errorf("izin verilmeyen imaj: %s", srv.Image)
	}
	if _, err := s.helper(ctx, l, nil, nil, 30*time.Minute, "create", srv.Image, strconv.Itoa(srv.MemoryMB), bindAddr(srv)); err != nil {
		return err
	}
	if srv.External {
		if _, err := s.helper(ctx, l, nil, nil, 2*time.Minute, append([]string{"hba"}, srv.AllowIPs...)...); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) recordVersion(ctx context.Context, srv Server) {
	if s.DryRun {
		s.Store.SetVersion(ctx, srv.ID, "18.6 (dry-run)")
		return
	}
	if res, err := s.helper(ctx, nil, nil, nil, 30*time.Second, "version"); err == nil {
		if v := strings.TrimSpace(res.Stdout); v != "" {
			s.Store.SetVersion(ctx, srv.ID, v)
		}
	}
}

func (s *Service) jobInstall(ctx context.Context, l *jobs.Log, p map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	srv, err := s.Store.Server(ctx)
	if err != nil || srv.ID != paramID(p, "server_id") {
		return errors.New("sunucu kaydı bulunamadı")
	}
	s.Store.SetServerStatus(ctx, srv.ID, StatusInstalling, "")
	if st := s.LiveStatus(ctx); s.DryRun || st.Container == "absent" {
		l.Printf("İmaj: %s · bellek: %d MB · dinleme: %s:%d", srv.Image, srv.MemoryMB, Host, Port)
		l.Printf("İmaj indiriliyor (~160 MB) ve container oluşturuluyor…")
		if err := s.createContainer(ctx, l, srv); err != nil {
			l.Printf("Kurulum başarısız; yarım kalan container kaldırılıyor…")
			s.helper(context.WithoutCancel(ctx), l, nil, nil, 2*time.Minute, "remove-container")
			return s.failServer(ctx, srv.ID, err)
		}
	} else {
		l.Printf("Container zaten var (%s); oluşturma adımı atlandı.", st.Container)
		if _, err := s.helper(ctx, l, nil, nil, 3*time.Minute, "ready"); err != nil {
			return s.failServer(ctx, srv.ID, err)
		}
	}
	l.Progress(90)
	s.recordVersion(ctx, srv)
	s.Store.SetServerStatus(ctx, srv.ID, StatusRunning, "")
	l.Progress(100)
	l.Printf("PostgreSQL hazır: %s:%d (yalnızca yerel). Veri: %s", Host, Port, DataDir)
	l.Printf("Süper kullanıcının (postgres) şifresi yok ve TCP ile bağlanamaz; yönetim yalnızca root helper'ı üzerinden.")
	return nil
}

// RemoveFailed removes a server that never finished installing.
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
	if roles, _ := s.Store.Roles(ctx); len(roles) > 0 {
		return errors.New("sunucuda roller var")
	}
	if _, err := s.helper(ctx, w, nil, nil, 2*time.Minute, "purge"); err != nil {
		return err
	}
	return s.Store.DeleteServer(ctx, srv.ID)
}

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
	if _, err := s.helper(ctx, nil, nil, nil, 3*time.Minute, op); err != nil {
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

func settingsText(srv Server) string {
	ext := "kapalı (yalnızca 127.0.0.1)"
	if srv.External {
		ext = "açık (*:5432, pg_hba + UFW ile kısıtlı)"
	}
	return fmt.Sprintf("bellek: %d MB\ndış erişim: %s\nizinli IP'ler: %s", srv.MemoryMB, ext, strings.Join(srv.AllowIPs, ", "))
}

// StartSettings stores memory/external access and queues a container
// recreate (data volume is kept). It returns the job id and the diff.
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
	ips, err := databases.ParseAllowIPs(in.AllowIPs)
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
	id, err := s.Jobs.Submit(ctx, jobs.Spec{Kind: "pg.server.recreate", TargetType: "db_server", TargetID: "postgres",
		Summary: "PostgreSQL ayarları uygulanıyor (container yeniden oluşturuluyor)", Params: map[string]any{"server_id": srv.ID}, Retryable: true})
	return id, logs.LineDiff(before, after), err
}

// jobRecreate: firewall first (refuses when UFW is inactive, before anything
// is torn down), then container remove + create on the same data directory.
func (s *Service) jobRecreate(ctx context.Context, l *jobs.Log, p map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	srv, err := s.Store.Server(ctx)
	if err != nil || srv.ID != paramID(p, "server_id") {
		return errors.New("sunucu kaydı bulunamadı")
	}
	if srv.External {
		l.Printf("UFW kuralları güncelleniyor (yalnızca 5432/tcp, izinli IP'ler: %s)…", strings.Join(srv.AllowIPs, ", "))
		if _, err := s.helper(ctx, l, nil, nil, 2*time.Minute, append([]string{"firewall"}, srv.AllowIPs...)...); err != nil {
			return fmt.Errorf("güvenlik duvarı kuralları uygulanamadı, container'a dokunulmadı: %w", err)
		}
	} else {
		l.Printf("Panelin eklediği 5432 UFW kuralları (varsa) kaldırılıyor…")
		if _, err := s.helper(ctx, l, nil, nil, 2*time.Minute, "firewall-clear"); err != nil {
			return err
		}
	}
	l.Progress(20)
	l.Printf("Container yeniden oluşturuluyor (veri dizini %s korunur)…", DataDir)
	if _, err := s.helper(ctx, l, nil, nil, 3*time.Minute, "remove-container"); err != nil {
		return s.failServer(ctx, srv.ID, err)
	}
	if err := s.createContainer(ctx, l, srv); err != nil {
		return s.failServer(ctx, srv.ID, err)
	}
	s.recordVersion(ctx, srv)
	s.Store.SetServerStatus(ctx, srv.ID, StatusRunning, "")
	l.Progress(100)
	l.Printf("Ayarlar uygulandı: %s", strings.ReplaceAll(settingsText(srv), "\n", " · "))
	return nil
}

// --- roles ---

func (s *Service) customerName(ctx context.Context, id int64) (string, error) {
	var name string
	err := s.DB.QueryRowContext(ctx, `SELECT name FROM customers WHERE id=?`, id).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return "", errors.New("müşteri bulunamadı")
	}
	return name, err
}

// EnsureRole returns the customer's role, creating it (on the server and in
// the panel DB) if needed. created reports a new role.
func (s *Service) EnsureRole(ctx context.Context, customerID int64) (Role, bool, error) {
	if r, err := s.Store.RoleForCustomer(ctx, customerID); err == nil {
		return r, false, nil
	}
	if _, err := s.runningServer(ctx); err != nil {
		return Role{}, false, err
	}
	cname, err := s.customerName(ctx, customerID)
	if err != nil {
		return Role{}, false, err
	}
	base := databases.LoginBase(cname)
	name := base
	for i := 2; s.Store.RoleNameTaken(ctx, name); i++ {
		name = base + "_" + strconv.Itoa(i)
	}
	if !ValidName(name) {
		return Role{}, false, ErrName
	}
	pw := databases.GeneratePassword()
	sealed, err := s.Box.SealString(pw)
	if err != nil {
		return Role{}, false, err
	}
	if _, err := s.helper(ctx, nil, strings.NewReader(pw+"\n"), []string{pw}, time.Minute, "role-create", name); err != nil {
		return Role{}, false, fmt.Errorf("rol oluşturulamadı: %w", err)
	}
	r := Role{CustomerID: customerID, CustomerName: cname, Name: name, PasswordSealed: sealed}
	if err := s.Store.InsertRole(ctx, &r); err != nil {
		s.helper(context.WithoutCancel(ctx), nil, nil, nil, time.Minute, "role-drop", name)
		return Role{}, false, err
	}
	s.Activity.Record(ctx, logs.Entry{Action: "pg.role.create", TargetType: "customer", TargetID: strconv.FormatInt(customerID, 10),
		Summary: "PostgreSQL rolü oluşturuldu: " + name + " (" + cname + ")"}, nil)
	return r, true, nil
}

// ResetPassword sets a new random password; connection strings written to
// site env files are updated (the returned sites need a restart).
func (s *Service) ResetPassword(ctx context.Context, roleID int64) ([]string, error) {
	r, err := s.Store.Role(ctx, roleID)
	if err != nil {
		return nil, err
	}
	pw := databases.GeneratePassword()
	sealed, err := s.Box.SealString(pw)
	if err != nil {
		return nil, err
	}
	if _, err := s.helper(ctx, nil, strings.NewReader(pw+"\n"), []string{pw}, time.Minute, "role-password", r.Name); err != nil {
		return nil, err
	}
	if err := s.Store.SetRolePassword(ctx, r.ID, sealed); err != nil {
		return nil, err
	}
	dbs, _ := s.Store.Databases(ctx, DBFilter{RoleID: r.ID})
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

// SetRoleEnabled enables/disables login (disabling ends its sessions).
func (s *Service) SetRoleEnabled(ctx context.Context, roleID int64, enabled bool) error {
	r, err := s.Store.Role(ctx, roleID)
	if err != nil {
		return err
	}
	flag := "0"
	if enabled {
		flag = "1"
	}
	if _, err := s.helper(ctx, nil, nil, nil, time.Minute, "role-enable", r.Name, flag); err != nil {
		return err
	}
	return s.Store.SetRoleDisabled(ctx, r.ID, !enabled)
}

// DropRole removes a role that owns no databases.
func (s *Service) DropRole(ctx context.Context, roleID int64) (Role, error) {
	r, err := s.Store.Role(ctx, roleID)
	if err != nil {
		return r, err
	}
	if r.DBCount > 0 {
		return r, ErrRoleHasDatabases
	}
	if _, err := s.helper(ctx, nil, nil, nil, time.Minute, "role-drop", r.Name); err != nil {
		return r, err
	}
	return r, s.Store.DeleteRole(ctx, r.ID)
}

// PrepareCustomerDelete drops the customer's role before the customer row is
// deleted; databases must be deleted first.
func (s *Service) PrepareCustomerDelete(ctx context.Context, customerID int64) error {
	if s.Store.CountForCustomer(ctx, customerID) > 0 {
		return errors.New("müşterinin PostgreSQL veritabanları var; önce veritabanlarını silin")
	}
	r, err := s.Store.RoleForCustomer(ctx, customerID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = s.DropRole(ctx, r.ID)
	return err
}

// --- databases ---

// CreateInput is the new database form (also used by restore/import).
type CreateInput struct {
	CustomerID int64
	Name       string
	SiteID     int64
	WriteEnv   bool
	EnvKey     string
}

func (s *Service) siteHasEnv(site sites.Site) bool {
	p, ok := s.Sites.Runtimes.Get(site.RuntimeID)
	return ok && p.Def().HasUnit()
}

// envKeyFor validates the site link of in and returns the env key to write ("" = none).
func (s *Service) envKeyFor(ctx context.Context, in CreateInput) (string, error) {
	if in.SiteID == 0 {
		if in.WriteEnv {
			return "", errors.New("ortam değişkenine yazmak için bir site seçin")
		}
		return "", nil
	}
	site, err := s.Sites.Store.Get(ctx, in.SiteID)
	if err != nil {
		return "", errors.New("site bulunamadı")
	}
	if site.CustomerID != in.CustomerID {
		return "", errors.New("site bu müşteriye ait değil")
	}
	if !in.WriteEnv {
		return "", nil
	}
	if !s.siteHasEnv(site) {
		return "", errors.New("bu sitenin ortam değişkeni yok (statik site)")
	}
	key := strings.TrimSpace(in.EnvKey)
	if key == "" {
		key = DefaultEnvKey(site.RuntimeID)
	}
	if !sites.ValidEnvKey(key) {
		return "", fmt.Errorf("geçersiz değişken adı: %s", key)
	}
	return key, nil
}

// StartCreate validates, stores the database row and queues pg.create.
func (s *Service) StartCreate(ctx context.Context, in CreateInput) (Database, int64, error) {
	in.Name = strings.TrimSpace(strings.ToLower(in.Name))
	if !ValidName(in.Name) {
		return Database{}, 0, ErrName
	}
	if s.Store.DBNameTaken(ctx, in.Name) {
		return Database{}, 0, errors.New("bu adda bir PostgreSQL veritabanı zaten var")
	}
	if _, err := s.runningServer(ctx); err != nil {
		return Database{}, 0, err
	}
	d := Database{CustomerID: in.CustomerID, Name: in.Name, SiteID: in.SiteID, Status: DBCreating}
	key, err := s.envKeyFor(ctx, in)
	if err != nil {
		return d, 0, err
	}
	d.EnvKey = key
	role, _, err := s.EnsureRole(ctx, in.CustomerID)
	if err != nil {
		return d, 0, err
	}
	if role.Disabled {
		return d, 0, errors.New("müşterinin PostgreSQL rolü devre dışı")
	}
	d.RoleID, d.RoleName = role.ID, role.Name
	if err := s.Store.InsertDatabase(ctx, &d); err != nil {
		return d, 0, err
	}
	id, err := s.Jobs.Submit(ctx, jobs.Spec{Kind: "pg.create", TargetType: "database", TargetID: d.Name,
		Summary: "PostgreSQL veritabanı oluşturuluyor: " + d.Name + " (sahip: " + role.Name + ")",
		Params:  map[string]any{"database_id": d.ID}, Retryable: true})
	if err != nil {
		s.Store.DeleteDatabase(ctx, d.ID)
	}
	return d, id, err
}

func (s *Service) jobCreate(ctx context.Context, l *jobs.Log, p map[string]any) error {
	d, err := s.Store.Database(ctx, paramID(p, "database_id"))
	if err != nil {
		return errors.New("veritabanı kaydı bulunamadı")
	}
	l.Printf("%s oluşturuluyor, sahibi %s yapılıyor…", d.Name, d.RoleName)
	if _, err := s.helper(ctx, l, nil, nil, 2*time.Minute, "db-create", d.Name, d.RoleName); err != nil {
		s.Store.SetDBStatus(context.WithoutCancel(ctx), d.ID, DBError)
		return err
	}
	s.Store.SetDBStatus(ctx, d.ID, DBReady)
	l.Progress(70)
	s.RefreshSizes(ctx)
	if d.SiteID > 0 && d.EnvKey != "" {
		l.Printf("Bağlantı dizesi %s sitesinin %s değişkenine yazılıyor…", d.SiteDomain, d.EnvKey)
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
	r, err := s.Store.Role(ctx, d.RoleID)
	if err != nil {
		return ConnInfo{}, d, err
	}
	pw, err := s.Box.OpenString(r.PasswordSealed)
	if err != nil {
		return ConnInfo{}, d, err
	}
	return ConnInfo{Host: Host, Port: Port, Database: d.Name, User: r.Name, Password: pw}, d, nil
}

// writeSiteEnv puts the connection string into the site's env and records
// the key-level diff.
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
		Summary: "PostgreSQL bağlantısı ortam değişkenine yazıldı: " + d.EnvKey, Diff: diff}, nil)
	return nil
}

// StartDrop queues pg.drop (backup first).
func (s *Service) StartDrop(ctx context.Context, d Database) (int64, error) {
	if d.Status == DBDropping {
		return 0, errors.New("silme zaten sürüyor")
	}
	s.Store.SetDBStatus(ctx, d.ID, DBDropping)
	id, err := s.Jobs.Submit(ctx, jobs.Spec{Kind: "pg.drop", TargetType: "database", TargetID: d.Name,
		Summary: "PostgreSQL veritabanı siliniyor: " + d.Name, Params: map[string]any{"database_id": d.ID, "prev_status": d.Status}})
	if err != nil {
		s.Store.SetDBStatus(ctx, d.ID, d.Status)
	}
	return id, err
}

func (s *Service) dropOne(ctx context.Context, l *jobs.Log, d Database) error {
	args := []string{"db-drop", d.Name}
	if d.Status != DBError && d.Status != DBCreating {
		args = append(args, "backup") // pg_dump -Fc to BackupDir/pre-drop-*.dump first
	}
	if _, err := s.helper(ctx, l, nil, nil, 2*time.Hour, args...); err != nil {
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
	if err := s.dropOne(ctx, l, d); err != nil {
		s.Store.SetDBStatus(context.WithoutCancel(ctx), d.ID, prev)
		return fmt.Errorf("silinemedi (yedek alınamadıysa silme yapılmaz): %w", err)
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

// siteDeleted runs inside the site delete job (site lock held — must not
// call SaveEnv). Without drop_dbs the databases stay, unlinked.
func (s *Service) siteDeleted(ctx context.Context, l *jobs.Log, site sites.Site, p map[string]any) error {
	dbs, err := s.Store.Databases(ctx, DBFilter{SiteID: site.ID})
	if err != nil || len(dbs) == 0 {
		return err
	}
	names := make([]string, len(dbs))
	for i, d := range dbs {
		names[i] = d.Name
	}
	if drop, _ := p["drop_dbs"].(bool); !drop {
		l.Printf("PostgreSQL veritabanları korunuyor (siteden ayrılıyor): %s", strings.Join(names, ", "))
		return nil
	}
	var failed []string
	for _, d := range dbs {
		l.Printf("→ PostgreSQL veritabanı siliniyor: %s", d.Name)
		if err := s.dropOne(ctx, l, d); err != nil {
			l.Printf("✗ %s: %v", d.Name, err)
			failed = append(failed, d.Name)
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("silinemeyen PostgreSQL veritabanları: %s", strings.Join(failed, ", "))
	}
	return nil
}

// ParseSizes parses `hp-pg.sh sizes` (name=bytes lines).
func ParseSizes(out string) map[string]int64 {
	m := map[string]int64{}
	for _, line := range strings.Split(out, "\n") {
		if mm := sizeRe.FindStringSubmatch(strings.TrimSpace(line)); mm != nil {
			n, _ := strconv.ParseInt(mm[2], 10, 64)
			m[mm[1]] = n
		}
	}
	return m
}

// RefreshSizes reads database sizes from the server.
func (s *Service) RefreshSizes(ctx context.Context) error {
	res, err := s.helper(ctx, nil, nil, nil, time.Minute, "sizes")
	if err != nil {
		return err
	}
	return s.Store.SetSizes(ctx, ParseSizes(res.Stdout))
}

// Maintain is part of the daily maintenance: refresh sizes.
func (s *Service) Maintain(ctx context.Context) {
	if _, err := s.runningServer(ctx); err != nil {
		return
	}
	if err := s.RefreshSizes(ctx); err != nil && s.Log != nil {
		s.Log.Warn("pg size refresh failed", "err", err)
	}
}

// StartIsolationTest queues the two-role isolation test.
func (s *Service) StartIsolationTest(ctx context.Context) (int64, error) {
	if _, err := s.runningServer(ctx); err != nil {
		return 0, err
	}
	return s.Jobs.Submit(ctx, jobs.Spec{Kind: "pg.isolation-test", TargetType: "db_server", TargetID: "postgres",
		Summary: "PostgreSQL müşteri izolasyon testi", Retryable: true})
}

func (s *Service) jobIsolation(ctx context.Context, l *jobs.Log, _ map[string]any) error {
	l.Printf("İki geçici rol + veritabanı oluşturuluyor; her biri diğerine bağlanmayı, süper kullanıcı işlemlerini ve sunucu dosyalarını dener…")
	_, err := s.helper(ctx, l, nil, nil, 5*time.Minute, "isolation-test")
	return err
}

// --- backup / restore / import ---

// DumpTo writes `pg_dump -Fc` of db to BackupDir/<file>.dump (root-owned;
// hp-backup.sh create moves it into the backup).
func (s *Service) DumpTo(ctx context.Context, w io.Writer, db, file string) error {
	_, err := s.helper(ctx, w, nil, nil, 4*time.Hour, "dump", db, file)
	return err
}

// Source is where a restore reads its dump from: a local backup or an upload.
type Source struct {
	Domain, Backup, DB string // backup: /var/backups/hostpanel/<domain>/<backup>/db-pg-<db>.dump
	Upload             string // upload: path under the upload dir
}

func (src Source) args() []string {
	if src.Upload != "" {
		return []string{"upload", src.Upload}
	}
	return []string{"backup", src.Domain, src.Backup, src.DB}
}

// RestoreFrom restores a dump as in.Name, owned by the customer's role. An
// existing panel database of the same name is replaced (same customer only);
// otherwise a new one is created. The dump is applied as the owner role in one
// transaction into a temporary database and swapped in only on success.
func (s *Service) RestoreFrom(ctx context.Context, w io.Writer, src Source, in CreateInput) (Database, error) {
	in.Name = strings.TrimSpace(strings.ToLower(in.Name))
	if !ValidName(in.Name) {
		return Database{}, ErrName
	}
	if _, err := s.runningServer(ctx); err != nil {
		return Database{}, err
	}
	var d Database
	created := false
	if existing, err := s.Store.DatabaseByName(ctx, in.Name); err == nil {
		if existing.CustomerID != in.CustomerID {
			return d, errors.New("bu adda başka bir müşteriye ait veritabanı var")
		}
		d = existing
	} else {
		role, _, err := s.EnsureRole(ctx, in.CustomerID)
		if err != nil {
			return d, err
		}
		d = Database{CustomerID: in.CustomerID, RoleID: role.ID, RoleName: role.Name, SiteID: in.SiteID, Name: in.Name, Status: DBCreating}
		if err := s.Store.InsertDatabase(ctx, &d); err != nil {
			return d, err
		}
		created = true
	}
	role, err := s.Store.Role(ctx, d.RoleID)
	if err != nil {
		return d, err
	}
	pw, err := s.Box.OpenString(role.PasswordSealed)
	if err != nil {
		return d, err
	}
	args := append([]string{"restore", d.Name, role.Name}, src.args()...)
	if _, err := s.helper(ctx, w, strings.NewReader(pw+"\n"), []string{pw}, 4*time.Hour, args...); err != nil {
		if created {
			s.Store.DeleteDatabase(context.WithoutCancel(ctx), d.ID)
		}
		return d, err
	}
	s.Store.SetDBStatus(ctx, d.ID, DBReady)
	s.RefreshSizes(ctx)
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

// ImportInput is the migration tab's "PostgreSQL dökümü yükle" form.
type ImportInput struct {
	Upload   string // pgimport-<n>.dump in UploadDir
	Name     string
	WriteEnv bool
	EnvKey   string
}

// StartImport checks the upload and queues pg.import for site.
func (s *Service) StartImport(ctx context.Context, site sites.Site, in ImportInput) (int64, error) {
	in.Name = strings.TrimSpace(strings.ToLower(in.Name))
	if !ValidName(in.Name) {
		return 0, ErrName
	}
	if !ImportRe.MatchString(in.Upload) {
		return 0, errors.New("geçersiz yükleme")
	}
	if in.EnvKey != "" && !sites.ValidEnvKey(in.EnvKey) {
		return 0, errors.New("geçersiz değişken adı")
	}
	if existing, err := s.Store.DatabaseByName(ctx, in.Name); err == nil && existing.CustomerID != site.CustomerID {
		return 0, errors.New("bu adda başka bir müşteriye ait veritabanı var")
	}
	if _, err := s.runningServer(ctx); err != nil {
		return 0, err
	}
	return s.Jobs.Submit(ctx, jobs.Spec{Kind: "pg.import", TargetType: "site", TargetID: site.Domain,
		Summary: "PostgreSQL dökümü içe aktarılıyor: " + in.Name + " → " + site.Domain,
		Params:  map[string]any{"site_id": site.ID, "upload": in.Upload, "name": in.Name, "write_env": in.WriteEnv, "env_key": in.EnvKey}})
}

func (s *Service) jobImport(ctx context.Context, l *jobs.Log, p map[string]any) error {
	site, err := s.Sites.Store.Get(ctx, paramID(p, "site_id"))
	if err != nil {
		return errors.New("site bulunamadı")
	}
	upload, _ := p["upload"].(string)
	if !ImportRe.MatchString(upload) {
		return errors.New("geçersiz yükleme")
	}
	path := filepath.Join(s.UploadDir, upload)
	defer os.Remove(path)
	name, _ := p["name"].(string)
	writeEnv, _ := p["write_env"].(bool)
	envKey, _ := p["env_key"].(string)
	l.Printf("Döküm kontrol ediliyor…")
	if _, err := s.helper(ctx, l, nil, nil, 10*time.Minute, "check-dump", path); err != nil {
		return err
	}
	l.Progress(20)
	d, err := s.RestoreFrom(ctx, l, Source{Upload: path}, CreateInput{CustomerID: site.CustomerID,
		Name: name, SiteID: site.ID, WriteEnv: writeEnv, EnvKey: envKey})
	if err != nil {
		return err
	}
	l.Progress(100)
	l.Printf("Veritabanı hazır: %s (sahibi %s)", d.Name, d.RoleName)
	if writeEnv && d.EnvKey != "" {
		l.Printf("Bağlantı dizesi %s değişkenine yazıldı; site yeniden başlatılınca geçerli olur", d.EnvKey)
	}
	return nil
}

// SaveUpload stores an uploaded custom-format dump as pgimport-<n>.dump in
// UploadDir. Anything that does not start with the pg_dump -Fc signature is
// refused right away (plain .sql would run psql meta commands on restore).
func (s *Service) SaveUpload(r io.Reader, limit int64) (string, int64, error) {
	head := make([]byte, 5)
	if _, err := io.ReadFull(r, head); err != nil || string(head) != "PGDMP" {
		return "", 0, errors.New("dosya pg_dump custom formatında değil (pg_dump -Fc ile alın; düz .sql kabul edilmez)")
	}
	if err := os.MkdirAll(s.UploadDir, 0o750); err != nil {
		return "", 0, err
	}
	name := fmt.Sprintf("pgimport-%d.dump", time.Now().UnixNano())
	path := filepath.Join(s.UploadDir, name)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return "", 0, err
	}
	n, err := io.Copy(f, io.MultiReader(bytes.NewReader(head), io.LimitReader(r, limit)))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > limit {
		err = fmt.Errorf("dosya çok büyük (en fazla %d MB)", limit>>20)
	}
	if err != nil {
		os.Remove(path)
		return "", 0, err
	}
	return name, n, nil
}

// DiscardUpload removes an upload that was not queued.
func (s *Service) DiscardUpload(name string) {
	if ImportRe.MatchString(name) {
		os.Remove(filepath.Join(s.UploadDir, name))
	}
}
