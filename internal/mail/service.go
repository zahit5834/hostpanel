package mail

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"net/smtp"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zahit5834/hostpanel/internal/exec"
	"github.com/zahit5834/hostpanel/internal/jobs"
	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/pubdns"
	"github.com/zahit5834/hostpanel/internal/sites"
	"github.com/zahit5834/hostpanel/internal/store"
)

const settingDockerInstalled = "docker_installed" // shared with the database services

// leEmailRe + validLEEmail mirror lib.sh validate_email
// (^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}$); the lengths
// are checked in Go so the compiled program stays small (RAM budget).
var leEmailRe = regexp.MustCompile(`^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z][A-Za-z]+$`)

func validLEEmail(s string) bool {
	local, domain, _ := strings.Cut(s, "@")
	dot := strings.LastIndexByte(domain, '.')
	return leEmailRe.MatchString(s) && len(local) <= 64 && dot >= 0 && dot <= 253 && len(domain)-dot-1 <= 63
}

// Service manages the mail container, its domains, mailboxes and aliases.
type Service struct {
	Store      *Store
	DB         *sql.DB
	Runner     exec.Runner // privileged helper (dry-run in dev)
	Jobs       *jobs.Manager
	Activity   *logs.Activity
	Log        *slog.Logger
	ScriptsDir string
	DryRun     bool
	// MemTotalMB caps the memory setting (0 = no cap).
	MemTotalMB int
	// Fake replaces the account files in dry-run (hp-mail.sh is only logged).
	Fake *Fake

	// ServerIPs returns the addresses of this server (DNS pre-check, PTR).
	ServerIPs func(ctx context.Context) []netip.Addr
	// PublicDNS answers like the outside world (nil = pubdns.Default); the
	// system resolver reads /etc/hosts first (127.0.1.1 for the own hostname).
	PublicDNS PublicResolver
	// Changed is called with the mail names whose DNS records changed.
	Changed func(ctx context.Context, names []string)
	// NameTaken rejects a mail host name used by a site or the panel.
	NameTaken func(ctx context.Context, host string) error

	mu sync.Mutex // serializes container-level operations
}

// Register adds the job handlers.
func (s *Service) Register() {
	s.Jobs.Register("mail.install", s.jobInstall)
	s.Jobs.Register("mail.recreate", s.jobRecreate)
	s.Jobs.Register("mail.mailbox.delete", s.jobDeleteMailbox)
	s.Jobs.Register("mail.update", s.jobImageUpdate)
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

// ErrNoServer means the mail server has not been installed yet.
var ErrNoServer = errors.New("posta sunucusu kurulu değil")

func (s *Service) changed(ctx context.Context, names ...string) {
	if s.Changed != nil && len(names) > 0 {
		s.Changed(ctx, names)
	}
}

// --- status ---

// LiveStatus asks Docker (root helper). In dry-run it is derived from the DB.
func (s *Service) LiveStatus(ctx context.Context) Status {
	if s.DryRun {
		var st Status
		st.Docker, st.Container = "absent", "absent"
		if store.GetSetting(ctx, s.DB, settingDockerInstalled, "") == "1" {
			st.Docker = "active"
		}
		if srv, err := s.Store.Server(ctx); err == nil {
			switch srv.Status {
			case StatusRunning:
				st.Container, st.CPU, st.Mem, st.MemPct = "running", "0.31%", "348MiB / 1GiB", "34.0%"
				st.StartedAt, st.Image, st.Health = srv.UpdatedAt.UTC().Format(time.RFC3339), srv.Image, "healthy"
				st.CertUntil = srv.CreatedAt.Add(90 * 24 * time.Hour)
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

// DockerPresent is a cheap, unprivileged check that picks the page state.
func (s *Service) DockerPresent(ctx context.Context) bool {
	if s.DryRun {
		return store.GetSetting(ctx, s.DB, settingDockerInstalled, "") == "1"
	}
	_, err := os.Stat("/usr/bin/docker")
	return err == nil
}

// Installed reports whether a server row exists and finished installing.
func (s *Service) Installed(ctx context.Context) bool {
	srv, err := s.Store.Server(ctx)
	return err == nil && (srv.Status == StatusRunning || srv.Status == StatusStopped)
}

// Host returns the mail host name ("" when no server is recorded).
func (s *Service) Host(ctx context.Context) string {
	srv, err := s.Store.Server(ctx)
	if err != nil {
		return ""
	}
	return srv.Hostname
}

// DNSInfo is what the DNS service publishes: the mail host and the domains.
func (s *Service) DNSInfo(ctx context.Context) (string, []Domain) {
	srv, err := s.Store.Server(ctx)
	if err != nil {
		return "", nil
	}
	ds, _ := s.Store.Domains(ctx, 0)
	return srv.Hostname, ds
}

func (s *Service) server(ctx context.Context) (Server, error) {
	srv, err := s.Store.Server(ctx)
	if err != nil {
		return srv, ErrNoServer
	}
	if srv.Status == StatusInstalling || srv.Status == StatusError {
		return srv, errors.New("posta sunucusunun kurulumu tamamlanmadı")
	}
	return srv, nil
}

func (s *Service) runningServer(ctx context.Context) (Server, error) {
	srv, err := s.server(ctx)
	if err != nil {
		return srv, err
	}
	if srv.Status != StatusRunning {
		return srv, errors.New("posta sunucusu çalışmıyor")
	}
	return srv, nil
}

// --- install / recreate ---

func (s *Service) checkMemory(mb int, clamav bool) error {
	if mb < MinMemoryMB || mb > MaxMemoryMB {
		return fmt.Errorf("bellek %d–%d MB arasında olmalı", MinMemoryMB, MaxMemoryMB)
	}
	if clamav && mb < ClamAVMinMemoryMB {
		return fmt.Errorf("ClamAV açıkken bellek en az %d MB olmalı (virüs imzaları ~1.2 GB RAM tutar)", ClamAVMinMemoryMB)
	}
	if s.MemTotalMB > 0 && mb > s.MemTotalMB-512 {
		return fmt.Errorf("bellek sunucudaki toplam RAM'in (%d MB) en az 512 MB altında olmalı", s.MemTotalMB)
	}
	return nil
}

// InstallInput is the install form.
type InstallInput struct {
	Hostname   string // mail.example.com: the server's name (PTR, MX target, TLS)
	Domain     string // first mail domain
	CustomerID int64  // owner of the first domain (0 = none)
	LEEmail    string
	MemoryMB   int
}

func (s *Service) checkHostname(ctx context.Context, host string) error {
	if !sites.ValidDomain(host) || strings.Count(host, ".") < 2 {
		return errors.New("posta sunucusu adı mail.ornek.com biçiminde tam bir ad olmalı")
	}
	if s.NameTaken != nil {
		return s.NameTaken(ctx, host)
	}
	return nil
}

// StartInstall stores the server and its first domain and queues the install.
func (s *Service) StartInstall(ctx context.Context, in InstallInput) (int64, error) {
	in.Hostname, in.Domain = sites.NormalizeDomain(in.Hostname), sites.NormalizeDomain(in.Domain)
	in.LEEmail = strings.TrimSpace(in.LEEmail)
	if err := s.checkHostname(ctx, in.Hostname); err != nil {
		return 0, err
	}
	if !sites.ValidDomain(in.Domain) {
		return 0, errors.New("geçersiz alan adı")
	}
	if in.Domain == in.Hostname {
		return 0, errors.New("posta sunucusu adı ile posta alan adı aynı olamaz (ör. sunucu mail.ornek.com, alan adı ornek.com)")
	}
	if !validLEEmail(in.LEEmail) {
		return 0, errors.New("sertifika (Let's Encrypt) için geçerli bir e-posta adresi girin")
	}
	if err := s.checkMemory(in.MemoryMB, false); err != nil {
		return 0, err
	}
	if _, err := s.Store.Server(ctx); err == nil {
		return 0, errors.New("posta sunucusu zaten kurulu")
	}
	if !s.LiveStatus(ctx).DockerInstalled() {
		return 0, errors.New("önce Docker'ı kurun")
	}
	srv := Server{Image: DefaultImage, Hostname: in.Hostname, LEEmail: in.LEEmail, MemoryMB: in.MemoryMB,
		MsgLimitMB: DefaultMsgLimitMB, Status: StatusInstalling}
	if err := s.Store.InsertServer(ctx, &srv); err != nil {
		return 0, err
	}
	d := Domain{Name: in.Domain, CustomerID: in.CustomerID}
	if err := s.Store.InsertDomain(ctx, &d); err != nil {
		s.Store.DeleteServer(ctx, srv.ID)
		return 0, err
	}
	// Before the job: the host's A record (when a panel zone covers it) has
	// to be published by the time the job checks DNS.
	s.changed(ctx, in.Hostname, in.Domain)
	id, err := s.Jobs.Submit(ctx, jobs.Spec{Kind: "mail.install", TargetType: "mail", TargetID: in.Hostname,
		Summary: fmt.Sprintf("Posta sunucusu kuruluyor (%s, %d MB)", in.Hostname, in.MemoryMB),
		Params:  map[string]any{"server_id": srv.ID}, Retryable: true})
	if err != nil {
		s.Store.DeleteDomain(ctx, d.ID)
		s.Store.DeleteServer(ctx, srv.ID)
		s.changed(ctx, in.Hostname, in.Domain)
	}
	return id, err
}

func (s *Service) failServer(ctx context.Context, id int64, err error) error {
	s.Store.SetServerStatus(context.WithoutCancel(ctx), id, StatusError, err.Error())
	return err
}

// postmasterDomain is the oldest mail domain (POSTMASTER_ADDRESS).
func (s *Service) postmasterDomain(ctx context.Context) (string, error) {
	ds, err := s.Store.Domains(ctx, 0)
	if err != nil || len(ds) == 0 {
		return "", errors.New("posta alan adı kaydı yok")
	}
	first := ds[0]
	for _, d := range ds[1:] {
		if d.ID < first.ID {
			first = d
		}
	}
	return first.Name, nil
}

func (s *Service) createContainer(ctx context.Context, l *jobs.Log, srv Server) error {
	pm, err := s.postmasterDomain(ctx)
	if err != nil {
		return err
	}
	clam := "0"
	if srv.ClamAV {
		clam = "1"
	}
	if _, err := s.helper(ctx, l, nil, nil, 15*time.Minute, "create", srv.Image, srv.Hostname,
		strconv.Itoa(srv.MemoryMB), clam, strconv.Itoa(srv.MsgLimitMB), pm); err != nil {
		return err
	}
	l.Printf("Posta sunucusunun hazır olması bekleniyor (en fazla 3 dk)…")
	_, err = s.helper(ctx, l, nil, nil, 5*time.Minute, "wait")
	return err
}

// vhostRev is the revision of the mail host's nginx vhost (lib.sh
// render_mail_vhost). 2: port 443 with the mail certificate + catch-all.
const (
	vhostRev        = "2"
	settingVhostRev = "mail_vhost_rev"
)

// EnsureVhost re-renders the mail host's vhost once per revision. A panel
// update installs the new scripts but runs the previous hp-update.sh, so the
// panel does this itself on its first start.
func (s *Service) EnsureVhost(ctx context.Context) {
	if store.GetSetting(ctx, s.DB, settingVhostRev, "") == vhostRev {
		return
	}
	srv, err := s.Store.Server(ctx)
	if err != nil || srv.Hostname == "" || srv.Status == StatusInstalling || srv.Status == StatusError {
		return // an install (or its retry) writes the current vhost itself
	}
	if _, err := s.helper(ctx, nil, nil, nil, time.Minute, "vhost", srv.Hostname); err != nil {
		s.Log.Warn("mail vhost refresh failed", "err", err)
		return
	}
	store.SetSetting(ctx, s.DB, settingVhostRev, vhostRev)
	s.Log.Info("mail vhost refreshed", "host", srv.Hostname, "rev", vhostRev)
}

// PublicResolver is the subset of *pubdns.Resolver used (fakeable in tests).
type PublicResolver interface {
	LookupA(ctx context.Context, host string) ([]netip.Addr, error)
	LookupPTR(ctx context.Context, ip netip.Addr) ([]string, error)
}

func (s *Service) public() PublicResolver {
	if s.PublicDNS != nil {
		return s.PublicDNS
	}
	return pubdns.Default
}

// lookupA returns the public A records of host. Public resolvers are asked
// directly; only if none of them can be reached does it fall back to the
// system resolver, ignoring loopback answers (/etc/hosts).
func (s *Service) lookupA(ctx context.Context, host string) ([]netip.Addr, error) {
	got, err := s.public().LookupA(ctx, host)
	if err == nil || errors.Is(err, pubdns.ErrNotFound) || ctx.Err() != nil {
		return got, err
	}
	lctx, cancel := lookupCtx(ctx)
	sys, serr := net.DefaultResolver.LookupNetIP(lctx, "ip4", host)
	cancel()
	if serr != nil {
		return nil, err
	}
	var out, loop []netip.Addr
	for _, a := range sys {
		if a = a.Unmap(); a.IsLoopback() {
			loop = append(loop, a)
		} else {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w; sistem çözümleyicisi yalnızca %v döndürdü (/etc/hosts kaydı, dışarıdan görünen değil)", err, loop)
	}
	return out, nil
}

// resolvesHere waits until host has a public A record on this server.
func (s *Service) resolvesHere(ctx context.Context, l *jobs.Log, host string) error {
	var mine []netip.Addr
	if s.ServerIPs != nil {
		mine = s.ServerIPs(ctx)
	}
	var last string
	for try := 0; try < 6; try++ {
		if try > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(10 * time.Second):
			}
		}
		got, err := s.lookupA(ctx, host)
		if err != nil {
			last = lookupErr(err)
			continue
		}
		var names []string
		for _, a := range got {
			a = a.Unmap()
			names = append(names, a.String())
			for _, m := range mine {
				if m == a {
					l.Printf("DNS: %s → %s (bu sunucu)", host, a)
					return nil
				}
			}
		}
		last = "A kaydı " + strings.Join(names, ", ") + " adresini gösteriyor"
	}
	return fmt.Errorf("%s bu sunucuya çözülmüyor (%s). A kaydını sunucunun IP'sine yönlendirin (Ayarlar → Genel'deki genel IP listesi de kontrol edilir), sonra yeniden deneyin", host, last)
}

// relayOpen reports whether the server accepts mail for a foreign recipient
// from an unauthenticated client (it must not).
func relayOpen(ctx context.Context, host string) (bool, error) {
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", "127.0.0.1:25")
	if err != nil {
		return false, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(40 * time.Second))
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return false, err
	}
	defer c.Close()
	if err := c.Hello("relaytest.invalid"); err != nil {
		return false, err
	}
	if err := c.Mail("relaytest@example.org"); err != nil {
		return false, nil // refused already at MAIL FROM
	}
	return c.Rcpt("relaytest@example.com") == nil, nil
}

func (s *Service) relayTest(ctx context.Context, l *jobs.Log, srv Server) error {
	var open bool
	var err error
	for try := 0; try < 3; try++ {
		if open, err = relayOpen(ctx, srv.Hostname); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
	if err != nil {
		l.Printf("UYARI: açık röle testi yapılamadı (%v). Kurulumdan sonra dışarıdan bir araçla denetleyin.", err)
		return nil
	}
	if open {
		s.helper(context.WithoutCancel(ctx), l, nil, nil, 3*time.Minute, "stop")
		return errors.New("sunucu kimlik doğrulamasız dış alıcıya posta kabul etti (açık röle); container durduruldu")
	}
	l.Printf("Açık röle testi: kimliksiz dış alıcı reddedildi ✓")
	return nil
}

// jobInstall: pre-checks → directories + first account → port 80 vhost →
// certificate → container → DKIM → DNS → open relay test.
func (s *Service) jobInstall(ctx context.Context, l *jobs.Log, p map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	srv, err := s.Store.Server(ctx)
	if err != nil || srv.ID != paramID(p, "server_id") {
		return errors.New("sunucu kaydı bulunamadı")
	}
	first, err := s.postmasterDomain(ctx)
	if err != nil {
		return s.failServer(ctx, srv.ID, err)
	}
	s.Store.SetServerStatus(ctx, srv.ID, StatusInstalling, "")
	fail := func(err error) error { return s.failServer(ctx, srv.ID, err) }

	l.Printf("Ön kontroller (Docker, nginx, certbot, 25/465/587/993 portları)…")
	if _, err := s.helper(ctx, l, nil, nil, time.Minute, "precheck", srv.Hostname); err != nil {
		return fail(err)
	}
	if !s.DryRun {
		if err := s.resolvesHere(ctx, l, srv.Hostname); err != nil {
			return fail(err)
		}
	}
	l.Progress(10)

	l.Printf("Dizinler ve ilk hesap (postmaster@%s) hazırlanıyor…", first)
	if _, err := s.helper(ctx, l, nil, nil, time.Minute, "prepare", first); err != nil {
		return fail(err)
	}
	l.Printf("Sertifika için 80. port vhost'u yazılıyor…")
	if _, err := s.helper(ctx, l, nil, nil, time.Minute, "vhost", srv.Hostname); err != nil {
		return fail(err)
	}
	l.Progress(20)
	l.Printf("Let's Encrypt sertifikası alınıyor (%s)…", srv.Hostname)
	if _, err := s.helper(ctx, l, nil, nil, 5*time.Minute, "cert", srv.Hostname, srv.LEEmail); err != nil {
		return fail(fmt.Errorf("sertifika alınamadı: %w", err))
	}
	l.Progress(35)

	st := s.LiveStatus(ctx)
	if s.DryRun || st.Container == "absent" {
		l.Printf("İmaj indiriliyor ve container oluşturuluyor (%s)…", srv.Image)
		if err := s.createContainer(ctx, l, srv); err != nil {
			s.helper(context.WithoutCancel(ctx), l, nil, nil, 3*time.Minute, "remove")
			return fail(err)
		}
	} else {
		l.Printf("Container zaten var (%s); yeniden oluşturulmadı.", st.Container)
		if !st.Running() {
			if _, err := s.helper(ctx, l, nil, nil, 3*time.Minute, "start"); err != nil {
				return fail(err)
			}
		}
		if _, err := s.helper(ctx, l, nil, nil, 5*time.Minute, "wait"); err != nil {
			return fail(err)
		}
	}
	l.Progress(80)

	ds, _ := s.Store.Domains(ctx, 0)
	var names []string
	for _, d := range ds {
		txt, err := s.dkim(ctx, l, d.Name)
		if err != nil {
			return fail(err)
		}
		s.Store.SetDKIM(ctx, d.ID, txt)
		names = append(names, d.Name)
	}
	if s.Fake != nil {
		s.Fake.setAccount("postmaster@" + first)
	}
	l.Progress(90)

	if !s.DryRun {
		if err := s.relayTest(ctx, l, srv); err != nil {
			return fail(err)
		}
	}
	s.Store.SetServerStatus(ctx, srv.ID, StatusRunning, "")
	s.changed(ctx, append(names, srv.Hostname)...)
	l.Progress(100)
	l.Printf("Posta sunucusu hazır: %s (SMTP 25, gönderim 465/587, IMAP 993).", srv.Hostname)
	l.Printf("İlk hesap postmaster@%s rastgele bir şifreyle oluşturuldu; kullanmak için E-posta → %s → \"Şifre sıfırla\".", first, first)
	l.Printf("Bu portlar Docker tarafından yayınlanır ve UFW kurallarından geçmez. PTR (ters DNS) kaydını sağlayıcı panelinden %s yapın.", srv.Hostname)
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
	if _, err := s.helper(ctx, w, nil, nil, 3*time.Minute, "purge"); err != nil {
		return err
	}
	names := []string{srv.Hostname}
	ds, _ := s.Store.Domains(ctx, 0)
	for _, d := range ds {
		names = append(names, d.Name)
		if err := s.Store.DeleteDomain(ctx, d.ID); err != nil {
			return err
		}
	}
	if err := s.Store.DeleteServer(ctx, srv.ID); err != nil {
		return err
	}
	if s.Fake != nil {
		s.Fake.reset()
	}
	s.changed(ctx, names...)
	return nil
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
	srv, err := s.server(ctx)
	if err != nil {
		return err
	}
	if _, err := s.helper(ctx, nil, nil, nil, 3*time.Minute, op); err != nil {
		return err
	}
	return s.Store.SetServerStatus(ctx, srv.ID, status, "")
}

// SettingsInput is the server settings form.
type SettingsInput struct {
	MemoryMB   int
	ClamAV     bool
	MsgLimitMB int
}

func settingsText(srv Server) string {
	clam := "kapalı"
	if srv.ClamAV {
		clam = "açık"
	}
	return fmt.Sprintf("bellek: %d MB\nvirüs taraması (ClamAV): %s\nen büyük ileti: %d MB", srv.MemoryMB, clam, srv.MsgLimitMB)
}

// StartSettings stores the settings and queues a container recreate (mail
// and configuration are kept). It returns the job id and the diff.
func (s *Service) StartSettings(ctx context.Context, in SettingsInput) (int64, string, error) {
	srv, err := s.server(ctx)
	if err != nil {
		return 0, "", err
	}
	if err := s.checkMemory(in.MemoryMB, in.ClamAV); err != nil {
		return 0, "", err
	}
	if in.MsgLimitMB < 1 || in.MsgLimitMB > MaxMsgLimitMB {
		return 0, "", fmt.Errorf("en büyük ileti boyutu 1–%d MB arasında olmalı", MaxMsgLimitMB)
	}
	before := settingsText(srv)
	srv.MemoryMB, srv.ClamAV, srv.MsgLimitMB = in.MemoryMB, in.ClamAV, in.MsgLimitMB
	after := settingsText(srv)
	if before == after {
		return 0, "", errors.New("değişiklik yok")
	}
	if err := s.Store.UpdateServerSettings(ctx, srv); err != nil {
		return 0, "", err
	}
	id, err := s.Jobs.Submit(ctx, jobs.Spec{Kind: "mail.recreate", TargetType: "mail", TargetID: srv.Hostname,
		Summary: "Posta sunucusu ayarları uygulanıyor (container yeniden oluşturuluyor)", Params: map[string]any{"server_id": srv.ID}, Retryable: true})
	return id, logs.LineDiff(before, after), err
}

// jobRecreate removes the container and creates it again on the same
// directories (mail, accounts, DKIM keys and the certificate are kept).
func (s *Service) jobRecreate(ctx context.Context, l *jobs.Log, p map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	srv, err := s.Store.Server(ctx)
	if err != nil || srv.ID != paramID(p, "server_id") {
		return errors.New("sunucu kaydı bulunamadı")
	}
	l.Printf("Container yeniden oluşturuluyor (veri %s altında korunur)…", DataDir)
	if _, err := s.helper(ctx, l, nil, nil, 3*time.Minute, "remove"); err != nil {
		return s.failServer(ctx, srv.ID, err)
	}
	l.Progress(20)
	if err := s.createContainer(ctx, l, srv); err != nil {
		return s.failServer(ctx, srv.ID, err)
	}
	s.Store.SetServerStatus(ctx, srv.ID, StatusRunning, "")
	l.Progress(100)
	l.Printf("Ayarlar uygulandı: %s", strings.ReplaceAll(settingsText(srv), "\n", " · "))
	return nil
}

// --- domains ---

// dkim makes sure domain has a signing key and returns its DNS record.
func (s *Service) dkim(ctx context.Context, w io.Writer, domain string) (string, error) {
	res, err := s.helper(ctx, w, nil, nil, 2*time.Minute, "dkim", domain)
	if err != nil {
		return "", err
	}
	if s.DryRun {
		return fakeDKIM(domain), nil
	}
	txt := ParseDKIM(res.Stdout)
	if txt == "" {
		return "", fmt.Errorf("%s için DKIM kaydı okunamadı", domain)
	}
	return txt, nil
}

// AddDomain creates the DKIM key of a new mail domain and records it.
func (s *Service) AddDomain(ctx context.Context, name string, customerID int64) (Domain, error) {
	name = sites.NormalizeDomain(name)
	if !sites.ValidDomain(name) {
		return Domain{}, errors.New("geçersiz alan adı")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	srv, err := s.runningServer(ctx)
	if err != nil {
		return Domain{}, err
	}
	if name == srv.Hostname {
		return Domain{}, errors.New("posta sunucusunun kendi adı posta alan adı olamaz")
	}
	if _, err := s.Store.DomainByName(ctx, name); err == nil {
		return Domain{}, errors.New("bu alan adı zaten ekli")
	}
	txt, err := s.dkim(ctx, nil, name)
	if err != nil {
		return Domain{}, err
	}
	d := Domain{Name: name, CustomerID: customerID, DKIMSelector: DKIMSelector, DKIMTXT: txt}
	if err := s.Store.InsertDomain(ctx, &d); err != nil {
		return Domain{}, err
	}
	s.changed(ctx, name)
	return d, nil
}

// DeleteDomain removes an empty mail domain (its DKIM key is archived).
func (s *Service) DeleteDomain(ctx context.Context, id int64) (Domain, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, err := s.Store.Domain(ctx, id)
	if err != nil {
		return d, errors.New("alan adı bulunamadı")
	}
	if _, err := s.server(ctx); err != nil {
		return d, err
	}
	l, err := s.Listing(ctx)
	if err != nil {
		return d, err
	}
	if own := l.ForDomain(d.Name); len(own.Mailboxes)+len(own.Aliases) > 0 {
		return d, errors.New("önce bu alan adındaki posta kutularını ve yönlendirmeleri silin")
	}
	if _, err := s.helper(ctx, nil, nil, nil, 2*time.Minute, "domain-del", d.Name); err != nil {
		return d, err
	}
	if err := s.Store.DeleteDomain(ctx, id); err != nil {
		return d, err
	}
	s.changed(ctx, d.Name)
	return d, nil
}

// --- mailboxes and aliases ---

// Listing reads the account and alias files (no password hashes).
func (s *Service) Listing(ctx context.Context) (Listing, error) {
	if s.Fake != nil {
		if s.Fake.empty() && s.Installed(ctx) { // panel restarted: the fake lost its state
			if pm, err := s.postmasterDomain(ctx); err == nil {
				s.Fake.setAccount("postmaster@" + pm)
			}
		}
		return s.Fake.listing(), nil
	}
	res, err := s.helper(ctx, nil, nil, nil, 30*time.Second, "list")
	if err != nil {
		return Listing{}, err
	}
	return ParseList(res.Stdout), nil
}

// WithUsage fills the used space of the mailboxes (best effort: the
// container has to be running).
func (s *Service) WithUsage(ctx context.Context, l Listing) Listing {
	if s.Fake != nil || len(l.Mailboxes) == 0 {
		return l
	}
	res, err := s.helper(ctx, nil, nil, nil, 30*time.Second, "usage")
	if err != nil {
		return l
	}
	used := ParseUsage(res.Stdout)
	for i := range l.Mailboxes {
		if n, ok := used[l.Mailboxes[i].Address]; ok {
			l.Mailboxes[i].UsedKiB, l.Mailboxes[i].HasUsage = n, true
		}
	}
	return l
}

const pwAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"

// GeneratePassword returns 20 random characters without look-alikes (~116 bits).
func GeneratePassword() string {
	b := make([]byte, 20)
	for i := range b {
		for {
			var r [1]byte
			if _, err := rand.Read(r[:]); err != nil {
				panic(err)
			}
			if int(r[0]) < 256-256%len(pwAlphabet) {
				b[i] = pwAlphabet[int(r[0])%len(pwAlphabet)]
				break
			}
		}
	}
	return string(b)
}

func checkQuota(mb int) error {
	if mb < 0 || mb > MaxQuotaMB {
		return fmt.Errorf("kota 0 (sınırsız) – %d MB arasında olmalı", MaxQuotaMB)
	}
	return nil
}

// ownAddress validates addr and requires its domain to be a mail domain.
func (s *Service) ownAddress(ctx context.Context, addr string) error {
	if !ValidAddress(addr) {
		return errors.New("geçersiz adres")
	}
	if _, err := s.Store.DomainByName(ctx, DomainOf(addr)); err != nil {
		return errors.New("adres panelde kayıtlı bir posta alan adında değil")
	}
	return nil
}

// setPassword sends the password on stdin (never argv; masked in logs).
func (s *Service) setPassword(ctx context.Context, addr, pw, mode string) error {
	_, err := s.helper(ctx, nil, strings.NewReader(pw+"\n"), []string{pw}, time.Minute, "account-set", addr, mode)
	return err
}

// CreateMailbox adds an account. An empty password is generated; either way
// it is returned once and stored nowhere in the panel.
func (s *Service) CreateMailbox(ctx context.Context, domainID int64, local, password string, quotaMB int) (addr, pw string, err error) {
	d, err := s.Store.Domain(ctx, domainID)
	if err != nil {
		return "", "", errors.New("alan adı bulunamadı")
	}
	local = strings.ToLower(strings.TrimSpace(local))
	if !ValidLocal(local) {
		return "", "", ErrLocal
	}
	addr = local + "@" + d.Name
	if !ValidAddress(addr) {
		return "", "", errors.New("adres çok uzun")
	}
	if err := checkQuota(quotaMB); err != nil {
		return "", "", err
	}
	if pw = password; pw == "" {
		pw = GeneratePassword()
	} else if err := CheckPassword(pw); err != nil {
		return "", "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.server(ctx); err != nil {
		return "", "", err
	}
	l, err := s.Listing(ctx)
	if err != nil {
		return "", "", err
	}
	if l.HasMailbox(addr) {
		return "", "", errors.New("bu posta kutusu zaten var")
	}
	if _, ok := l.Alias(addr); ok {
		return "", "", errors.New("bu adres bir yönlendirme olarak kullanılıyor")
	}
	if err := s.setPassword(ctx, addr, pw, "create"); err != nil {
		return "", "", err
	}
	if s.Fake != nil {
		s.Fake.setAccount(addr)
	}
	if quotaMB > 0 {
		if err := s.setQuota(ctx, addr, quotaMB); err != nil {
			return addr, pw, fmt.Errorf("posta kutusu oluşturuldu ama kota yazılamadı: %w", err)
		}
	}
	return addr, pw, nil
}

// ResetPassword replaces the password of an existing mailbox.
func (s *Service) ResetPassword(ctx context.Context, addr, password string) (string, error) {
	if err := s.ownAddress(ctx, addr); err != nil {
		return "", err
	}
	pw := password
	if pw == "" {
		pw = GeneratePassword()
	} else if err := CheckPassword(pw); err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.server(ctx); err != nil {
		return "", err
	}
	l, err := s.Listing(ctx)
	if err != nil {
		return "", err
	}
	if !l.HasMailbox(addr) {
		return "", errors.New("posta kutusu bulunamadı")
	}
	if err := s.setPassword(ctx, addr, pw, "reset"); err != nil {
		return "", err
	}
	return pw, nil
}

func (s *Service) setQuota(ctx context.Context, addr string, mb int) error {
	if _, err := s.helper(ctx, nil, nil, nil, time.Minute, "quota-set", addr, strconv.Itoa(mb)); err != nil {
		return err
	}
	if s.Fake != nil {
		s.Fake.setQuota(addr, mb)
	}
	return nil
}

// SetQuota changes the quota of a mailbox (0 = unlimited).
func (s *Service) SetQuota(ctx context.Context, addr string, mb int) error {
	if err := s.ownAddress(ctx, addr); err != nil {
		return err
	}
	if err := checkQuota(mb); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.server(ctx); err != nil {
		return err
	}
	l, err := s.Listing(ctx)
	if err != nil {
		return err
	}
	if !l.HasMailbox(addr) {
		return errors.New("posta kutusu bulunamadı")
	}
	return s.setQuota(ctx, addr, mb)
}

// StartDeleteMailbox queues the removal of a mailbox (its mail is archived
// first, which can take a while).
func (s *Service) StartDeleteMailbox(ctx context.Context, addr string) (int64, error) {
	if err := s.ownAddress(ctx, addr); err != nil {
		return 0, err
	}
	if _, err := s.server(ctx); err != nil {
		return 0, err
	}
	l, err := s.Listing(ctx)
	if err != nil {
		return 0, err
	}
	if !l.HasMailbox(addr) {
		return 0, errors.New("posta kutusu bulunamadı")
	}
	if len(l.Mailboxes) == 1 {
		return 0, errors.New("sunucudaki son posta kutusu silinemez (posta sunucusu en az bir hesap ister)")
	}
	return s.Jobs.Submit(ctx, jobs.Spec{Kind: "mail.mailbox.delete", TargetType: "mail", TargetID: addr,
		Summary: "Posta kutusu siliniyor: " + addr, Params: map[string]any{"address": addr}})
}

func (s *Service) jobDeleteMailbox(ctx context.Context, l *jobs.Log, p map[string]any) error {
	addr, _ := p["address"].(string)
	if !ValidAddress(addr) {
		return errors.New("geçersiz adres")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	l.Printf("%s: postalar arşivleniyor, sonra hesap, kota ve bu adrese giden yönlendirmeler siliniyor…", addr)
	if _, err := s.helper(ctx, l, nil, nil, 2*time.Hour, "account-del", addr); err != nil {
		return err
	}
	if s.Fake != nil {
		s.Fake.delAccount(addr)
	}
	l.Printf("Posta kutusu silindi. Arşiv: /var/backups/hostpanel/%s/ (pre-delete-%s-*.tar.zst)", BackupDomain, addr)
	return nil
}

// MaxAliasTargets bounds the targets of one alias (mirrors hp-mail.sh).
const MaxAliasTargets = 50

// AddAlias forwards local@domain to target (a mailbox here or elsewhere).
func (s *Service) AddAlias(ctx context.Context, domainID int64, local, target string) (string, error) {
	d, err := s.Store.Domain(ctx, domainID)
	if err != nil {
		return "", errors.New("alan adı bulunamadı")
	}
	local = strings.ToLower(strings.TrimSpace(local))
	if !ValidLocal(local) {
		return "", ErrLocal
	}
	alias := local + "@" + d.Name
	target = NormalizeAddress(target)
	if !ValidAddress(alias) {
		return "", errors.New("adres çok uzun")
	}
	if !ValidTarget(target) {
		return "", errors.New("hedef geçerli bir e-posta adresi olmalı")
	}
	if alias == target {
		return "", errors.New("bir adres kendisine yönlendirilemez")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.server(ctx); err != nil {
		return "", err
	}
	l, err := s.Listing(ctx)
	if err != nil {
		return "", err
	}
	if l.HasMailbox(alias) {
		return "", errors.New("bu adres bir posta kutusu; aynı adres hem kutu hem yönlendirme olamaz")
	}
	if a, ok := l.Alias(alias); ok {
		for _, t := range a.Targets {
			if t == target {
				return "", errors.New("bu yönlendirme zaten var")
			}
		}
		if len(a.Targets) >= MaxAliasTargets {
			return "", fmt.Errorf("bir adres en fazla %d hedefe yönlendirilebilir", MaxAliasTargets)
		}
	}
	if _, err := s.helper(ctx, nil, nil, nil, time.Minute, "alias-add", alias, target); err != nil {
		return "", err
	}
	if s.Fake != nil {
		s.Fake.addAlias(alias, target)
	}
	return alias, nil
}

// DeleteAlias removes one target of an alias.
func (s *Service) DeleteAlias(ctx context.Context, alias, target string) error {
	if err := s.ownAddress(ctx, alias); err != nil {
		return err
	}
	if !ValidTarget(target) {
		return errors.New("geçersiz hedef")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.server(ctx); err != nil {
		return err
	}
	if _, err := s.helper(ctx, nil, nil, nil, time.Minute, "alias-del", alias, target); err != nil {
		return err
	}
	if s.Fake != nil {
		s.Fake.delAlias(alias, target)
	}
	return nil
}

// --- queue and bans ---

// Queue returns the number of messages waiting in the Postfix queue.
func (s *Service) Queue(ctx context.Context) (int, error) {
	if s.Fake != nil {
		return s.Fake.queue, nil
	}
	res, err := s.helper(ctx, nil, nil, nil, 30*time.Second, "queue")
	if err != nil {
		return 0, err
	}
	return ParseQueue(res.Stdout), nil
}

// Flush asks Postfix to retry every queued message now.
func (s *Service) Flush(ctx context.Context) error {
	if _, err := s.runningServer(ctx); err != nil {
		return err
	}
	_, err := s.helper(ctx, nil, nil, nil, time.Minute, "flush")
	return err
}

// Bans lists the addresses blocked by the container's Fail2ban.
func (s *Service) Bans(ctx context.Context) ([]Ban, error) {
	if s.Fake != nil {
		return s.Fake.bans, nil
	}
	res, err := s.helper(ctx, nil, nil, nil, 30*time.Second, "bans")
	if err != nil {
		return nil, err
	}
	return ParseBans(res.Stdout), nil
}

// Unban lifts the block on one address.
func (s *Service) Unban(ctx context.Context, ip string) error {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return errors.New("geçersiz IP adresi")
	}
	if _, err := s.runningServer(ctx); err != nil {
		return err
	}
	_, err = s.helper(ctx, nil, nil, nil, time.Minute, "unban", a.String())
	return err
}

// --- DNS records and checks ---

// Record is a DNS record a mail domain needs (shown when the zone is not
// managed by the panel).
type Record struct {
	Name  string
	Type  string
	Value string
}

// Records returns the records of domain d for mail host.
func Records(d Domain, host string) []Record {
	rs := []Record{
		{d.Name, "MX", "10 " + host + "."},
		{d.Name, "TXT", "v=spf1 mx ~all"},
	}
	if d.DKIMTXT != "" {
		rs = append(rs, Record{d.DKIMSelector + "._domainkey." + d.Name, "TXT", d.DKIMTXT})
	}
	return append(rs, Record{"_dmarc." + d.Name, "TXT", "v=DMARC1; p=quarantine"})
}

// Check is one line of the deliverability checks.
type Check struct {
	Name   string
	OK     bool
	Detail string
}

func lookupCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 5*time.Second)
}

func lookupErr(err error) string {
	var de *net.DNSError
	if errors.As(err, &de) && de.IsNotFound || errors.Is(err, pubdns.ErrNotFound) {
		return "kayıt yok"
	}
	return "sorgulanamadı: " + err.Error()
}

// CheckServer tests what only the outside world decides: the A record, the
// PTR record of the server's public address and outbound port 25.
func (s *Service) CheckServer(ctx context.Context) []Check {
	srv, err := s.Store.Server(ctx)
	if err != nil {
		return nil
	}
	if s.DryRun {
		return []Check{{"Kontroller", true, "dry-run: ağ kontrolleri atlandı"}}
	}
	var out []Check
	var mine []netip.Addr
	if s.ServerIPs != nil {
		mine = s.ServerIPs(ctx)
	}

	c := Check{Name: "A kaydı (" + srv.Hostname + ")"}
	got, err := s.lookupA(ctx, srv.Hostname)
	var public []netip.Addr
	if err != nil {
		c.Detail = lookupErr(err)
	} else {
		var names []string
		for _, a := range got {
			a = a.Unmap()
			names = append(names, a.String())
			for _, m := range mine {
				if m == a {
					c.OK = true
					public = append(public, a)
				}
			}
		}
		c.Detail = strings.Join(names, ", ")
		if !c.OK {
			c.Detail += " (bu sunucunun adresi değil)"
		}
	}
	out = append(out, c)

	c = Check{Name: "PTR (ters DNS)"}
	if len(public) == 0 {
		c.Detail = "A kaydı düzelmeden denetlenemez"
	}
	for _, a := range public {
		names, err := s.public().LookupPTR(ctx, a)
		if err != nil {
			c.Detail = a.String() + ": " + lookupErr(err)
			continue
		}
		c.Detail = a.String() + " → " + strings.Join(names, ", ")
		for _, n := range names {
			if strings.EqualFold(strings.TrimSuffix(n, "."), srv.Hostname) {
				c.OK = true
			}
		}
		if !c.OK {
			c.Detail += " (olması gereken: " + srv.Hostname + "; sağlayıcı panelinden ayarlanır)"
		}
	}
	out = append(out, c)

	c = Check{Name: "Giden 25. port"}
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "tcp4", "gmail-smtp-in.l.google.com:25")
	if err != nil {
		c.Detail = "gmail-smtp-in.l.google.com:25 adresine bağlanılamadı (sağlayıcı giden 25'i engelliyor olabilir): " + err.Error()
	} else {
		conn.Close()
		c.OK, c.Detail = true, "açık (gmail-smtp-in.l.google.com:25)"
	}
	return append(out, c)
}

func lookupTXT(ctx context.Context, name string) ([]string, error) {
	lctx, cancel := lookupCtx(ctx)
	defer cancel()
	return net.DefaultResolver.LookupTXT(lctx, name)
}

func txtCheck(ctx context.Context, label, name, prefix, want string) Check {
	c := Check{Name: label}
	txts, err := lookupTXT(ctx, name)
	if err != nil {
		c.Detail = lookupErr(err)
		return c
	}
	for _, t := range txts {
		if strings.HasPrefix(t, prefix) {
			c.Detail = t
			c.OK = want == "" || strings.Join(strings.Fields(t), "") == strings.Join(strings.Fields(want), "")
			if !c.OK {
				c.Detail = "yayındaki kayıt panelin anahtarıyla aynı değil"
			} else if len(c.Detail) > 80 {
				c.Detail = c.Detail[:80] + "…"
			}
			return c
		}
	}
	c.Detail = "kayıt yok"
	return c
}

// CheckDomain looks up the published MX, SPF, DKIM and DMARC records.
func (s *Service) CheckDomain(ctx context.Context, d Domain) []Check {
	host := s.Host(ctx)
	if s.DryRun {
		return []Check{{"Kontroller", true, "dry-run: DNS sorguları atlandı"}}
	}
	c := Check{Name: "MX"}
	lctx, cancel := lookupCtx(ctx)
	mxs, err := net.DefaultResolver.LookupMX(lctx, d.Name)
	cancel()
	if err != nil {
		c.Detail = lookupErr(err)
	} else {
		var names []string
		for _, mx := range mxs {
			h := strings.TrimSuffix(mx.Host, ".")
			names = append(names, fmt.Sprintf("%d %s", mx.Pref, h))
			if strings.EqualFold(h, host) {
				c.OK = true
			}
		}
		c.Detail = strings.Join(names, ", ")
		if !c.OK {
			c.Detail += " (olması gereken: " + host + ")"
		}
	}
	out := []Check{c, txtCheck(ctx, "SPF", d.Name, "v=spf1", "")}
	out = append(out, txtCheck(ctx, "DKIM", d.DKIMSelector+"._domainkey."+d.Name, "v=DKIM1", d.DKIMTXT))
	return append(out, txtCheck(ctx, "DMARC", "_dmarc."+d.Name, "v=DMARC1", ""))
}

// --- backup / restore (called by the backups service) ---

// Backup writes /var/backups/hostpanel/_mail/<name>/ (configuration and all
// mail; the container keeps running) and returns its size.
func (s *Service) Backup(ctx context.Context, w io.Writer, name string) (int64, error) {
	if _, err := s.server(ctx); err != nil {
		return 0, err
	}
	res, err := s.helper(ctx, w, nil, nil, 6*time.Hour, "backup", name)
	if err != nil {
		return 0, err
	}
	size, _ := strconv.ParseInt(parseKV(res.Stdout, "size"), 10, 64)
	return size, nil
}

// Restore replaces configuration and mail with the backup's (the helper
// keeps the previous directories and puts them back on failure), then
// brings the panel's domain list and DNS in line with the restored files.
func (s *Service) Restore(ctx context.Context, w io.Writer, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	srv, err := s.server(ctx)
	if err != nil {
		return err
	}
	if _, err := s.helper(ctx, w, nil, nil, 6*time.Hour, "restore", name); err != nil {
		return err
	}
	s.Store.SetServerStatus(ctx, srv.ID, StatusRunning, "")
	l, err := s.Listing(ctx)
	if err != nil {
		return fmt.Errorf("geri yüklendi ama hesap listesi okunamadı: %w", err)
	}
	for _, name := range l.Domains() {
		if name == srv.Hostname || !sites.ValidDomain(name) {
			continue
		}
		if _, err := s.Store.DomainByName(ctx, name); err == nil {
			continue
		}
		d := Domain{Name: name}
		if err := s.Store.InsertDomain(ctx, &d); err != nil {
			return err
		}
		fmt.Fprintf(w, "Yedekteki alan adı panele eklendi: %s (müşterisiz)\n", name)
	}
	ds, err := s.Store.Domains(ctx, 0)
	if err != nil {
		return err
	}
	names := []string{srv.Hostname}
	for _, d := range ds {
		names = append(names, d.Name)
		txt, err := s.dkim(ctx, w, d.Name)
		if err != nil {
			fmt.Fprintf(w, "UYARI: %s için DKIM kaydı okunamadı: %v\n", d.Name, err)
			continue
		}
		if txt != d.DKIMTXT {
			s.Store.SetDKIM(ctx, d.ID, txt)
			fmt.Fprintf(w, "%s: DKIM kaydı yedektekiyle güncellendi (DNS yeniden uygulanıyor)\n", d.Name)
		}
	}
	s.changed(ctx, names...)
	return nil
}
