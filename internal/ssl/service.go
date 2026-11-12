package ssl

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/zahit5834/hostpanel/internal/crypto"
	"github.com/zahit5834/hostpanel/internal/exec"
	"github.com/zahit5834/hostpanel/internal/jobs"
	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/notify"
	"github.com/zahit5834/hostpanel/internal/sites"
	"github.com/zahit5834/hostpanel/internal/store"
)

// Settings keys.
const (
	SettingACMEEmail  = "acme_email"
	SettingServerIPs  = "server_ips"
	SettingServerID   = "server_id"
	settingRenewOff   = "ssl_renew_log_offset"
	settingCertbotErr = "ssl_certbot_fail_reported"
)

// Service runs certificate jobs. Privileged work goes through hp-ssl.sh.
type Service struct {
	Store      *Store
	Sites      *sites.Service
	DB         *sql.DB
	Box        *crypto.Box
	Runner     exec.Runner // privileged (dry-run in dev)
	Probe      exec.Runner // unprivileged read-only (systemctl show)
	Jobs       *jobs.Manager
	Activity   *logs.Activity
	Log        *slog.Logger
	ScriptsDir string
	RenewLog   string // /var/log/hostpanel-root/ssl-renewals.log
	DryRun     bool

	Roots   *x509.CertPool                            // nil: system pool (tests inject a test CA)
	Checker func(ctx context.Context) *Checker        // nil: real DNS + HTTP
	Notify  func(ctx context.Context, e notify.Event) // nil: no notifications
	// ACMEReady reports why DNS-01 can't be used for names (nil: it can);
	// injected by the dns package, nil = DNS validation unavailable.
	ACMEReady func(ctx context.Context, names []string) error
	// ACMEDelegation lists zones whose public delegation does not point at
	// this server (warning only: the lookup may lag behind the registrar).
	ACMEDelegation func(ctx context.Context, names []string) []string
}

// DelegationWarning is a warning for DNS-01 when some zones are not (yet)
// delegated to this server ("" = none).
func (s *Service) DelegationWarning(ctx context.Context, names []string) string {
	if s.ACMEDelegation == nil {
		return ""
	}
	if bad := s.ACMEDelegation(ctx, names); len(bad) > 0 {
		return "Zone'un nameserver'ları henüz bu sunucuyu göstermiyor (" + strings.Join(bad, ", ") +
			"); Let's Encrypt doğrulama kaydını göremez. Registrar'da NS'leri değiştirin ve DNS sayfasında yetki devrini kontrol edin."
	}
	return ""
}

// Let's Encrypt validation methods.
const (
	MethodHTTP = "http" // HTTP-01 through the ACME webroot
	MethodDNS  = "dns"  // DNS-01 through the panel's BIND (wildcards)
)

// DNSReady is ACMEReady for the site's names (nil: DNS validation usable).
func (s *Service) DNSReady(ctx context.Context, names []string) error {
	if s.ACMEReady == nil {
		return errors.New("DNS doğrulaması için panelin DNS sunucusu gerekir")
	}
	return s.ACMEReady(ctx, names)
}

// Register binds job kinds and hooks certificate lookup into nginx rendering.
func (s *Service) Register() {
	s.Jobs.Register("ssl.letsencrypt", s.jobLE)
	s.Jobs.Register("ssl.install", s.jobCustom)
	s.Jobs.Register("ssl.renew", s.jobRenew)
	s.Jobs.Register("ssl.remove", s.jobRemove)
	s.Sites.CertFor = s.CertPaths
}

// EnsureServerID creates the random id served by the probe location.
func EnsureServerID(ctx context.Context, db *sql.DB) string {
	id := store.GetSetting(ctx, db, SettingServerID, "")
	if len(id) == 32 {
		return id
	}
	b := make([]byte, 16)
	rand.Read(b)
	id = hex.EncodeToString(b)
	store.SetSetting(ctx, db, SettingServerID, id)
	return id
}

// CertPaths is sites.Service.CertFor.
func (s *Service) CertPaths(ctx context.Context, siteID int64) *sites.TLSPaths {
	c, err := s.Store.Active(ctx, siteID)
	if err != nil {
		return nil
	}
	cert, key := c.Paths()
	return &sites.TLSPaths{Cert: cert, Key: key, Names: c.Names}
}

// ActiveBySite maps site id → active certificate (site list, dashboard).
func (s *Service) ActiveBySite(ctx context.Context) map[int64]*Certificate {
	out := map[int64]*Certificate{}
	list, _ := s.Store.ActiveAll(ctx)
	for i := range list {
		out[list[i].SiteID] = &list[i]
	}
	return out
}

func (s *Service) helper(ctx context.Context, w io.Writer, stdin io.Reader, secrets []string, args ...string) (exec.Result, error) {
	c := exec.Helper(s.ScriptsDir, "hp-ssl.sh", args...)
	c.Output, c.Stdin, c.Secrets = w, stdin, secrets
	c.Timeout = 5 * time.Minute
	return s.Runner.Run(ctx, c)
}

// ServerIPs are the interface addresses plus the manually configured public ones (NAT).
func (s *Service) ServerIPs(ctx context.Context) []netip.Addr {
	ips := LocalIPs()
	for _, f := range strings.FieldsFunc(store.GetSetting(ctx, s.DB, SettingServerIPs, ""), func(r rune) bool {
		return r == ',' || r == ' ' || r == '\n' || r == '\r'
	}) {
		if a, err := netip.ParseAddr(f); err == nil {
			ips = append(ips, a.Unmap())
		}
	}
	return ips
}

// ParseIPList validates the server_ips setting.
func ParseIPList(raw string) (string, error) {
	var out []string
	for _, f := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' }) {
		a, err := netip.ParseAddr(f)
		if err != nil {
			return "", fmt.Errorf("geçersiz IP: %s", f)
		}
		out = append(out, a.Unmap().String())
	}
	return strings.Join(out, ", "), nil
}

func (s *Service) checker(ctx context.Context) *Checker {
	if s.Checker != nil {
		return s.Checker(ctx)
	}
	return NewChecker(s.ServerIPs(ctx), store.GetSetting(ctx, s.DB, SettingServerID, ""))
}

// SiteNames lists every name the site's nginx config answers for, primary first.
func SiteNames(site sites.Site) []string {
	names := append([]string{site.Domain, site.WWWName()}, site.Aliases...)
	if site.Wildcard {
		names = append(names, site.WildcardName())
	}
	return names
}

// Precheck runs the DNS + HTTP checks for the site's names.
func (s *Service) Precheck(ctx context.Context, site sites.Site) []NameCheck {
	return s.checker(ctx).Check(ctx, SiteNames(site))
}

// --- Let's Encrypt ---

// LEInput is the Let's Encrypt form.
type LEInput struct {
	Names   []string
	Email   string
	Staging bool
	Method  string // MethodHTTP (default) | MethodDNS; a "*." name needs DNS
}

// StartLE validates the request and queues ssl.letsencrypt.
func (s *Service) StartLE(ctx context.Context, site sites.Site, in LEInput) (int64, error) {
	allowed := map[string]bool{}
	for _, n := range SiteNames(site) {
		allowed[n] = true
	}
	var names []string
	hasPrimary, wild := false, false
	for _, n := range in.Names {
		if !allowed[n] {
			return 0, fmt.Errorf("site bu adı sunmuyor: %s", n)
		}
		hasPrimary = hasPrimary || n == site.Domain
		wild = wild || strings.HasPrefix(n, "*.")
		names = append(names, n)
	}
	switch in.Method {
	case "", MethodHTTP:
		if wild {
			return 0, errors.New("*. adlı (wildcard) sertifika yalnızca DNS doğrulamasıyla alınabilir")
		}
		in.Method = MethodHTTP
	case MethodDNS:
		if err := s.DNSReady(ctx, names); err != nil {
			return 0, err
		}
	default:
		return 0, errors.New("geçersiz doğrulama yöntemi")
	}
	if !hasPrimary {
		// certbot's lineage is named after the domain and nginx serves it; keep it first.
		return 0, fmt.Errorf("%s seçili olmalı", site.Domain)
	}
	in.Email = strings.TrimSpace(in.Email)
	if !ValidEmail(in.Email) {
		return 0, errors.New("geçerli bir e-posta adresi girin (Let's Encrypt bildirimleri için)")
	}
	store.SetSetting(ctx, s.DB, SettingACMEEmail, in.Email)
	label := "Let's Encrypt"
	if in.Staging {
		label += " (test)"
	}
	return s.Jobs.Submit(ctx, jobs.Spec{Kind: "ssl.letsencrypt", TargetType: "site", TargetID: site.Domain,
		Summary: label + " sertifikası alınıyor: " + strings.Join(names, ", "),
		Params:  map[string]any{"site_id": site.ID, "names": names, "email": in.Email, "staging": in.Staging, "method": in.Method}})
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
	switch v := p[key].(type) {
	case []string:
		return v
	case []any:
		var out []string
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func (s *Service) jobLE(ctx context.Context, l *jobs.Log, p map[string]any) error {
	site, err := s.Sites.Store.Get(ctx, paramID(p, "site_id"))
	if err != nil {
		return fmt.Errorf("site bulunamadı: %w", err)
	}
	names := paramStrings(p, "names")
	email, _ := p["email"].(string)
	staging, _ := p["staging"].(bool)
	method, challenge, helperMethod := MethodHTTP, "http-01", "webroot"
	if m, _ := p["method"].(string); m == MethodDNS {
		method, challenge, helperMethod = MethodDNS, "dns-01", "dns"
	}
	defer s.Sites.Lock(site.ID)()

	if method == MethodDNS {
		if err := s.DNSReady(ctx, names); err != nil {
			return err
		}
		l.Printf("DNS doğrulaması: certbot _acme-challenge TXT kayıtlarını panelin DNS sunucusuna yazar (zone'un NS kayıtları bu sunucuyu göstermeli).")
		if w := s.DelegationWarning(ctx, names); w != "" {
			l.Printf("UYARI: %s", w)
		}
	}
	l.Printf("DNS / HTTP ön kontrolü…")
	for _, c := range s.checker(ctx).Check(ctx, names) {
		mark := "✓"
		if !c.OK() {
			mark = "✗"
		}
		l.Printf("  %s %s → %s", mark, c.Name, strings.Join(c.IPs, ", "))
		for _, pr := range c.Problems {
			l.Printf("      %s", pr)
		}
	}
	l.Progress(10)

	prev, _ := s.Store.Active(ctx, site.ID)
	force := "0"
	if prev.ID != 0 && prev.Kind == KindLE && prev.Staging != staging {
		force = "1" // switching between staging and production needs a fresh certificate
	}
	args := append([]string{"issue", site.Domain, email, helperMethod, btoa(staging), force}, names...)
	l.Printf("certbot çalıştırılıyor (%s)…", challenge)
	if _, err := s.helper(ctx, l, nil, nil, args...); err != nil {
		return fmt.Errorf("sertifika alınamadı: %w", err)
	}
	l.Progress(60)
	chain, err := s.leChain(ctx, site.Domain, names)
	if err != nil {
		return err
	}
	info, err := LeafInfo(chain)
	if err != nil {
		return err
	}
	c := Certificate{SiteID: site.ID, Domain: site.Domain, Kind: KindLE, Challenge: challenge, Names: info.Names,
		Issuer: info.Issuer, Serial: info.Serial, Fingerprint: info.Fingerprint, KeyType: info.KeyType,
		NotBefore: info.NotBefore, NotAfter: info.NotAfter, Status: StatusPending, Staging: staging, CertPEM: chain}
	if err := s.Store.Insert(ctx, &c); err != nil {
		return err
	}
	l.Printf("Sertifika: %s · %s · bitiş %s", info.Issuer, strings.Join(info.Names, ", "), info.NotAfter.Local().Format("02.01.2006"))
	return s.activate(ctx, l, site, c)
}

func btoa(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// leChain reads the issued fullchain (public). In dry-run there is none, so a
// throwaway self-signed certificate stands in to exercise the rest of the flow.
func (s *Service) leChain(ctx context.Context, domain string, names []string) (string, error) {
	if s.DryRun {
		return fakeCert(names)
	}
	res, err := s.helper(ctx, nil, nil, nil, "show", domain)
	if err != nil {
		return "", fmt.Errorf("sertifika okunamadı: %w", err)
	}
	return res.Stdout, nil
}

func fakeCert(names []string) (string, error) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: names[0]},
		DNSNames: names, NotBefore: now, NotAfter: now.AddDate(0, 0, 90)}
	issuer := &x509.Certificate{Subject: pkix.Name{CommonName: "DRY-RUN"}} // the issuer name comes from the parent
	der, err := x509.CreateCertificate(rand.Reader, tpl, issuer, k.Public(), k)
	if err != nil {
		return "", err
	}
	c, _ := x509.ParseCertificate(der)
	return EncodeCerts([]*x509.Certificate{c}), nil
}

// activate makes c the site's certificate and installs nginx with it. If nginx
// rejects the config the helper keeps the old file, and the DB is reverted too.
func (s *Service) activate(ctx context.Context, l *jobs.Log, site sites.Site, c Certificate) error {
	prevID, err := s.Store.Activate(ctx, site.ID, c.ID)
	if err != nil {
		return err
	}
	l.Printf("nginx yapılandırması HTTPS ile güncelleniyor…")
	if err := s.Sites.ApplyNginx(ctx, l, site); err != nil {
		s.Store.Revert(context.WithoutCancel(ctx), c.ID, prevID, err.Error())
		return fmt.Errorf("nginx yapılandırması uygulanamadı, önceki durum korundu: %w", err)
	}
	l.Progress(90)
	if prevID != 0 {
		if prev, err := s.Store.Get(ctx, prevID); err == nil {
			s.cleanupFiles(ctx, l, prev, c)
		}
	}
	l.Printf("HTTPS etkin: https://%s/", site.Domain)
	return nil
}

// cleanupFiles removes the replaced certificate's files unless the new one
// lives in the same place (LE renew/expand keeps the lineage).
func (s *Service) cleanupFiles(ctx context.Context, l *jobs.Log, old, cur Certificate) {
	switch {
	case old.Kind == KindCustom:
		s.helper(context.WithoutCancel(ctx), l, nil, nil, "delete", old.Domain, "custom", strconv.FormatInt(old.ID, 10))
	case old.Kind == KindLE && cur.Kind != KindLE:
		s.helper(context.WithoutCancel(ctx), l, nil, nil, "delete", old.Domain, "le")
	}
}

// --- custom (purchased) certificates ---

// CreateCSR generates a key + CSR and stores both (key sealed).
func (s *Service) CreateCSR(ctx context.Context, in CSRInput, siteID int64) (CSR, error) {
	if err := in.Validate(); err != nil {
		return CSR{}, err
	}
	key, err := GenerateKey(in.KeyType)
	if err != nil {
		return CSR{}, err
	}
	csrPEM, err := CreateCSR(key, in)
	if err != nil {
		return CSR{}, err
	}
	keyPEM, err := MarshalKey(key)
	if err != nil {
		return CSR{}, err
	}
	sealed, err := s.Box.SealString(keyPEM)
	if err != nil {
		return CSR{}, err
	}
	c := CSR{SiteID: siteID, CommonName: in.CommonName, SANs: in.SANs, Subject: in.Subject, KeyType: in.KeyType, KeySealed: sealed, PEM: csrPEM}
	return c, s.Store.InsertCSR(ctx, &c)
}

// InstallInput is the purchased certificate form.
type InstallInput struct {
	CSRID    int64  // key source: a CSR generated here…
	KeyPEM   string // …or a pasted key
	CertPEM  string
	ChainPEM string
}

// Verify resolves the key and checks the certificate for site.
func (s *Service) Verify(ctx context.Context, site sites.Site, in InstallInput) Report {
	keyPEM := in.KeyPEM
	if in.CSRID != 0 {
		csr, err := s.Store.GetCSR(ctx, in.CSRID)
		if err != nil {
			return Report{Checks: []Check{{LevelErr, "CSR bulunamadı"}}}
		}
		if keyPEM, err = s.Box.OpenString(csr.KeySealed); err != nil {
			return Report{Checks: []Check{{LevelErr, "CSR anahtarı çözülemedi"}}}
		}
	}
	if len(in.CertPEM)+len(in.ChainPEM)+len(keyPEM) > 60<<10 {
		return Report{Checks: []Check{{LevelErr, "Girdi çok büyük (en fazla 60 KB)"}}}
	}
	return Verify(VerifyInput{CertPEM: in.CertPEM, ChainPEM: in.ChainPEM, KeyPEM: keyPEM, Primary: site.Domain, Names: SiteNames(site)}, time.Now(), s.Roots)
}

// StartCustom verifies again, stores the certificate (key sealed) and queues the install.
func (s *Service) StartCustom(ctx context.Context, site sites.Site, in InstallInput) (int64, Report, error) {
	r := s.Verify(ctx, site, in)
	if !r.OK {
		return 0, r, errors.New("doğrulama başarısız")
	}
	sealed, err := s.Box.SealString(r.KeyPEM)
	if err != nil {
		return 0, r, err
	}
	c := Certificate{SiteID: site.ID, Domain: site.Domain, Kind: KindCustom, Names: r.Info.Names, Issuer: r.Info.Issuer,
		Serial: r.Info.Serial, Fingerprint: r.Info.Fingerprint, KeyType: r.Info.KeyType, NotBefore: r.Info.NotBefore,
		NotAfter: r.Info.NotAfter, Status: StatusPending, CertPEM: r.FullChain, KeySealed: sealed}
	if err := s.Store.Insert(ctx, &c); err != nil {
		return 0, r, err
	}
	if in.CSRID != 0 {
		s.Store.LinkCSR(ctx, in.CSRID, c.ID)
	}
	id, err := s.Jobs.Submit(ctx, jobs.Spec{Kind: "ssl.install", TargetType: "site", TargetID: site.Domain,
		Summary: "Ücretli sertifika kuruluyor: " + r.Info.Issuer, Params: map[string]any{"cert_id": c.ID}})
	return id, r, err
}

func (s *Service) jobCustom(ctx context.Context, l *jobs.Log, p map[string]any) error {
	c, err := s.Store.Get(ctx, paramID(p, "cert_id"))
	if err != nil {
		return fmt.Errorf("sertifika kaydı bulunamadı: %w", err)
	}
	site, err := s.Sites.Store.Get(ctx, c.SiteID)
	if err != nil {
		return fmt.Errorf("site bulunamadı: %w", err)
	}
	defer s.Sites.Lock(site.ID)()
	key, err := s.Box.OpenString(c.KeySealed)
	if err != nil {
		return errors.New("private key çözülemedi")
	}
	if !KeyMatches(c.CertPEM, key) {
		return errors.New("private key sertifikayla eşleşmiyor")
	}
	l.Printf("Sertifika: %s · %s · bitiş %s", c.Issuer, strings.Join(c.Names, ", "), c.NotAfter.Local().Format("02.01.2006"))
	id := strconv.FormatInt(c.ID, 10)
	bundle := strings.NewReader(key + "\n" + c.CertPEM)
	if _, err := s.helper(ctx, l, bundle, []string{key}, "install-custom", c.Domain, id); err != nil {
		s.Store.SetStatus(context.WithoutCancel(ctx), c.ID, StatusError, err.Error())
		return fmt.Errorf("sertifika dosyaları yazılamadı: %w", err)
	}
	l.Progress(50)
	if err := s.activate(ctx, l, site, c); err != nil {
		s.helper(context.WithoutCancel(ctx), l, nil, nil, "delete", c.Domain, "custom", id)
		return err
	}
	return nil
}

// --- renew / remove ---

// StartRenew queues a Let's Encrypt renewal.
func (s *Service) StartRenew(ctx context.Context, c Certificate, force bool) (int64, error) {
	if c.Kind != KindLE {
		return 0, errors.New("ücretli sertifikalar yenilenmez; yeni sertifikayı satın alıp kurun")
	}
	return s.Jobs.Submit(ctx, jobs.Spec{Kind: "ssl.renew", TargetType: "site", TargetID: c.Domain,
		Summary: "Sertifika yenileniyor: " + c.Domain, Params: map[string]any{"cert_id": c.ID, "force": force}})
}

func (s *Service) jobRenew(ctx context.Context, l *jobs.Log, p map[string]any) error {
	c, err := s.Store.Get(ctx, paramID(p, "cert_id"))
	if err != nil {
		return err
	}
	force, _ := p["force"].(bool)
	defer s.Sites.Lock(c.SiteID)()
	if !force && c.DaysLeft() > 30 {
		l.Printf("Bitişe %d gün var; certbot 30 günden fazla kalan sertifikayı yenilemez (zorla yenile seçeneğini kullanın).", c.DaysLeft())
	}
	if _, err := s.helper(ctx, l, nil, nil, "renew", c.Domain, btoa(force)); err != nil {
		return fmt.Errorf("yenileme başarısız: %w", err)
	}
	return s.refresh(ctx, l, c)
}

// refresh re-reads an LE certificate from disk and updates the row if it changed.
func (s *Service) refresh(ctx context.Context, l *jobs.Log, c Certificate) error {
	chain, err := s.leChain(ctx, c.Domain, c.Names)
	if err != nil {
		return err
	}
	info, err := LeafInfo(chain)
	if err != nil {
		return err
	}
	if info.Fingerprint == c.Fingerprint {
		if l != nil {
			l.Printf("Sertifika değişmedi (bitiş %s).", c.NotAfter.Local().Format("02.01.2006"))
		}
		return nil
	}
	if l != nil {
		l.Printf("Yeni bitiş tarihi: %s", info.NotAfter.Local().Format("02.01.2006"))
	}
	return s.Store.SetInfo(ctx, c.ID, info, chain)
}

// StartRemove queues removing the site's certificate (back to HTTP).
func (s *Service) StartRemove(ctx context.Context, site sites.Site) (int64, error) {
	if _, err := s.Store.Active(ctx, site.ID); err != nil {
		return 0, errors.New("sitenin etkin sertifikası yok")
	}
	return s.Jobs.Submit(ctx, jobs.Spec{Kind: "ssl.remove", TargetType: "site", TargetID: site.Domain,
		Summary: "SSL kaldırılıyor: " + site.Domain, Params: map[string]any{"site_id": site.ID}})
}

func (s *Service) jobRemove(ctx context.Context, l *jobs.Log, p map[string]any) error {
	site, err := s.Sites.Store.Get(ctx, paramID(p, "site_id"))
	if err != nil {
		return err
	}
	defer s.Sites.Lock(site.ID)()
	c, err := s.Store.Active(ctx, site.ID)
	if err != nil {
		return errors.New("etkin sertifika yok")
	}
	s.Store.SetStatus(ctx, c.ID, StatusRemoved, "")
	l.Printf("nginx yapılandırması HTTP'ye çevriliyor…")
	if err := s.Sites.ApplyNginx(ctx, l, site); err != nil {
		s.Store.SetStatus(context.WithoutCancel(ctx), c.ID, StatusActive, "")
		return fmt.Errorf("nginx yapılandırması uygulanamadı, sertifika yerinde bırakıldı: %w", err)
	}
	l.Progress(60)
	what := []string{"delete", c.Domain, "le"}
	if c.Kind == KindCustom {
		what = []string{"delete", c.Domain, "custom", strconv.FormatInt(c.ID, 10)}
	}
	if _, err := s.helper(context.WithoutCancel(ctx), l, nil, nil, what...); err != nil {
		l.Printf("Uyarı: sertifika dosyaları silinemedi: %v", err)
	}
	return nil
}

// --- export ---

// Export returns a zip with cert.pem, chain.pem, fullchain.pem and privkey.pem.
func (s *Service) Export(ctx context.Context, c Certificate) ([]byte, error) {
	certs, err := ParseCerts(c.CertPEM)
	if err != nil || len(certs) == 0 {
		return nil, errors.New("sertifika verisi okunamadı")
	}
	var key string
	switch c.Kind {
	case KindCustom:
		if key, err = s.Box.OpenString(c.KeySealed); err != nil {
			return nil, errors.New("private key çözülemedi")
		}
	case KindLE:
		if s.DryRun {
			return nil, errors.New("dry-run modunda Let's Encrypt anahtarı yok")
		}
		res, err := s.helper(ctx, nil, nil, nil, "export-key", c.Domain)
		if err != nil {
			return nil, fmt.Errorf("private key okunamadı: %w", err)
		}
		key = res.Stdout
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range []struct{ name, body string }{
		{"cert.pem", EncodeCerts(certs[:1])},
		{"chain.pem", EncodeCerts(certs[1:])},
		{"fullchain.pem", EncodeCerts(certs)},
		{"privkey.pem", key},
	} {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: c.Domain + "/" + f.name, Method: zip.Deflate, Modified: time.Now()})
		if err != nil {
			return nil, err
		}
		io.WriteString(w, f.body)
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// --- daily maintenance ---

// Thresholds (days left) reported once each. Purchased certificates are
// reported early; Let's Encrypt renews itself at 30 days, so only a failing
// renewal reaches 15/7. -1 means expired.
var (
	thresholdsCustom = []int{30, 15, 7, -1}
	thresholdsLE     = []int{15, 7, -1}
)

// Maintain runs from the panel's daily maintenance: ingest certbot renewals,
// refresh Let's Encrypt expiry dates, report certbot failures and expiring certificates.
func (s *Service) Maintain(ctx context.Context) {
	s.ingestRenewals(ctx)
	list, _ := s.Store.ActiveAll(ctx)
	hasLE := false
	for _, c := range list {
		if c.Kind == KindLE {
			hasLE = true
			if !s.DryRun {
				if err := s.refresh(ctx, nil, c); err != nil {
					s.Log.Warn("ssl refresh", "domain", c.Domain, "err", err)
				}
			}
		}
	}
	if hasLE && !s.DryRun {
		s.checkCertbotService(ctx)
	}
	list, _ = s.Store.ActiveAll(ctx) // reload after refresh
	for _, c := range list {
		s.checkExpiry(ctx, c)
	}
}

func (s *Service) ingestRenewals(ctx context.Context) {
	f, err := os.Open(s.RenewLog)
	if err != nil {
		return
	}
	defer f.Close()
	st, _ := f.Stat()
	off, _ := strconv.ParseInt(store.GetSetting(ctx, s.DB, settingRenewOff, "0"), 10, 64)
	if st == nil || off > st.Size() {
		off = 0 // truncated/rotated
	}
	f.Seek(off, io.SeekStart)
	r := bufio.NewReader(f)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			break // incomplete last line is read next time
		}
		off += int64(len(line))
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[1] != "renewed" || !sites.ValidDomain(fields[2]) {
			continue
		}
		s.Activity.Record(ctx, logs.Entry{Action: "ssl.renew", TargetType: "site", TargetID: fields[2],
			Summary: "Sertifika otomatik yenilendi (certbot, " + fields[0] + ")"}, nil)
	}
	store.SetSetting(ctx, s.DB, settingRenewOff, strconv.FormatInt(off, 10))
}

func (s *Service) checkCertbotService(ctx context.Context) {
	res, err := s.Probe.Run(ctx, exec.Cmd{Name: "systemctl", Args: []string{"show", "certbot.service", "--property=Result", "--value"}, Timeout: 5 * time.Second})
	result := strings.TrimSpace(res.Stdout)
	if err != nil || result == "" || result == "success" {
		return
	}
	today := time.Now().Format("2006-01-02")
	if store.GetSetting(ctx, s.DB, settingCertbotErr, "") == today {
		return
	}
	store.SetSetting(ctx, s.DB, settingCertbotErr, today)
	tail, _ := s.Probe.Run(ctx, exec.Cmd{Name: "journalctl", Args: []string{"-u", "certbot.service", "-n", "30", "--no-pager", "-o", "short-iso"}, Timeout: 10 * time.Second})
	s.Activity.Record(ctx, logs.Entry{Action: "ssl.renew", Status: logs.StatusFailed, Summary: "certbot otomatik yenileme başarısız (" + result + ")",
		Error: strings.TrimSpace(tail.Stdout)}, nil)
}

func (s *Service) checkExpiry(ctx context.Context, c Certificate) {
	th := thresholdsLE
	if c.Kind == KindCustom {
		th = thresholdsCustom
	}
	days := c.DaysLeft()
	expired := time.Now().After(c.NotAfter)
	// th is ordered from earliest to latest warning; report only progress.
	idx, prev := -1, -1
	for i, t := range th {
		if (t >= 0 && days <= t) || (t < 0 && expired) {
			idx = i
		}
		if c.NotifiedDays != 0 && t == c.NotifiedDays {
			prev = i
		}
	}
	if idx < 0 || idx <= prev {
		return
	}
	crossed := th[idx]
	summary := fmt.Sprintf("SSL sertifikasının bitmesine %d gün kaldı: %s (%s)", days, c.Domain, c.NotAfter.Local().Format("02.01.2006"))
	if crossed < 0 {
		summary = "SSL sertifikasının süresi doldu: " + c.Domain
	}
	s.Activity.Record(ctx, logs.Entry{Action: "ssl.expiring", TargetType: "site", TargetID: c.Domain, Summary: summary}, nil)
	if s.Notify != nil {
		s.Notify(ctx, notify.Event{Kind: notify.KindSSLExpiring, Key: fmt.Sprintf("ssl:%s:%d", c.Domain, crossed),
			Title: summary, Text: "Bitiş: " + c.NotAfter.Format("2006-01-02 15:04 MST")})
	}
	s.Store.SetNotified(ctx, c.ID, crossed)
}
