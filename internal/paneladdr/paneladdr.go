// Package paneladdr lets the admin serve the panel on a name of their own
// (settings → panel address): panel.<a DNS zone or site domain> on port 443
// with a Let's Encrypt certificate, the self-signed IP entry staying open as
// a fallback. Root does the nginx/certbot part (hp-update.sh panel-domain);
// the panel picks the name, publishes its DNS record and waits until the
// outside world resolves it here.
package paneladdr

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zahit5834/hostpanel/internal/config"
	"github.com/zahit5834/hostpanel/internal/exec"
	"github.com/zahit5834/hostpanel/internal/jobs"
	"github.com/zahit5834/hostpanel/internal/pubdns"
)

// Addr is where nginx serves the panel.
type Addr struct {
	Domain string // "" = IP only
	Port   int    // the domain's port (443 after a change here), or the IP entry's port in IP mode
	IPPort int    // the self-signed IP entry next to the domain (0 = none)
}

// FallbackPort is the IP entry's port (0 = none).
func (a Addr) FallbackPort() int {
	if a.Domain == "" {
		return a.Port
	}
	return a.IPPort
}

// URL is the domain address ("" in IP mode).
func (a Addr) URL() string {
	if a.Domain == "" {
		return ""
	}
	if a.Port == 443 {
		return "https://" + a.Domain
	}
	return fmt.Sprintf("https://%s:%d", a.Domain, a.Port)
}

// next is the address after switching to name: domain on 443, the IP entry
// keeps its port (mirrors hp-update.sh panel_ip_entry).
func (a Addr) next(name string) Addr {
	ip := a.IPPort
	if ip == 0 {
		ip = 8443
		if a.Domain == "" && a.Port != 443 && a.Port != 0 {
			ip = a.Port
		}
	}
	if name == "" {
		return Addr{Port: ip}
	}
	return Addr{Domain: name, Port: 443, IPPort: ip}
}

// Holder keeps the live address: config.yaml at start-up, updated after a
// change (the panel is not restarted for it).
type Holder struct {
	mu sync.RWMutex
	a  Addr
}

// NewHolder starts from the configuration.
func NewHolder(cfg config.Config) *Holder {
	return &Holder{a: Addr{Domain: cfg.PanelDomain, Port: cfg.PanelPort, IPPort: cfg.PanelIPPort}}
}

// Get returns the address.
func (h *Holder) Get() Addr {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.a
}

// Domain returns the panel's name ("" = IP only).
func (h *Holder) Domain() string { return h.Get().Domain }

func (h *Holder) set(a Addr) {
	h.mu.Lock()
	h.a = a
	h.mu.Unlock()
}

// --- validation (pure) ---

var labelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
var domainRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// Taken is what a panel name must not collide with.
type Taken struct {
	Bases  []string          // offered parent names (DNS zones + site domains)
	Names  map[string]string // name → owner text (site names, mail host, nameservers)
	Manual map[string]string // name → manual DNS record type at that exact name (A/AAAA/CNAME)
}

// Name builds and checks label.base (Turkish errors).
func Name(label, base string, t Taken) (string, error) {
	label = strings.ToLower(strings.TrimSpace(label))
	base = strings.ToLower(strings.TrimSpace(base))
	if !labelRe.MatchString(label) {
		return "", errors.New("ön ek yalnızca küçük harf, rakam ve tire içerebilir (ör. panel)")
	}
	if !slices.Contains(t.Bases, base) {
		return "", errors.New("listeden bir alan adı seçin")
	}
	name := label + "." + base
	if len(name) > 253 || !domainRe.MatchString(name) {
		return "", fmt.Errorf("geçersiz ad: %s", name)
	}
	if owner, ok := t.Names[name]; ok {
		return "", fmt.Errorf("%s zaten kullanılıyor (%s); başka bir ön ek seçin", name, owner)
	}
	if typ, ok := t.Manual[name]; ok {
		return "", fmt.Errorf("DNS zone'unda %s adında elle girilmiş %s kaydı var; kaldırın ya da başka bir ön ek seçin", name, typ)
	}
	return name, nil
}

// --- service ---

// Service runs the change as a job.
type Service struct {
	Addr       *Holder
	Jobs       *jobs.Manager
	Runner     exec.Runner
	ScriptsDir string
	DryRun     bool
	// Hooks (injected; avoid import cycles):
	Taken     func(ctx context.Context) Taken
	ZoneFor   func(ctx context.Context, host string) string             // panel DNS zone covering host ("" = none)
	ApplyDNS  func(ctx context.Context, l *jobs.Log, host string) error // write that zone now
	Delegated func(ctx context.Context, zone string) (bool, string)
	ServerIPs func(ctx context.Context) []netip.Addr
	Email     func(ctx context.Context) string // Let's Encrypt account e-mail ("" = none)
	Target    func(ctx context.Context) string // the name being set up (DNS publishes it meanwhile)
	SetTarget func(ctx context.Context, name string)
	Changed   func(ctx context.Context, old, cur Addr) // activity + notification
	Public    func(ctx context.Context, host string) ([]netip.Addr, error)
	Wait      time.Duration // between DNS tries (tests: 0)
}

// DNSName is what DNS publishes for the panel: the name being set up, else
// the live one.
func (s *Service) DNSName(ctx context.Context) string {
	if t := s.Target(ctx); t != "" {
		return t
	}
	return s.Addr.Domain()
}

// Register adds the job handler.
func (s *Service) Register() { s.Jobs.Register("panel.domain", s.job) }

// Start queues the change; name "" goes back to the IP entry only.
func (s *Service) Start(ctx context.Context, name string) (int64, error) {
	cur := s.Addr.Get()
	if name == cur.Domain {
		return 0, errors.New("panel zaten bu adreste")
	}
	summary := "Panel adresi: https://" + name
	if name == "" {
		summary = "Panel adresi: yalnızca IP"
	}
	return s.Jobs.Submit(ctx, jobs.Spec{Kind: "panel.domain", TargetType: "panel", TargetID: "address", Summary: summary,
		Params: map[string]any{"name": name}, Retryable: true})
}

func (s *Service) helper(ctx context.Context, l *jobs.Log, args ...string) (string, error) {
	cmd := exec.Helper(s.ScriptsDir, "hp-update.sh", args...)
	cmd.Output, cmd.Timeout = l, 10*time.Minute
	res, err := s.Runner.Run(ctx, cmd)
	return res.Stdout, err
}

func (s *Service) job(ctx context.Context, l *jobs.Log, p map[string]any) error {
	name, _ := p["name"].(string)
	old := s.Addr.Get()
	if name == "" {
		if old.Domain == "" {
			l.Printf("Panel zaten yalnızca IP adresinden açılıyor.")
			return nil
		}
		l.Printf("Alan adı kaldırılıyor; panel yalnızca IP adresinden açılacak…")
		if _, err := s.helper(ctx, l, "panel-domain", "clear"); err != nil {
			return err
		}
		cur := old.next("")
		s.Addr.set(cur)
		if err := s.ApplyDNS(ctx, l, old.Domain); err != nil {
			l.Printf("UYARI: DNS kaydı kaldırılamadı: %v", err)
		}
		l.Printf("Panel adresi: https://<sunucu-ip>:%d", cur.Port)
		s.Changed(ctx, old, cur)
		return nil
	}
	// Re-check: the name was validated on submit, things may have changed.
	t := s.Taken(ctx)
	if owner, ok := t.Names[name]; ok {
		return fmt.Errorf("%s artık kullanılıyor (%s)", name, owner)
	}
	if !domainRe.MatchString(name) {
		return fmt.Errorf("geçersiz ad: %s", name)
	}
	s.SetTarget(ctx, name)
	ok := false
	defer func() {
		if !ok { // DNS back to what it was
			s.SetTarget(context.WithoutCancel(ctx), "")
			if err := s.ApplyDNS(context.WithoutCancel(ctx), l, name); err != nil {
				l.Printf("UYARI: DNS geri alınamadı: %v", err)
			}
		}
	}()
	if zone := s.ZoneFor(ctx, name); zone != "" {
		l.Printf("DNS: %s kaydı %s zone'una ekleniyor…", name, zone)
		if err := s.ApplyDNS(ctx, l, name); err != nil {
			return fmt.Errorf("DNS kaydı yazılamadı: %w", err)
		}
		if good, why := s.Delegated(ctx, zone); !good {
			l.Printf("UYARI: %s zone'unun yetki devri doğrulanmadı (%s); genel DNS bu kaydı görmeyebilir.", zone, why)
		}
	} else {
		l.Printf("DNS: %s zone'u panelde değil; A kaydının DNS sağlayıcınızda bu sunucuyu göstermesi gerekiyor.", name)
	}
	if !s.DryRun {
		if err := s.waitHere(ctx, l, name); err != nil {
			return err
		}
	}
	email := s.Email(ctx)
	if email == "" {
		email = "-"
		l.Printf("Not: Ayarlar → Genel'de Let's Encrypt e-postası yok; sertifika e-postasız alınıyor.")
	}
	l.Printf("Sertifika alınıyor ve nginx yapılandırılıyor (panel bu sırada eski adresten çalışmaya devam eder)…")
	if _, err := s.helper(ctx, l, "panel-domain", "set", name, email); err != nil {
		return err
	}
	ok = true
	cur := old.next(name)
	s.Addr.set(cur)
	s.SetTarget(ctx, "")
	if old.Domain != "" && old.Domain != name {
		if err := s.ApplyDNS(ctx, l, old.Domain); err != nil {
			l.Printf("UYARI: eski adın DNS kaydı kaldırılamadı: %v", err)
		}
	}
	l.Printf("Panel adresi: %s", cur.URL())
	l.Printf("Yedek giriş: https://<sunucu-ip>:%d (self-signed)", cur.IPPort)
	s.Changed(ctx, old, cur)
	return nil
}

// waitHere waits until public resolvers answer host with one of this
// server's IPv4 addresses (12 tries, s.Wait apart).
func (s *Service) waitHere(ctx context.Context, l *jobs.Log, host string) error {
	mine := s.ServerIPs(ctx)
	lookup := s.Public
	if lookup == nil {
		lookup = pubdns.Default.LookupA
	}
	last := ""
	for try := 0; try < 12; try++ {
		if try > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(s.Wait):
			}
		}
		got, err := lookup(ctx, host)
		if err != nil {
			if errors.Is(err, pubdns.ErrNotFound) {
				last = "kayıt yok"
			} else {
				last = "sorgulanamadı: " + err.Error()
			}
			l.Printf("DNS bekleniyor (%d/12): %s", try+1, last)
			continue
		}
		var seen []string
		for _, a := range got {
			a = a.Unmap()
			seen = append(seen, a.String())
			if slices.Contains(mine, a) {
				l.Printf("DNS: %s → %s (bu sunucu)", host, a)
				return nil
			}
		}
		last = "A kaydı " + strings.Join(seen, ", ") + " adresini gösteriyor"
		l.Printf("DNS bekleniyor (%d/12): %s", try+1, last)
	}
	return fmt.Errorf("%s bu sunucuya çözülmüyor (%s). A kaydını sunucunun IP'sine yönlendirin, birkaç dakika sonra işi yeniden deneyin; panel adresi değişmedi", host, last)
}

// Bases sorts and dedupes the offered parent names.
func Bases(names ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, list := range names {
		for _, n := range list {
			if n != "" && !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	sort.Strings(out)
	return out
}
