package ssl

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// ProbePath is served by every site's nginx config with the panel's server id,
// so an HTTP fetch proves the name really reaches this server (works behind
// NAT and CDN proxies where DNS alone is misleading).
const ProbePath = "/.well-known/hostpanel-probe"

// Resolver is the subset of *net.Resolver used (fakeable in tests).
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// NameCheck is the pre-check result for one name.
type NameCheck struct {
	Name     string
	IPs      []string
	Foreign  []string // addresses that are not this server's
	HTTP     bool     // probe answered with our token
	Problems []string
	Notes    []string
}

// OK means Let's Encrypt's HTTP-01 validation is expected to succeed.
func (n NameCheck) OK() bool { return n.HTTP && len(n.Problems) == 0 }

// Checker runs DNS + HTTP pre-checks.
type Checker struct {
	Resolver  Resolver
	Client    *http.Client
	ServerIPs []netip.Addr
	Token     string
	// Port is only overridden in tests (default 80).
	Port string
}

// NewChecker uses the system resolver and a short-timeout, non-redirecting client.
func NewChecker(serverIPs []netip.Addr, token string) *Checker {
	return &Checker{
		Resolver: net.DefaultResolver,
		Client: &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}},
		ServerIPs: serverIPs, Token: token,
	}
}

// Check examines names concurrently (lists are short: a site's names).
func (c *Checker) Check(ctx context.Context, names []string) []NameCheck {
	out := make([]NameCheck, len(names))
	var wg sync.WaitGroup
	for i, n := range names {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i] = c.one(ctx, n)
		}()
	}
	wg.Wait()
	return out
}

func (c *Checker) has(a netip.Addr) bool {
	for _, s := range c.ServerIPs {
		if s == a {
			return true
		}
	}
	return false
}

func (c *Checker) hasV6() bool {
	for _, s := range c.ServerIPs {
		if s.Is6() && !s.Is4In6() {
			return true
		}
	}
	return false
}

func (c *Checker) one(ctx context.Context, name string) NameCheck {
	r := NameCheck{Name: name}
	lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := c.Resolver.LookupIPAddr(lctx, name)
	if err != nil || len(addrs) == 0 {
		r.Problems = append(r.Problems, "DNS kaydı bulunamadı (A/AAAA yok). Alan adının DNS'inde bu sunucunun IP'sine A kaydı ekleyin.")
		return r
	}
	var v4, v6Foreign bool
	for _, ip := range addrs {
		a, ok := netip.AddrFromSlice(ip.IP)
		if !ok {
			continue
		}
		a = a.Unmap()
		r.IPs = append(r.IPs, a.String())
		if a.Is4() {
			v4 = true
		}
		if !c.has(a) {
			r.Foreign = append(r.Foreign, a.String())
			if a.Is6() {
				v6Foreign = true
			}
		}
	}
	if !v4 {
		r.Notes = append(r.Notes, "A (IPv4) kaydı yok.")
	}
	r.HTTP, err = c.probe(ctx, name)
	switch {
	case r.HTTP && len(r.Foreign) > 0:
		r.Notes = append(r.Notes, "Kayıtlar ("+strings.Join(r.Foreign, ", ")+") bu sunucuya ait değil ama istekler buraya ulaşıyor (CDN/proxy veya NAT olabilir).")
	case !r.HTTP && len(r.Foreign) > 0:
		r.Problems = append(r.Problems, "Kayıt(lar) "+strings.Join(r.Foreign, ", ")+" bu sunucuyu göstermiyor; kaydı sunucu IP'sine çevirin.")
	case !r.HTTP:
		msg := "Alan adı bu sunucuyu gösteriyor ama HTTP (80) üzerinden erişilemedi"
		if err != nil {
			msg += ": " + err.Error()
		}
		r.Problems = append(r.Problems, msg+". Port 80'in açık olduğundan ve site yapılandırmasının yüklü olduğundan emin olun.")
	}
	if v6Foreign && !c.hasV6() {
		r.Problems = append(r.Problems, "AAAA (IPv6) kaydı var ama sunucunun IPv6 adresi yok; Let's Encrypt IPv6'yı tercih eder ve doğrulama başarısız olur. AAAA kaydını silin.")
	}
	return r
}

func (c *Checker) probe(ctx context.Context, name string) (bool, error) {
	host := name
	if c.Port != "" {
		host = net.JoinHostPort(name, c.Port)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+host+ProbePath, nil)
	if err != nil {
		return false, err
	}
	res, err := c.Client.Do(req)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 256))
	return res.StatusCode == http.StatusOK && strings.TrimSpace(string(b)) == c.Token, nil
}

// LocalIPs returns the server's non-loopback, non-link-local interface addresses.
func LocalIPs() []netip.Addr {
	var out []netip.Addr
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		p, err := netip.ParsePrefix(a.String())
		if err != nil {
			continue
		}
		ip := p.Addr().Unmap()
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() {
			continue
		}
		out = append(out, ip)
	}
	return out
}
