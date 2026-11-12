package hostsec

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zahit5834/hostpanel/internal/exec"
)

// F2BJail is one "fail2ban-client status <jail>".
type F2BJail struct {
	Name                   string
	CurFailed, TotalFailed int
	CurBanned, TotalBanned int
	Banned                 []string
	Files                  string
}

// F2BConfig is what the panel sets for the host jails.
type F2BConfig struct {
	MaxRetry, FindMin, BanMin int
	Recidive                  bool
}

// F2BStatus is the parsed output of "hp-ssh.sh f2b-status".
type F2BStatus struct {
	Installed bool
	Active    bool
	Config    F2BConfig
	Ignore    []string
	Jails     []F2BJail
}

// Jail returns the named jail (nil when it is not running).
func (s F2BStatus) Jail(name string) *F2BJail {
	for i := range s.Jails {
		if s.Jails[i].Name == name {
			return &s.Jails[i]
		}
	}
	return nil
}

// TotalBanned counts the currently banned addresses over all jails.
func (s F2BStatus) TotalBanned() int {
	n := 0
	for _, j := range s.Jails {
		n += j.CurBanned
	}
	return n
}

// ParseF2BStatus reads hp-ssh.sh f2b-status.
func ParseF2BStatus(out string) F2BStatus {
	st := F2BStatus{Config: F2BConfig{MaxRetry: 5, FindMin: 15, BanMin: 60}}
	var cur *F2BJail
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if name, ok := strings.CutPrefix(line, "--- jail "); ok {
			st.Jails = append(st.Jails, F2BJail{Name: strings.TrimSpace(name)})
			cur = &st.Jails[len(st.Jails)-1]
			continue
		}
		if cur == nil {
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			switch k {
			case "installed":
				st.Installed = v == "1"
			case "active":
				st.Active = v == "1"
			case "config":
				f := strings.Fields(v)
				if len(f) == 4 {
					st.Config.MaxRetry, _ = strconv.Atoi(f[0])
					st.Config.FindMin, _ = strconv.Atoi(f[1])
					st.Config.BanMin, _ = strconv.Atoi(f[2])
					st.Config.Recidive = f[3] == "1"
				}
			case "ignore":
				st.Ignore = append(st.Ignore, v)
			}
			continue
		}
		// "|- Currently failed:\t0", "`- Banned IP list:\t1.2.3.4 5.6.7.8"
		line = strings.TrimLeft(line, "|`- ")
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		n, _ := strconv.Atoi(v)
		switch strings.TrimSpace(k) {
		case "Currently failed":
			cur.CurFailed = n
		case "Total failed":
			cur.TotalFailed = n
		case "Currently banned":
			cur.CurBanned = n
		case "Total banned":
			cur.TotalBanned = n
		case "Banned IP list":
			cur.Banned = strings.Fields(v)
		case "File list", "Journal matches":
			cur.Files = v
		}
	}
	return st
}

// MaxIgnore is the largest ignore list (hp-ssh.sh enforces the same).
const MaxIgnore = 50

// ParseIgnoreList validates the "never ban" list (one IP/CIDR per line or
// comma separated). Loopback is always ignored and therefore dropped here.
func ParseIgnoreList(raw string) ([]string, error) {
	var out []string
	for _, f := range strings.FieldsFunc(raw, func(r rune) bool { return r == '\n' || r == '\r' || r == ',' || r == ' ' || r == '\t' }) {
		var p netip.Prefix
		if strings.Contains(f, "/") {
			pp, err := netip.ParsePrefix(f)
			if err != nil {
				return nil, fmt.Errorf("geçersiz IP/CIDR: %s", f)
			}
			if pp.Bits() == 0 {
				return nil, fmt.Errorf("/0 kabul edilmez: %s", f)
			}
			p = pp.Masked()
		} else {
			a, err := netip.ParseAddr(f)
			if err != nil {
				return nil, fmt.Errorf("geçersiz IP/CIDR: %s", f)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		a := p.Addr()
		if a.IsLoopback() {
			continue
		}
		if a.IsUnspecified() {
			return nil, fmt.Errorf("geçersiz adres: %s", f)
		}
		s := p.String()
		if p.IsSingleIP() {
			s = a.String()
		}
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	if len(out) > MaxIgnore {
		return nil, fmt.Errorf("en fazla %d muaf adres", MaxIgnore)
	}
	return out, nil
}

// Covers reports whether ip is inside one of the ignore entries.
func Covers(list []string, ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	if a.IsLoopback() {
		return true
	}
	for _, e := range list {
		if p, err := netip.ParsePrefix(e); err == nil && p.Contains(a) {
			return true
		}
		if b, err := netip.ParseAddr(e); err == nil && b == a {
			return true
		}
	}
	return false
}

// Validate checks the ranges hp-ssh.sh accepts.
func (c F2BConfig) Validate() error {
	switch {
	case c.MaxRetry < 3 || c.MaxRetry > 20:
		return errors.New("deneme sayısı 3–20 olmalı")
	case c.FindMin < 5 || c.FindMin > 1440:
		return errors.New("deneme süresi 5–1440 dakika olmalı")
	case c.BanMin < 10 || c.BanMin > 10080:
		return errors.New("engel süresi 10 dakika – 7 gün (10080 dk) olmalı")
	}
	return nil
}

// Fail2ban runs the host fail2ban parts of hp-ssh.sh.
type Fail2ban struct {
	Runner     exec.Runner
	ScriptsDir string
	DryRun     bool

	mu   sync.Mutex
	fake *F2BStatus
}

func (f *Fail2ban) fakeState() *F2BStatus {
	if f.fake == nil {
		f.fake = &F2BStatus{Installed: true, Active: true, Config: F2BConfig{MaxRetry: 5, FindMin: 15, BanMin: 60},
			Ignore: []string{"203.0.113.10"},
			Jails: []F2BJail{
				{Name: "hostpanel", TotalFailed: 3, CurBanned: 1, TotalBanned: 2, Banned: []string{"198.51.100.23"}, Files: "/var/log/hostpanel/auth.log"},
				{Name: "sshd", CurFailed: 2, TotalFailed: 140, CurBanned: 2, TotalBanned: 31, Banned: []string{"185.48.180.8", "203.205.18.230"}, Files: "/var/log/auth.log"},
			}}
	}
	return f.fake
}

// Status reads the jails.
func (f *Fail2ban) Status(ctx context.Context) (F2BStatus, error) {
	if f.DryRun {
		f.mu.Lock()
		defer f.mu.Unlock()
		st := *f.fakeState()
		st.Jails = slices.Clone(st.Jails)
		return st, nil
	}
	cmd := exec.Helper(f.ScriptsDir, "hp-ssh.sh", "f2b-status")
	cmd.Timeout = 30 * time.Second
	res, err := f.Runner.Run(ctx, cmd)
	if err != nil {
		return F2BStatus{}, err
	}
	return ParseF2BStatus(res.Stdout), nil
}

var jailNames = []string{"sshd", "hostpanel", "recidive"}

// Unban lifts a ban.
func (f *Fail2ban) Unban(ctx context.Context, jail, ip string) error {
	if !slices.Contains(jailNames, jail) {
		return errors.New("geçersiz jail")
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return errors.New("geçersiz IP")
	}
	ip = a.String()
	if f.DryRun {
		f.mu.Lock()
		defer f.mu.Unlock()
		st := f.fakeState()
		for i := range st.Jails {
			if j := &st.Jails[i]; j.Name == jail {
				if k := slices.Index(j.Banned, ip); k >= 0 {
					j.Banned = slices.Delete(j.Banned, k, k+1)
					j.CurBanned--
					return nil
				}
			}
		}
		return errors.New("bu IP bu jail'de engelli değil")
	}
	_, err = f.Runner.Run(ctx, exec.Helper(f.ScriptsDir, "hp-ssh.sh", "f2b-unban", jail, ip))
	return err
}

// Configure rewrites the jail file. clientIP (the admin's address, unless
// loopback) must stay in the ignore list: a typo in the panel password must
// not lock the admin out of the panel and SSH.
func (f *Fail2ban) Configure(ctx context.Context, c F2BConfig, ignore []string, clientIP string) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if len(ignore) > MaxIgnore {
		return fmt.Errorf("en fazla %d muaf adres", MaxIgnore)
	}
	if !Covers(ignore, clientIP) {
		return fmt.Errorf("şu anki IP adresiniz (%s) muaf listede değil; kendinizi engellememek için listeye ekleyin", clientIP)
	}
	if f.DryRun {
		f.mu.Lock()
		defer f.mu.Unlock()
		st := f.fakeState()
		st.Config, st.Ignore = c, slices.Clone(ignore)
		return nil
	}
	rec := "0"
	if c.Recidive {
		rec = "1"
	}
	cmd := exec.Helper(f.ScriptsDir, "hp-ssh.sh", "f2b-config", strconv.Itoa(c.MaxRetry), strconv.Itoa(c.FindMin), strconv.Itoa(c.BanMin), rec)
	cmd.Stdin = strings.NewReader(strings.Join(ignore, "\n") + "\n")
	cmd.Timeout = 60 * time.Second
	_, err := f.Runner.Run(ctx, cmd)
	return err
}
