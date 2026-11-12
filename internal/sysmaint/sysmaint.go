// Package sysmaint is the operating-system maintenance side of the panel
// (Faz 11): package updates, reboots and the boot report, memory/swap/OOM
// and a few system services. Reads are unprivileged (apt list, /proc, the
// journal, /run/reboot-required); every change goes through hp-system.sh.
package sysmaint

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zahit5834/hostpanel/internal/exec"
)

// Service reads system state and runs hp-system.sh.
type Service struct {
	Runner     exec.Runner // root helper
	Probe      exec.Runner // unprivileged commands (apt list, journalctl, busctl); DryRun in dry-run
	ScriptsDir string
	DryRun     bool
	// Root lets tests point /proc, /etc, /var paths at a temp tree ("" = /).
	Root string

	mu  sync.Mutex
	apt AptInfo

	fakeReboot time.Time // dry-run planned reboot
	fakeAuto   *bool
	fakeSwap   int // MB, dry-run
}

func (s *Service) path(p string) string { return s.Root + p }

// --- packages ---

// Pkg is one upgradable package.
type Pkg struct {
	Name, Suite, New, Old, Arch string
	Security                    bool
}

// HoldPkgs are kept back on request (a Docker upgrade restarts every container).
var HoldPkgs = []string{"docker.io", "containerd", "runc"}

// ParseUpgradable reads "apt list --upgradable"
// ("snapd/noble-updates 2.78+ubuntu24.04 amd64 [upgradable from: 2.77.1+ubuntu24.04]").
func ParseUpgradable(out string) []Pkg {
	var res []Pkg
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || !strings.Contains(f[0], "/") {
			continue
		}
		name, suites, _ := strings.Cut(f[0], "/")
		p := Pkg{Name: name, Suite: suites, New: f[1], Arch: f[2]}
		if i := strings.Index(line, "[upgradable from: "); i >= 0 {
			p.Old = strings.TrimSuffix(strings.TrimSpace(line[i+len("[upgradable from: "):]), "]")
		}
		for _, su := range strings.Split(suites, ",") {
			if strings.HasSuffix(su, "-security") {
				p.Security = true
			}
		}
		res = append(res, p)
	}
	return res
}

// AptInfo is the update overview.
type AptInfo struct {
	At       time.Time
	Pkgs     []Pkg
	Security int
	Held     []string // HoldPkgs present in the list
	Err      string
}

const aptTTL = time.Hour

// Upgradable lists the upgradable packages (cached for an hour; refresh forces).
func (s *Service) Upgradable(ctx context.Context, refresh bool) AptInfo {
	s.mu.Lock()
	cur := s.apt
	s.mu.Unlock()
	if !refresh && !cur.At.IsZero() && time.Since(cur.At) < aptTTL {
		return cur
	}
	info := AptInfo{At: time.Now()}
	var out string
	if s.DryRun {
		out = dryApt
	} else {
		res, err := s.Probe.Run(ctx, exec.Cmd{Name: "apt", Args: []string{"list", "--upgradable"}, Timeout: time.Minute,
			Env: append(os.Environ(), "LC_ALL=C")})
		out = res.Stdout
		if err != nil && out == "" {
			info.Err = "apt list çalıştırılamadı: " + err.Error()
		}
	}
	info.Pkgs = ParseUpgradable(out)
	slices.SortStableFunc(info.Pkgs, func(a, b Pkg) int {
		if a.Security != b.Security {
			if a.Security {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Name, b.Name)
	})
	for _, p := range info.Pkgs {
		if p.Security {
			info.Security++
		}
		if slices.Contains(HoldPkgs, p.Name) {
			info.Held = append(info.Held, p.Name)
		}
	}
	s.mu.Lock()
	s.apt = info
	s.mu.Unlock()
	return info
}

// Invalidate drops the cache (after an upgrade).
func (s *Service) Invalidate() {
	s.mu.Lock()
	s.apt = AptInfo{}
	s.mu.Unlock()
}

const dryApt = `Listing...
openssl/noble-updates,noble-security 3.0.13-0ubuntu3.7 amd64 [upgradable from: 3.0.13-0ubuntu3.6]
libssl3t64/noble-updates,noble-security 3.0.13-0ubuntu3.7 amd64 [upgradable from: 3.0.13-0ubuntu3.6]
snapd/noble-updates 2.78+ubuntu24.04 amd64 [upgradable from: 2.77.1+ubuntu24.04]
docker.io/noble-updates 28.2.2-0ubuntu1~24.04.1 amd64 [upgradable from: 27.5.1-0ubuntu3~24.04.2]
`

// AutoUpdates is the unattended-upgrades state.
type AutoUpdates struct {
	Known   bool
	On      bool
	LastRun time.Time
}

var aptPeriodicRe = regexp.MustCompile(`^\s*APT::Periodic::Unattended-Upgrade\s+"([0-9]+)"\s*;`)

// AutoStatus reads /etc/apt/apt.conf.d/20auto-upgrades and the last run.
func (s *Service) AutoStatus() AutoUpdates {
	if s.DryRun {
		s.mu.Lock()
		defer s.mu.Unlock()
		on := true
		if s.fakeAuto != nil {
			on = *s.fakeAuto
		}
		return AutoUpdates{Known: true, On: on, LastRun: time.Now().Add(-5 * time.Hour)}
	}
	var a AutoUpdates
	if b, err := os.ReadFile(s.path("/etc/apt/apt.conf.d/20auto-upgrades")); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if m := aptPeriodicRe.FindStringSubmatch(l); m != nil {
				a.Known, a.On = true, m[1] != "0"
			}
		}
		if !a.Known {
			a.Known = true // file without the line: apt's default is off
		}
	}
	if fi, err := os.Stat(s.path("/var/log/unattended-upgrades/unattended-upgrades.log")); err == nil {
		a.LastRun = fi.ModTime()
	}
	return a
}

// SetAuto switches unattended-upgrades on/off.
func (s *Service) SetAuto(ctx context.Context, on bool) error {
	if s.DryRun {
		s.mu.Lock()
		s.fakeAuto = &on
		s.mu.Unlock()
		return nil
	}
	v := "off"
	if on {
		v = "on"
	}
	_, err := s.Runner.Run(ctx, exec.Helper(s.ScriptsDir, "hp-system.sh", "unattended", v))
	return err
}

// AptRun is the command line of the system.apt job (output goes to w).
func (s *Service) AptRun(ctx context.Context, mode string, hold bool, w io.Writer) (string, error) {
	if mode != "security" && mode != "all" {
		return "", errors.New("geçersiz güncelleme türü")
	}
	h := "nohold"
	if hold {
		h = "hold"
	}
	cmd := exec.Helper(s.ScriptsDir, "hp-system.sh", "apt-run", mode, h)
	cmd.Timeout = 2 * time.Hour
	cmd.Output = w
	res, err := s.Runner.Run(ctx, cmd)
	s.Invalidate()
	return res.Stdout, err
}

// --- needrestart ---

// Restart is the needrestart -b result.
type Restart struct {
	Missing  bool
	Services []string // "nginx.service"
	Kernel   int      // KSTA: 0 unknown, 1 current, 2 ABI upgrade, 3 version upgrade
	KCur     string
	KExp     string
}

// KernelPending reports whether a newer kernel waits for a reboot.
func (r Restart) KernelPending() bool { return r.Kernel >= 2 }

// ParseNeedrestart reads "needrestart -b" lines.
func ParseNeedrestart(out string) Restart {
	var r Restart
	for _, l := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), ": ")
		if !ok {
			continue
		}
		switch k {
		case "NEEDRESTART-MISSING":
			r.Missing = true
		case "NEEDRESTART-SVC":
			if !slices.Contains(r.Services, v) {
				r.Services = append(r.Services, v)
			}
		case "NEEDRESTART-KSTA":
			r.Kernel, _ = strconv.Atoi(v)
		case "NEEDRESTART-KCUR":
			r.KCur = v
		case "NEEDRESTART-KEXP":
			r.KExp = v
		}
	}
	return r
}

// Needrestart asks the root helper which services run outdated libraries.
func (s *Service) Needrestart(ctx context.Context) (Restart, error) {
	if s.DryRun {
		return ParseNeedrestart("NEEDRESTART-VER: 3.6\nNEEDRESTART-KCUR: 6.8.0-147-generic\nNEEDRESTART-KEXP: 6.8.0-149-generic\nNEEDRESTART-KSTA: 3\nNEEDRESTART-SVC: nginx.service\nNEEDRESTART-SVC: fail2ban.service\nNEEDRESTART-SVC: hp-site-ornek.service\n"), nil
	}
	cmd := exec.Helper(s.ScriptsDir, "hp-system.sh", "needrestart")
	cmd.Timeout = 2 * time.Minute
	res, err := s.Runner.Run(ctx, cmd)
	if err != nil {
		return Restart{}, err
	}
	return ParseNeedrestart(res.Stdout), nil
}

// --- reboot ---

// RebootInfo is the reboot card.
type RebootInfo struct {
	Required  bool
	Pkgs      []string
	Scheduled time.Time // zero = none
	Kind      string    // reboot|poweroff…
	BootID    string
	BootedAt  time.Time
}

// ParseScheduled reads busctl's ScheduledShutdown property:
// `(st) "reboot" 1794460055000000` (usec; 0 or "" = none).
func ParseScheduled(out string) (string, time.Time) {
	f := strings.Fields(strings.TrimSpace(out))
	if len(f) != 3 || f[0] != "(st)" {
		return "", time.Time{}
	}
	kind := strings.Trim(f[1], `"`)
	us, err := strconv.ParseUint(f[2], 10, 64)
	if err != nil || us == 0 || us == ^uint64(0) || kind == "" {
		return "", time.Time{}
	}
	return kind, time.UnixMicro(int64(us))
}

// BootID is the kernel's random id of this boot.
func (s *Service) BootID() string {
	b, _ := os.ReadFile(s.path("/proc/sys/kernel/random/boot_id"))
	return strings.TrimSpace(string(b))
}

// Reboot reads the reboot state.
func (s *Service) Reboot(ctx context.Context) RebootInfo {
	ri := RebootInfo{BootID: s.BootID()}
	if _, err := os.Stat(s.path("/var/run/reboot-required")); err == nil {
		ri.Required = true
	}
	if b, err := os.ReadFile(s.path("/var/run/reboot-required.pkgs")); err == nil {
		for _, p := range strings.Fields(string(b)) {
			if !slices.Contains(ri.Pkgs, p) {
				ri.Pkgs = append(ri.Pkgs, p)
			}
		}
	}
	if b, err := os.ReadFile(s.path("/proc/uptime")); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			if sec, err := strconv.ParseFloat(f[0], 64); err == nil {
				ri.BootedAt = time.Now().Add(-time.Duration(sec * float64(time.Second))).Truncate(time.Second)
			}
		}
	}
	if s.DryRun {
		s.mu.Lock()
		if !s.fakeReboot.IsZero() && s.fakeReboot.After(time.Now()) {
			ri.Kind, ri.Scheduled = "reboot", s.fakeReboot
		}
		s.mu.Unlock()
		if len(ri.Pkgs) == 0 {
			ri.Required, ri.Pkgs = true, []string{"linux-image-6.8.0-149-generic", "linux-base"}
		}
		return ri
	}
	res, err := s.Probe.Run(ctx, exec.Cmd{Name: "busctl", Args: []string{"get-property", "org.freedesktop.login1",
		"/org/freedesktop/login1", "org.freedesktop.login1.Manager", "ScheduledShutdown"}, Timeout: 5 * time.Second})
	if err == nil {
		ri.Kind, ri.Scheduled = ParseScheduled(res.Stdout)
	}
	return ri
}

var hhmmRe = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)

// ScheduleReboot plans a reboot: when is "+N" minutes (1–1440) or "HH:MM".
func (s *Service) ScheduleReboot(ctx context.Context, when string) (time.Time, error) {
	var at time.Time
	now := time.Now()
	if m, ok := strings.CutPrefix(when, "+"); ok {
		n, err := strconv.Atoi(m)
		if err != nil || n < 1 || n > 1440 {
			return at, errors.New("1–1440 dakika")
		}
		at = now.Add(time.Duration(n) * time.Minute)
	} else if hhmmRe.MatchString(when) {
		h, _ := strconv.Atoi(when[:2])
		mi, _ := strconv.Atoi(when[3:])
		at = time.Date(now.Year(), now.Month(), now.Day(), h, mi, 0, 0, time.Local)
		if !at.After(now) {
			at = at.Add(24 * time.Hour)
		}
	} else {
		return at, errors.New("geçersiz zaman (+dakika ya da SS:DD)")
	}
	if s.DryRun {
		s.mu.Lock()
		s.fakeReboot = at
		s.mu.Unlock()
		return at, nil
	}
	_, err := s.Runner.Run(ctx, exec.Helper(s.ScriptsDir, "hp-system.sh", "reboot", "at", when))
	return at, err
}

// CancelReboot cancels a planned reboot.
func (s *Service) CancelReboot(ctx context.Context) error {
	if s.DryRun {
		s.mu.Lock()
		s.fakeReboot = time.Time{}
		s.mu.Unlock()
		return nil
	}
	_, err := s.Runner.Run(ctx, exec.Helper(s.ScriptsDir, "hp-system.sh", "reboot", "cancel"))
	return err
}

// --- memory / swap ---

// Mem is /proc/meminfo (bytes).
type Mem struct {
	Total, Available, SwapTotal, SwapFree uint64
}

// ReadMem parses /proc/meminfo.
func (s *Service) ReadMem() Mem {
	var m Mem
	f, err := os.Open(s.path("/proc/meminfo"))
	if err != nil {
		return m
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		fs := strings.Fields(v)
		if len(fs) == 0 {
			continue
		}
		n, _ := strconv.ParseUint(fs[0], 10, 64)
		n *= 1024
		switch k {
		case "MemTotal":
			m.Total = n
		case "MemAvailable":
			m.Available = n
		case "SwapTotal":
			m.SwapTotal = n
		case "SwapFree":
			m.SwapFree = n
		}
	}
	if s.DryRun && m.SwapTotal == 0 {
		s.mu.Lock()
		m.SwapTotal = uint64(s.fakeSwap) << 20
		s.mu.Unlock()
		m.SwapFree = m.SwapTotal
	}
	return m
}

// CreateSwap makes /swapfile (only when there is no swap at all).
func (s *Service) CreateSwap(ctx context.Context, mb int) error {
	if mb < 1024 || mb > 16384 {
		return errors.New("swap boyutu 1024–16384 MB olmalı")
	}
	if s.ReadMem().SwapTotal > 0 {
		return errors.New("sunucuda zaten swap var")
	}
	if s.DryRun {
		s.mu.Lock()
		s.fakeSwap = mb
		s.mu.Unlock()
		return nil
	}
	cmd := exec.Helper(s.ScriptsDir, "hp-system.sh", "swap-create", strconv.Itoa(mb))
	cmd.Timeout = 10 * time.Minute
	_, err := s.Runner.Run(ctx, cmd)
	return err
}

// Reservation is one consumer of the memory plan.
type Reservation struct {
	Label string
	MB    int
	Link  string
}

// Plan sums what the panel's services may take at most.
type Plan struct {
	TotalMB    int
	Items      []Reservation
	ReservedMB int
	Pct        int
	SwapMB     int
}

// Over reports a plan above physical RAM.
func (p Plan) Over() bool { return p.ReservedMB > p.TotalMB }

// MakePlan builds the plan from the reservations.
func MakePlan(m Mem, items []Reservation) Plan {
	p := Plan{TotalMB: int(m.Total >> 20), SwapMB: int(m.SwapTotal >> 20)}
	for _, it := range items {
		if it.MB > 0 {
			p.Items = append(p.Items, it)
			p.ReservedMB += it.MB
		}
	}
	if p.TotalMB > 0 {
		p.Pct = p.ReservedMB * 100 / p.TotalMB
	}
	return p
}

// --- OOM ---

// OOM is one kernel OOM kill.
type OOM struct {
	Time    time.Time
	Process string
	PID     int
	CGroup  string // task_memcg, e.g. /system.slice/hp-site-x.service
	Limit   bool   // cgroup limit (CONSTRAINT_MEMCG) rather than the whole machine
}

// Unit is the systemd unit of the cgroup ("hp-site-x.service", "docker-<id>.scope").
func (o OOM) Unit() string {
	i := strings.LastIndexByte(o.CGroup, '/')
	return o.CGroup[i+1:]
}

// ParseOOM reads journalctl -k -o short-iso lines containing "oom-kill:"
// ("2026-11-12T05:00:00+0000 host kernel: oom-kill:constraint=CONSTRAINT_MEMCG,…,task_memcg=/system.slice/x.service,task=dotnet,pid=1234,uid=1001").
func ParseOOM(out string) []OOM {
	var res []OOM
	for _, l := range strings.Split(out, "\n") {
		i := strings.Index(l, "oom-kill:")
		if i < 0 {
			continue
		}
		var o OOM
		ts, _, _ := strings.Cut(l, " ")
		for _, layout := range []string{"2006-01-02T15:04:05-0700", time.RFC3339Nano} {
			if t, err := time.Parse(layout, ts); err == nil {
				o.Time = t
				break
			}
		}
		for _, kv := range strings.Split(l[i+len("oom-kill:"):], ",") {
			k, v, _ := strings.Cut(strings.TrimSpace(kv), "=")
			switch k {
			case "constraint":
				o.Limit = v == "CONSTRAINT_MEMCG"
			case "task_memcg":
				o.CGroup = v
			case "task":
				o.Process = v
			case "pid":
				o.PID, _ = strconv.Atoi(v)
			}
		}
		if o.Process != "" {
			res = append(res, o)
		}
	}
	return res
}

// OOMSince returns the kernel OOM kills after since (journal; the panel is in
// the systemd-journal group).
func (s *Service) OOMSince(ctx context.Context, since time.Time) ([]OOM, error) {
	if s.DryRun {
		return nil, nil
	}
	res, err := s.Probe.Run(ctx, exec.Cmd{Name: "journalctl", Args: []string{"-k", "-q", "--no-pager", "-o", "short-iso",
		"--since", "@" + strconv.FormatInt(since.Unix(), 10), "-g", "oom-kill:"}, Timeout: 20 * time.Second})
	if err != nil && res.Stdout == "" {
		// exit 1 with no output = no match
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.Code == 1 {
			return nil, nil
		}
		return nil, err
	}
	return ParseOOM(res.Stdout), nil
}

// --- services ---

// ManagedServices can be reloaded/restarted from Sunucu → Genel.
var ManagedServices = []struct{ Name, Label string }{
	{"nginx", "nginx"},
	{"docker", "Docker"},
	{"named", "BIND (DNS)"},
	{"fail2ban", "fail2ban"},
}

// ServiceAction reloads or restarts one of ManagedServices.
func (s *Service) ServiceAction(ctx context.Context, action, name string) (string, error) {
	if action != "reload" && action != "restart" {
		return "", errors.New("geçersiz işlem")
	}
	ok := false
	for _, m := range ManagedServices {
		ok = ok || m.Name == name
	}
	if !ok {
		return "", errors.New("bu servis panelden yönetilmez")
	}
	if s.DryRun {
		return "", nil
	}
	cmd := exec.Helper(s.ScriptsDir, "hp-system.sh", "service", action, name)
	cmd.Timeout = 3 * time.Minute
	res, err := s.Runner.Run(ctx, cmd)
	return res.Stdout, err
}

// NginxTest runs nginx -t (root reads the keys).
func (s *Service) NginxTest(ctx context.Context) (string, error) {
	if s.DryRun {
		return "nginx: the configuration file /etc/nginx/nginx.conf syntax is ok\nnginx: configuration file /etc/nginx/nginx.conf test is successful (dry-run)\n", nil
	}
	res, err := s.Runner.Run(ctx, exec.Helper(s.ScriptsDir, "hp-system.sh", "nginx-test"))
	return res.Stdout + res.Stderr, err
}

// NginxDump returns nginx -T (≤ 1 MB).
func (s *Service) NginxDump(ctx context.Context) (string, error) {
	if s.DryRun {
		return "# configuration file /etc/nginx/nginx.conf:\nuser www-data;\n(dry-run)\n", nil
	}
	cmd := exec.Helper(s.ScriptsDir, "hp-system.sh", "nginx-dump")
	cmd.Timeout = time.Minute
	res, err := s.Runner.Run(ctx, cmd)
	return res.Stdout, err
}

// SudoersSum is the sha256 of /etc/sudoers.d/hostpanel ("missing" if absent).
func (s *Service) SudoersSum(ctx context.Context) (string, error) {
	res, err := s.Runner.Run(ctx, exec.Helper(s.ScriptsDir, "hp-system.sh", "sudoers-sum"))
	return strings.TrimSpace(res.Stdout), err
}
