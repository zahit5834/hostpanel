package dns

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zahit5834/hostpanel/internal/exec"
	"github.com/zahit5834/hostpanel/internal/jobs"
	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/sites"
	"github.com/zahit5834/hostpanel/internal/store"
)

// Settings keys.
const (
	SettingInstalled  = "dns_installed"
	SettingNS1        = "dns_ns1"
	SettingNS2        = "dns_ns2"
	SettingHostmaster = "dns_hostmaster"
	SettingIPs        = "dns_ips"
)

// Zone defaults (seconds).
const (
	DefaultTTL     = 3600
	defaultRefresh = 3600
	defaultRetry   = 900
	defaultExpire  = 1209600
	defaultMinimum = 300
	checkCacheTTL  = 10 * time.Minute
)

// Service manages zones and drives hp-dns.sh.
type Service struct {
	Store      *Store
	DB         *sql.DB
	Runner     exec.Runner
	Jobs       *jobs.Manager
	Activity   *logs.Activity
	Log        *slog.Logger
	Sites      *sites.Service
	ScriptsDir string
	DryRun     bool
	// DefaultIPs proposes zone IPs before the admin saves any (ssl.Service.ServerIPs).
	DefaultIPs func(ctx context.Context) []netip.Addr
	// LookupNS answers delegation checks (nil = system resolver).
	LookupNS func(ctx context.Context, zone string) ([]*net.NS, error)
	// LocalAddr is the local BIND for "answers locally" checks (default 127.0.0.1:53).
	LocalAddr string
	// Mail returns the mail server's name and mail domains (nil = no mail).
	Mail func(ctx context.Context) (host string, domains []MailDomain)

	mu    sync.Mutex // one apply at a time
	cache sync.Map   // zone → delegationCache
}

// Register adds the job handlers and the site hook.
func (s *Service) Register() {
	s.Jobs.Register("dns.install", s.jobInstall)
	s.Jobs.Register("dns.apply", s.jobApply)
	s.Jobs.Register("dns.zone.delete", s.jobZoneDelete)
	if s.Sites != nil {
		s.Sites.Changed = s.SitesChanged
	}
}

func (s *Service) helper(ctx context.Context, w io.Writer, stdin io.Reader, timeout time.Duration, args ...string) (exec.Result, error) {
	c := exec.Helper(s.ScriptsDir, "hp-dns.sh", args...)
	c.Output, c.Stdin, c.Timeout = w, stdin, timeout
	return s.Runner.Run(ctx, c)
}

// Installed reports whether BIND was installed by the panel.
func (s *Service) Installed(ctx context.Context) bool {
	return store.GetSetting(ctx, s.DB, SettingInstalled, "") == "1"
}

// Settings returns the saved settings; IPs fall back to the server's public
// addresses until the admin saves a list.
func (s *Service) Settings(ctx context.Context) Settings {
	st := Settings{
		NS1:        store.GetSetting(ctx, s.DB, SettingNS1, ""),
		NS2:        store.GetSetting(ctx, s.DB, SettingNS2, ""),
		Hostmaster: store.GetSetting(ctx, s.DB, SettingHostmaster, ""),
	}
	if raw := store.GetSetting(ctx, s.DB, SettingIPs, ""); raw != "" {
		st.IPs, _ = ParseIPs(raw)
	} else if s.DefaultIPs != nil {
		for _, ip := range s.DefaultIPs(ctx) {
			if ip.IsGlobalUnicast() && !ip.IsPrivate() {
				st.IPs = append(st.IPs, ip)
			}
		}
	}
	return st
}

// ParseIPs parses a comma/space separated IP list (no duplicates).
func ParseIPs(raw string) ([]netip.Addr, error) {
	var out []netip.Addr
	seen := map[netip.Addr]bool{}
	for _, f := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' }) {
		a, err := netip.ParseAddr(f)
		if err != nil || a.Zone() != "" {
			return nil, fmt.Errorf("geçersiz IP: %s", f)
		}
		a = a.Unmap()
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out, nil
}

// FormatIPs joins ips for the settings form.
func FormatIPs(ips []netip.Addr) string {
	out := make([]string, len(ips))
	for i, ip := range ips {
		out[i] = ip.String()
	}
	return strings.Join(out, ", ")
}

// SaveSettings validates and stores the settings, then re-renders every zone.
func (s *Service) SaveSettings(ctx context.Context, in Settings) error {
	if err := in.Validate(); err != nil {
		return err
	}
	old := s.Settings(ctx)
	store.SetSetting(ctx, s.DB, SettingNS1, in.NS1)
	store.SetSetting(ctx, s.DB, SettingNS2, in.NS2)
	store.SetSetting(ctx, s.DB, SettingHostmaster, in.Hostmaster)
	store.SetSetting(ctx, s.DB, SettingIPs, FormatIPs(in.IPs))
	before := fmt.Sprintf("ns1: %s\nns2: %s\nyönetici: %s\nIP: %s", old.NS1, old.NS2, old.Hostmaster, FormatIPs(old.IPs))
	after := fmt.Sprintf("ns1: %s\nns2: %s\nyönetici: %s\nIP: %s", in.NS1, in.NS2, in.Hostmaster, FormatIPs(in.IPs))
	s.Activity.Record(ctx, logs.Entry{Action: "dns.settings", TargetType: "dns", TargetID: "settings",
		Summary: "DNS ayarları kaydedildi", Diff: logs.LineDiff(before, after)}, nil)
	s.cache.Clear()
	_, err := s.submitApply(ctx, 0, true)
	return err
}

// --- install ---

// StartInstall submits the BIND installation job.
func (s *Service) StartInstall(ctx context.Context) (int64, error) {
	if !s.Settings(ctx).Ready() {
		return 0, errors.New("önce ns1/ns2, yönetici e-postası ve IP'leri kaydedin")
	}
	return s.Jobs.Submit(ctx, jobs.Spec{Kind: "dns.install", TargetType: "dns", TargetID: "bind9",
		Summary: "DNS sunucusu (BIND 9) kuruluyor", Retryable: true})
}

func (s *Service) jobInstall(ctx context.Context, l *jobs.Log, _ map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	l.Printf("Ubuntu deposundan bind9 kuruluyor (yalnızca yetkili sunucu: recursion kapalı)…")
	if _, err := s.helper(ctx, l, nil, 20*time.Minute, "install"); err != nil {
		return err
	}
	store.SetSetting(ctx, s.DB, SettingInstalled, "1")
	l.Progress(70)
	if err := s.applyAll(ctx, l); err != nil {
		return err
	}
	l.Progress(100)
	l.Printf("DNS sunucusu hazır. Registrar'da ns1/ns2 için glue (IP) kayıtlarını girmeyi unutmayın.")
	return nil
}

// --- zones ---

// CreateZone stores a new zone and schedules its first apply.
func (s *Service) CreateZone(ctx context.Context, name string, customerID int64, dnssec bool) (Zone, int64, error) {
	n, err := NormalizeZoneName(name)
	if err != nil {
		return Zone{}, 0, err
	}
	if _, err := s.Store.ZoneByName(ctx, n); err == nil {
		return Zone{}, 0, fmt.Errorf("%s zone'u zaten var", n)
	}
	z := Zone{Name: n, CustomerID: customerID, DefaultTTL: DefaultTTL, Refresh: defaultRefresh, Retry: defaultRetry,
		Expire: defaultExpire, Minimum: defaultMinimum, DNSSEC: dnssec, AutoSites: true}
	if err := s.Store.InsertZone(ctx, &z); err != nil {
		if strings.Contains(err.Error(), "FOREIGN KEY") {
			return Zone{}, 0, errors.New("müşteri bulunamadı")
		}
		return Zone{}, 0, err
	}
	s.Activity.Record(ctx, logs.Entry{Action: "dns.zone.create", TargetType: "dns_zone", TargetID: n,
		Summary: "DNS zone'u oluşturuldu: " + n}, map[string]any{"zone": n, "customer_id": customerID, "dnssec": dnssec})
	job, err := s.submitApply(ctx, z.ID, true)
	return z, job, err
}

// UpdateZone saves zone settings (customer, default TTL, DNSSEC, automatic site records).
func (s *Service) UpdateZone(ctx context.Context, z Zone) (int64, error) {
	old, err := s.Store.Zone(ctx, z.ID)
	if err != nil {
		return 0, err
	}
	if z.DefaultTTL < MinTTL || z.DefaultTTL > MaxTTL {
		return 0, fmt.Errorf("varsayılan TTL %d–%d saniye olmalı", MinTTL, MaxTTL)
	}
	if err := s.Store.UpdateZone(ctx, z); err != nil {
		if strings.Contains(err.Error(), "FOREIGN KEY") {
			return 0, errors.New("müşteri bulunamadı")
		}
		return 0, err
	}
	before := fmt.Sprintf("müşteri: %d\nTTL: %d\nDNSSEC: %v\notomatik site kayıtları: %v", old.CustomerID, old.DefaultTTL, old.DNSSEC, old.AutoSites)
	after := fmt.Sprintf("müşteri: %d\nTTL: %d\nDNSSEC: %v\notomatik site kayıtları: %v", z.CustomerID, z.DefaultTTL, z.DNSSEC, z.AutoSites)
	action := "dns.zone.update"
	if old.DNSSEC != z.DNSSEC {
		action = "dns.dnssec"
	}
	s.Activity.Record(ctx, logs.Entry{Action: action, TargetType: "dns_zone", TargetID: old.Name,
		Summary: "DNS zone ayarları güncellendi: " + old.Name, Diff: logs.LineDiff(before, after)}, nil)
	return s.submitApply(ctx, z.ID, old.DNSSEC != z.DNSSEC)
}

// DeleteZone removes the zone from the panel and schedules removal from BIND
// (files are archived under /var/backups/hostpanel/dns first).
func (s *Service) DeleteZone(ctx context.Context, id int64) (int64, error) {
	z, err := s.Store.Zone(ctx, id)
	if err != nil {
		return 0, err
	}
	if err := s.Store.DeleteZone(ctx, id); err != nil {
		return 0, err
	}
	s.cache.Delete(z.Name)
	s.Activity.Record(ctx, logs.Entry{Action: "dns.zone.delete", TargetType: "dns_zone", TargetID: z.Name,
		Summary: "DNS zone'u silindi: " + z.Name}, map[string]any{"zone": z.Name})
	if !s.Installed(ctx) {
		return 0, nil
	}
	return s.Jobs.Submit(ctx, jobs.Spec{Kind: "dns.zone.delete", TargetType: "dns_zone", TargetID: z.Name,
		Summary: "DNS zone'u BIND'den kaldırılıyor: " + z.Name, Params: map[string]any{"zone": z.Name}, Retryable: true})
}

// --- records ---

// SaveRecord validates and stores r (insert when r.ID == 0, else update).
func (s *Service) SaveRecord(ctx context.Context, z Zone, r Record) (Record, int64, error) {
	r.ZoneID = z.ID
	if err := r.Normalize(z.Name); err != nil {
		return r, 0, err
	}
	all, err := s.Store.Records(ctx, z.ID)
	if err != nil {
		return r, 0, err
	}
	var others []Record
	var old *Record
	for i := range all {
		if all[i].ID == r.ID {
			old = &all[i]
			continue
		}
		others = append(others, all[i])
	}
	if r.ID != 0 && old == nil {
		return r, 0, sql.ErrNoRows
	}
	if err := CheckConflicts(r, others); err != nil {
		return r, 0, err
	}
	line := func(x Record) string { return fmt.Sprintf("%s %s %s (TTL %d)", x.Name, x.Type, x.Display(), x.TTL) }
	if old == nil {
		if err := s.Store.InsertRecord(ctx, &r); err != nil {
			return r, 0, err
		}
		s.Activity.Record(ctx, logs.Entry{Action: "dns.record.create", TargetType: "dns_zone", TargetID: z.Name,
			Summary: fmt.Sprintf("DNS kaydı eklendi: %s %s", r.FQDN(z.Name), r.Type), Diff: logs.LineDiff("", line(r))}, nil)
	} else {
		if err := s.Store.UpdateRecord(ctx, r); err != nil {
			return r, 0, err
		}
		s.Activity.Record(ctx, logs.Entry{Action: "dns.record.update", TargetType: "dns_zone", TargetID: z.Name,
			Summary: fmt.Sprintf("DNS kaydı güncellendi: %s %s", r.FQDN(z.Name), r.Type), Diff: logs.LineDiff(line(*old), line(r))}, nil)
	}
	job, err := s.submitApply(ctx, z.ID, false)
	return r, job, err
}

// DeleteRecord removes one record.
func (s *Service) DeleteRecord(ctx context.Context, z Zone, id int64) (int64, error) {
	r, err := s.Store.Record(ctx, z.ID, id)
	if err != nil {
		return 0, err
	}
	if err := s.Store.DeleteRecord(ctx, z.ID, id); err != nil {
		return 0, err
	}
	s.Activity.Record(ctx, logs.Entry{Action: "dns.record.delete", TargetType: "dns_zone", TargetID: z.Name,
		Summary: fmt.Sprintf("DNS kaydı silindi: %s %s", r.FQDN(z.Name), r.Type),
		Diff:    logs.LineDiff(fmt.Sprintf("%s %s %s (TTL %d)", r.Name, r.Type, r.Display(), r.TTL), "")}, nil)
	return s.submitApply(ctx, z.ID, false)
}

// --- rendering ---

// Input collects everything zone z is rendered from.
func (s *Service) Input(ctx context.Context, z Zone) (RenderInput, error) {
	in := RenderInput{Zone: z, Settings: s.Settings(ctx)}
	var err error
	if in.Records, err = s.Store.Records(ctx, z.ID); err != nil {
		return in, err
	}
	zones, err := s.Store.ZoneNames(ctx)
	if err != nil {
		return in, err
	}
	if s.Sites != nil {
		list, err := s.Sites.Store.List(ctx, 0)
		if err != nil {
			return in, err
		}
		for _, st := range list {
			var mine []string
			for _, n := range st.HostNames() {
				if ZoneFor(n, zones) == z.Name {
					mine = append(mine, n)
				}
			}
			if len(mine) > 0 {
				in.Sites = append(in.Sites, SiteNames{Domain: st.Domain, Names: mine})
			}
		}
	}
	if s.Mail != nil {
		host, domains := s.Mail(ctx)
		in.MailHost = host
		for _, d := range domains {
			if ZoneFor(d.Name, zones) == z.Name {
				in.MailDomains = append(in.MailDomains, d)
			}
		}
	}
	return in, nil
}

// Preview renders z with its current serial (no side effects).
func (s *Service) Preview(ctx context.Context, z Zone) (string, []Record, error) {
	in, err := s.Input(ctx, z)
	if err != nil {
		return "", nil, err
	}
	auto := AutoRecords(in)
	SortRecords(auto)
	return Render(in), auto, nil
}

// submitApply schedules a re-render of zone id (0 = every zone); config also
// regenerates BIND's zone list. Nothing happens before BIND is installed: the
// install job applies everything.
func (s *Service) submitApply(ctx context.Context, id int64, config bool) (int64, error) {
	if !s.Installed(ctx) {
		return 0, nil
	}
	target, summary := "all", "DNS zone'ları uygulanıyor"
	if id > 0 {
		z, err := s.Store.Zone(ctx, id)
		if err != nil {
			return 0, err
		}
		target, summary = z.Name, "DNS zone'u uygulanıyor: "+z.Name
	}
	return s.Jobs.Submit(ctx, jobs.Spec{Kind: "dns.apply", TargetType: "dns_zone", TargetID: target, Summary: summary,
		Params: map[string]any{"zone_id": id, "config": config}, Retryable: true})
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

func (s *Service) jobApply(ctx context.Context, l *jobs.Log, p map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := paramID(p, "zone_id")
	if id == 0 {
		return s.applyAll(ctx, l)
	}
	z, err := s.Store.Zone(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		l.Printf("Zone artık yok; atlandı.")
		return nil
	}
	if err != nil {
		return err
	}
	if err := s.writeZone(ctx, l, z); err != nil {
		return err
	}
	if cfg, _ := p["config"].(bool); cfg {
		return s.syncConfig(ctx, l)
	}
	return nil
}

// applyAll writes every zone, then BIND's zone list. Callers hold s.mu.
func (s *Service) applyAll(ctx context.Context, l *jobs.Log) error {
	zones, err := s.Store.Zones(ctx, 0)
	if err != nil {
		return err
	}
	var failed []string
	for _, z := range zones {
		if err := s.writeZone(ctx, l, z); err != nil {
			l.Printf("✗ %s: %v", z.Name, err)
			failed = append(failed, z.Name)
		}
	}
	if err := s.syncConfig(ctx, l); err != nil {
		return err
	}
	if len(failed) > 0 {
		return fmt.Errorf("şu zone'lar uygulanamadı: %s", strings.Join(failed, ", "))
	}
	return nil
}

// writeZone bumps the serial, renders, self-validates and installs the zone file.
func (s *Service) writeZone(ctx context.Context, l *jobs.Log, z Zone) error {
	st := s.Settings(ctx)
	if !st.Ready() {
		return errors.New("DNS ayarları eksik (ns1/ns2, yönetici e-postası, IP)")
	}
	z.Serial = NextSerial(z.Serial, time.Now())
	in, err := s.Input(ctx, z)
	if err != nil {
		return err
	}
	content := Render(in)
	if err := ValidateZoneFile(content, z.Name); err != nil {
		return fmt.Errorf("üretilen zone dosyası geçersiz: %w", err)
	}
	l.Printf("→ %s (serial %d, %d satır)", z.Name, z.Serial, strings.Count(content, "\n"))
	if _, err := s.helper(ctx, l, strings.NewReader(content), time.Minute, "write-zone", z.Name); err != nil {
		return err
	}
	return s.Store.SetSerial(ctx, z.ID, z.Serial)
}

// syncConfig hands the zone list to the helper, which writes BIND's config itself.
func (s *Service) syncConfig(ctx context.Context, l *jobs.Log) error {
	zones, err := s.Store.Zones(ctx, 0)
	if err != nil {
		return err
	}
	var b strings.Builder
	for _, z := range zones {
		fmt.Fprintf(&b, "%s %d\n", z.Name, boolInt(z.DNSSEC))
	}
	l.Printf("→ BIND zone listesi (%d zone)", len(zones))
	_, err = s.helper(ctx, l, strings.NewReader(b.String()), time.Minute, "sync-config")
	return err
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (s *Service) jobZoneDelete(ctx context.Context, l *jobs.Log, p map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	name, _ := p["zone"].(string)
	if !ValidZoneName(name) {
		return fmt.Errorf("geçersiz zone: %q", name)
	}
	if err := s.syncConfig(ctx, l); err != nil {
		return err
	}
	_, err := s.helper(ctx, l, nil, time.Minute, "delete-zone", name)
	return err
}

// SitesChanged re-renders the zones covering names (site created, deleted or
// its names changed). Injected into sites.Service.Changed.
func (s *Service) SitesChanged(ctx context.Context, names []string) {
	if !s.Installed(ctx) {
		return
	}
	zones, err := s.Store.ZoneNames(ctx)
	if err != nil {
		return
	}
	seen := map[string]bool{}
	for _, n := range names {
		zn := ZoneFor(n, zones)
		if zn == "" || seen[zn] {
			continue
		}
		seen[zn] = true
		z, err := s.Store.ZoneByName(ctx, zn)
		if err != nil || !z.AutoSites {
			continue
		}
		if _, err := s.submitApply(ctx, z.ID, false); err != nil && s.Log != nil {
			s.Log.Warn("dns apply after site change", "zone", zn, "err", err)
		}
	}
}

// MailChanged re-renders the zones covering names (mail server installed or
// removed, mail domain added/removed, DKIM key created). Unlike sites, mail
// records do not depend on the zone's AutoSites switch.
func (s *Service) MailChanged(ctx context.Context, names []string) {
	if !s.Installed(ctx) {
		return
	}
	zones, err := s.Store.ZoneNames(ctx)
	if err != nil {
		return
	}
	seen := map[string]bool{}
	for _, n := range names {
		zn := ZoneFor(n, zones)
		if zn == "" || seen[zn] {
			continue
		}
		seen[zn] = true
		z, err := s.Store.ZoneByName(ctx, zn)
		if err != nil {
			continue
		}
		if _, err := s.submitApply(ctx, z.ID, false); err != nil && s.Log != nil {
			s.Log.Warn("dns apply after mail change", "zone", zn, "err", err)
		}
	}
}

// ZoneCovering returns the zone that serves host ("" when none).
func (s *Service) ZoneCovering(ctx context.Context, host string) string {
	zones, err := s.Store.ZoneNames(ctx)
	if err != nil {
		return ""
	}
	return ZoneFor(host, zones)
}

// --- checks (unprivileged) ---

// Delegation is the result of the public NS lookup for a zone.
type Delegation struct {
	OK      bool     // public NS set is exactly ns1+ns2
	Found   []string // NS names the resolver returned
	Err     string
	Checked time.Time
}

type delegationCache struct {
	d   Delegation
	exp time.Time
}

// CheckDelegation looks the zone's NS records up through the system resolver
// (cached 10 minutes; refresh forces a new lookup).
func (s *Service) CheckDelegation(ctx context.Context, zone string, refresh bool) Delegation {
	if v, ok := s.cache.Load(zone); ok && !refresh {
		if c := v.(delegationCache); time.Now().Before(c.exp) {
			return c.d
		}
	}
	st := s.Settings(ctx)
	lookup := s.LookupNS
	if lookup == nil {
		lookup = net.DefaultResolver.LookupNS
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	d := Delegation{Checked: time.Now()}
	ns, err := lookup(cctx, zone)
	if err != nil {
		d.Err = "NS kaydı bulunamadı (registrar'da nameserver'lar henüz değiştirilmemiş olabilir)"
	}
	want := map[string]bool{st.NS1: true, st.NS2: true}
	match := 0
	for _, n := range ns {
		h := strings.TrimSuffix(strings.ToLower(n.Host), ".")
		d.Found = append(d.Found, h)
		if want[h] {
			match++
		}
	}
	sort.Strings(d.Found)
	d.OK = err == nil && match == 2 && len(d.Found) == 2
	s.cache.Store(zone, delegationCache{d: d, exp: time.Now().Add(checkCacheTTL)})
	return d
}

// CheckLocal asks the local BIND for the zone's NS records.
func (s *Service) CheckLocal(ctx context.Context, zone string) error {
	if s.DryRun {
		return nil
	}
	addr := s.LocalAddr
	if addr == "" {
		addr = "127.0.0.1:53"
	}
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ns, err := r.LookupNS(cctx, zone)
	if err != nil {
		return fmt.Errorf("yerel DNS sunucusu %s için yanıt vermedi: %v", zone, err)
	}
	if len(ns) == 0 {
		return fmt.Errorf("yerel DNS sunucusu %s için NS döndürmedi", zone)
	}
	return nil
}

// DS returns the DS records to enter at the registrar (empty until BIND has
// generated the keys).
func (s *Service) DS(ctx context.Context, zone string) (string, error) {
	res, err := s.helper(ctx, nil, nil, 30*time.Second, "ds", zone)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(res.Stdout), nil
}

// Status returns key=value pairs from "hp-dns.sh status".
func (s *Service) Status(ctx context.Context) map[string]string {
	out := map[string]string{}
	res, err := s.helper(ctx, nil, nil, 15*time.Second, "status")
	if err != nil {
		out["error"] = err.Error()
		return out
	}
	sc := bufio.NewScanner(strings.NewReader(res.Stdout))
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), "="); ok {
			out[k] = v
		}
	}
	return out
}
