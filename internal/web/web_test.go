package web

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/zahit5834/hostpanel/internal/auth"
	"github.com/zahit5834/hostpanel/internal/backups"
	"github.com/zahit5834/hostpanel/internal/config"
	"github.com/zahit5834/hostpanel/internal/crons"
	"github.com/zahit5834/hostpanel/internal/crypto"
	"github.com/zahit5834/hostpanel/internal/customers"
	"github.com/zahit5834/hostpanel/internal/databases"
	"github.com/zahit5834/hostpanel/internal/dns"
	"github.com/zahit5834/hostpanel/internal/domains"
	"github.com/zahit5834/hostpanel/internal/exec"
	"github.com/zahit5834/hostpanel/internal/hostsec"
	"github.com/zahit5834/hostpanel/internal/images"
	"github.com/zahit5834/hostpanel/internal/jobs"
	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/mail"
	"github.com/zahit5834/hostpanel/internal/metrics"
	"github.com/zahit5834/hostpanel/internal/monitor"
	"github.com/zahit5834/hostpanel/internal/notify"
	"github.com/zahit5834/hostpanel/internal/panelcfg"
	"github.com/zahit5834/hostpanel/internal/pgsql"
	"github.com/zahit5834/hostpanel/internal/runtimes"
	"github.com/zahit5834/hostpanel/internal/sites"
	"github.com/zahit5834/hostpanel/internal/ssl"
	"github.com/zahit5834/hostpanel/internal/store"
	"github.com/zahit5834/hostpanel/internal/sysmaint"
	"github.com/zahit5834/hostpanel/internal/traffic"
	"github.com/zahit5834/hostpanel/internal/update"
)

func newTestServer(t *testing.T) (*httptest.Server, *Server) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.DataDir, cfg.LogDir, cfg.RootLogDir, cfg.SecureCookies, cfg.DryRun = dir, dir, dir, false, true
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	db, err := store.Open(cfg.DBPath())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	store.Migrate(ctx, db)
	key, _ := crypto.LoadKey(filepath.Join(dir, "k"), true, true)
	box, _ := crypto.New(key)
	log := slog.New(slog.NewTextHandler(testLogOut, nil))
	act := logs.NewActivity(db)
	a := auth.New(db, box, key)
	a.SetAdminPassword(ctx, "admin", "correct-horse-1")
	jm := jobs.NewManager(db, cfg.JobLogDir(), act, jobs.NewBroker(), log)
	cfg.ScriptsDir, cfg.TemplatesDir, cfg.RuntimesDir = "../../deploy/scripts", "../../deploy/templates", "../../deploy/runtimes"
	runner := &exec.DryRun{Activity: act}
	probe := fakeProbe{}
	reg, err := runtimes.Load(cfg.RuntimesDir, probe, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range reg.All() {
		p.Def().Versions.Available = "" // no network in tests
	}
	svc := &sites.Service{Store: sites.NewStore(db), Box: box, Runner: runner, Probe: probe, Runtimes: reg, Jobs: jm,
		Activity: act, Log: log, ScriptsDir: cfg.ScriptsDir, TemplatesDir: cfg.TemplatesDir,
		UploadDir: filepath.Join(dir, "uploads"), DryRun: true}
	svc.ProbeToken = ssl.EnsureServerID(ctx, db)
	svc.Register()
	sslSvc := &ssl.Service{Store: ssl.NewStore(db), Sites: svc, DB: db, Box: box, Runner: runner, Probe: probe, Jobs: jm,
		Activity: act, Log: log, ScriptsDir: cfg.ScriptsDir, RenewLog: filepath.Join(dir, "ssl-renewals.log"), DryRun: true,
		Checker: func(context.Context) *ssl.Checker {
			return &ssl.Checker{Resolver: testResolver{}, Client: &http.Client{Transport: noNetwork{}}, Token: "x"}
		}}
	sslSvc.Register()
	dbSvc := &databases.Service{Store: databases.NewStore(db), DB: db, Box: box, Runner: runner, Jobs: jm, Activity: act,
		Log: log, Sites: svc, ScriptsDir: cfg.ScriptsDir, DryRun: true, Fake: databases.NewFakeServer("")}
	dbSvc.Register()
	pgSvc := &pgsql.Service{Store: pgsql.NewStore(db), DB: db, Box: box, Runner: runner, Jobs: jm, Activity: act,
		Log: log, Sites: svc, ScriptsDir: cfg.ScriptsDir, UploadDir: svc.UploadDir, DryRun: true}
	pgSvc.Register()
	bkSvc := &backups.Service{Store: backups.NewStore(db), DB: db, Box: box, Runner: runner, Probe: probe, Jobs: jm,
		Activity: act, Log: log, Sites: svc, DBs: dbSvc, PG: pgSvc, ScriptsDir: cfg.ScriptsDir, UploadDir: svc.UploadDir, DryRun: true}
	bkSvc.Register()
	notifySvc := &notify.Service{DB: db, Box: box, Activity: act, Log: log, Client: &http.Client{Transport: noNetwork{}}}
	sslSvc.Notify, bkSvc.Notify = notifySvc.Send, notifySvc.Send
	monSvc := &monitor.Service{Store: monitor.NewStore(db), Sites: svc, Probe: probe, Activity: act, Log: log,
		Notify: notifySvc.Send, DryRun: true, DiskFunc: func() int { return 10 }}
	dnsSvc := &dns.Service{Store: dns.NewStore(db), DB: db, Runner: runner, Jobs: jm, Activity: act, Log: log,
		Sites: svc, ScriptsDir: cfg.ScriptsDir, DryRun: true,
		DefaultIPs: func(context.Context) []netip.Addr { return []netip.Addr{netip.MustParseAddr("185.48.180.32")} },
		LookupNS: func(_ context.Context, zone string) ([]*net.NS, error) {
			if zone == "ornek.com" {
				return []*net.NS{{Host: "ns1.ornek.com."}, {Host: "ns2.ornek.com."}}, nil
			}
			return nil, &net.DNSError{Err: "no such host", Name: zone, IsNotFound: true}
		}}
	dnsSvc.Register()
	mailSvc := &mail.Service{Store: mail.NewStore(db), DB: db, Runner: runner, Jobs: jm, Activity: act, Log: log,
		ScriptsDir: cfg.ScriptsDir, DryRun: true, MemTotalMB: 8000, Fake: mail.NewFake(), Changed: dnsSvc.MailChanged,
		ServerIPs: func(context.Context) []netip.Addr { return []netip.Addr{netip.MustParseAddr("185.48.180.32")} }}
	mailSvc.Register()
	svc.MailHost = mailSvc.Host
	bkSvc.Mail = mailSvc
	dnsSvc.Mail = func(ctx context.Context) (string, []dns.MailDomain) {
		host, ds := mailSvc.DNSInfo(ctx)
		var out []dns.MailDomain
		for _, d := range ds {
			out = append(out, dns.MailDomain{Name: d.Name, DKIMSelector: d.DKIMSelector, DKIMTXT: d.DKIMTXT})
		}
		return host, out
	}
	s := &Server{Cfg: cfg, DB: db, Auth: a, Activity: act, Jobs: jm, Runner: runner, Log: log, Version: "test",
		Customers: customers.New(db), Sites: svc, Runtimes: reg, SSL: sslSvc, DBs: dbSvc, PG: pgSvc, Backups: bkSvc,
		Monitor: monSvc, Notify: notifySvc, DNS: dnsSvc, Mail: mailSvc,
		Crons: &crons.Service{Store: crons.NewStore(db), Sites: svc, Runner: runner, Activity: act, Log: log,
			ScriptsDir: cfg.ScriptsDir, DryRun: true, Notify: notifySvc.Send}, BaseCtx: ctx}
	bkSvc.Crons = s.Crons
	s.SSH = &hostsec.SSH{Runner: runner, ScriptsDir: cfg.ScriptsDir, DryRun: true, AuthLog: filepath.Join(dir, "auth.log")}
	s.F2B = &hostsec.Fail2ban{Runner: runner, ScriptsDir: cfg.ScriptsDir, DryRun: true}
	s.Sys = &sysmaint.Service{Runner: runner, Probe: runner, ScriptsDir: cfg.ScriptsDir, DryRun: true}
	s.Traffic = &traffic.Service{DB: db, Sites: svc, Log: log}
	s.Metrics = &metrics.Service{DB: db, Log: log}
	s.Domains = &domains.Service{DB: db, Log: log, Client: &http.Client{Transport: noNetwork{}}}
	// Container registries: local stand-ins (MCR tag list + Docker Hub tags).
	reg2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v2/mssql/") {
			w.Write([]byte(`{"name":"mssql/server","tags":["2025-CU10-ubuntu-24.04","2025-CU10-GDR1-ubuntu-24.04","2027-CU1-ubuntu-24.04"]}`))
			return
		}
		w.Write([]byte(`{"results":[{"name":"17.0.0-r1"},{"name":"17.0.1-r1"},{"name":"latest"}]}`))
	}))
	t.Cleanup(reg2.Close)
	s.Images = &images.Service{DB: db, Notify: notifySvc.Send, Log: log, MCR: reg2.URL, Hub: reg2.URL, Engines: []images.Engine{
		{ID: images.MSSQL, Label: "MSSQL", Current: func(ctx context.Context) string {
			if srv, err := dbSvc.Store.Server(ctx); err == nil && srv.Status != databases.StatusInstalling {
				return srv.Image
			}
			return ""
		}},
		{ID: images.Mail, Label: "Posta sunucusu", Current: func(ctx context.Context) string {
			if srv, err := mailSvc.Store.Server(ctx); err == nil && srv.Status != mail.StatusInstalling {
				return srv.Image
			}
			return ""
		}},
	}}
	// Releases come from a local stand-in for the GitHub API.
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"tag_name":"v0.2.0","name":"v0.2.0","body":"- yeni <script>x</script>","html_url":"https://github.com/zahit5834/hostpanel/releases/tag/v0.2.0","published_at":"2026-11-06T10:00:00Z"}`))
	}))
	t.Cleanup(gh.Close)
	s.Update = &update.Service{DB: db, Runner: runner, ScriptsDir: cfg.ScriptsDir, Activity: act, Log: log,
		Notify: notifySvc.Send, Version: "v0.1.0", Repo: config.DefaultRepo, API: gh.URL,
		StatusPath: filepath.Join(dir, "update-status.json"), LogPath: filepath.Join(dir, "update.log"), Dev: true}
	s.ExportConfig = func(ctx context.Context, pass string, w io.Writer) (panelcfg.Manifest, error) {
		return panelcfg.Export(ctx, db, panelcfg.ExportOptions{DataDir: dir, MasterKey: key, RuntimesDir: cfg.RuntimesDir,
			Version: "v0.1.0", Server: "srv1"}, pass, w)
	}
	s.RegisterJobs()
	if err := s.Init(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	jm.Start(ctx, 1)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts, s
}

// fakeProbe answers read-only probes: .NET reports one installed ASP.NET Core runtime.
type fakeProbe struct{}

func (fakeProbe) Run(ctx context.Context, c exec.Cmd) (exec.Result, error) {
	if strings.HasSuffix(c.Name, "dotnet") && len(c.Args) == 1 && c.Args[0] == "--list-sdks" {
		return exec.Result{Stdout: "10.0.403 [/usr/share/dotnet/sdk]\n"}, nil
	}
	if strings.HasSuffix(c.Name, "php-fpm8.3") {
		return exec.Result{Stdout: "PHP 8.3.6 (fpm-fcgi) (built: Jul 14 2025 18:30:55)\n"}, nil
	}
	if strings.HasSuffix(c.Name, "dotnet") {
		return exec.Result{Stdout: "Microsoft.AspNetCore.App 10.0.14 [/usr/share/dotnet/shared/Microsoft.AspNetCore.App]\n"}, nil
	}
	return exec.Result{Stdout: "inactive\n"}, nil
}

// testResolver resolves every name to 192.0.2.1 (not this server).
type testResolver struct{}

func (testResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}}, nil
}

type noNetwork struct{}

func (noNetwork) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("no network in tests")
}

func client() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

var csrfRe = regexp.MustCompile(`name="csrf-token" content="([^"]+)"`)

func login(t *testing.T, ts *httptest.Server, c *http.Client) string {
	t.Helper()
	res, err := c.PostForm(ts.URL+"/login", url.Values{"username": {"admin"}, "password": {"correct-horse-1"}})
	if err != nil || res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/" {
		t.Fatalf("login: %v %v", err, res.Status)
	}
	res, _ = c.Get(ts.URL + "/")
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	m := csrfRe.FindSubmatch(body)
	if res.StatusCode != 200 || m == nil {
		t.Fatalf("dashboard %d", res.StatusCode)
	}
	return string(m[1])
}

func TestSecurityHeadersAndAuthRedirect(t *testing.T) {
	ts, _ := newTestServer(t)
	res, err := client().Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/login" {
		t.Fatalf("unauth status %d", res.StatusCode)
	}
	csp := res.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe") {
		t.Fatalf("csp %q", csp)
	}
	if res.Header.Get("X-Frame-Options") != "DENY" {
		t.Fatal("no XFO")
	}
}

func TestLoginCSRFAndPages(t *testing.T) {
	ts, _ := newTestServer(t)
	c := client()
	csrf := login(t, ts, c)

	for _, p := range []string{"/logs/activity", "/logs/jobs", "/logs/system", "/settings/security", "/healthz"} {
		res, _ := c.Get(ts.URL + p)
		if res.StatusCode != 200 {
			t.Fatalf("%s → %d", p, res.StatusCode)
		}
		res.Body.Close()
	}

	// POST without token is rejected.
	res, _ := c.PostForm(ts.URL+"/logs/selftest", nil)
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("no-csrf status %d", res.StatusCode)
	}
	// Cross-site POST with a valid token is rejected too.
	req, _ := http.NewRequest("POST", ts.URL+"/logs/selftest", nil)
	req.Header.Set("X-CSRF-Token", csrf)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	res, _ = c.Do(req)
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site status %d", res.StatusCode)
	}
	// Valid request starts a job.
	req, _ = http.NewRequest("POST", ts.URL+"/logs/selftest", nil)
	req.Header.Set("X-CSRF-Token", csrf)
	res, _ = c.Do(req)
	loc := res.Header.Get("HX-Redirect")
	if res.StatusCode != http.StatusNoContent || !strings.HasPrefix(loc, "/logs/jobs/") {
		t.Fatalf("selftest %d %q", res.StatusCode, loc)
	}

	// Stream the job via SSE until "done".
	sc := &http.Client{Jar: c.Jar, Timeout: 15 * time.Second}
	res, err := sc.Get(ts.URL + loc + "/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var got []string
	r := bufio.NewScanner(res.Body)
	for r.Scan() {
		got = append(got, r.Text())
		if r.Text() == "event: done" {
			break
		}
	}
	all := strings.Join(got, "\n")
	if !strings.Contains(all, "[DRY-RUN] sudo -n") || !strings.Contains(all, "Adım 5/5") || !strings.Contains(all, "event: done") {
		t.Fatalf("stream:\n%s", all)
	}
	// Job detail page and activity detail render.
	res2, _ := c.Get(ts.URL + loc)
	if res2.StatusCode != 200 {
		t.Fatalf("job page %d", res2.StatusCode)
	}
}

func TestLoginRateLimit(t *testing.T) {
	ts, s := newTestServer(t)
	c := client()
	for i := 0; i < auth.MaxFailures; i++ {
		res, _ := c.PostForm(ts.URL+"/login", url.Values{"username": {"admin"}, "password": {"nope"}})
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d → %d", i, res.StatusCode)
		}
	}
	res, _ := c.PostForm(ts.URL+"/login", url.Values{"username": {"admin"}, "password": {"correct-horse-1"}})
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", res.StatusCode)
	}
	lines, _ := logs.TailLines(s.Cfg.AuthLogPath(), 10)
	if len(lines) < auth.MaxFailures || !strings.Contains(lines[0], "login failed ip=127.0.0.1") {
		t.Fatalf("auth log %q", lines)
	}
}

func TestAllowlist(t *testing.T) {
	p, err := parseAllowlist("203.0.113.0/24\n198.51.100.7")
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{"203.0.113.9": true, "198.51.100.7": true, "198.51.100.8": false, "127.0.0.1": true, "::1": true}
	for ip, want := range cases {
		if allowed(p, ip) != want {
			t.Errorf("%s: want %v", ip, want)
		}
	}
	if !allowed(nil, "1.2.3.4") {
		t.Error("empty list must allow all")
	}
}

func TestTwoFactorWebFlow(t *testing.T) {
	ts, _ := newTestServer(t)
	c := client()
	csrf := login(t, ts, c)
	post := func(path string, v url.Values) (*http.Response, string) {
		v.Set("_csrf", csrf)
		res, err := c.PostForm(ts.URL+path, v)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		return res, string(b)
	}
	_, body := post("/settings/2fa/start", url.Values{})
	if !strings.Contains(body, `src="data:image/png;base64,`) {
		t.Fatal("QR image not rendered")
	}
	secret := regexp.MustCompile(`Elle giriş: <code>([A-Z2-7]+)</code>`).FindStringSubmatch(body)
	sealed := regexp.MustCompile(`name="sealed" value="([^"]+)"`).FindStringSubmatch(body)
	if secret == nil || sealed == nil {
		t.Fatal("setup fields missing")
	}
	code := func(at time.Time) string {
		c, _ := totp.GenerateCodeCustom(secret[1], at, totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		return c
	}
	sealedVal := strings.ReplaceAll(sealed[1], "&#43;", "+")
	_, body = post("/settings/2fa/enable", url.Values{"sealed": {sealedVal}, "code": {code(time.Now().Add(-30 * time.Second))}})
	if !strings.Contains(body, "İki adımlı doğrulama etkin") {
		t.Fatalf("enable failed: %s", regexp.MustCompile(`alert err">[^<]*`).FindString(body))
	}
	post("/logout", url.Values{})

	// Password alone now yields the MFA stage, which cannot reach the dashboard.
	res, _ := c.PostForm(ts.URL+"/login", url.Values{"username": {"admin"}, "password": {"correct-horse-1"}})
	if res.Header.Get("Location") != "/login/2fa" {
		t.Fatalf("expected 2fa redirect, got %q", res.Header.Get("Location"))
	}
	res, _ = c.Get(ts.URL + "/")
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("mfa-stage session reached dashboard: %d", res.StatusCode)
	}
	res, _ = c.Get(ts.URL + "/login/2fa")
	b, _ := io.ReadAll(res.Body)
	m := regexp.MustCompile(`name="_csrf" value="([^"]+)"`).FindSubmatch(b)
	res, _ = c.PostForm(ts.URL+"/login/2fa", url.Values{"_csrf": {string(m[1])}, "code": {code(time.Now())}})
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/" {
		t.Fatalf("2fa submit %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	res, _ = c.Get(ts.URL + "/")
	if res.StatusCode != 200 {
		t.Fatalf("dashboard after 2fa %d", res.StatusCode)
	}
}

var testLogOut io.Writer = io.Discard
