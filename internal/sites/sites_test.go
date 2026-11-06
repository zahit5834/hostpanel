package sites

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"hostpanel/internal/crypto"
	"hostpanel/internal/customers"
	"hostpanel/internal/exec"
	"hostpanel/internal/jobs"
	"hostpanel/internal/logs"
	"hostpanel/internal/runtimes"
	"hostpanel/internal/store"
)

const templatesDir = "../../deploy/templates"

func TestDomainAndNames(t *testing.T) {
	for d, want := range map[string]bool{"ornek.com": true, "a.b.com.tr": true, "Ornek.com": false, "ornek": false, "-a.com": false, "a_b.com": false} {
		if ValidDomain(d) != want {
			t.Errorf("%s: want %v", d, want)
		}
	}
	if n := NormalizeDomain(" HTTPS://Ornek.com:443/x "); n != "ornek.com" {
		t.Fatal(n)
	}
	al, err := ParseAliases("www.ornek.com, shop.ornek.com\nornek.net ornek.com", "ornek.com")
	if err != nil || strings.Join(al, ",") != "shop.ornek.com,ornek.net" {
		t.Fatalf("%v %v", al, err)
	}
	if _, err := ParseAliases("bad_alias", "ornek.com"); err == nil {
		t.Fatal("bad alias accepted")
	}
	if s := BaseShortName("www.ornek-site.com.tr"); s != "ornek_site_com_tr" {
		t.Fatal(s)
	}
	if s := BaseShortName("123.com"); s != "s123_com" {
		t.Fatal(s)
	}
	long := BaseShortName("averyveryverylongdomainname.example.com")
	if len(long) > MaxShortName {
		t.Fatal(long)
	}
	taken := map[string]bool{"ornek_com": true, "ornek_com_2": true}
	if s := UniqueShortName("ornek.com", func(n string) bool { return taken[n] }); s != "ornek_com_3" {
		t.Fatal(s)
	}
	if _, err := ParsePersistentDirs("wwwroot/uploads, App_Data"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"../x", ".env", "a/../b"} {
		if _, err := ParsePersistentDirs(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestFreePortSkipsUsed(t *testing.T) {
	used := map[int]bool{5000: true, 5001: true}
	p, err := FreePort(used)
	if err != nil || p < 5002 || p > PortMax {
		t.Fatalf("%d %v", p, err)
	}
}

// The Go validator must reject exactly what the bash one rejects.
func TestValidateConfMatchesBashTestdata(t *testing.T) {
	f, err := os.Open("../../deploy/scripts/testdata_nginx_bad.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if err := ValidateConf(sc.Text()+"\n", "ornek.com"); err == nil {
			t.Errorf("accepted: %s", sc.Text())
		}
	}
	if err := ValidateSnippet("location /api { proxy_read_timeout 600s; }", "ornek.com"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSnippet("access_log off;", "ornek.com"); err == nil {
		t.Fatal("log directive accepted in snippet")
	}
	if err := ValidateSnippet("location / {", "ornek.com"); err == nil {
		t.Fatal("unbalanced braces accepted")
	}
}

func loadRegistry(t *testing.T) *runtimes.Registry {
	r, err := runtimes.Load("../../deploy/runtimes", &exec.DryRun{}, false)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRenderNginxModes(t *testing.T) {
	reg := loadRegistry(t)
	dotnet, _ := reg.Get("dotnet")
	static, _ := reg.Get("static")
	site := Site{Domain: "ornek.com", Port: 5003, WWWMode: WWWToWWW, Aliases: []string{"shop.ornek.com"}, MaxUploadMB: 50, Gzip: true,
		CustomSnippet: "location /hub { proxy_read_timeout 1h; }", Fields: map[string]string{}}
	conf, err := RenderNginx(templatesDir, "proxy.conf.tpl", NginxDataFor(site, dotnet.Def(), ModeApp, "/opt/hostpanel/templates"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"server_name ornek.com;", "return 301 $scheme://www.ornek.com$request_uri;",
		"server_name www.ornek.com shop.ornek.com;", "proxy_pass http://127.0.0.1:5003;",
		"access_log /var/log/nginx/hp-ornek.com.access.log;", "client_max_body_size 50m;", "gzip on;",
		"/.well-known/acme-challenge/", "location /hub { proxy_read_timeout 1h; }", "alias /opt/hostpanel/templates/pages/;",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("missing %q in:\n%s", want, conf)
		}
	}
	stopped, _ := RenderNginx(templatesDir, "proxy.conf.tpl", NginxDataFor(site, dotnet.Def(), ModeStopped, "/opt/hostpanel/templates"))
	if !strings.Contains(stopped, "return 503;") || strings.Contains(stopped, "proxy_pass") {
		t.Fatalf("stopped mode:\n%s", stopped)
	}
	disabled, _ := RenderNginx(templatesDir, "proxy.conf.tpl", NginxDataFor(site, dotnet.Def(), ModeDisabled, "/opt/hostpanel/templates"))
	if !strings.Contains(disabled, "/__hostpanel/disabled.html") {
		t.Fatal("disabled page missing")
	}
	ph, _ := RenderNginx(templatesDir, "proxy.conf.tpl", NginxDataFor(site, dotnet.Def(), ModePlaceholder, "/opt/hostpanel/templates"))
	if !strings.Contains(ph, "root /var/www/sites/ornek.com/current;") {
		t.Fatalf("placeholder:\n%s", ph)
	}
	site.Fields = map[string]string{"index": "index.html", "spa": "evet"}
	site.WWWMode = WWWNone
	st, err := RenderNginx(templatesDir, "static.conf.tpl", NginxDataFor(site, static.Def(), ModeApp, "/opt/hostpanel/templates"))
	if err != nil || !strings.Contains(st, "try_files $uri $uri/ /index.html;") || !strings.Contains(st, "server_name ornek.com www.ornek.com shop.ornek.com;") {
		t.Fatalf("%v\n%s", err, st)
	}
	// A snippet that sneaks in a log directive fails the full-config check.
	site.CustomSnippet = "error_log /etc/cron.d/x;"
	if _, err := RenderNginx(templatesDir, "static.conf.tpl", NginxDataFor(site, static.Def(), ModeApp, "/opt/hostpanel/templates")); err == nil {
		t.Fatal("bad snippet rendered")
	}
}

func TestRenderNginxTLS(t *testing.T) {
	reg := loadRegistry(t)
	dotnet, _ := reg.Get("dotnet")
	site := Site{Domain: "ornek.com", Port: 5003, WWWMode: WWWToApex, MaxUploadMB: 50, HSTS: true, Fields: map[string]string{}}
	d := NginxDataFor(site, dotnet.Def(), ModeApp, "/opt/hostpanel/templates")
	d.ProbeToken = "0123456789abcdef0123456789abcdef"

	// HSTS/force_https are ignored without a certificate.
	conf, err := RenderNginx(templatesDir, "proxy.conf.tpl", d)
	if err != nil || strings.Contains(conf, "443") || strings.Contains(conf, "Strict-Transport") || !strings.Contains(conf, `return 200 "0123456789abcdef0123456789abcdef";`) {
		t.Fatalf("no TLS: %v\n%s", err, conf)
	}

	// Certificate without force_https: one server block on 80 + 443.
	d.TLS = &TLSPaths{Cert: "/etc/letsencrypt/live/ornek.com/fullchain.pem", Key: "/etc/letsencrypt/live/ornek.com/privkey.pem", Names: []string{"ornek.com", "www.ornek.com"}}
	conf, err = RenderNginx(templatesDir, "proxy.conf.tpl", d)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"listen 80;", "listen 443 ssl http2;", "ssl_certificate /etc/letsencrypt/live/ornek.com/fullchain.pem;",
		"ssl_protocols TLSv1.2 TLSv1.3;", `Strict-Transport-Security "max-age=31536000" always;`, "return 301 $scheme://ornek.com$request_uri;"} {
		if !strings.Contains(conf, want) {
			t.Errorf("missing %q in:\n%s", want, conf)
		}
	}
	// The www redirect server is covered by the certificate, so it listens on 443 too.
	if strings.Count(conf, "listen 443 ssl http2;") != 2 {
		t.Errorf("expected 2 TLS server blocks:\n%s", conf)
	}

	// force_https: port 80 only redirects (ACME + probe excepted).
	site.ForceHTTPS = true
	d.ForceHTTPS = true
	conf, err = RenderNginx(templatesDir, "proxy.conf.tpl", d)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"return 301 https://$host$request_uri;", "return 301 https://ornek.com$request_uri;"} {
		if !strings.Contains(conf, want) {
			t.Errorf("missing %q in:\n%s", want, conf)
		}
	}
	main := conf[strings.LastIndex(conf, "server {"):]
	if strings.Contains(main, "listen 80;") || !strings.Contains(main, "proxy_pass") {
		t.Errorf("main server must be 443-only:\n%s", main)
	}
	if strings.Count(conf, "/.well-known/acme-challenge/") != 3 {
		t.Errorf("ACME location must exist in every port-80 block:\n%s", conf)
	}
	// Maintenance page keeps HSTS despite its own add_header.
	d.Mode = ModeMaintenance
	conf, _ = RenderNginx(templatesDir, "proxy.conf.tpl", d)
	loc := conf[strings.Index(conf, "add_header Retry-After"):]
	if !strings.Contains(loc, "Strict-Transport-Security") {
		t.Errorf("HSTS missing in 503 location:\n%s", conf)
	}
	// A certificate path outside the site's own directories never renders.
	d.TLS.Key = "/etc/letsencrypt/live/baska.com/privkey.pem"
	if _, err := RenderNginx(templatesDir, "proxy.conf.tpl", d); err == nil {
		t.Fatal("foreign key path rendered")
	}
	if err := ValidateSnippet("ssl_certificate /etc/letsencrypt/live/ornek.com/fullchain.pem;", "ornek.com"); err == nil {
		t.Fatal("ssl directive accepted in snippet")
	}
}

func TestEnvDiffHidesValues(t *testing.T) {
	d := envDiff(map[string]string{"A": "1", "B": "secret-old"}, map[string]string{"B": "secret-new", "C": "x"})
	if strings.Contains(d, "secret") || !strings.Contains(d, "- A") || !strings.Contains(d, "+ C=***") {
		t.Fatal(d)
	}
}

// recRunner records helper invocations and can fail a given script/action.
type recRunner struct {
	mu     sync.Mutex
	calls  []string
	failOn string            // "script action" prefix
	out    map[string]string // "script action" prefix → stdout
}

func (r *recRunner) Run(ctx context.Context, c exec.Cmd) (exec.Result, error) {
	args := c.Args
	if c.Name == "sudo" && len(args) > 1 {
		args = append([]string{filepath.Base(args[1])}, args[2:]...)
	}
	call := strings.Join(args, " ")
	r.mu.Lock()
	r.calls = append(r.calls, call)
	r.mu.Unlock()
	if c.Stdin != nil {
		io.Copy(io.Discard, c.Stdin)
	}
	if r.failOn != "" && strings.HasPrefix(call, r.failOn) {
		return exec.Result{ExitCode: 1}, errors.New("simulated failure")
	}
	for prefix, out := range r.out {
		if strings.HasPrefix(call, prefix) {
			if c.Output != nil {
				io.WriteString(c.Output, out)
			}
			return exec.Result{Stdout: out}, nil
		}
	}
	return exec.Result{}, nil
}

func (r *recRunner) list() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

type env struct {
	svc  *Service
	run  *recRunner
	jobs *jobs.Manager
	cust int64
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	store.Migrate(ctx, db)
	key, _ := crypto.LoadKey(filepath.Join(dir, "k"), true, true)
	box, _ := crypto.New(key)
	act := logs.NewActivity(db)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	jm := jobs.NewManager(db, filepath.Join(dir, "jobs"), act, jobs.NewBroker(), log)
	run := &recRunner{}
	// fake=true: pretend the available versions are installed (no network in tests → use a stub list).
	reg, _ := runtimes.Load("../../deploy/runtimes", &exec.DryRun{}, false)
	svc := &Service{Store: NewStore(db), Box: box, Runner: run, Probe: run, Runtimes: reg, Jobs: jm, Activity: act, Log: log,
		ScriptsDir: "/opt/hostpanel/scripts", TemplatesDir: templatesDir, UploadDir: filepath.Join(dir, "uploads"), DryRun: true}
	svc.Register()
	jm.Start(ctx, 1)
	c := &customers.Customer{Name: "Test"}
	customers.New(db).Create(ctx, c)
	return &env{svc: svc, run: run, jobs: jm, cust: c.ID}
}

func wait(t *testing.T, jm *jobs.Manager, id int64) jobs.Job {
	t.Helper()
	for i := 0; i < 500; i++ {
		j, _ := jm.Get(context.Background(), id)
		if j.Done() && !jm.IsActive(id) {
			return j
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("job timeout")
	return jobs.Job{}
}

func TestCreateStaticDeployRollbackDelete(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	site, jobID, err := e.svc.Create(ctx, CreateInput{CustomerID: e.cust, Domain: "Ornek.com", RuntimeID: "static",
		MemoryMaxMB: 512, CPUQuotaPct: 100, Fields: map[string]string{}, PersistentDirs: "uploads"})
	if err != nil {
		t.Fatal(err)
	}
	if j := wait(t, e.jobs, jobID); j.Status != jobs.StatusSuccess {
		t.Fatalf("create: %+v", j)
	}
	want := []string{
		"hp-site-user.sh create site_ornek_com ornek.com",
		"hp-site-dirs.sh create ornek.com site_ornek_com",
		"hp-nginx-site.sh install ornek.com",
	}
	if got := e.run.list(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("create calls:\n%s", strings.Join(got, "\n"))
	}
	site, _ = e.svc.Store.Get(ctx, site.ID)
	if site.Status != StatusAwaitingDeploy || site.Port != 0 {
		t.Fatalf("%+v", site)
	}

	// Deploy a zip.
	zip := "PK\x03\x04rest-of-zip"
	name, size, err := e.svc.SaveUpload(strings.NewReader(zip), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.SaveUpload(strings.NewReader("not a zip"), 1<<20); err == nil {
		t.Fatal("non-zip accepted")
	}
	if _, _, err := e.svc.SaveUpload(strings.NewReader("PK\x03\x04"+strings.Repeat("x", 100)), 50); err == nil {
		t.Fatal("oversize accepted")
	}
	e.run.calls = nil
	jid, _ := e.svc.StartDeploy(ctx, site, name, size, "")
	if j := wait(t, e.jobs, jid); j.Status != jobs.StatusSuccess {
		t.Fatalf("deploy: %+v", j)
	}
	calls := strings.Join(e.run.list(), "\n")
	if !strings.Contains(calls, "hp-site-deploy.sh extract ornek.com site_ornek_com") || !strings.Contains(calls, " uploads") ||
		!strings.Contains(calls, "hp-site-deploy.sh activate ornek.com") || !strings.Contains(calls, "hp-site-deploy.sh prune ornek.com 5") {
		t.Fatalf("deploy calls:\n%s", calls)
	}
	if strings.Contains(calls, "hp-site-service.sh") {
		t.Fatal("static site must not touch systemd")
	}
	if _, err := os.Stat(filepath.Join(e.svc.UploadDir, name)); !os.IsNotExist(err) {
		t.Fatal("upload not cleaned up")
	}
	site, _ = e.svc.Store.Get(ctx, site.ID)
	if site.Status != StatusRunning {
		t.Fatalf("status %s", site.Status)
	}
	rels, _ := e.svc.Store.Releases(ctx, site.ID)
	if len(rels) != 2 || rels[0].Status != ReleaseActive || rels[1].Name != PlaceholderRelease {
		t.Fatalf("%+v", rels)
	}

	// Rollback to the placeholder.
	jid, _ = e.svc.StartDeploy(ctx, site, "", 0, PlaceholderRelease)
	if j := wait(t, e.jobs, jid); j.Status != jobs.StatusSuccess {
		t.Fatalf("rollback: %+v", j)
	}
	if e.svc.Store.ActiveRelease(ctx, site.ID) != PlaceholderRelease {
		t.Fatal("rollback did not switch")
	}

	// Stop → nginx 503 mode.
	if st, err := e.svc.Operate(ctx, site, OpStop); err != nil || st != StatusStopped {
		t.Fatalf("%s %v", st, err)
	}

	// Delete.
	e.run.calls = nil
	jid, _ = e.svc.StartDelete(ctx, site, false)
	if j := wait(t, e.jobs, jid); j.Status != jobs.StatusSuccess {
		t.Fatalf("delete: %+v", j)
	}
	calls = strings.Join(e.run.list(), "\n")
	for _, w := range []string{"hp-site-archive.sh ornek.com", "hp-nginx-site.sh remove ornek.com", "hp-site-dirs.sh delete ornek.com", "hp-site-user.sh delete site_ornek_com ornek.com"} {
		if !strings.Contains(calls, w) {
			t.Fatalf("missing %q in:\n%s", w, calls)
		}
	}
	if !strings.HasPrefix(calls, "hp-site-archive.sh") {
		t.Fatal("archive must run first")
	}
	if _, err := e.svc.Store.Get(ctx, site.ID); err == nil {
		t.Fatal("site row not deleted")
	}
}

func TestCreateRollsBackOnFailure(t *testing.T) {
	e := newEnv(t)
	e.run.failOn = "hp-nginx-site.sh install"
	ctx := context.Background()
	site, jobID, err := e.svc.Create(ctx, CreateInput{CustomerID: e.cust, Domain: "fail.com", RuntimeID: "static",
		MemoryMaxMB: 512, CPUQuotaPct: 100, Fields: map[string]string{}})
	if err != nil {
		t.Fatal(err)
	}
	if j := wait(t, e.jobs, jobID); j.Status != jobs.StatusFailed {
		t.Fatalf("%+v", j)
	}
	got := e.run.list()
	want := []string{
		"hp-site-user.sh create site_fail_com fail.com",
		"hp-site-dirs.sh create fail.com site_fail_com",
		"hp-nginx-site.sh install fail.com",
		"hp-site-dirs.sh delete fail.com", // undo in reverse order
		"hp-site-user.sh delete site_fail_com fail.com",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("calls:\n%s", strings.Join(got, "\n"))
	}
	if _, err := e.svc.Store.Get(ctx, site.ID); err == nil {
		t.Fatal("site row kept after failed create")
	}
}

func TestPrepareValidation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	base := CreateInput{CustomerID: e.cust, Domain: "x.com", RuntimeID: "dotnet", RuntimeVersion: "10.0.14",
		MemoryMaxMB: 512, CPUQuotaPct: 100, Fields: map[string]string{"entryPoint": "App.dll"}}
	// dotnet not installed (DryRun probe returns nothing, fake=false).
	if _, err := e.svc.Prepare(ctx, base); err == nil || !strings.Contains(err.Error(), "kurulu değil") {
		t.Fatalf("%v", err)
	}
	in := base
	in.Domain = "www.x.com"
	if _, err := e.svc.Prepare(ctx, in); err == nil {
		t.Fatal("www domain accepted")
	}
	in = base
	in.RuntimeID, in.MemoryMaxMB = "static", 10
	if _, err := e.svc.Prepare(ctx, in); err == nil {
		t.Fatal("tiny memory accepted")
	}
}

type stdoutRunner struct{ out string }

func (s stdoutRunner) Run(ctx context.Context, c exec.Cmd) (exec.Result, error) {
	return exec.Result{Stdout: s.out}, nil
}

func TestCreateDotnetAndDeployRevert(t *testing.T) {
	e := newEnv(t)
	reg, _ := runtimes.Load("../../deploy/runtimes", stdoutRunner{out: "Microsoft.AspNetCore.App 10.0.14 [/usr/share/dotnet/shared/Microsoft.AspNetCore.App]\n"}, false)
	e.svc.Runtimes = reg
	ctx := context.Background()
	site, jobID, err := e.svc.Create(ctx, CreateInput{CustomerID: e.cust, Domain: "api.ornek.com", RuntimeID: "dotnet", RuntimeVersion: "10.0.14",
		MemoryMaxMB: 768, CPUQuotaPct: 150, Fields: map[string]string{"entryPoint": "Api.dll"}})
	if err != nil {
		t.Fatal(err)
	}
	if j := wait(t, e.jobs, jobID); j.Status != jobs.StatusSuccess {
		t.Fatalf("%+v", j)
	}
	calls := strings.Join(e.run.list(), "\n")
	unit := "hp-site-unit.sh install api.ornek.com api_ornek_com proxy-service.service.tpl 768 150 -- /usr/share/dotnet/dotnet Api.dll"
	if !strings.Contains(calls, unit) || !strings.Contains(calls, "hp-site-env.sh write api.ornek.com") {
		t.Fatalf("calls:\n%s", calls)
	}
	site, _ = e.svc.Store.Get(ctx, site.ID)
	if site.Port < PortMin || site.Port > PortMax {
		t.Fatalf("port %d", site.Port)
	}

	// Env: runtime-managed keys are protected; values are sealed at rest.
	if _, err := e.svc.SaveEnv(ctx, site, map[string]string{"ASPNETCORE_URLS": "x"}); err == nil {
		t.Fatal("reserved key accepted")
	}
	if _, err := e.svc.SaveEnv(ctx, site, map[string]string{"ConnectionStrings__Default": "Server=db;Password=p\nx"}); err == nil {
		t.Fatal("multiline value accepted")
	}
	diff, err := e.svc.SaveEnv(ctx, site, map[string]string{"ConnectionStrings__Default": "Server=db;Password=p"})
	if err != nil || strings.Contains(diff, "Password") {
		t.Fatalf("%v %q", err, diff)
	}
	sealed, _ := e.svc.Store.EnvSealed(ctx, site.ID)
	if strings.Contains(sealed["ConnectionStrings__Default"], "Server") {
		t.Fatal("env stored in plaintext")
	}
	env, _ := e.svc.Env(ctx, site.ID)
	if env["ConnectionStrings__Default"] != "Server=db;Password=p" {
		t.Fatal("env round trip")
	}

	// First deploy succeeds; second fails at restart → automatic revert to the first.
	deploy := func() jobs.Job {
		name, size, err := e.svc.SaveUpload(strings.NewReader("PK\x03\x04data"), 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		jid, _ := e.svc.StartDeploy(ctx, site, name, size, "")
		return wait(t, e.jobs, jid)
	}
	if j := deploy(); j.Status != jobs.StatusSuccess {
		t.Fatalf("%+v", j)
	}
	first := e.svc.Store.ActiveRelease(ctx, site.ID)
	time.Sleep(1100 * time.Millisecond) // release names have 1 s resolution
	e.run.failOn = "hp-site-service.sh restart"
	j := deploy()
	if j.Status != jobs.StatusFailed || !strings.Contains(j.Error, "geri dönüldü") {
		t.Fatalf("%+v", j)
	}
	if got := e.svc.Store.ActiveRelease(ctx, site.ID); got != first {
		t.Fatalf("active=%s want %s", got, first)
	}
	rels, _ := e.svc.Store.Releases(ctx, site.ID)
	if rels[0].Status != ReleaseFailed {
		t.Fatalf("%+v", rels)
	}
}
