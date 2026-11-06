package sites

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/zahit5834/hostpanel/internal/exec"
	"github.com/zahit5834/hostpanel/internal/jobs"
	"github.com/zahit5834/hostpanel/internal/runtimes"
)

func TestPHPSiteLifecycle(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	// fake=true: PHP 8.3 (static source list) counts as installed.
	e.svc.Runtimes, _ = runtimes.Load("../../deploy/runtimes", &exec.DryRun{}, true)
	site, jobID, err := e.svc.Create(ctx, CreateInput{CustomerID: e.cust, Domain: "php-site.com", RuntimeID: "php", RuntimeVersion: "8.3",
		MemoryMaxMB: 512, CPUQuotaPct: 100, Fields: map[string]string{"docroot": "public", "maxChildren": "8"}, PersistentDirs: "public/uploads storage"})
	if err != nil {
		t.Fatal(err)
	}
	if j := wait(t, e.jobs, jobID); j.Status != jobs.StatusSuccess {
		t.Fatalf("create: %+v", j)
	}
	calls := strings.Join(e.run.list(), "\n")
	for _, w := range []string{
		"hp-site-env.sh write php-site.com",
		"hp-php-pool.sh install php-site.com php_site_com 256 8 50",
		"hp-site-unit.sh install php-site.com php_site_com php-fpm.service.tpl 512 100 -- /usr/sbin/php-fpm8.3 --nodaemonize --fpm-config=/etc/hostpanel/php/php-site.com.conf",
	} {
		if !strings.Contains(calls, w) {
			t.Fatalf("missing %q in:\n%s", w, calls)
		}
	}
	site, _ = e.svc.Store.Get(ctx, site.ID)
	if site.Port != 0 {
		t.Fatalf("PHP site got a port: %d", site.Port)
	}

	// nginx config: socket of this site, docroot, uploads without PHP, no include.
	prov, _ := e.svc.Runtimes.Get("php")
	conf, err := RenderNginx(templatesDir, prov.Def().NginxTemplate, NginxDataFor(site, prov.Def(), ModeApp, templatesDir))
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{
		"root /var/www/sites/php-site.com/current/public;",
		"fastcgi_pass unix:/var/www/sites/php-site.com/run/php.sock;",
		"try_files $uri $uri/ /index.php$is_args$args;",
		"location ^~ /uploads/ {",
		"fastcgi_param SCRIPT_FILENAME $realpath_root$fastcgi_script_name;",
	} {
		if !strings.Contains(conf, w) {
			t.Fatalf("missing %q in:\n%s", w, conf)
		}
	}
	if strings.Contains(conf, "include") || strings.Contains(conf, "/storage/") {
		t.Fatalf("unexpected include / non-web persistent dir:\n%s", conf)
	}
	if err := ValidateConf(strings.ReplaceAll(conf, "php-site.com/run", "baska.com/run"), "php-site.com"); err == nil {
		t.Fatal("another site's socket accepted")
	}
	if err := ValidateSnippet("location /x { fastcgi_pass unix:/var/www/sites/php-site.com/run/php.sock; }", "php-site.com"); err == nil {
		t.Fatal("fastcgi_pass accepted in snippet")
	}

	// Deploy: restart of the php-fpm unit, no HTTP health check on a port.
	name, size, _ := e.svc.SaveUpload(strings.NewReader("PK\x03\x04zip"), 1<<20)
	e.run.calls = nil
	jid, _ := e.svc.StartDeploy(ctx, site, name, size, "")
	if j := wait(t, e.jobs, jid); j.Status != jobs.StatusSuccess {
		t.Fatalf("deploy: %+v", j)
	}
	if calls := strings.Join(e.run.list(), "\n"); !strings.Contains(calls, "hp-site-service.sh restart php_site_com") {
		t.Fatalf("deploy calls:\n%s", calls)
	}

	// Settings: max_children change rewrites the pool and the unit.
	site, _ = e.svc.Store.Get(ctx, site.ID)
	e.run.calls = nil
	fields := map[string]string{"docroot": "public", "maxChildren": "12"}
	res, err := e.svc.UpdateSettings(ctx, site, SettingsInput{WWWMode: site.WWWMode, RuntimeVersion: "8.3", Fields: fields,
		MemoryMaxMB: 512, CPUQuotaPct: 100, PersistentDirs: "public/uploads storage", MaxUploadMB: 50, HealthPath: "/"})
	if err != nil || !res.UnitChanged {
		t.Fatalf("%+v %v", res, err)
	}
	if calls := strings.Join(e.run.list(), "\n"); !strings.Contains(calls, "hp-php-pool.sh install php-site.com php_site_com 256 12 50") {
		t.Fatalf("settings calls:\n%s", calls)
	}

	// Delete removes pool, git key and stops crons.
	e.run.calls = nil
	jid, _ = e.svc.StartDelete(ctx, site, false)
	if j := wait(t, e.jobs, jid); j.Status != jobs.StatusSuccess {
		t.Fatalf("delete: %+v", j)
	}
	calls = strings.Join(e.run.list(), "\n")
	for _, w := range []string{"hp-site-cron.sh stop-all php_site_com", "hp-php-pool.sh remove php-site.com", "hp-site-git.sh remove php-site.com", "hp-site-unit.sh remove php_site_com"} {
		if !strings.Contains(calls, w) {
			t.Fatalf("missing %q in:\n%s", w, calls)
		}
	}
}

func TestGitValidation(t *testing.T) {
	for _, u := range []string{"git@github.com:acme/app.git", "ssh://git@gitlab.example.com:2222/acme/app.git", "https://github.com/acme/app", "deploy@git.ornek.com.tr:repos/app"} {
		if !ValidGitURL(u) {
			t.Errorf("rejected %s", u)
		}
	}
	for _, u := range []string{"", "file:///etc", "ext::sh -c id", "-oProxyCommand=x", "git@-host:x", "https://user:pw@github.com/a/b",
		"https://github.com/../x", "git@github.com:-x", "git@github.com:a b", "http://github.com/a/b", "git@github.com:a;b", "ssh://h/$(id)"} {
		if ValidGitURL(u) {
			t.Errorf("accepted %s", u)
		}
	}
	for _, b := range []string{"main", "release/1.2", "feature_x-y"} {
		if !ValidBranch(b) {
			t.Errorf("rejected branch %s", b)
		}
	}
	for _, b := range []string{"", "-f", "a..b", "a//b", "a/", "a.lock", "a/.b", "x y", "a~1", "a^", "@{-1}"} {
		if ValidBranch(b) {
			t.Errorf("accepted branch %s", b)
		}
	}
	if !ValidOutputDir(".") || !ValidOutputDir("dist/web") || ValidOutputDir("../x") || ValidOutputDir("/abs") || ValidOutputDir(".git") {
		t.Fatal("ValidOutputDir")
	}
	g := GitSettings{RepoURL: "git@github.com:a/b.git", Branch: "main", BuildCommand: "npm ci\nrm -rf /"}
	if err := g.Validate(); err == nil {
		t.Fatal("multi-line build command accepted")
	}
}

func TestGitDeploy(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	site, jobID, _ := e.svc.Create(ctx, CreateInput{CustomerID: e.cust, Domain: "git.com", RuntimeID: "static",
		MemoryMaxMB: 512, CPUQuotaPct: 100, Fields: map[string]string{}, PersistentDirs: "uploads"})
	wait(t, e.jobs, jobID)
	site, _ = e.svc.Store.Get(ctx, site.ID)
	if _, err := e.svc.StartGitDeploy(ctx, site); err == nil {
		t.Fatal("deploy without settings")
	}
	e.run.out = map[string]string{
		"hp-site-git.sh keygen": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample hostpanel-deploy@git.com\n",
		"hp-site-git.sh fetch":  "[hp-site-git.sh] fetch\ncommit=0123456789abcdef0123456789abcdef01234567\nsubject=İlk sürüm\n",
	}
	g, err := e.svc.SaveGit(ctx, site, GitSettings{RepoURL: "git@github.com:acme/site.git", Branch: "main",
		BuildCommand: "npm ci && npm run build", OutputDir: "dist/"})
	if err != nil || !strings.HasPrefix(g.PublicKey, "ssh-ed25519 ") || g.OutputDir != "dist" {
		t.Fatalf("%+v %v", g, err)
	}
	e.run.calls = nil
	jid, err := e.svc.StartGitDeploy(ctx, site)
	if err != nil {
		t.Fatal(err)
	}
	if j := wait(t, e.jobs, jid); j.Status != jobs.StatusSuccess {
		log, _ := os.ReadFile(e.jobs.LogPath(jid))
		t.Fatalf("git deploy: %+v\n%s", j, log)
	}
	calls := e.run.list()
	order := []string{"hp-site-git.sh fetch git.com site_git_com main ", "hp-site-git.sh build git.com site_git_com ",
		"hp-site-git.sh release git.com site_git_com ", "hp-site-deploy.sh activate git.com "}
	i := 0
	for _, c := range calls {
		if i < len(order) && strings.HasPrefix(c, order[i]) {
			i++
		}
	}
	if i != len(order) {
		t.Fatalf("calls:\n%s", strings.Join(calls, "\n"))
	}
	for _, c := range calls {
		if strings.HasPrefix(c, "hp-site-git.sh build") && !strings.HasSuffix(c, " static - 900 1024 100") {
			t.Fatalf("build args: %s", c)
		}
		if strings.HasPrefix(c, "hp-site-git.sh release") && !strings.HasSuffix(c, " dist uploads") {
			t.Fatalf("release args: %s", c)
		}
	}
	rels, _ := e.svc.Store.Releases(ctx, site.ID)
	if rels[0].Source != SourceGit || rels[0].ShortCommit() != "0123456" || rels[0].Status != ReleaseActive {
		t.Fatalf("%+v", rels[0])
	}
	g, _ = e.svc.Store.Git(ctx, site.ID)
	if g.LastSubject != "İlk sürüm" {
		t.Fatalf("%+v", g)
	}

	// A failing build cleans up and marks the release failed; the old one stays active.
	e.run.failOn = "hp-site-git.sh build"
	e.run.calls = nil
	jid, _ = e.svc.StartGitDeploy(ctx, site)
	if j := wait(t, e.jobs, jid); j.Status != jobs.StatusFailed {
		t.Fatalf("%+v", j)
	}
	if calls := strings.Join(e.run.list(), "\n"); !strings.Contains(calls, "hp-site-git.sh clean git.com ") || strings.Contains(calls, "activate") {
		t.Fatalf("calls:\n%s", calls)
	}
	if e.svc.Store.ActiveRelease(ctx, site.ID) != rels[0].Name {
		t.Fatal("active release changed after failed build")
	}
}

func TestGitDotnetNeedsSDK(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	site := Site{ID: 1, Domain: "net.com", RuntimeID: "dotnet", RuntimeVersion: "10.0.14", Status: StatusRunning}
	g := GitSettings{RepoURL: "https://github.com/a/b", Branch: "main", BuildCommand: "dotnet publish -c Release -o .hp-out"}
	if err := e.svc.gitPreflight(ctx, site, g); err == nil || !strings.Contains(err.Error(), "SDK") {
		t.Fatalf("%v", err)
	}
	g.BuildCommand = ""
	if err := e.svc.gitPreflight(ctx, site, g); err != nil {
		t.Fatal(err)
	}
}
