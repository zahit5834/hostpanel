package web

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zahit5834/hostpanel/internal/crons"
	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/sites"
)

func TestCronGitPHPDryRun(t *testing.T) {
	ts, s := newTestServer(t)
	c := client()
	w := webClient{t: t, ts: ts, c: c, csrf: login(t, ts, c)}
	ctx := context.Background()
	w.post("/customers", url.Values{"name": {"Acme"}})

	// --- PHP site through the wizard ---
	if _, body := w.get("/sites/new", false); !strings.Contains(body, `value="php"`) {
		t.Fatal("PHP not offered in the wizard")
	}
	if code, body := w.get("/sites/runtime-fields?runtime=php", true); code != 200 || !strings.Contains(body, "field_docroot") || !strings.Contains(body, `value="8.3"`) {
		t.Fatalf("php fields %d %s", code, body)
	}
	res := w.post("/sites", url.Values{"customer_id": {"1"}, "domain": {"php.example.com"}, "runtime": {"php"},
		"version": {"8.3"}, "field_docroot": {"public"}, "field_maxChildren": {"4"}})
	waitJob(t, s, jobFromLocation(t, res.Header.Get("Location")))
	site, err := s.Sites.Store.GetByDomain(ctx, "php.example.com")
	if err != nil || site.Status != sites.StatusAwaitingDeploy || site.Fields["maxChildren"] != "4" {
		t.Fatalf("%+v %v", site, err)
	}
	base := "/sites/" + strconv.FormatInt(site.ID, 10)
	res = w.multipartPost(base+"/deploy", nil, "zip", "site.zip", testZip(t))
	waitJob(t, s, jobFromLocation(t, res.Header.Get("HX-Redirect")))
	site, _ = s.Sites.Store.Get(ctx, site.ID)
	if site.Status != sites.StatusRunning {
		t.Fatalf("status %s", site.Status)
	}
	if code, body := w.get(base, false); code != 200 || !strings.Contains(body, "Ortam Değişkenleri") || !strings.Contains(body, "hp-site-") {
		t.Fatalf("site page %d", code)
	}
	if code, body := w.get(base+"?tab=settings", false); code != 200 || !strings.Contains(body, "fastcgi_pass unix:/var/www/sites/php.example.com/run/php.sock") {
		t.Fatalf("settings %d", code)
	}

	// --- runtimes page: PHP via apt, .NET SDK list ---
	if code, body := w.get("/runtimes", false); code != 200 || !strings.Contains(body, "<h2>PHP</h2>") || !strings.Contains(body, "10.0.403") {
		t.Fatalf("runtimes %d", code)
	}
	res = w.post("/runtimes/dotnet/install-sdk", url.Values{"version": {"10.0"}})
	if loc := res.Header.Get("Location"); !strings.HasPrefix(loc, "/logs/jobs/") {
		t.Fatalf("install-sdk → %d %s", res.StatusCode, loc)
	}

	// --- cron tab ---
	if code, body := w.get(base+"?tab=cron", false); code != 200 || !strings.Contains(body, "Yeni görev") {
		t.Fatalf("cron tab %d", code)
	}
	res = w.post(base+"/crons", url.Values{"name": {"Zamanlayıcı"}, "schedule": {"* * * *"}, "command": {"php artisan schedule:run"}, "enabled": {"1"}})
	if res.StatusCode != 400 {
		t.Fatalf("bad schedule accepted: %d", res.StatusCode)
	}
	res = w.post(base+"/crons", url.Values{"name": {"Zamanlayıcı"}, "schedule": {"*/5 * * * *"}, "command": {`cd current && php artisan schedule:run >> "$HOME/cron.log" 2>&1`},
		"timeout_sec": {"300"}, "enabled": {"1"}})
	if res.StatusCode != 303 {
		t.Fatalf("save cron %d", res.StatusCode)
	}
	list, _ := s.Crons.Store.BySite(ctx, site.ID)
	if len(list) != 1 || list[0].TimeoutSec != 300 || list[0].NextRunAt.IsZero() {
		t.Fatalf("%+v", list)
	}
	cid := strconv.FormatInt(list[0].ID, 10)
	if res = w.post(base+"/crons/"+cid+"/run", nil); res.StatusCode != 303 {
		t.Fatalf("run now %d", res.StatusCode)
	}
	s.Crons.Wait()
	runs, _ := s.Crons.Store.Runs(ctx, crons.RunFilter{SiteID: site.ID})
	if len(runs) != 1 || runs[0].Status != crons.StatusOK || !strings.Contains(runs[0].Output, "[DRY-RUN]") {
		t.Fatalf("%+v", runs)
	}
	if _, body := w.get(base+"?tab=cron", false); !strings.Contains(body, "5 dakikada bir") || !strings.Contains(body, "Başarılı") {
		t.Fatal("cron list")
	}
	if code, body := w.get("/logs/cron?site="+strconv.FormatInt(site.ID, 10)+"&status=ok&since="+url.QueryEscape(time.Now().Add(-time.Hour).Format("2006-01-02T15:04")), false); code != 200 ||
		!strings.Contains(body, "Zamanlayıcı") || !strings.Contains(body, "elle") {
		t.Fatalf("cron logs %d", code)
	}
	if got, _ := s.Activity.Query(ctx, logs.Filter{Action: "site.cron.create"}); len(got) != 1 || !strings.Contains(got[0].Diff, "+ zamanlama=*/5 * * * *") {
		t.Fatalf("%+v", got)
	}
	if res = w.post(base+"/crons/"+cid+"/delete", nil); res.StatusCode != 303 {
		t.Fatalf("delete %d", res.StatusCode)
	}

	// --- git deploy on a .NET site ---
	res = w.post("/sites", url.Values{"customer_id": {"1"}, "domain": {"net.example.com"}, "runtime": {"dotnet"},
		"version": {"10.0.14"}, "field_entryPoint": {"App.dll"}})
	waitJob(t, s, jobFromLocation(t, res.Header.Get("Location")))
	net, _ := s.Sites.Store.GetByDomain(ctx, "net.example.com")
	nbase := "/sites/" + strconv.FormatInt(net.ID, 10)
	if _, body := w.get(nbase+"?tab=deploy", false); !strings.Contains(body, "dotnet publish -c Release -o hp-publish") {
		t.Fatal("git defaults missing")
	}
	res = w.post(nbase+"/git", url.Values{"repo_url": {"file:///etc"}, "branch": {"main"}})
	if res.StatusCode != 400 {
		t.Fatalf("file:// accepted %d", res.StatusCode)
	}
	res = w.post(nbase+"/git", url.Values{"repo_url": {"git@github.com:acme/app.git"}, "branch": {"main"},
		"build_command": {"dotnet publish -c Release -o hp-publish"}, "output_dir": {"hp-publish"}, "build_timeout": {"900"}})
	if res.StatusCode != 303 {
		t.Fatalf("git save %d", res.StatusCode)
	}
	if _, body := w.get(nbase+"?tab=deploy", false); !strings.Contains(body, "ssh-ed25519 ") || !strings.Contains(body, "Git'ten deploy et (main)") {
		i := strings.Index(body, `id="git"`)
		t.Fatalf("deploy key / deploy button missing:\n%s", body[i:min(len(body), i+1500)])
	}
	res = w.post(nbase+"/git/deploy", nil)
	jid := jobFromLocation(t, res.Header.Get("Location"))
	waitJob(t, s, jid)
	rels, _ := s.Sites.Store.Releases(ctx, net.ID)
	if len(rels) < 2 || rels[0].Source != sites.SourceGit || rels[0].Status != sites.ReleaseActive || rels[0].ShortCommit() != "0000000" {
		t.Fatalf("%+v", rels)
	}
	if _, body := w.get(nbase+"?tab=deploy", false); !strings.Contains(body, "<code title=\"0000000000000000000000000000000000000000\">0000000</code>") {
		t.Fatal("release commit column")
	}
	if got, _ := s.Activity.Query(ctx, logs.Filter{Action: "site.git.keygen"}); len(got) != 1 {
		t.Fatalf("keygen activity %+v", got)
	}
}
