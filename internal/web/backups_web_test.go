package web

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"

	"hostpanel/internal/backups"
	"hostpanel/internal/databases"
	"hostpanel/internal/jobs"
	"hostpanel/internal/logs"
	"hostpanel/internal/sites"
)

// multipartPost sends an HTMX-style upload (CSRF header) and returns the response.
func (w webClient) multipartPost(path string, fields [][2]string, fileField, fileName string, content []byte) *http.Response {
	w.t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for _, f := range fields {
		mw.WriteField(f[0], f[1])
	}
	fw, _ := mw.CreateFormFile(fileField, fileName)
	fw.Write(content)
	mw.Close()
	req, _ := http.NewRequest("POST", w.ts.URL+path, &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-CSRF-Token", w.csrf)
	req.Header.Set("HX-Request", "true")
	res, err := w.c.Do(req)
	if err != nil {
		w.t.Fatal(err)
	}
	return res
}

func TestBackupsLifecycleDryRun(t *testing.T) {
	if os.Getenv("HP_DEBUG") != "" {
		testLogOut = os.Stderr
	}
	ts, s := newTestServer(t)
	c := client()
	w := webClient{t: t, ts: ts, c: c, csrf: login(t, ts, c)}
	ctx := context.Background()
	fake := s.DBs.Fake

	// Setup: MSSQL, one customer, two .NET sites (the first with a database and a deploy).
	mustJob(t, s, w.post("/databases/docker", nil))
	mustJob(t, s, w.post("/databases/server", url.Values{"edition": {"Express"}, "memory_mb": {"2048"}, "accept_eula": {"1"}}))
	w.post("/customers", url.Values{"name": {"Acme"}})
	for _, d := range []string{"shop.example.com", "staging.example.com"} {
		f := url.Values{"customer_id": {"1"}, "domain": {d}, "runtime": {"dotnet"}, "version": {"10.0.14"}, "field_entryPoint": {"App.dll"}}
		if d == "shop.example.com" {
			f.Set("create_db", "1")
		}
		res := w.post("/sites", f)
		waitJob(t, s, jobFromLocation(t, res.Header.Get("Location")))
	}
	latestJob(t, s, "db.create")
	shop, _ := s.Sites.Store.GetByDomain(ctx, "shop.example.com")
	staging, _ := s.Sites.Store.GetByDomain(ctx, "staging.example.com")
	shopBase := "/sites/" + strconv.FormatInt(shop.ID, 10)
	stagingBase := "/sites/" + strconv.FormatInt(staging.ID, 10)
	res := w.multipartPost(shopBase+"/deploy", nil, "zip", "site.zip", testZip(t))
	waitJob(t, s, jobFromLocation(t, res.Header.Get("HX-Redirect")))
	w.post(shopBase+"/env", url.Values{"key": {"API_TOKEN"}, "value": {"secret-123"}})
	shopDBs, _ := s.DBs.Store.Databases(ctx, databases.DBFilter{SiteID: shop.ID})
	if len(shopDBs) != 1 {
		t.Fatalf("shop dbs %+v", shopDBs)
	}

	for _, p := range []string{"/backups", "/backups?tab=plans", "/backups?tab=settings", shopBase + "?tab=backups", shopBase + "?tab=import", "/sites/new?import=1"} {
		if code, body := w.get(p, false); code != 200 {
			t.Fatalf("%s → %d\n%s", p, code, body)
		}
	}
	if _, body := w.get("/sites", false); !strings.Contains(body, "/sites/new?import=1") {
		t.Fatal("sites list misses the import entry")
	}

	// 1. rclone + Drive (OAuth) with crypt.
	if _, body := w.get("/backups?tab=settings", false); !strings.Contains(body, "rclone'u kur") {
		t.Fatal("rclone install button missing")
	}
	_, log := mustJob(t, s, w.post("/backups/rclone", nil))
	if !strings.Contains(log, "hp-backup.sh rclone-install") {
		t.Fatalf("rclone log:\n%s", log)
	}
	if res := w.post("/backups/remote", url.Values{"type": {"drive_oauth"}, "token": {"not a token"}, "crypt": {"1"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad token accepted: %d", res.StatusCode)
	}
	if res := w.post("/backups/remote", url.Values{"type": {"drive_sa"}, "sa_json": {`{"type":"service_account","client_email":"a@b","private_key":"-----BEGIN PRIVATE KEY-----"}`}}); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("service account without shared drive accepted: %d", res.StatusCode)
	}
	token := `{"access_token":"ya29.SECRETACCESS","token_type":"Bearer","refresh_token":"1//SECRETREFRESH","expiry":"2026-11-05T13:00:00Z"}`
	code, body := w.postHX("/backups/remote", url.Values{"type": {"drive_oauth"}, "token": {"Paste this:\n" + token + "\n"}, "crypt": {"1"},
		"root_folder": {"HostPanel-Backups"}, "server_name": {"srv1"}})
	keys, _ := s.Backups.CryptKeys(ctx)
	if code != 200 || keys == nil || !strings.Contains(body, keys.Password) {
		t.Fatalf("remote config %d (keys %v)", code, keys)
	}
	// Reconfiguring keeps the keys (older backups stay readable).
	w.post("/backups/remote", url.Values{"type": {"drive_oauth"}, "token": {token}, "crypt": {"1"}, "server_name": {"srv1"}})
	if k2, _ := s.Backups.CryptKeys(ctx); k2 == nil || k2.Password != keys.Password {
		t.Fatal("crypt keys changed on reconfigure")
	}
	entries, _ := s.Activity.Query(ctx, logs.Filter{Action: "exec.dryrun", Limit: 500})
	sawConfig := false
	for _, e := range entries {
		for _, secret := range []string{"SECRETACCESS", "SECRETREFRESH", keys.Password, keys.Salt} {
			if strings.Contains(e.Summary, secret) {
				t.Fatalf("secret in command log: %s", e.Summary)
			}
		}
		if strings.Contains(e.Summary, "hp-backup.sh remote-config drive-oauth HostPanel-Backups 1 -") {
			sawConfig = true
		}
	}
	if !sawConfig {
		t.Fatal("remote-config helper not called")
	}
	if code, body = w.postHX("/backups/remote/keys", nil); code != 200 || !strings.Contains(body, keys.Salt) {
		t.Fatalf("reveal keys %d", code)
	}
	if e, _ := s.Activity.Query(ctx, logs.Filter{Action: "backup.crypt.reveal", Limit: 1}); len(e) != 1 {
		t.Fatal("key reveal not logged")
	}
	_, log = mustJob(t, s, w.post("/backups/remote/test", nil))
	if !strings.Contains(log, "hp-backup.sh remote-test srv1") {
		t.Fatalf("remote test log:\n%s", log)
	}
	if res := w.post("/backups/remote/options", url.Values{"bwlimit": {"2M"}, "server_name": {"srv1"}}); res.StatusCode != 200 {
		t.Fatalf("options %d", res.StatusCode)
	}
	if res := w.post("/backups/remote/options", url.Values{"bwlimit": {"2M --dry-run"}, "server_name": {"srv1"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad bwlimit accepted %d", res.StatusCode)
	}

	// 2. Manual backup → Drive.
	if res := w.post(shopBase+"/backup", url.Values{}); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("backup without components %d", res.StatusCode)
	}
	_, log = mustJob(t, s, w.post(shopBase+"/backup", url.Values{"components": {"files", "db", "config", "ssl"}, "upload": {"1"}}))
	list, _ := s.Backups.Store.Backups(ctx, backups.Filter{SiteID: shop.ID})
	if len(list) != 1 || list[0].Status != backups.StatusSuccess || !list[0].Local || !list[0].Remote || list[0].RemoteSrv != "srv1" {
		t.Fatalf("backups %+v", list)
	}
	manual := list[0]
	dbName := shopDBs[0].Name
	for _, want := range []string{
		"BACKUP DATABASE [" + dbName + "] TO DISK = '/var/opt/mssql/backup/hpbk-" + manual.Name + "-" + dbName + ".bak'",
		"hp-backup.sh create shop.example.com " + manual.Name + " files,db,config,ssl ",
		"hp-backup.sh upload srv1 shop.example.com " + manual.Name + " 2M",
	} {
		if !strings.Contains(log, want) {
			t.Errorf("backup log misses %q:\n%s", want, log)
		}
	}

	// 3. Plans: validation, two runs, retention.
	if res := w.post("/backups/plans", url.Values{"name": {"x"}, "scope": {"all"}, "components": {"files"}, "destination": {"local"},
		"keep_local": {"3"}, "kind": {"custom"}, "expr": {"@every 1m"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad cron accepted %d", res.StatusCode)
	}
	res = w.post("/backups/plans", url.Values{"name": {"Gece"}, "scope": {"sites"}, "site_ids": {strconv.FormatInt(shop.ID, 10)},
		"components": {"files", "db", "config"}, "destination": {"both"}, "keep_local": {"1"}, "keep_remote": {"1"},
		"kind": {"daily"}, "time": {"03:15"}, "enabled": {"1"}})
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("plan create %d", res.StatusCode)
	}
	plans, _ := s.Backups.Store.Plans(ctx)
	if len(plans) != 1 || plans[0].Schedule != "15 3 * * *" || plans[0].NextRunAt.IsZero() {
		t.Fatalf("plans %+v", plans)
	}
	plan := plans[0]
	if code, body := w.get("/backups?tab=plans", false); code != 200 || !strings.Contains(body, "Her gün 03:15") {
		t.Fatalf("plans tab %d", code)
	}
	runURL := "/backups/plans/" + strconv.FormatInt(plan.ID, 10) + "/run"
	mustJob(t, s, w.post(runURL, nil))
	_, log = mustJob(t, s, w.post(runURL, nil))
	planBackups, _ := s.Backups.Store.Backups(ctx, backups.Filter{PlanID: plan.ID})
	if len(planBackups) != 1 || !planBackups[0].Local || !planBackups[0].Remote {
		t.Fatalf("after retention: %+v", planBackups)
	}
	if !strings.Contains(log, "hp-backup.sh delete shop.example.com") || !strings.Contains(log, "hp-backup.sh remote-delete srv1 shop.example.com") {
		t.Fatalf("retention not applied:\n%s", log)
	}
	if list, _ := s.Backups.Store.Backups(ctx, backups.Filter{SiteID: shop.ID}); len(list) != 2 {
		t.Fatalf("manual backup must not be pruned by the plan: %d", len(list))
	}

	// 4. Restore into the same site.
	restoreURL := "/backups/" + strconv.FormatInt(manual.ID, 10) + "/restore"
	if code, body := w.get(restoreURL, false); code != 200 || !strings.Contains(body, "staging.example.com") {
		t.Fatalf("restore page %d", code)
	}
	if res := w.post(restoreURL, url.Values{"target": {strconv.FormatInt(shop.ID, 10)}, "components": {"files"}, "confirm": {"wrong"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("restore without confirmation %d", res.StatusCode)
	}
	w.post(shopBase+"/env", url.Values{"key": {"API_TOKEN"}, "value": {"changed"}})
	res = w.post(restoreURL, url.Values{"target": {strconv.FormatInt(shop.ID, 10)}, "components": {"files", "db", "config"}, "confirm": {"shop.example.com"}})
	_, log = mustJob(t, s, res)
	for _, want := range []string{
		"hp-backup.sh verify shop.example.com " + manual.Name,
		"hp-backup.sh stage-db shop.example.com " + manual.Name + " " + dbName + " hprs-" + manual.Name + "-" + dbName + ".bak",
		"RESTORE DATABASE",
		"hp-backup.sh restore-files shop.example.com " + manual.Name + " shop.example.com " + shop.User() + " ",
		"hp-site-deploy.sh activate shop.example.com",
		"hp-backup.sh unstage hprs-",
	} {
		if !strings.Contains(log, want) {
			t.Errorf("restore log misses %q:\n%s", want, log)
		}
	}
	if pre, _ := s.Backups.Store.Backups(ctx, backups.Filter{SiteID: shop.ID, Limit: 1}); len(pre) != 1 || pre[0].Kind != backups.KindPreRestore {
		t.Fatalf("no pre-restore backup: %+v", pre)
	}
	if env, _ := s.Sites.Env(ctx, shop.ID); env["API_TOKEN"] != "changed" {
		// dry-run reads the source site's current config (nothing on disk), so the value is the current one
		t.Fatalf("env after restore %q", env["API_TOKEN"])
	}

	// Crons and git settings travel in config.json (clone: crons disabled).
	if res := w.post(shopBase+"/crons", url.Values{"name": {"Temizlik"}, "schedule": {"0 3 * * *"}, "command": {"echo ok"}, "enabled": {"1"}}); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("cron save %d", res.StatusCode)
	}
	if res := w.post(shopBase+"/git", url.Values{"repo_url": {"https://github.com/acme/shop.git"}, "branch": {"main"},
		"build_command": {"dotnet publish -c Release -o hp-publish"}, "output_dir": {"hp-publish"}, "build_timeout": {"900"}}); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("git save %d", res.StatusCode)
	}
	// 5. Clone into the other site: database mapped to a new one owned by the customer, env rewritten.
	res = w.post(restoreURL, url.Values{"target": {strconv.FormatInt(staging.ID, 10)}, "components": {"files", "db", "config"}, "confirm": {"staging.example.com"}})
	_, log = mustJob(t, s, res)
	cloneDB := databases.DBBase(staging.ShortName)
	if !strings.Contains(log, dbName+" → "+cloneDB) || !strings.Contains(log, "restore-files shop.example.com "+manual.Name+" staging.example.com "+staging.User()) {
		t.Fatalf("clone log:\n%s", log)
	}
	if fake.Databases()[cloneDB] != "c_acme" {
		t.Fatalf("clone database %v", fake.Databases())
	}
	env, _ := s.Sites.Env(ctx, staging.ID)
	if !strings.Contains(env["ConnectionStrings__DefaultConnection"], "Database="+cloneDB+";") || env["API_TOKEN"] != "changed" {
		t.Fatalf("clone env %v", env)
	}
	staging, _ = s.Sites.Store.Get(ctx, staging.ID)
	if staging.Status != sites.StatusRunning || len(staging.Aliases) != 0 {
		t.Fatalf("clone site %+v", staging)
	}
	if cl, _ := s.Crons.Store.BySite(ctx, staging.ID); len(cl) != 1 || cl[0].Name != "Temizlik" || cl[0].Enabled {
		t.Fatalf("clone crons %+v", cl)
	}
	if g, err := s.Sites.Store.Git(ctx, staging.ID); err != nil || g.RepoURL != "https://github.com/acme/shop.git" || g.OutputDir != "hp-publish" {
		t.Fatalf("clone git %+v %v", g, err)
	}

	// 6. Taşıma: .bak upload and env paste.
	res = w.multipartPost(stagingBase+"/import/db", [][2]string{{"name", "legacy_db"}, {"write_env", "1"}, {"env_key", "ConnectionStrings__Legacy"}},
		"bak", "legacy.bak", []byte("TAPE fake backup"))
	if res.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("bak upload %d %s", res.StatusCode, b)
	}
	j := waitJob(t, s, jobFromLocation(t, res.Header.Get("HX-Redirect")))
	if log := jobLog(t, s, j.ID); j.Status != jobs.StatusSuccess || !strings.Contains(log, "hp-backup.sh stage-upload") {
		t.Fatalf("import job %s %s\n%s", j.Status, j.Error, log)
	}
	if fake.Databases()["legacy_db"] != "c_acme" {
		t.Fatalf("imported db %v", fake.Databases())
	}
	if env, _ := s.Sites.Env(ctx, staging.ID); !strings.Contains(env["ConnectionStrings__Legacy"], "Database=legacy_db;") {
		t.Fatalf("import env %v", env)
	}
	if res := w.multipartPost(stagingBase+"/import/db", [][2]string{{"name", "master"}}, "bak", "x.bak", []byte("x")); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("reserved db name accepted %d", res.StatusCode)
	}
	if res := w.post(stagingBase+"/import/env", url.Values{"dotenv": {"# eski sunucu\nexport SMTP_HOST=mail.example.com\nSMTP_PASS=\"p w\"\n"}}); res.StatusCode != 200 {
		t.Fatalf("env import %d", res.StatusCode)
	}
	if env, _ := s.Sites.Env(ctx, staging.ID); env["SMTP_PASS"] != "p w" || env["SMTP_HOST"] != "mail.example.com" || env["API_TOKEN"] != "changed" {
		t.Fatalf("env after import %v", env)
	}
	if res := w.post(stagingBase+"/import/env", url.Values{"dotenv": {"ASPNETCORE_URLS=http://0.0.0.0:80"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("reserved env key accepted %d", res.StatusCode)
	}

	// 7. Delete copies.
	delURL := "/backups/" + strconv.FormatInt(manual.ID, 10) + "/delete"
	mustJob(t, s, w.post(delURL, url.Values{"where": {"local"}}))
	if b, _ := s.Backups.Store.Backup(ctx, manual.ID); b.Local || !b.Remote {
		t.Fatalf("after local delete %+v", b)
	}
	mustJob(t, s, w.post(delURL, url.Values{"where": {"remote"}}))
	if _, err := s.Backups.Store.Backup(ctx, manual.ID); err == nil {
		t.Fatal("backup row kept without any copy")
	}

	// 8. Import wizard lands on the Taşıma tab.
	res = w.post("/sites", url.Values{"customer_id": {"1"}, "domain": {"moved.example.com"}, "runtime": {"static"}, "import": {"1"}})
	if res.StatusCode != http.StatusSeeOther || !strings.Contains(res.Header.Get("Location"), "tab=import") {
		t.Fatalf("import wizard redirect %d %q", res.StatusCode, res.Header.Get("Location"))
	}
}
