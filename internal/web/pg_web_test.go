package web

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/zahit5834/hostpanel/internal/backups"
	"github.com/zahit5834/hostpanel/internal/jobs"
	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/pgsql"
)

func TestPostgresLifecycleDryRun(t *testing.T) {
	if os.Getenv("HP_DEBUG") != "" {
		testLogOut = os.Stderr
	}
	ts, s := newTestServer(t)
	c := client()
	w := webClient{t: t, ts: ts, c: c, csrf: login(t, ts, c)}
	ctx := context.Background()

	// 1. Docker (shared job) → install.
	if code, body := w.get("/postgres", false); code != 200 || !strings.Contains(body, "Docker'ı kur") {
		t.Fatalf("postgres page %d", code)
	}
	res := w.post("/databases/docker", url.Values{"back": {"postgres"}})
	if loc := res.Header.Get("Location"); !strings.HasPrefix(loc, "/postgres?job=") {
		t.Fatalf("docker redirect %q", loc)
	}
	waitJob(t, s, jobFromLocation(t, res.Header.Get("Location")))
	if code, body := w.get("/postgres", false); code != 200 || !strings.Contains(body, pgsql.DefaultImage) {
		t.Fatalf("install form %d", code)
	}
	if res := w.post("/postgres/server", url.Values{"memory_mb": {"256"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("install with 256 MB %d", res.StatusCode)
	}
	_, log := mustJob(t, s, w.post("/postgres/server", url.Values{"memory_mb": {"2048"}}))
	if !strings.Contains(log, "hp-pg.sh create "+pgsql.DefaultImage+" 2048 127.0.0.1") {
		t.Fatalf("install log:\n%s", log)
	}
	if srv, err := s.PG.Store.Server(ctx); err != nil || srv.Status != pgsql.StatusRunning {
		t.Fatalf("server %+v %v", srv, err)
	}
	if res := w.post("/postgres/server", url.Values{"memory_mb": {"2048"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("second install %d", res.StatusCode)
	}
	if code, body := w.get("/postgres/status", true); code != 200 || strings.Contains(body, "<html") {
		t.Fatalf("status fragment %d", code)
	}

	// 2. Customers; role from the customer page.
	w.post("/customers", url.Values{"name": {"Oto Panom"}})
	w.post("/customers", url.Values{"name": {"Acme"}})
	if res := w.post("/postgres/roles", url.Values{"customer_id": {"1"}, "back": {"customer"}}); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("role create %d", res.StatusCode)
	}
	role, err := s.PG.Store.RoleForCustomer(ctx, 1)
	if err != nil || role.Name != "c_oto_panom" {
		t.Fatalf("role %+v %v", role, err)
	}
	if code, body := w.get("/customers/1", false); code != 200 || !strings.Contains(body, "c_oto_panom") {
		t.Fatalf("customer page %d", code)
	}

	// 3. Wizard with a PostgreSQL database → env.
	if code, body := w.get("/sites/new", false); code != 200 || !strings.Contains(body, `name="create_pgdb"`) {
		t.Fatalf("wizard misses the PostgreSQL option (%d)", code)
	}
	res = w.post("/sites", url.Values{"customer_id": {"1"}, "domain": {"otopanom.com"}, "runtime": {"dotnet"}, "version": {"10.0.14"},
		"field_entryPoint": {"App.dll"}, "create_pgdb": {"1"}})
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("site create %d", res.StatusCode)
	}
	waitJob(t, s, jobFromLocation(t, res.Header.Get("Location")))
	j := latestJob(t, s, "pg.create")
	if j.Status != jobs.StatusSuccess {
		t.Fatalf("pg.create %s: %s\n%s", j.Status, j.Error, jobLog(t, s, j.ID))
	}
	if log := jobLog(t, s, j.ID); !strings.Contains(log, "hp-pg.sh db-create otopanom_com c_oto_panom") {
		t.Fatalf("create log:\n%s", log)
	}
	site, _ := s.Sites.Store.GetByDomain(ctx, "otopanom.com")
	dbs, _ := s.PG.Store.Databases(ctx, pgsql.DBFilter{SiteID: site.ID})
	if len(dbs) != 1 || dbs[0].Name != "otopanom_com" || dbs[0].Status != pgsql.DBReady || dbs[0].EnvKey != "ConnectionStrings__DefaultConnection" {
		t.Fatalf("site dbs %+v", dbs)
	}
	siteDB := dbs[0]
	pw1, _ := s.PG.Box.OpenString(role.PasswordSealed)
	env, _ := s.Sites.Env(ctx, site.ID)
	if cs := env["ConnectionStrings__DefaultConnection"]; cs != "Host=127.0.0.1;Port=5432;Database=otopanom_com;Username=c_oto_panom;Password="+pw1 {
		t.Fatalf("env %q", cs)
	}
	siteBase := "/sites/" + strconv.FormatInt(site.ID, 10)
	if code, body := w.get(siteBase, false); code != 200 || !strings.Contains(body, "otopanom_com") {
		t.Fatalf("site page %d", code)
	}
	if code, body := w.get(siteBase+"?tab=import", false); code != 200 || !strings.Contains(body, "/import/pg") {
		t.Fatalf("import tab %d", code)
	}

	// 4. Validation.
	for _, name := range []string{"Bad-Name", "postgres", "pg_x", "otopanom_com"} {
		if res := w.post("/postgres", url.Values{"customer_id": {"2"}, "name": {name}}); res.StatusCode != http.StatusBadRequest {
			t.Fatalf("name %q → %d", name, res.StatusCode)
		}
	}
	if res := w.post("/postgres", url.Values{"customer_id": {"2"}, "name": {"acme_x"}, "site_id": {strconv.FormatInt(site.ID, 10)}}); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("foreign site %d", res.StatusCode)
	}
	_, log = mustJob(t, s, w.post("/postgres", url.Values{"customer_id": {"2"}, "name": {"acme_db"}}))
	if !strings.Contains(log, "hp-pg.sh db-create acme_db c_acme") {
		t.Fatalf("acme create:\n%s", log)
	}

	// 5. Connection info (POST, logged).
	code, body := w.postHX("/postgres/"+strconv.FormatInt(siteDB.ID, 10)+"/connection", nil)
	if code != 200 || !strings.Contains(body, "Host=127.0.0.1;Port=5432;Database=otopanom_com") || !strings.Contains(body, "postgresql://c_oto_panom:") {
		t.Fatalf("connection %d:\n%s", code, body)
	}
	if e, _ := s.Activity.Query(ctx, logs.Filter{Action: "pg.reveal", Limit: 1}); len(e) != 1 {
		t.Fatal("pg.reveal not logged")
	}

	// 6. Password reset rewrites the env; secrets never reach the logs.
	roleBase := "/postgres/roles/" + strconv.FormatInt(role.ID, 10)
	if res := w.post(roleBase+"/password", nil); res.StatusCode != 200 {
		t.Fatalf("password reset %d", res.StatusCode)
	}
	role, _ = s.PG.Store.Role(ctx, role.ID)
	pw2, _ := s.PG.Box.OpenString(role.PasswordSealed)
	env, _ = s.Sites.Env(ctx, site.ID)
	if pw2 == pw1 || !strings.HasSuffix(env["ConnectionStrings__DefaultConnection"], "Password="+pw2) {
		t.Fatal("env not updated after password reset")
	}
	for _, p := range []string{"/logs/jobs", "/logs"} {
		if _, body := w.get(p, false); strings.Contains(body, pw2) || strings.Contains(body, pw1) {
			t.Fatalf("password visible on %s", p)
		}
	}
	if res := w.post(roleBase+"/disable", nil); res.StatusCode != 200 {
		t.Fatalf("disable %d", res.StatusCode)
	}
	if r, _ := s.PG.Store.Role(ctx, role.ID); !r.Disabled {
		t.Fatal("role not disabled")
	}
	w.post(roleBase+"/enable", nil)
	if res := w.post(roleBase+"/delete", nil); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("deleting a role with databases %d", res.StatusCode)
	}

	// 7. Isolation test.
	_, log = mustJob(t, s, w.post("/postgres/isolation-test", nil))
	if !strings.Contains(log, "hp-pg.sh isolation-test") {
		t.Fatalf("isolation log:\n%s", log)
	}

	// 8. Migration: plain SQL refused, custom-format dump accepted.
	res = w.multipartPost(siteBase+"/import/pg", [][2]string{{"name", "otopanom"}, {"write_env", "1"}, {"env_key", "ConnectionStrings__Oto"}},
		"dump", "otopanom.sql", []byte("-- PostgreSQL database dump\n\\! id\n"))
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("plain sql upload %d", res.StatusCode)
	}
	res = w.multipartPost(siteBase+"/import/pg", [][2]string{{"name", "otopanom"}, {"write_env", "1"}, {"env_key", "ConnectionStrings__Oto"}},
		"dump", "otopanom.dump", []byte("PGDMP\x01\x0e\x00fake"))
	if res.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("dump upload %d %s", res.StatusCode, b)
	}
	j = waitJob(t, s, jobFromLocation(t, res.Header.Get("HX-Redirect")))
	log = jobLog(t, s, j.ID)
	if j.Status != jobs.StatusSuccess || !strings.Contains(log, "hp-pg.sh check-dump ") || !strings.Contains(log, "hp-pg.sh restore otopanom c_oto_panom upload ") {
		t.Fatalf("import %s %s\n%s", j.Status, j.Error, log)
	}
	if strings.Contains(log, pw2) {
		t.Fatal("role password in the import log")
	}
	if d, err := s.PG.Store.DatabaseByName(ctx, "otopanom"); err != nil || d.Status != pgsql.DBReady || d.CustomerID != 1 {
		t.Fatalf("imported db %+v %v", d, err)
	}
	env, _ = s.Sites.Env(ctx, site.ID)
	if !strings.Contains(env["ConnectionStrings__Oto"], "Database=otopanom;") {
		t.Fatalf("import env %v", env)
	}
	if entries, _ := os.ReadDir(s.PG.UploadDir); len(entries) != 0 {
		for _, e := range entries {
			if pgsql.ImportRe.MatchString(e.Name()) {
				t.Fatalf("upload left behind: %s", e.Name())
			}
		}
	}
	// Another customer cannot take over the name.
	res = w.multipartPost(siteBase+"/import/pg", [][2]string{{"name", "acme_db"}}, "dump", "x.dump", []byte("PGDMPx"))
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("foreign name import %d", res.StatusCode)
	}

	// 9. Backup includes PostgreSQL dumps; clone maps them to the target.
	_, log = mustJob(t, s, w.post(siteBase+"/backup", url.Values{"components": {"files", "db", "config"}}))
	list, _ := s.Backups.Store.Backups(ctx, backups.Filter{SiteID: site.ID})
	if len(list) != 1 || list[0].Status != backups.StatusSuccess {
		t.Fatalf("backups %+v", list)
	}
	bk := list[0]
	for _, want := range []string{"hp-pg.sh dump otopanom_com hpbk-" + bk.Name + "-otopanom_com", "pg:otopanom_com", "pg:otopanom"} {
		if !strings.Contains(log, want) {
			t.Errorf("backup log misses %q:\n%s", want, log)
		}
	}
	res = w.post("/sites", url.Values{"customer_id": {"1"}, "domain": {"test.otopanom.com"}, "runtime": {"dotnet"}, "version": {"10.0.14"}, "field_entryPoint": {"App.dll"}})
	waitJob(t, s, jobFromLocation(t, res.Header.Get("Location")))
	staging, _ := s.Sites.Store.GetByDomain(ctx, "test.otopanom.com")
	restoreURL := "/backups/" + strconv.FormatInt(bk.ID, 10) + "/restore"
	_, log = mustJob(t, s, w.post(restoreURL, url.Values{"target": {strconv.FormatInt(site.ID, 10)}, "components": {"db"}, "confirm": {"otopanom.com"}}))
	if !strings.Contains(log, "hp-pg.sh restore otopanom_com c_oto_panom backup otopanom.com "+bk.Name+" otopanom_com") {
		t.Fatalf("restore log:\n%s", log)
	}
	_, log = mustJob(t, s, w.post(restoreURL, url.Values{"target": {strconv.FormatInt(staging.ID, 10)}, "components": {"db", "config"}, "confirm": {"test.otopanom.com"}}))
	cloneDBs, _ := s.PG.Store.Databases(ctx, pgsql.DBFilter{SiteID: staging.ID})
	if len(cloneDBs) != 2 {
		t.Fatalf("clone dbs %+v\n%s", cloneDBs, log)
	}
	for _, d := range cloneDBs {
		if d.CustomerID != 1 || d.Status != pgsql.DBReady || !strings.Contains(log, "hp-pg.sh restore "+d.Name+" c_oto_panom backup otopanom.com "+bk.Name+" ") {
			t.Fatalf("clone db %+v\n%s", d, log)
		}
	}
	env, _ = s.Sites.Env(ctx, staging.ID)
	if cs := env["ConnectionStrings__DefaultConnection"]; !strings.Contains(cs, "Database="+cloneDBs[0].Name+";") && !strings.Contains(cs, "Database="+cloneDBs[1].Name+";") {
		t.Fatalf("clone env %v", env)
	}

	// 10. Drop: typed confirmation, pre-drop dump.
	acme, _ := s.PG.Store.DatabaseByName(ctx, "acme_db")
	delPath := "/postgres/" + strconv.FormatInt(acme.ID, 10) + "/delete"
	if res := w.post(delPath, url.Values{"confirm": {"acme"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("drop without confirmation %d", res.StatusCode)
	}
	_, log = mustJob(t, s, w.post(delPath, url.Values{"confirm": {"acme_db"}}))
	if !strings.Contains(log, "hp-pg.sh db-drop acme_db backup") || s.PG.Store.DBNameTaken(ctx, "acme_db") {
		t.Fatalf("drop log:\n%s", log)
	}

	// 11. Other pages.
	for _, p := range []string{"/postgres", "/databases", "/logs/system?source=postgres", "/server"} {
		if code, body := w.get(p, false); code != 200 {
			t.Fatalf("%s → %d\n%s", p, code, body)
		}
	}

	// 12. Site delete with drop_dbs; customer delete is refused while databases remain.
	if res := w.post(siteBase+"/delete", url.Values{"confirm": {"otopanom.com"}, "drop_dbs": {"1"}}); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("site delete %d", res.StatusCode)
	}
	j = latestJob(t, s, "site.delete")
	if j.Status != jobs.StatusSuccess || !strings.Contains(jobLog(t, s, j.ID), "hp-pg.sh db-drop otopanom_com backup") {
		t.Fatalf("site delete %s: %s\n%s", j.Status, j.Error, jobLog(t, s, j.ID))
	}
	if s.PG.Store.DBNameTaken(ctx, "otopanom_com") || s.PG.Store.DBNameTaken(ctx, "otopanom") {
		t.Fatal("site databases not dropped")
	}
	if res := w.post("/customers/1/delete", nil); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("customer delete with sites/databases %d", res.StatusCode)
	}
	res = w.post("/customers/2/delete", nil)
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("customer delete %d", res.StatusCode)
	}
	if _, err := s.PG.Store.RoleForCustomer(ctx, 2); err == nil {
		t.Fatal("role of the deleted customer still stored")
	}
}
