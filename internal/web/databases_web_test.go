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

	"hostpanel/internal/databases"
	"hostpanel/internal/jobs"
	"hostpanel/internal/logs"
)

// postHX posts like HTMX does (CSRF header) and returns the fragment.
func (w webClient) postHX(path string, form url.Values) (int, string) {
	w.t.Helper()
	if form == nil {
		form = url.Values{}
	}
	req, _ := http.NewRequest("POST", w.ts.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	req.Header.Set("X-CSRF-Token", w.csrf)
	res, err := w.c.Do(req)
	if err != nil {
		w.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

// mustJob waits for the job in the redirect and requires success.
func mustJob(t *testing.T, s *Server, res *http.Response) (int64, string) {
	t.Helper()
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d", res.StatusCode)
	}
	id := jobFromLocation(t, res.Header.Get("Location"))
	j := waitJob(t, s, id)
	log := jobLog(t, s, id)
	if j.Status != jobs.StatusSuccess {
		t.Fatalf("job %s %s: %s\n%s", j.Kind, j.Status, j.Error, log)
	}
	return id, log
}

func latestJob(t *testing.T, s *Server, kind string) jobs.Job {
	t.Helper()
	list, err := s.Jobs.List(context.Background(), "", kind, "", 0, 1)
	if err != nil || len(list) == 0 {
		t.Fatalf("no %s job (%v)", kind, err)
	}
	return waitJob(t, s, list[0].ID)
}

func TestDatabasesLifecycleDryRun(t *testing.T) {
	if os.Getenv("HP_DEBUG") != "" {
		testLogOut = os.Stderr
	}
	ts, s := newTestServer(t)
	c := client()
	w := webClient{t: t, ts: ts, c: c, csrf: login(t, ts, c)}
	ctx := context.Background()
	fake := s.DBs.Fake

	// 1. Docker
	if code, body := w.get("/databases", false); code != 200 || !strings.Contains(body, "Docker'ı kur") {
		t.Fatalf("databases page %d", code)
	}
	_, log := mustJob(t, s, w.post("/databases/docker", nil))
	if !strings.Contains(log, "hp-mssql.sh install-docker") {
		t.Fatalf("docker job log:\n%s", log)
	}

	// 2. MSSQL install: EULA and memory are validated.
	if code, body := w.get("/databases", false); code != 200 || !strings.Contains(body, "MSSQL'i kur") || !strings.Contains(body, databases.DefaultImage) {
		t.Fatalf("install form %d", code)
	}
	if res := w.post("/databases/server", url.Values{"edition": {"Express"}, "memory_mb": {"2048"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("install without EULA %d", res.StatusCode)
	}
	if res := w.post("/databases/server", url.Values{"edition": {"Express"}, "memory_mb": {"1024"}, "accept_eula": {"1"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("install with 1 GB %d", res.StatusCode)
	}
	if res := w.post("/databases/server", url.Values{"edition": {"key"}, "product_key": {"nope"}, "memory_mb": {"2048"}, "accept_eula": {"1"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad product key %d", res.StatusCode)
	}
	_, log = mustJob(t, s, w.post("/databases/server", url.Values{"edition": {"Express"}, "memory_mb": {"2048"}, "accept_eula": {"1"}}))
	for _, want := range []string{"hp-mssql.sh create " + databases.DefaultImage + " 2048 127.0.0.1", "ALTER LOGIN [sa]", "sa şifresi yenilendi", "max server memory (MB)', 1536"} {
		if !strings.Contains(log, want) {
			t.Errorf("install log misses %q:\n%s", want, log)
		}
	}
	srv, err := s.DBs.Store.Server(ctx)
	if err != nil || srv.Status != databases.StatusRunning || srv.SAPendingSealed != "" {
		t.Fatalf("server %+v %v", srv, err)
	}
	saPW, _ := s.DBs.Box.OpenString(srv.SASealed)
	if !fake.CheckSA(saPW) || strings.Contains(log, saPW) {
		t.Fatal("sa password not rotated to the stored one, or leaked into the job log")
	}
	if code, body := w.get("/databases/status", true); code != 200 || !strings.Contains(body, "running") || strings.Contains(body, "<html") {
		t.Fatalf("status fragment %d:\n%s", code, body)
	}
	if res := w.post("/databases/server", url.Values{"edition": {"Express"}, "memory_mb": {"2048"}, "accept_eula": {"1"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("second install %d", res.StatusCode)
	}

	// 3. Customer with "create login", second customer without.
	if code, body := w.get("/customers/new", false); code != 200 || !strings.Contains(body, `name="create_login"`) {
		t.Fatalf("customer form misses the login option (%d)", code)
	}
	w.post("/customers", url.Values{"name": {"Şahin Yazılım"}, "create_login": {"1"}})
	w.post("/customers", url.Values{"name": {"Acme"}})
	l1, err := s.DBs.Store.LoginForCustomer(ctx, 1)
	if err != nil || l1.Name != "c_sahin_yazilim" {
		t.Fatalf("login %+v %v", l1, err)
	}
	if _, enabled, ok := fake.Login("c_sahin_yazilim"); !ok || !enabled {
		t.Fatal("login not created on the server")
	}

	// 4. Site wizard with "create database": connection string lands in the env.
	if code, body := w.get("/sites/new", false); code != 200 || !strings.Contains(body, `name="create_db"`) {
		t.Fatalf("wizard misses the database option (%d)", code)
	}
	res := w.post("/sites", url.Values{"customer_id": {"1"}, "domain": {"sahin.com.tr"}, "runtime": {"dotnet"}, "version": {"10.0.14"},
		"field_entryPoint": {"App.dll"}, "create_db": {"1"}})
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("site create %d", res.StatusCode)
	}
	waitJob(t, s, jobFromLocation(t, res.Header.Get("Location")))
	if j := latestJob(t, s, "db.create"); j.Status != jobs.StatusSuccess {
		t.Fatalf("db.create %s: %s\n%s", j.Status, j.Error, jobLog(t, s, j.ID))
	}
	site, _ := s.Sites.Store.GetByDomain(ctx, "sahin.com.tr")
	dbs, _ := s.DBs.Store.Databases(ctx, databases.DBFilter{SiteID: site.ID})
	if len(dbs) != 1 || dbs[0].Name != "sahin_com_tr" || dbs[0].Status != databases.DBReady || dbs[0].EnvKey != "ConnectionStrings__DefaultConnection" {
		t.Fatalf("site dbs %+v", dbs)
	}
	siteDB := dbs[0]
	if fake.Databases()["sahin_com_tr"] != "c_sahin_yazilim" {
		t.Fatalf("server databases %v", fake.Databases())
	}
	env, _ := s.Sites.Env(ctx, site.ID)
	pw1, _ := s.DBs.Box.OpenString(l1.PasswordSealed)
	if cs := env["ConnectionStrings__DefaultConnection"]; !strings.Contains(cs, "Database=sahin_com_tr;User Id=c_sahin_yazilim;Password="+pw1+";") {
		t.Fatalf("env connection string %q", cs)
	}
	siteBase := "/sites/" + strconv.FormatInt(site.ID, 10)
	if code, body := w.get(siteBase, false); code != 200 || !strings.Contains(body, "sahin_com_tr") || !strings.Contains(body, `name="drop_dbs"`) {
		t.Fatalf("site page %d", code)
	}

	// 5. Validation: names, foreign site.
	if res := w.post("/databases", url.Values{"customer_id": {"2"}, "name": {"Bad-Name"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad name %d", res.StatusCode)
	}
	if res := w.post("/databases", url.Values{"customer_id": {"2"}, "name": {"master"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("reserved name %d", res.StatusCode)
	}
	if res := w.post("/databases", url.Values{"customer_id": {"2"}, "name": {"acme_x"}, "site_id": {strconv.FormatInt(site.ID, 10)}}); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("foreign site %d", res.StatusCode)
	}
	if res := w.post("/databases", url.Values{"customer_id": {"1"}, "name": {"sahin_com_tr"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("duplicate name %d", res.StatusCode)
	}

	// 6. Second customer's database: its login is created on demand.
	mustJob(t, s, w.post("/databases", url.Values{"customer_id": {"2"}, "name": {"acme_db"}}))
	if fake.Databases()["acme_db"] != "c_acme" {
		t.Fatalf("server databases %v", fake.Databases())
	}

	// 7. Connection info (POST, logged).
	code, body := w.postHX("/databases/"+strconv.FormatInt(siteDB.ID, 10)+"/connection", nil)
	if code != 200 || !strings.Contains(body, "Server=127.0.0.1,1433;Database=sahin_com_tr") || !strings.Contains(body, "mssql://c_sahin_yazilim:") {
		t.Fatalf("connection %d:\n%s", code, body)
	}
	if e, _ := s.Activity.Query(ctx, logs.Filter{Action: "db.reveal", Limit: 1}); len(e) != 1 {
		t.Fatal("db.reveal not logged")
	}

	// 8. Password reset updates the site env.
	if res := w.post("/databases/logins/"+strconv.FormatInt(l1.ID, 10)+"/password", nil); res.StatusCode != 200 {
		t.Fatalf("password reset %d", res.StatusCode)
	}
	l1, _ = s.DBs.Store.Login(ctx, l1.ID)
	pw2, _ := s.DBs.Box.OpenString(l1.PasswordSealed)
	if serverPW, _, _ := fake.Login("c_sahin_yazilim"); pw2 == pw1 || serverPW != pw2 {
		t.Fatal("password not reset on the server")
	}
	env, _ = s.Sites.Env(ctx, site.ID)
	if !strings.Contains(env["ConnectionStrings__DefaultConnection"], "Password="+pw2+";") {
		t.Fatal("env not updated after password reset")
	}

	// 9. Disable / enable.
	w.post("/databases/logins/"+strconv.FormatInt(l1.ID, 10)+"/disable", nil)
	if _, enabled, _ := fake.Login("c_sahin_yazilim"); enabled {
		t.Fatal("login still enabled")
	}
	w.post("/databases/logins/"+strconv.FormatInt(l1.ID, 10)+"/enable", nil)
	if _, enabled, _ := fake.Login("c_sahin_yazilim"); !enabled {
		t.Fatal("login still disabled")
	}
	if res := w.post("/databases/logins/"+strconv.FormatInt(l1.ID, 10)+"/delete", nil); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("deleting a login with databases %d", res.StatusCode)
	}

	// 10. Isolation test job.
	_, log = mustJob(t, s, w.post("/databases/isolation-test", nil))
	if !strings.Contains(log, "İzolasyon testi başarılı") || strings.Contains(log, "✗") {
		t.Fatalf("isolation log:\n%s", log)
	}

	// 11. Drop needs the exact name; a backup is taken first.
	acme, _ := s.DBs.Store.Databases(ctx, databases.DBFilter{CustomerID: 2})
	delPath := "/databases/" + strconv.FormatInt(acme[0].ID, 10) + "/delete"
	if res := w.post(delPath, url.Values{"confirm": {"acme"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("drop without confirmation %d", res.StatusCode)
	}
	_, log = mustJob(t, s, w.post(delPath, url.Values{"confirm": {"acme_db"}}))
	if !strings.Contains(log, "BACKUP DATABASE [acme_db] TO DISK = '/var/opt/mssql/backup/pre-drop-acme_db-") || !strings.Contains(log, "DROP DATABASE [acme_db]") {
		t.Fatalf("drop log:\n%s", log)
	}
	if _, ok := fake.Databases()["acme_db"]; ok || s.DBs.Store.DBNameTaken(ctx, "acme_db") {
		t.Fatal("database not dropped")
	}

	// 12. Settings: external access needs IPs, applies the firewall before recreating.
	if res := w.post("/databases/server/settings", url.Values{"memory_mb": {"2048"}, "external": {"1"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("external without IPs %d", res.StatusCode)
	}
	if res := w.post("/databases/server/settings", url.Values{"memory_mb": {"2048"}, "external": {"1"}, "allow_ips": {"0.0.0.0/0"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("external to the world %d", res.StatusCode)
	}
	_, log = mustJob(t, s, w.post("/databases/server/settings", url.Values{"memory_mb": {"2560"}, "external": {"1"}, "allow_ips": {"203.0.113.7\n198.51.100.0/24"}}))
	fw := strings.Index(log, "hp-mssql.sh firewall 203.0.113.7 198.51.100.0/24")
	rm := strings.Index(log, "hp-mssql.sh remove-container")
	cr := strings.Index(log, "hp-mssql.sh create "+databases.DefaultImage+" 2560 0.0.0.0")
	if fw < 0 || rm < fw || cr < rm || !strings.Contains(log, "sa şifresi yenilendi") {
		t.Fatalf("recreate log order:\n%s", log)
	}
	srv, _ = s.DBs.Store.Server(ctx)
	saPW, _ = s.DBs.Box.OpenString(srv.SASealed)
	if !srv.External || srv.MemoryMB != 2560 || !fake.CheckSA(saPW) {
		t.Fatalf("server after settings %+v", srv)
	}

	// 13. Container ops and pages.
	if res := w.post("/databases/server/op/stop", nil); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("stop %d", res.StatusCode)
	}
	if res := w.post("/databases/server/op/start", nil); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("start %d", res.StatusCode)
	}
	if res := w.post("/databases/server/op/rm", nil); res.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown op %d", res.StatusCode)
	}
	for _, p := range []string{"/databases", "/customers/1", "/customers/2", "/logs/system?source=mssql"} {
		if code, body := w.get(p, false); code != 200 {
			t.Fatalf("%s → %d\n%s", p, code, body)
		}
	}

	// 14. Site delete with "drop databases".
	if res := w.post(siteBase+"/delete", url.Values{"confirm": {"sahin.com.tr"}, "drop_dbs": {"1"}}); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("site delete %d", res.StatusCode)
	}
	if j := latestJob(t, s, "site.delete"); j.Status != jobs.StatusSuccess {
		t.Fatalf("site delete %s: %s\n%s", j.Status, j.Error, jobLog(t, s, j.ID))
	}
	if len(fake.Databases()) != 0 || s.DBs.Store.DBNameTaken(ctx, "sahin_com_tr") {
		t.Fatalf("site database not dropped: %v", fake.Databases())
	}

	// 15. Customer delete drops the SQL login.
	res = w.post("/customers/2/delete", nil)
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("customer delete %d", res.StatusCode)
	}
	if _, _, ok := fake.Login("c_acme"); ok {
		t.Fatal("login of the deleted customer still exists")
	}
}
