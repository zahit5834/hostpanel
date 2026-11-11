package web

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zahit5834/hostpanel/internal/databases"
	"github.com/zahit5834/hostpanel/internal/images"
	"github.com/zahit5834/hostpanel/internal/mail"
	"github.com/zahit5834/hostpanel/internal/sites"
)

func TestImageUpdatesDryRun(t *testing.T) {
	if os.Getenv("HP_DEBUG") != "" {
		testLogOut = os.Stderr
	}
	ts, s := newTestServer(t)
	c := client()
	w := webClient{t: t, ts: ts, c: c, csrf: login(t, ts, c)}
	ctx := context.Background()

	if _, body := w.get("/settings/update", false); !strings.Contains(body, "Kurulu container yok") {
		t.Fatal("images section without containers")
	}
	mustJob(t, s, w.post("/databases/docker", nil))
	mustJob(t, s, w.post("/databases/server", url.Values{"edition": {"Express"}, "memory_mb": {"2048"}, "accept_eula": {"1"}}))
	if _, body := w.get("/databases", false); !strings.Contains(body, "henüz kontrol edilmedi") || strings.Contains(body, "/databases/server/update") {
		t.Fatal("update card before the first check")
	}

	// check → offer within the line, newer year only as information
	if res := w.post("/settings/update/images", nil); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("check %d", res.StatusCode)
	}
	gdr := images.MSSQLRepo + ":2025-CU10-GDR1-ubuntu-24.04"
	_, body := w.get("/settings/update", false)
	if !strings.Contains(body, "Yeni: 2025-CU10-GDR1-ubuntu-24.04") || !strings.Contains(body, "2027-CU1-ubuntu-24.04") {
		t.Fatalf("settings/update:\n%s", body)
	}
	if _, body = w.get("/databases", false); !strings.Contains(body, `value="`+gdr+`"`) {
		t.Fatal("update form missing on /databases")
	}
	for _, bad := range []string{databases.DefaultImage, images.MSSQLRepo + ":2027-CU1-ubuntu-24.04", "evil/img:2025-CU11-ubuntu-24.04"} {
		if res := w.post("/databases/server/update", url.Values{"image": {bad}}); res.StatusCode != http.StatusBadRequest {
			t.Errorf("update to %s: %d", bad, res.StatusCode)
		}
	}
	_, log := mustJob(t, s, w.post("/databases/server/update", url.Values{"image": {gdr}}))
	for _, want := range []string{"hp-mssql.sh pull " + gdr, "hp-mssql.sh snapshot", "hp-mssql.sh remove-container",
		"hp-mssql.sh create " + gdr + " 2048 127.0.0.1", "sa şifresi yenilendi", "MSSQL güncellendi"} {
		if !strings.Contains(log, want) {
			t.Errorf("update log misses %q:\n%s", want, log)
		}
	}
	srv, _ := s.DBs.Store.Server(ctx)
	if srv.Image != gdr || srv.Status != databases.StatusRunning {
		t.Fatalf("%+v", srv)
	}
	saPW, _ := s.DBs.Box.OpenString(srv.SASealed)
	if !s.DBs.Fake.CheckSA(saPW) || strings.Contains(log, saPW) {
		t.Fatal("sa not consistent after the update")
	}
	if _, body = w.get("/databases", false); strings.Contains(body, "/databases/server/update") {
		t.Fatal("stale offer after the update")
	}

	// mail server
	w.post("/customers", url.Values{"name": {"Acme"}})
	mustJob(t, s, w.post("/mail/server", url.Values{"hostname": {"mail.ornek.com"}, "domain": {"ornek.com"}, "customer_id": {"1"},
		"le_email": {"admin@ornek.com"}, "memory_mb": {"1024"}}))
	w.post("/settings/update/images", nil)
	next := images.MailRepo + ":17.0.1-r1"
	if _, body = w.get("/mail", false); !strings.Contains(body, `value="`+next+`"`) {
		t.Fatal("mail update form missing")
	}
	_, log = mustJob(t, s, w.post("/mail/server/update", url.Values{"image": {next}}))
	if !strings.Contains(log, "hp-mail.sh pull "+next) || !strings.Contains(log, "hp-mail.sh create "+next+" mail.ornek.com") {
		t.Fatalf("mail update log:\n%s", log)
	}
	if m, _ := s.Mail.Store.Server(ctx); m.Image != next || m.Status != mail.StatusRunning {
		t.Fatalf("%+v", m)
	}
}

func TestTrafficUptimeDryRun(t *testing.T) {
	if os.Getenv("HP_DEBUG") != "" {
		testLogOut = os.Stderr
	}
	ts, s := newTestServer(t)
	c := client()
	w := webClient{t: t, ts: ts, c: c, csrf: login(t, ts, c)}
	ctx := context.Background()

	w.post("/customers", url.Values{"name": {"Acme"}})
	res := w.post("/sites", url.Values{"customer_id": {"1"}, "domain": {"app.example.com"}, "runtime": {"dotnet"},
		"version": {"10.0.14"}, "field_entryPoint": {"App.dll"}})
	waitJob(t, s, jobFromLocation(t, res.Header.Get("Location")))
	s.DB.ExecContext(ctx, `UPDATE sites SET created_at=?`, time.Now().AddDate(0, 0, -5).Unix())
	site, _ := s.Sites.Store.GetByDomain(ctx, "app.example.com")
	base := "/sites/" + strconv.FormatInt(site.ID, 10)
	res = w.multipartPost(base+"/deploy", nil, "zip", "site.zip", testZip(t))
	waitJob(t, s, jobFromLocation(t, res.Header.Get("HX-Redirect")))

	logFile := filepath.Join(t.TempDir(), "access.log")
	s.Traffic.LogPath = func(sites.Site) string { return logFile }
	now := time.Now()
	yday := now.AddDate(0, 0, -1)
	var b strings.Builder
	for i, ip := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.2", "127.0.0.1"} {
		fmt.Fprintf(&b, "%s - - [%s] \"GET /urun/%d HTTP/1.1\" 200 1000 \"-\" \"Mozilla/5.0\"\n", ip, yday.Format("02/Jan/2006:15:04:05 -0700"), i%2)
	}
	fmt.Fprintf(&b, "198.51.100.9 - - [%s] \"GET /x HTTP/1.1\" 503 10 \"-\" \"Googlebot/2.1\"\n", now.Format("02/Jan/2006:15:04:05 -0700"))
	fmt.Fprintf(&b, "198.51.100.10 - - [%s] \"GET /<script> HTTP/1.1\" 200 10 \"-\" \"Mozilla/5.0\"\n", now.Format("02/Jan/2006:15:04:05 -0700"))
	os.WriteFile(logFile, []byte(b.String()), 0o644)

	// two health checks → uptime rows
	w.postHX(base+"/health/check", nil)
	w.postHX(base+"/health/check", nil)

	if _, body := w.get(base+"?tab=stats", false); !strings.Contains(body, `hx-get="`+base+`/stats"`) {
		t.Fatal("stats tab loader missing")
	}
	code, body := w.get(base+"/stats", true)
	if code != 200 || strings.Contains(body, "<html") {
		t.Fatalf("stats fragment %d", code)
	}
	for _, want := range []string{"Son 30 gün", `<div class="label">İstek</div><div class="value">5</div>`, "bot/araç: 1",
		`<div class="value">100.00%</div>`, "/urun/1", "Bu dönemde kesinti yok", "&lt;script&gt;"} {
		if !strings.Contains(body, want) {
			t.Errorf("stats fragment misses %q", want)
		}
	}
	if strings.Contains(body, "/<script>") {
		t.Error("path not escaped")
	}
	if _, body = w.get(base+"/stats?days=7", true); !strings.Contains(body, "Son 7 gün") {
		t.Fatal("7-day range")
	}
	// yesterday was stored by the tab; the overview shows stored days only
	if days, _ := s.Traffic.Range(ctx, site.ID, "2000-01-01"); len(days) == 0 || days[len(days)-1].Requests != 3 {
		t.Fatalf("stored days %+v", days)
	}
	if code, body = w.get("/stats", false); code != 200 || !strings.Contains(body, "app.example.com") || !strings.Contains(body, "%100.00") {
		t.Fatalf("overview %d", code)
	}
	if _, body = w.get("/stats?days=30", false); !strings.Contains(body, `href="/stats?days=30">30 gün`) {
		t.Fatal("30-day overview")
	}
}
