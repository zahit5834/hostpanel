package web

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/zahit5834/hostpanel/internal/backups"
	"github.com/zahit5834/hostpanel/internal/jobs"
	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/metrics"
	"github.com/zahit5834/hostpanel/internal/runtimes"
	"github.com/zahit5834/hostpanel/internal/store"
)

func TestParseUnitShow(t *testing.T) {
	out := "LoadState=loaded\nActiveState=active\n\nLoadState=not-found\nActiveState=inactive\n\nLoadState=loaded\nActiveState=failed\n"
	b := ParseUnitShow(out, 4)
	if b[0]["ActiveState"] != "active" || b[1]["LoadState"] != "not-found" || b[2]["ActiveState"] != "failed" || len(b[3]) != 0 {
		t.Fatalf("%v", b)
	}
}

func TestNextSummary(t *testing.T) {
	loc := time.FixedZone("TR", 3*3600)
	now := time.Date(2026, 11, 12, 9, 30, 0, 0, loc) // Thursday
	if !NextSummary(now, SummarySchedule{Mode: "off"}).IsZero() {
		t.Fatal("off")
	}
	if got := NextSummary(now, SummarySchedule{Mode: "daily", Hour: 8}); !got.Equal(time.Date(2026, 11, 13, 8, 0, 0, 0, loc)) {
		t.Fatalf("daily past %v", got)
	}
	if got := NextSummary(now, SummarySchedule{Mode: "daily", Hour: 10}); !got.Equal(time.Date(2026, 11, 12, 10, 0, 0, 0, loc)) {
		t.Fatalf("daily later today %v", got)
	}
	if got := NextSummary(now, SummarySchedule{Mode: "weekly", Hour: 8, Weekday: 1}); !got.Equal(time.Date(2026, 11, 16, 8, 0, 0, 0, loc)) {
		t.Fatalf("weekly %v", got)
	}
	if got := NextSummary(now, SummarySchedule{Mode: "weekly", Hour: 10, Weekday: 4}); !got.Equal(time.Date(2026, 11, 12, 10, 0, 0, 0, loc)) {
		t.Fatalf("weekly today %v", got)
	}
	if (SummarySchedule{Mode: "hourly"}).Validate() == nil || (SummarySchedule{Mode: "daily", Hour: 24}).Validate() == nil {
		t.Fatal("bad schedule accepted")
	}
}

func TestBuildChart(t *testing.T) {
	from := time.Unix(0, 0)
	to := from.Add(time.Hour)
	pts := []metrics.Point{{TS: from, CPU: 50}, {TS: from.Add(5 * time.Minute), CPU: 100},
		{TS: from.Add(50 * time.Minute), CPU: 0}} // gap → a second line
	c := buildChart("CPU", pts, from, to, 100, fmtPct, series{"s1", "cpu", func(p metrics.Point) float64 { return p.CPU }})
	if len(c.Lines) != 2 || c.Lines[0].Points != "0.0,60.0 50.0,0.0" || c.Lines[1].Points != "500.0,120.0" || c.Max != "100%" || c.Now != "cpu 0%" {
		t.Fatalf("%+v", c)
	}
	if niceMax(3.2) != 5 || niceMax(0) != 1 || niceMax(1200) != 2000 {
		t.Fatal("niceMax")
	}
}

// Faz 12 end to end in dry-run: domains, metrics, disk assistant, bulk
// operations, backup drill, runtime patch, summary and Telegram commands.
func TestOpsDryRun(t *testing.T) {
	if os.Getenv("HP_DEBUG") != "" {
		testLogOut = os.Stderr
	}
	ts, s := newTestServer(t)
	c := client()
	w := webClient{t: t, ts: ts, c: c, csrf: login(t, ts, c)}
	ctx := context.Background()

	w.post("/customers", url.Values{"name": {"Acme"}})
	for _, d := range []string{"app.example.com", "shop.ornek.com.tr"} {
		res := w.post("/sites", url.Values{"customer_id": {"1"}, "domain": {d}, "runtime": {"dotnet"},
			"version": {"10.0.14"}, "field_entryPoint": {"App.dll"}})
		waitJob(t, s, jobFromLocation(t, res.Header.Get("Location")))
	}
	app, _ := s.Sites.Store.GetByDomain(ctx, "app.example.com")
	shop, _ := s.Sites.Store.GetByDomain(ctx, "shop.ornek.com.tr")
	res := w.multipartPost("/sites/"+strconv.FormatInt(app.ID, 10)+"/deploy", nil, "zip", "site.zip", testZip(t))
	waitJob(t, s, jobFromLocation(t, res.Header.Get("HX-Redirect")))

	// --- I4 domains ---
	code, body := w.get("/domains", false)
	if code != 200 || !strings.Contains(body, "example.com") || !strings.Contains(body, "ornek.com.tr") || !strings.Contains(body, "site app.example.com") {
		t.Fatalf("domains %d", code)
	}
	day := time.Now().AddDate(0, 0, 5).Format("2006-01-02")
	if code, body = w.postHX("/domains/manual", url.Values{"name": {"ornek.com.tr"}, "date": {day}}); code != 200 || !strings.Contains(body, "Kaydedildi") {
		t.Fatalf("manual %d %s", code, body)
	}
	if code, _ = w.postHX("/domains/manual", url.Values{"name": {"ornek.com.tr"}, "date": {"2026-13-40"}}); code != 400 {
		t.Fatalf("bad date %d", code)
	}
	if _, body = w.get("/", false); !strings.Contains(body, "ornek.com.tr: alan adı kaydı") {
		t.Fatal("dashboard domain alert missing")
	}
	if _, body = w.get("/customers/1", false); !strings.Contains(body, "Alan adı kayıtları") || !strings.Contains(body, "ornek.com.tr") {
		t.Fatal("customer domain card missing")
	}
	if _, body = w.postHX("/domains/refresh", nil); !strings.Contains(body, "Dry-run") {
		t.Fatal("refresh in dry-run")
	}

	// --- S6 metrics ---
	if _, body = w.get("/server?tab=metrics", false); !strings.Contains(body, "Bu aralıkta örnek yok") {
		t.Fatal("empty metrics page")
	}
	s.Metrics.Tick(ctx)
	time.Sleep(20 * time.Millisecond)
	s.Metrics.Tick(ctx)
	if _, body = w.get("/server?tab=metrics&range=7d", false); !strings.Contains(body, "<polyline") || !strings.Contains(body, "Yük (1 dk)") {
		t.Fatal("chart missing")
	}
	if _, body = w.postHX("/server/metrics", url.Values{"enabled": {"0"}}); !strings.Contains(body, "Kaydı başlat") || s.Metrics.Enabled(ctx) {
		t.Fatal("metrics toggle")
	}

	// --- S4 disk assistant ---
	os.MkdirAll(s.Sites.UploadDir, 0o750)
	old := filepath.Join(s.Sites.UploadDir, "upload-123.zip")
	os.WriteFile(old, []byte("PK"), 0o640)
	os.Chtimes(old, time.Now().Add(-48*time.Hour), time.Now().Add(-48*time.Hour))
	os.WriteFile(filepath.Join(s.Sites.UploadDir, "upload-456.zip"), []byte("PK"), 0o640) // fresh: still uploading
	if _, body = w.get("/server?tab=clean", false); !strings.Contains(body, `hx-get="/server/part/clean"`) {
		t.Fatal("clean tab")
	}
	code, body = w.get("/server/part/clean", true)
	if code != 200 || !strings.Contains(body, "eski-site.com/pre-delete") || !strings.Contains(body, "upload-123.zip") ||
		strings.Contains(body, "upload-456.zip") || !strings.Contains(body, "yalnızca bilgi") {
		t.Fatalf("clean part %d", code)
	}
	if code, body = w.postHX("/server/clean", url.Values{"cat": {"predelete"}, "id": {"eski-site.com/pre-delete-20261001-101500.tar.zst"}}); code != 200 || !strings.Contains(body, "Silindi") {
		t.Fatalf("clean delete %d %s", code, body)
	}
	if code, _ = w.postHX("/server/clean", url.Values{"cat": {"mail"}, "id": {"pre-delete-eski@ornek.com-20261012-120000.tar.zst"}}); code != 502 {
		t.Fatalf("mail archive deleted: %d", code)
	}
	if code, _ = w.postHX("/server/clean", url.Values{"cat": {"uploads"}, "id": {"upload-123.zip"}}); code != 200 {
		t.Fatalf("upload delete %d", code)
	}
	if _, err := os.Stat(old); err == nil {
		t.Fatal("upload not removed")
	}
	if code, _ = w.postHX("/server/clean", url.Values{"cat": {"uploads"}, "id": {"upload-456.zip"}}); code != 502 {
		t.Fatalf("fresh upload removed: %d", code)
	}
	if _, body = w.get("/server/part/clean", true); strings.Contains(body, "eski-site.com/pre-delete") {
		t.Fatal("deleted item still listed")
	}

	// --- K2 bulk ---
	ids := url.Values{"site": {strconv.FormatInt(app.ID, 10), strconv.FormatInt(shop.ID, 10)}}
	ids.Set("op", "rm -rf")
	if code, _ = w.postHX("/sites/bulk", ids); code != 400 {
		t.Fatalf("bad op %d", code)
	}
	ids.Set("op", "restart")
	if code, body = w.postHX("/sites/bulk", ids); code != 200 || !strings.Contains(body, "2 site için") {
		t.Fatalf("bulk %d %s", code, body)
	}
	byTarget := map[string]jobs.Job{}
	for i := 0; i < 200; i++ {
		list, _ := s.Jobs.List(ctx, "", "site.op", "", 0, 10)
		done := 0
		for _, j := range list {
			if j.Status != jobs.StatusQueued && j.Status != jobs.StatusRunning {
				byTarget[j.TargetID] = j
				done++
			}
		}
		if done == 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if byTarget["app.example.com"].Status != jobs.StatusSuccess || byTarget["shop.ornek.com.tr"].Status != jobs.StatusFailed {
		t.Fatalf("bulk results %+v", byTarget) // shop has no release: restart fails, app still restarts
	}
	ids.Set("op", "backup")
	if _, body = w.postHX("/sites/bulk", ids); !strings.Contains(body, "2 site için") {
		t.Fatal("bulk backup")
	}
	for i := 0; i < 300; i++ {
		list, _ := s.Backups.Store.Backups(ctx, backups.Filter{})
		if len(list) == 2 && list[0].Status == backups.StatusSuccess && list[1].Status == backups.StatusSuccess {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// --- Y1 backup drill ---
	if _, body = w.get("/backups?tab=verify", false); !strings.Contains(body, "Şimdi doğrula") || !strings.Contains(body, "app.example.com") {
		t.Fatal("verify tab")
	}
	res = w.post("/backups/verify", url.Values{"backup_id": {"0"}})
	j := waitJob(t, s, jobFromLocation(t, res.Header.Get("Location")))
	if j.Status != jobs.StatusSuccess {
		t.Fatalf("verify job %s %s", j.Status, j.Error)
	}
	v, _ := s.Backups.Store.Verifications(ctx, 5)
	if len(v) != 1 || v[0].Status != backups.StatusSuccess || v[0].Source != "local" {
		t.Fatalf("verification %+v", v)
	}
	if _, body = w.get("/backups?tab=verify", false); !strings.Contains(body, "geçti") {
		t.Fatal("verification row")
	}
	found := false
	e, _ := s.Activity.Query(ctx, logs.Filter{Action: "backup.verify"})
	for _, a := range e {
		found = found || strings.HasPrefix(a.Summary, "Yedek doğrulandı: ")
	}
	if !found {
		t.Fatalf("verify activity %+v", e)
	}
	// Weekly: the first maintenance only records the time; a week later it runs.
	s.Backups.MaintainVerify(ctx)
	if n, _ := s.Jobs.List(ctx, "", "backup.verify", "", 0, 10); len(n) != 1 {
		t.Fatal("first maintenance started a drill")
	}
	store.SetSetting(ctx, s.DB, "backup_verify_at", strconv.FormatInt(time.Now().AddDate(0, 0, -8).Unix(), 10))
	s.Backups.MaintainVerify(ctx)
	if n, _ := s.Jobs.List(ctx, "", "backup.verify", "", 0, 10); len(n) != 2 {
		t.Fatal("weekly drill not started")
	}
	w.postHX("/backups/verify/settings", url.Values{})
	if s.Backups.VerifyWeeklyOn(ctx) {
		t.Fatal("weekly still on")
	}

	// --- D1 runtime patch ---
	p, _ := s.Runtimes.Get("dotnet")
	p.Def().Versions.Available = "dotnet-releases"
	s.Runtimes.SeedAvailable("dotnet-releases", []runtimes.Available{{Version: "10.0.15", Label: "LTS"}, {Version: "9.0.11", Label: "STS"}})
	if _, body = w.get("/runtimes", false); !strings.Contains(body, "Kur ve siteleri taşı") || !strings.Contains(body, "10.0.15") {
		t.Fatal("patch offer missing")
	}
	s.RuntimePatchCheck(ctx)
	s.RuntimePatchCheck(ctx) // announced once (setting)
	if v := store.GetSetting(ctx, s.DB, setPatchNotified, ""); v != `["dotnet@10.0.15"]` {
		t.Fatalf("patch notified %q", v)
	}
	if code, _ = w.postHX("/runtimes/dotnet/patch", url.Values{"from": {"10.0.14"}, "to": {"11.0.0"}}); code != 400 {
		t.Fatalf("major change accepted %d", code)
	}
	res = w.post("/runtimes/dotnet/patch", url.Values{"from": {"10.0.14"}, "to": {"10.0.15"}})
	j = waitJob(t, s, jobFromLocation(t, res.Header.Get("Location")))
	if j.Status != jobs.StatusSuccess {
		t.Fatalf("patch job %s %s", j.Status, j.Error)
	}
	for _, id := range []int64{app.ID, shop.ID} {
		if st, _ := s.Sites.Store.Get(ctx, id); st.RuntimeVersion != "10.0.15" {
			t.Fatalf("%s still on %s", st.Domain, st.RuntimeVersion)
		}
	}

	// --- I2/I3/I5 settings ---
	base := url.Values{"smtp_port": {"587"}, "kind": {"summary", "site.status"}, "telegram_on": {"1"},
		"telegram_token": {"123456789:AAbbCCddEEffGGhhIIjjKKllMMnnOOppQQ"}, "telegram_chat": {"42"}}
	bad := url.Values{}
	for k, v := range base {
		bad[k] = v
	}
	bad.Set("heartbeat_url", "https://u:p@hc-ping.com/x")
	if code, _ = w.postHX("/settings/notify", bad); code != 400 {
		t.Fatalf("credentials in heartbeat accepted %d", code)
	}
	bad.Set("heartbeat_url", "")
	bad.Set("telegram_chat", "@kanal")
	bad.Set("telegram_commands", "1")
	if code, _ = w.postHX("/settings/notify", bad); code != 400 {
		t.Fatalf("commands with channel accepted %d", code)
	}
	base.Set("heartbeat_url", "https://hc-ping.com/secret-uuid")
	base.Set("summary_mode", "weekly")
	base.Set("summary_hour", "7")
	base.Set("summary_weekday", "1")
	base.Set("telegram_commands", "1")
	if code, body = w.postHX("/settings/notify", base); code != 200 || !strings.Contains(body, "Sonraki gönderim") ||
		!strings.Contains(body, "hc-ping.com/secret-uuid") {
		t.Fatalf("notify save %d", code)
	}
	if e, _ := s.Activity.Query(ctx, logs.Filter{Action: "settings.notify", Limit: 1}); len(e) != 1 || strings.Contains(e[0].Params, "secret-uuid") {
		t.Fatalf("heartbeat URL logged: %+v", e)
	}
	title, text := s.BuildSummary(ctx, "weekly", time.Now())
	if !strings.Contains(title, "Haftalık özet") || !strings.Contains(text, "Sunucu:\n• Disk: %") || !strings.Contains(text, "• 2 site") ||
		!strings.Contains(text, "Yedekler:\n• 2 başarılı") || !strings.Contains(text, "Son doğrulama: ✓") ||
		!strings.Contains(text, "• Alan adları: ornek.com.tr") || !strings.Contains(text, "fail2ban:") {
		t.Fatalf("summary:\n%s\n%s", title, text)
	}

	// Telegram commands (handler only; polling is covered in notify).
	if r := s.BotCommand(ctx, "durum", nil); !strings.Contains(r, "Siteler:") {
		t.Fatalf("durum %q", r)
	}
	if r := s.BotCommand(ctx, "siteler", nil); !strings.Contains(r, "app.example.com\n    running") {
		t.Fatalf("siteler %q", r)
	}
	if r := s.BotCommand(ctx, "yedekler", nil); !strings.Contains(r, "Son doğrulama: ✓") {
		t.Fatalf("yedekler %q", r)
	}
	if r := s.BotCommand(ctx, "yeniden_baslat", []string{"app.example.com", "123456"}); !strings.Contains(r, "2FA") {
		t.Fatalf("restart without 2FA %q", r)
	}
	setup, _ := s.Auth.NewTOTP("admin")
	first, _ := totp.GenerateCodeCustom(setup.Secret, time.Now().Add(-30*time.Second), totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if _, err := s.Auth.EnableTOTP(ctx, setup.Sealed, first); err != nil {
		t.Fatal(err)
	}
	if r := s.BotCommand(ctx, "yeniden_baslat", []string{"app.example.com", "000000"}); r != "Kod hatalı." {
		t.Fatalf("wrong code %q", r)
	}
	now, _ := totp.GenerateCodeCustom(setup.Secret, time.Now(), totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	r := s.BotCommand(ctx, "yeniden_baslat", []string{"app.example.com", now})
	m := regexp.MustCompile(`iş #([0-9]+)`).FindStringSubmatch(r)
	if m == nil {
		t.Fatalf("restart %q", r)
	}
	id, _ := strconv.ParseInt(m[1], 10, 64)
	if j := waitJob(t, s, id); j.Status != jobs.StatusSuccess {
		t.Fatalf("bot restart job %s", j.Status)
	}
	if r := s.BotCommand(ctx, "yeniden_baslat", []string{"app.example.com", now}); r != "Kod hatalı." {
		t.Fatalf("replayed code accepted %q", r)
	}
	if e, _ := s.Activity.Query(ctx, logs.Filter{Action: "telegram.command"}); len(e) != 3 {
		t.Fatalf("telegram activity %d", len(e))
	}
	if r := s.BotCommand(ctx, "rm", nil); !strings.Contains(r, "Bilinmeyen komut") {
		t.Fatal("unknown command")
	}

	// --- I1 infrastructure: two failed rounds → down (dashboard), then up ---
	store.SetSetting(ctx, s.DB, setInfraState, `{"unit:nginx.service":{"f":2,"d":true,"s":1,"w":"servis durumu: failed"}}`)
	if _, body = w.get("/", false); !strings.Contains(body, "nginx çalışmıyor") {
		t.Fatal("infra alert missing")
	}
}
