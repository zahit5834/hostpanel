package web

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/panelcfg"
)

func TestUpdateTransferDefaultsDryRun(t *testing.T) {
	ts, s := newTestServer(t)
	c := client()
	w := webClient{t: t, ts: ts, c: c, csrf: login(t, ts, c)}
	ctx := context.Background()

	// --- Güncelleme ---
	code, body := w.get("/settings/update", false)
	if code != 200 || !strings.Contains(body, "v0.2.0 sürümüne güncelle") || !strings.Contains(body, "&lt;script&gt;") {
		t.Fatalf("update page %d:\n%s", code, body)
	}
	if strings.Contains(body, "<script>x</script>") {
		t.Fatal("release notes not escaped")
	}
	if res := w.post("/settings/update/start", url.Values{"version": {"v0.3.0"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown version accepted: %d", res.StatusCode)
	}
	res := w.post("/settings/update/start", url.Values{"version": {"v0.2.0"}})
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/settings/update?started=1" {
		t.Fatalf("start %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	list, _ := s.Activity.Query(ctx, logs.Filter{Action: "panel.update.start"})
	if len(list) != 1 || list[0].Status != "success" {
		t.Fatalf("%+v", list)
	}
	if dry, _ := s.Activity.Query(ctx, logs.Filter{Text: "hp-update.sh start v0.2.0"}); len(dry) == 0 {
		t.Fatal("helper not called (dry-run log)")
	}
	if code, body := w.get("/settings/update/status?started=1", true); code != 200 || !strings.Contains(body, `hx-trigger="every 2s"`) {
		t.Fatalf("status poll %d %s", code, body)
	}
	os.WriteFile(s.Update.StatusPath, []byte(`{"id":"1","from":"v0.1.0","to":"v0.2.0","state":"running","step":"health"}`), 0o644)
	if _, body := w.get("/settings/update/status", true); !strings.Contains(body, "sürüyor") || !strings.Contains(body, "every 2s") {
		t.Fatalf("running status: %s", body)
	}
	if res := w.post("/settings/update/start", url.Values{"version": {"v0.2.0"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatal("second update while running")
	}
	os.WriteFile(s.Update.StatusPath, []byte(`{"id":"1","from":"v0.1.0","to":"v0.2.0","state":"success","step":"done"}`), 0o644)
	if _, body := w.get("/settings/update/status?started=1", true); !strings.Contains(body, "başarılı") || strings.Contains(body, "every 2s") {
		t.Fatalf("finished status still polling: %s", body)
	}
	s.Update.RecordFinished(ctx)
	if done, _ := s.Activity.Query(ctx, logs.Filter{Action: "panel.update"}); len(done) < 2 {
		t.Fatalf("result not recorded: %+v", done)
	}

	// --- Taşıma: export ---
	if code, body := w.get("/settings/transfer", false); code != 200 || !strings.Contains(body, "master.key") {
		t.Fatalf("transfer page %d", code)
	}
	if res := w.post("/settings/transfer/export", url.Values{"passphrase": {"uzun-bir-parola"}, "passphrase2": {"başka-bir-parola"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("mismatch accepted %d", res.StatusCode)
	}
	if res := w.post("/settings/transfer/export", url.Values{"passphrase": {"kısa"}, "passphrase2": {"kısa"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("short accepted %d", res.StatusCode)
	}
	w.post("/customers", url.Values{"name": {"Acme"}})
	res = w.postBody("/settings/transfer/export", url.Values{"passphrase": {"uzun-bir-parola"}, "passphrase2": {"uzun-bir-parola"}})
	file, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !strings.HasPrefix(res.Header.Get("Content-Disposition"), `attachment; filename="hostpanel-config-srv1-`) ||
		!bytes.HasPrefix(file, []byte(panelcfg.Magic)) {
		t.Fatalf("export %d %q %v", res.StatusCode, file[:min(len(file), 40)], res.Header.Get("Content-Disposition"))
	}
	arc, err := panelcfg.Open(bytes.NewReader(file), "uzun-bir-parola")
	if err != nil || arc.Manifest.Customers != 1 || arc.Manifest.Server != "srv1" {
		t.Fatalf("%+v %v", arc, err)
	}
	if ex, _ := s.Activity.Query(ctx, logs.Filter{Action: "panel.export"}); len(ex) != 1 || strings.Contains(ex[0].Params, "uzun-bir-parola") {
		t.Fatalf("export activity %+v", ex)
	}
	// Export without the CSRF token is refused.
	plain := client()
	login(t, ts, plain)
	resp, _ := plain.PostForm(ts.URL+"/settings/transfer/export", url.Values{"passphrase": {"uzun-bir-parola"}, "passphrase2": {"uzun-bir-parola"}})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("export without CSRF: %d", resp.StatusCode)
	}
	resp.Body.Close()

	// --- Genel: varsayılanlar ---
	if res := w.post("/settings/general", url.Values{"retention_activity_days": {"3"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("retention 3 accepted %d", res.StatusCode)
	}
	if res := w.post("/settings/general", url.Values{"retention_activity_days": {"90"}, "retention_job_days": {"14"},
		"default_memory_mb": {"768"}, "default_cpu_pct": {"150"}}); res.StatusCode != 200 {
		t.Fatalf("save general %d", res.StatusCode)
	}
	if d := s.panelDefaults(ctx); d.ActivityDays != 90 || d.JobDays != 14 || d.MemoryMB != 768 || d.CPUPct != 150 {
		t.Fatalf("%+v", d)
	}
	if _, body := w.get("/sites/new", false); !strings.Contains(body, `name="memory_max_mb" min="64" max="65536" value="768"`) {
		t.Fatal("wizard does not use the default memory limit")
	}

	// --- panel domain is reserved ---
	s.Sites.PanelDomain = func() string { return "panel.example.com" }
	res = w.postBody("/sites", url.Values{"customer_id": {"1"}, "domain": {"panel.example.com"}, "runtime": {"static"}})
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusBadRequest || !strings.Contains(string(b), "panelin kendi adresi") {
		t.Fatalf("panel domain as site: %d", res.StatusCode)
	}

	// --- Log Merkezi: update log source ---
	os.WriteFile(s.Cfg.UpdateLogPath(), []byte("=== güncelleme v0.1.0 → v0.2.0\n"), 0o640)
	if code, body := w.get("/logs/system?source=update", false); code != 200 || !strings.Contains(body, "güncelleme v0.1.0") {
		t.Fatalf("update log source %d", code)
	}
}

// postBody is post without closing the body (downloads, error pages).
func (w webClient) postBody(path string, form url.Values) *http.Response {
	w.t.Helper()
	form.Set("_csrf", w.csrf)
	res, err := w.c.PostForm(w.ts.URL+path, form)
	if err != nil {
		w.t.Fatal(err)
	}
	return res
}
