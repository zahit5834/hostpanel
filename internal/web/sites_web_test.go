package web

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"hostpanel/internal/jobs"
	"hostpanel/internal/sites"
)

type webClient struct {
	t    *testing.T
	ts   *httptest.Server
	c    *http.Client
	csrf string
}

func (w webClient) get(path string, hx bool) (int, string) {
	w.t.Helper()
	req, _ := http.NewRequest("GET", w.ts.URL+path, nil)
	if hx {
		req.Header.Set("HX-Request", "true")
	}
	res, err := w.c.Do(req)
	if err != nil {
		w.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

func (w webClient) post(path string, form url.Values) *http.Response {
	w.t.Helper()
	if form == nil {
		form = url.Values{}
	}
	form.Set("_csrf", w.csrf)
	res, err := w.c.PostForm(w.ts.URL+path, form)
	if err != nil {
		w.t.Fatal(err)
	}
	res.Body.Close()
	return res
}

func waitJob(t *testing.T, s *Server, id int64) jobs.Job {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		j, err := s.Jobs.Get(context.Background(), id)
		if err == nil && j.Status != jobs.StatusQueued && j.Status != jobs.StatusRunning {
			return j
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("job %d did not finish", id)
	return jobs.Job{}
}

func jobFromLocation(t *testing.T, loc string) int64 {
	t.Helper()
	u, _ := url.Parse(loc)
	id, err := strconv.ParseInt(u.Query().Get("job"), 10, 64)
	if err != nil {
		if i := strings.LastIndex(u.Path, "/"); i >= 0 {
			id, err = strconv.ParseInt(u.Path[i+1:], 10, 64)
		}
	}
	if err != nil {
		t.Fatalf("no job in %q", loc)
	}
	return id
}

func testZip(t *testing.T) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, _ := zw.Create("App.dll")
	f.Write([]byte("fake"))
	zw.Close()
	return buf.Bytes()
}

// TestSiteLifecycleDryRun walks the whole UI flow in dry-run mode:
// customer → .NET site wizard → tabs → env → zip deploy → stop → bad snippet → delete.
func TestSiteLifecycleDryRun(t *testing.T) {
	ts, s := newTestServer(t)
	c := client()
	w := webClient{t: t, ts: ts, c: c, csrf: login(t, ts, c)}
	ctx := context.Background()

	// Customer
	res := w.post("/customers", url.Values{"name": {"Acme Ltd"}, "email": {"info@acme.test"}})
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/customers/1" {
		t.Fatalf("customer create %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	if code, body := w.get("/customers?q=acme", true); code != 200 || !strings.Contains(body, "Acme Ltd") || strings.Contains(body, "<html") {
		t.Fatalf("customer search fragment %d", code)
	}

	for _, p := range []string{"/customers", "/customers/1", "/customers/1/edit", "/customers/new", "/sites", "/sites/new", "/runtimes"} {
		if code, body := w.get(p, false); code != 200 {
			t.Fatalf("%s → %d\n%s", p, code, body)
		}
	}

	// Wizard runtime fields fragment
	code, body := w.get("/sites/runtime-fields?runtime=dotnet", true)
	if code != 200 || !strings.Contains(body, `value="10.0.14"`) || !strings.Contains(body, `name="field_entryPoint"`) {
		t.Fatalf("runtime fields %d:\n%s", code, body)
	}

	// Invalid domain re-renders the wizard with the error and keeps the runtime fields.
	res = w.post("/sites", url.Values{"customer_id": {"1"}, "domain": {"bad_domain"}, "runtime": {"dotnet"}, "version": {"10.0.14"}})
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad domain %d", res.StatusCode)
	}

	res = w.post("/sites", url.Values{"customer_id": {"1"}, "domain": {"Ornek.com.tr"}, "www_mode": {"to_apex"},
		"runtime": {"dotnet"}, "version": {"10.0.14"}, "field_entryPoint": {"App.dll"}, "memory_max_mb": {"256"}, "cpu_quota_pct": {"50"}})
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("site create %d", res.StatusCode)
	}
	if j := waitJob(t, s, jobFromLocation(t, res.Header.Get("Location"))); j.Status != jobs.StatusSuccess {
		t.Fatalf("create job %s: %s", j.Status, j.Error)
	}
	site, err := s.Sites.Store.GetByDomain(ctx, "ornek.com.tr")
	if err != nil || site.Status != sites.StatusAwaitingDeploy || site.Port < 5000 || site.MemoryMaxMB != 256 {
		t.Fatalf("site %+v %v", site, err)
	}
	base := "/sites/" + strconv.FormatInt(site.ID, 10)

	for _, tab := range []string{"", "?tab=deploy", "?tab=env", "?tab=settings", "?tab=logs", "?tab=logs&source=journal", "?tab=logs&source=access"} {
		if code, body := w.get(base+tab, false); code != 200 {
			t.Fatalf("tab %q → %d\n%s", tab, code, body)
		}
	}
	if code, body := w.get(base+"?tab=logs&part=logs&source=activity", true); code != 200 || !strings.Contains(body, `id="site-logs"`) || strings.Contains(body, "<html") {
		t.Fatalf("logs fragment %d", code)
	}

	// Start without a release is refused.
	if res := w.post(base+"/op/start", nil); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("start before deploy %d", res.StatusCode)
	}

	// Env: special characters survive; reserved keys are rejected.
	res = w.post(base+"/env", url.Values{"key": {"API_TOKEN", ""}, "value": {`a$b"c'd`, ""}})
	if res.StatusCode != 200 {
		t.Fatalf("env save %d", res.StatusCode)
	}
	env, _ := s.Sites.Env(ctx, site.ID)
	if env["API_TOKEN"] != `a$b"c'd` {
		t.Fatalf("env %q", env)
	}
	if res := w.post(base+"/env", url.Values{"bulk": {"ASPNETCORE_URLS=http://0.0.0.0:80"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("reserved env key accepted: %d", res.StatusCode)
	}

	// Upload without CSRF header is rejected (multipart bodies are not parsed for _csrf).
	var mp bytes.Buffer
	mw := multipart.NewWriter(&mp)
	fw, _ := mw.CreateFormFile("zip", "site.zip")
	fw.Write(testZip(t))
	mw.Close()
	req, _ := http.NewRequest("POST", ts.URL+base+"/deploy", bytes.NewReader(mp.Bytes()))
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if res, _ := c.Do(req); res.StatusCode != http.StatusForbidden {
		t.Fatalf("upload without csrf %d", res.StatusCode)
	}
	req, _ = http.NewRequest("POST", ts.URL+base+"/deploy", bytes.NewReader(mp.Bytes()))
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-CSRF-Token", w.csrf)
	req.Header.Set("HX-Request", "true")
	res, _ = c.Do(req)
	if res.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("upload %d %s", res.StatusCode, b)
	}
	if j := waitJob(t, s, jobFromLocation(t, res.Header.Get("HX-Redirect"))); j.Status != jobs.StatusSuccess {
		t.Fatalf("deploy job %s: %s", j.Status, j.Error)
	}
	site, _ = s.Sites.Store.Get(ctx, site.ID)
	if site.Status != sites.StatusRunning {
		t.Fatalf("after deploy status %s", site.Status)
	}
	if code, body := w.get(base+"?tab=deploy", false); code != 200 || !strings.Contains(body, "badge st-active") {
		t.Fatalf("deploy tab after deploy %d", code)
	}

	// Ops
	if res := w.post(base+"/op/stop", nil); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("stop %d", res.StatusCode)
	}
	if site, _ = s.Sites.Store.Get(ctx, site.ID); site.Status != sites.StatusStopped {
		t.Fatalf("status after stop %s", site.Status)
	}
	if res := w.post(base+"/op/bogus", nil); res.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown op %d", res.StatusCode)
	}

	// Settings: a forbidden snippet is refused and nothing changes.
	res = w.post(base+"/settings", url.Values{"www_mode": {"to_apex"}, "field_entryPoint": {"App.dll"}, "max_upload_mb": {"50"},
		"custom_snippet": {"include /etc/passwd;"}})
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad snippet %d", res.StatusCode)
	}
	res = w.post(base+"/settings", url.Values{"www_mode": {"none"}, "field_entryPoint": {"App.dll"}, "max_upload_mb": {"100"},
		"memory_max_mb": {"256"}, "cpu_quota_pct": {"50"}, "gzip": {"1"}, "custom_snippet": {"location /api/ { proxy_read_timeout 300s; }"}})
	if res.StatusCode != 200 {
		t.Fatalf("settings %d", res.StatusCode)
	}
	if site, _ = s.Sites.Store.Get(ctx, site.ID); site.MaxUploadMB != 100 || site.WWWMode != "none" {
		t.Fatalf("settings not saved %+v", site)
	}

	// Customer with sites cannot be deleted.
	if res := w.post("/customers/1/delete", nil); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("customer delete with sites %d", res.StatusCode)
	}

	// Delete requires the exact domain.
	if res := w.post(base+"/delete", url.Values{"confirm": {"yanlis.com"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("delete wrong confirm %d", res.StatusCode)
	}
	res = w.post(base+"/delete", url.Values{"confirm": {"ornek.com.tr"}})
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("delete %d", res.StatusCode)
	}
	if j := waitJob(t, s, jobFromLocation(t, res.Header.Get("Location"))); j.Status != jobs.StatusSuccess {
		t.Fatalf("delete job %s: %s", j.Status, j.Error)
	}
	if _, err := s.Sites.Store.Get(ctx, site.ID); err == nil {
		t.Fatal("site row still present")
	}
	if res := w.post("/customers/1/delete", nil); res.StatusCode != http.StatusNoContent {
		t.Fatalf("customer delete %d", res.StatusCode)
	}
}
