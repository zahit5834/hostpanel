package web

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/monitor"
)

func TestMonitoringDryRun(t *testing.T) {
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
	site, _ := s.Sites.Store.GetByDomain(ctx, "app.example.com")
	base := "/sites/" + strconv.FormatInt(site.ID, 10)
	res = w.multipartPost(base+"/deploy", nil, "zip", "site.zip", testZip(t))
	waitJob(t, s, jobFromLocation(t, res.Header.Get("HX-Redirect")))

	// --- dashboard: CPU % needs two polls; site table + health + backup columns ---
	code, body := w.get("/", false)
	if code != 200 || !strings.Contains(body, "app.example.com") || !strings.Contains(body, "Son yedek") {
		t.Fatalf("dashboard %d", code)
	}
	time.Sleep(50 * time.Millisecond)
	code, body = w.get("/?part=metrics", true)
	if code != 200 || !regexp.MustCompile(`<div class="label">CPU</div><div class="value">(%[0-9]+|—)</div>`).MatchString(body) ||
		strings.Contains(body, "Son İşlemler") {
		t.Fatalf("metrics fragment %d %s", code, body)
	}

	// --- health check card ---
	if _, body = w.get(base, false); !strings.Contains(body, "Sağlık kontrolü") {
		t.Fatal("health card missing")
	}
	code, body = w.postHX(base+"/health", url.Values{"enabled": {"1"}, "path": {"/bad path"}, "expect": {"0"}, "interval": {"60"}})
	if code != 400 || !strings.Contains(body, "Geçersiz yol") {
		t.Fatalf("%d %s", code, body)
	}
	code, body = w.postHX(base+"/health", url.Values{"enabled": {"1"}, "path": {"/healthz"}, "expect": {"200"}, "interval": {"60"}})
	if code != 200 || !strings.Contains(body, "Kaydedildi") {
		t.Fatalf("%d %s", code, body)
	}
	if code, body = w.postHX(base+"/health/check", nil); code != 200 || !strings.Contains(body, "ayakta") {
		t.Fatalf("check now %d %s", code, body)
	}
	hc, _ := s.Monitor.Store.Get(ctx, site.ID)
	if hc.Path != "/healthz" || hc.Expect != 200 || hc.Interval != 60 || hc.State != monitor.StateUp {
		t.Fatalf("%+v", hc)
	}
	if got, _ := s.Activity.Query(ctx, logs.Filter{Action: "site.health.settings"}); len(got) != 1 || !strings.Contains(got[0].Diff, "+ path=/healthz") {
		t.Fatalf("%+v", got)
	}

	// --- server page (dry-run sample UFW rules) ---
	code, body = w.get("/server", false)
	if code != 200 || !strings.Contains(body, "OpenSSH") || !strings.Contains(body, "korumalı") || !strings.Contains(body, "nginx") {
		t.Fatalf("server %d", code)
	}
	for _, p := range []string{"/server/part/apt", "/server/part/disk"} {
		if code, _ := w.get(p, true); code != 200 {
			t.Fatalf("%s %d", p, code)
		}
	}
	if code, body = w.postHX("/server/ufw", url.Values{"action": {"deny"}, "port": {"22"}, "proto": {"tcp"}}); code != 400 ||
		!strings.Contains(body, "korumalı port (22)") {
		t.Fatalf("deny 22: %d", code)
	}
	if code, _ = w.postHX("/server/ufw", url.Values{"action": {"allow"}, "port": {"80;id"}, "proto": {"tcp"}}); code != 400 {
		t.Fatal("bad port accepted")
	}
	code, body = w.postHX("/server/ufw", url.Values{"action": {"allow"}, "port": {"8081"}, "proto": {"tcp"}, "from": {"10.0.0.0/8"}})
	if code != 200 || !strings.Contains(body, "Kural eklendi") {
		t.Fatalf("add %d", code)
	}
	if got, _ := s.Activity.Query(ctx, logs.Filter{Text: "hp-server.sh ufw-add allow 8081 tcp 10.0.0.0/8"}); len(got) != 1 {
		t.Fatalf("dry-run command not recorded: %+v", got)
	}
	st, _ := s.ufwStatus(ctx)
	var openssh, custom string
	for _, r := range st.Rules {
		switch r.No {
		case 1:
			openssh = r.Line
		case 4:
			custom = r.Line
		}
	}
	if code, _ = w.postHX("/server/ufw/1/delete", url.Values{"hash": {ruleHashOf(openssh)}}); code != 403 {
		t.Fatalf("protected rule delete %d", code)
	}
	if code, _ = w.postHX("/server/ufw/4/delete", url.Values{"hash": {"0000000000000000"}}); code != 409 {
		t.Fatalf("stale hash %d", code)
	}
	if code, body = w.postHX("/server/ufw/4/delete", url.Values{"hash": {ruleHashOf(custom)}}); code != 200 || !strings.Contains(body, "Kural silindi") {
		t.Fatalf("delete %d", code)
	}
	if got, _ := s.Activity.Query(ctx, logs.Filter{Action: "server.ufw."}); len(got) != 2 {
		t.Fatalf("%+v", got)
	}

	// --- notifications: save + test through a fake Telegram API ---
	var mu sync.Mutex
	var texts []string
	tg := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		mu.Lock()
		texts = append(texts, r.PostFormValue("text"))
		mu.Unlock()
		rw.Write([]byte(`{"ok":true}`))
	}))
	defer tg.Close()
	s.Notify.TelegramAPI, s.Notify.Client = tg.URL, &http.Client{Timeout: 5 * time.Second}
	token := "123456789:AAbbCCddEEffGGhhIIjjKKllMMnnOOppQQ"
	code, body = w.postHX("/settings/notify", url.Values{"telegram_on": {"1"}, "telegram_token": {token}, "telegram_chat": {"42"},
		"smtp_port": {"587"}, "kind": {"site.status", "disk.high"}})
	if code != 200 || !strings.Contains(body, "kaydedildi") || strings.Contains(body, "AAbb") {
		t.Fatalf("save %d", code)
	}
	if code, body = w.postHX("/settings/notify/test", nil); code != 200 || !strings.Contains(body, "gönderildi") {
		t.Fatalf("test %d %s", code, body)
	}
	mu.Lock()
	if len(texts) != 1 || !strings.Contains(texts[0], "test bildirimi") {
		t.Fatalf("%q", texts)
	}
	mu.Unlock()
	if code, _ = w.get("/settings/notify", false); code != 200 {
		t.Fatal(code)
	}

	// --- system logs: every source renders; date filter; live tail ---
	for _, src := range systemSources {
		p := "/logs/system?source=" + src.ID
		if src.Site {
			p += "&site=" + strconv.FormatInt(site.ID, 10)
		}
		if code, _ := w.get(p, false); code != 200 {
			t.Fatalf("%s %d", src.ID, code)
		}
	}
	panelLog := s.Cfg.PanelLogPath()
	var lines strings.Builder
	for h := 8; h <= 12; h++ {
		ts := time.Date(2026, 11, 5, h, 0, 0, 0, time.Local).Format(time.RFC3339)
		lines.WriteString(`{"time":"` + ts + `","level":"INFO","msg":"saat-` + strconv.Itoa(h) + `"}` + "\n")
	}
	os.WriteFile(panelLog, []byte(lines.String()), 0o640)
	_, body = w.get("/logs/system?source=panel&since=2026-11-05T09:00&until=2026-11-05T11:00", true)
	if !strings.Contains(body, "saat-9") || !strings.Contains(body, "saat-11") || strings.Contains(body, "saat-8") || strings.Contains(body, "saat-12") {
		t.Fatalf("date filter: %s", body)
	}
	if _, body = w.get("/logs/system?source=panel&live=1", true); !strings.Contains(body, `sse-connect="/logs/system/stream?`) {
		t.Fatal("live tail element missing")
	}

	sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(sctx, "GET", ts.URL+"/logs/system/stream?source=panel&q=canli", nil)
	sres, err := c.Do(req)
	if err != nil || sres.StatusCode != 200 {
		t.Fatalf("stream %v", err)
	}
	defer sres.Body.Close()
	rd := bufio.NewReader(sres.Body)
	if l, _ := rd.ReadString('\n'); !strings.HasPrefix(l, ": connected") {
		t.Fatalf("%q", l)
	}
	f, _ := os.OpenFile(panelLog, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(`{"level":"INFO","msg":"atlanır"}` + "\n" + `{"level":"INFO","msg":"canli <b>satir</b>"}` + "\n")
	f.Close()
	for {
		l, err := rd.ReadString('\n')
		if err != nil {
			t.Fatalf("stream ended: %v", err)
		}
		if strings.Contains(l, "atlanır") {
			t.Fatal("text filter not applied to live lines")
		}
		if strings.HasPrefix(l, "data: ") && strings.Contains(l, "canli") {
			if !strings.Contains(l, "&lt;b&gt;") {
				t.Fatalf("not escaped: %q", l)
			}
			break
		}
	}
}

func ruleHashOf(line string) string { return funcs["ruleHash"].(func(string) string)(line) }
