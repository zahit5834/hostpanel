package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zahit5834/hostpanel/internal/hostsec"
	"github.com/zahit5834/hostpanel/internal/logs"
)

const testPubKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl yeni@dizustu"

// Faz 11 end to end in dry-run: re-auth, sessions, SSH apply/confirm/revert and
// keys, fail2ban, updates job, reboot plan, services, audit page, and the
// security notifications (which must never carry secrets).
func TestHostSecurityDryRun(t *testing.T) {
	ts, s := newTestServer(t)
	c := client()
	w := webClient{t: t, ts: ts, c: c, csrf: login(t, ts, c)}
	ctx := context.Background()

	// Notifications through a fake Telegram API: every security event is captured.
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
	nctx, stop := context.WithCancel(ctx)
	defer stop()
	go s.Notify.Run(nctx)
	token := "123456789:AAbbCCddEEffGGhhIIjjKKllMMnnOOppQQ"
	if code, _ := w.postHX("/settings/notify", url.Values{"telegram_on": {"1"}, "telegram_token": {token}, "telegram_chat": {"42"},
		"smtp_port": {"587"}, "kind": {"security", "system"}}); code != 200 {
		t.Fatalf("notify save %d", code)
	}

	// --- server tabs render ---
	for _, tab := range []string{"general", "updates", "ssh", "fail2ban", "ufw"} {
		if code, body := w.get("/server?tab="+tab, false); code != 200 || !strings.Contains(body, `class="active">`) {
			t.Fatalf("tab %s %d", tab, code)
		}
	}
	if code, body := w.get("/server/part/upd", true); code != 200 || !strings.Contains(body, "güvenlik") {
		t.Fatalf("upd %d %s", code, body)
	}

	// --- G1 SSH ---
	code, body := w.get("/server?tab=ssh", false)
	if code != 200 || !strings.Contains(body, "admin@laptop") || !strings.Contains(body, "son giriş") {
		t.Fatalf("ssh tab %d", code)
	}
	// root=yes while password login goes off is refused.
	if code, body = w.postHX("/server/ssh/apply", url.Values{"password": {"no"}, "root": {"yes"}}); code != 400 {
		t.Fatalf("root yes + password off accepted: %d %s", code, body)
	}
	if code, body = w.postHX("/server/ssh/apply", url.Values{"password": {"no"}, "root": {"prohibit-password"}}); code != 200 ||
		!strings.Contains(body, "onay bekliyor") || !strings.Contains(body, `x-data="countdown"`) || !strings.Contains(body, `hx-trigger="every 5s"`) {
		t.Fatalf("apply %d %s", code, body)
	}
	// A second change while one is pending is refused.
	if code, _ = w.postHX("/server/ssh/apply", url.Values{"password": {"yes"}, "root": {"no"}}); code != 400 {
		t.Fatalf("second apply %d", code)
	}
	if code, body = w.postHX("/server/ssh/confirm", nil); code != 200 || !strings.Contains(body, "kalıcı") {
		t.Fatalf("confirm %d %s", code, body)
	}
	st, _ := s.SSH.Status(ctx)
	if !st.PasswordOff() || st.RootMode() != "prohibit-password" || st.Pending {
		t.Fatalf("%+v", st)
	}
	// Apply + revert restores the confirmed state.
	w.postHX("/server/ssh/apply", url.Values{"password": {"yes"}, "root": {"no"}})
	if code, _ = w.postHX("/server/ssh/revert", nil); code != 200 {
		t.Fatalf("revert %d", code)
	}
	if st, _ = s.SSH.Status(ctx); !st.PasswordOff() || st.Pending {
		t.Fatalf("after revert %+v", st)
	}

	// Keys: bad lines are refused, a good one is added; the key used for the
	// last login needs force, and the last key cannot go while password login is off.
	for _, bad := range []string{`command="/bin/sh" ` + testPubKey, "ssh-dss AAAAB3NzaC1kc3MAAACBAP x", testPubKey + "\nssh-ed25519 AAAA x"} {
		if code, _ = w.postHX("/server/ssh/keys", url.Values{"user": {"ubuntu"}, "key": {bad}}); code != 400 {
			t.Fatalf("bad key accepted (%d): %q", code, bad)
		}
	}
	if code, _ = w.postHX("/server/ssh/keys", url.Values{"user": {"www-data"}, "key": {testPubKey}}); code != 400 {
		t.Fatalf("non-admin user accepted: %d", code)
	}
	if code, body = w.postHX("/server/ssh/keys", url.Values{"user": {"ubuntu"}, "key": {testPubKey}}); code != 200 || !strings.Contains(body, "yeni@dizustu") {
		t.Fatalf("key add %d %s", code, body)
	}
	oldFP, _ := hostsec.FakeFingerprint("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKlEk+Xrz/i41WqjQPxzg3PwrmFRoDaBHz6Vo6g0TAzL admin@laptop")
	newFP, _ := hostsec.FakeFingerprint(testPubKey)
	if code, _ = w.postHX("/server/ssh/keys/delete", url.Values{"user": {"ubuntu"}, "fp": {oldFP}}); code != 409 {
		t.Fatalf("last-login key deleted without force: %d", code)
	}
	if code, _ = w.postHX("/server/ssh/keys/delete", url.Values{"user": {"ubuntu"}, "fp": {oldFP}, "force": {"1"}}); code != 200 {
		t.Fatalf("forced delete %d", code)
	}
	if code, _ = w.postHX("/server/ssh/keys/delete", url.Values{"user": {"ubuntu"}, "fp": {newFP}, "force": {"1"}}); code != 409 {
		t.Fatalf("last key deleted while password login is off: %d", code)
	}

	// --- G2 fail2ban ---
	if code, body = w.get("/server?tab=fail2ban", false); code != 200 || !strings.Contains(body, "198.51.100.23") {
		t.Fatalf("f2b tab %d", code)
	}
	for _, bad := range []url.Values{
		{"maxretry": {"1"}, "findtime": {"15"}, "bantime": {"60"}, "ignore": {"203.0.113.10"}},
		{"maxretry": {"5"}, "findtime": {"15"}, "bantime": {"60"}, "ignore": {"0.0.0.0/0"}},
	} {
		if code, _ = w.postHX("/server/f2b/config", bad); code != 400 {
			t.Fatalf("bad f2b config accepted: %d %v", code, bad)
		}
	}
	if code, body = w.postHX("/server/f2b/config", url.Values{"maxretry": {"4"}, "findtime": {"30"}, "bantime": {"120"},
		"recidive": {"1"}, "ignore": {"203.0.113.10\n198.51.100.0/24"}}); code != 200 || !strings.Contains(body, "Kaydedildi") {
		t.Fatalf("f2b config %d %s", code, body)
	}
	if code, body = w.postHX("/server/f2b/unban", url.Values{"jail": {"sshd"}, "ip": {"185.48.180.8"}}); code != 200 || strings.Contains(body, "<code>185.48.180.8</code>") {
		t.Fatalf("unban %d", code)
	}
	if code, _ = w.postHX("/server/f2b/unban", url.Values{"jail": {"sshd;x"}, "ip": {"1.2.3.4"}}); code != 400 {
		t.Fatalf("bad jail accepted: %d", code)
	}

	// --- S1 updates job ---
	res := w.post("/server/apt/run", url.Values{"mode": {"security"}})
	if res.StatusCode != http.StatusSeeOther || !strings.HasPrefix(res.Header.Get("Location"), "/logs/jobs/") {
		t.Fatalf("apt run %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	if j := waitJob(t, s, jobFromLocation(t, res.Header.Get("Location"))); j.Status != "success" {
		t.Fatalf("apt job %+v", j)
	}
	if res = w.post("/server/apt/run", url.Values{"mode": {"dist-upgrade"}}); res.StatusCode != 400 {
		t.Fatalf("bad mode %d", res.StatusCode)
	}

	// --- S2 reboot ---
	if res = w.post("/server/reboot", url.Values{"when": {"+10"}, "confirm": {"evet"}}); res.StatusCode != 400 {
		t.Fatalf("reboot without confirm word %d", res.StatusCode)
	}
	if res = w.post("/server/reboot", url.Values{"when": {"+10; rm"}, "confirm": {"YENIDEN-BASLAT"}}); res.StatusCode != 400 {
		t.Fatalf("bad when %d", res.StatusCode)
	}
	if res = w.post("/server/reboot", url.Values{"when": {"+10"}, "confirm": {"YENIDEN-BASLAT"}}); res.StatusCode != 200 {
		t.Fatalf("reboot plan %d", res.StatusCode)
	}
	if code, body = w.get("/server?tab=updates", false); !strings.Contains(body, "Planlı yeniden başlatma") {
		t.Fatalf("planned reboot not shown %d", code)
	}
	if res = w.post("/server/reboot/cancel", nil); res.StatusCode != 200 {
		t.Fatalf("cancel %d", res.StatusCode)
	}

	// --- S5 services ---
	if res = w.post("/server/service", url.Values{"action": {"restart"}, "name": {"docker"}}); res.StatusCode != 400 {
		t.Fatalf("docker restart without confirm %d", res.StatusCode)
	}
	if res = w.post("/server/service", url.Values{"action": {"restart"}, "name": {"ssh"}}); res.StatusCode == 200 {
		t.Fatal("ssh restart accepted")
	}
	if res = w.post("/server/service", url.Values{"action": {"reload"}, "name": {"nginx"}}); res.StatusCode != 200 {
		t.Fatalf("nginx reload %d", res.StatusCode)
	}
	if got, _ := s.Activity.Query(ctx, logs.Filter{Action: "service.reload"}); len(got) != 1 || got[0].Status != "success" {
		t.Fatalf("%+v", got)
	}

	// --- G3 audit page ---
	if code, body = w.get("/security", false); code != 200 || !strings.Contains(body, "Güvenlik denetimi") || !strings.Contains(body, "SSH") {
		t.Fatalf("audit %d", code)
	}

	// --- G4 re-auth: drop the elevation, critical actions redirect ---
	s.DB.Exec(`UPDATE sessions SET elevated_until=0`)
	req, _ := http.NewRequest("POST", ts.URL+"/server/ssh/apply", strings.NewReader(url.Values{"_csrf": {w.csrf}, "password": {"yes"}, "root": {"no"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", ts.URL+"/server?tab=ssh")
	res, _ = c.Do(req)
	res.Body.Close()
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/reauth?next="+url.QueryEscape("/server?tab=ssh") {
		t.Fatalf("not elevated: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	if code, _ = w.postHX("/server/ufw", url.Values{"action": {"allow"}, "port": {"8081"}, "proto": {"tcp"}}); code != 403 {
		t.Fatalf("hx not elevated %d", code)
	}
	if st, _ = s.SSH.Status(ctx); st.Pending {
		t.Fatal("action ran without elevation")
	}
	if code, body = w.get("/reauth?next=//evil.example/x", false); code != 200 || !strings.Contains(body, `name="next" value="/"`) {
		t.Fatalf("next not sanitised %d", code)
	}
	if res = w.post("/reauth", url.Values{"password": {"wrong"}, "next": {"/server?tab=ssh"}}); res.StatusCode != 401 {
		t.Fatalf("wrong password %d", res.StatusCode)
	}
	if res = w.post("/reauth", url.Values{"password": {"correct-horse-1"}, "next": {"/server?tab=ssh"}}); res.StatusCode != 303 ||
		res.Header.Get("Location") != "/server?tab=ssh" {
		t.Fatalf("reauth %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	if code, _ = w.postHX("/server/ssh/apply", url.Values{"password": {"yes"}, "root": {"no"}}); code != 200 {
		t.Fatalf("after reauth %d", code)
	}
	w.postHX("/server/ssh/revert", nil)

	// --- G5 sessions: a second login shows up and can be revoked ---
	c2 := client()
	login(t, ts, c2)
	if code, body = w.get("/settings/security", false); code != 200 || !strings.Contains(body, "bu cihaz") ||
		!strings.Contains(body, "Diğer tüm oturumları kapat") || !strings.Contains(body, "başarılı") {
		t.Fatalf("sessions %d", code)
	}
	if res = w.post("/settings/sessions/others/revoke", nil); res.StatusCode != 303 {
		t.Fatalf("revoke others %d", res.StatusCode)
	}
	if res, _ = c2.Get(ts.URL + "/"); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("revoked session still works: %d", res.StatusCode)
	}
	res.Body.Close()
	if res = w.post("/settings/sessions/"+strings.Repeat("0", 64)+"/revoke", nil); res.StatusCode != 404 {
		t.Fatalf("unknown session %d", res.StatusCode)
	}

	// --- notifications: security events went out, no secrets in them ---
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		all := strings.Join(texts, "\n---\n")
		mu.Unlock()
		if strings.Contains(all, "SSH değişikliği onaylandı") && strings.Contains(all, "fail2ban ayarları") &&
			strings.Contains(all, "SSH anahtarı eklendi") && strings.Contains(all, "yeniden başlatılacak") &&
			strings.Contains(all, "oturumları kapatıldı") {
			for _, secret := range []string{token, "correct-horse-1", "AAAAC3NzaC1lZDI1NTE5AAAAIOMqq"} {
				if strings.Contains(all, secret) {
					t.Fatalf("secret %q in notifications:\n%s", secret, all)
				}
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("missing notifications:\n%s", all)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
