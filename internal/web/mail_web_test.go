package web

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/zahit5834/hostpanel/internal/backups"
	"github.com/zahit5834/hostpanel/internal/jobs"
	"github.com/zahit5834/hostpanel/internal/mail"
)

var passRe = regexp.MustCompile(`<code id="mb-pass">([^<]+)</code>`)

func TestMailLifecycleDryRun(t *testing.T) {
	ts, s := newTestServer(t)
	c := client()
	w := webClient{t: t, ts: ts, c: c, csrf: login(t, ts, c)}
	ctx := context.Background()

	// DNS first, so the mail records land in a panel zone.
	w.post("/dns/settings", url.Values{"ns1": {"ns1.ornek.com"}, "ns2": {"ns2.ornek.com"},
		"hostmaster": {"hostmaster@ornek.com"}, "ips": {"185.48.180.32, 2a01:4f8::1"}})
	w.post("/customers", url.Values{"name": {"Acme"}})
	w.post("/dns/zones", url.Values{"name": {"ornek.com"}, "customer_id": {"1"}})
	mustJob(t, s, w.post("/dns/install", url.Values{}))

	// 1. Docker → install.
	if code, body := w.get("/mail", false); code != 200 || !strings.Contains(body, "Docker'ı kur") || !strings.Contains(body, `href="/mail" class="active"`) {
		t.Fatalf("mail page %d", code)
	}
	res := w.post("/databases/docker", url.Values{"back": {"mail"}})
	if loc := res.Header.Get("Location"); !strings.HasPrefix(loc, "/mail?job=") {
		t.Fatalf("docker redirect %q", loc)
	}
	waitJob(t, s, jobFromLocation(t, res.Header.Get("Location")))
	if code, body := w.get("/mail", false); code != 200 || !strings.Contains(body, mail.DefaultImage) {
		t.Fatalf("install form %d", code)
	}
	form := url.Values{"hostname": {"mail.ornek.com"}, "domain": {"ornek.com"}, "customer_id": {"1"},
		"le_email": {"admin@ornek.com"}, "memory_mb": {"1024"}}
	bad := url.Values{}
	for k, v := range form {
		bad[k] = v
	}
	bad.Set("domain", "mail.ornek.com")
	if res := w.post("/mail/server", bad); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("host = domain accepted: %d", res.StatusCode)
	}
	_, log := mustJob(t, s, w.post("/mail/server", form))
	for _, want := range []string{"hp-mail.sh precheck mail.ornek.com", "hp-mail.sh prepare ornek.com", "hp-mail.sh vhost mail.ornek.com",
		"hp-mail.sh cert mail.ornek.com admin@ornek.com", "hp-mail.sh create " + mail.DefaultImage + " mail.ornek.com 1024 0 25 ornek.com",
		"hp-mail.sh wait", "hp-mail.sh dkim ornek.com"} {
		if !strings.Contains(log, want) {
			t.Fatalf("install log misses %q:\n%s", want, log)
		}
	}
	if code, body := w.get("/mail/status", true); code != 200 || strings.Contains(body, "<html") || !strings.Contains(body, "healthy") {
		t.Fatalf("status fragment %d %s", code, body)
	}
	if code, body := w.get("/mail/ops", true); code != 200 || !strings.Contains(body, "Engellenen IP yok") {
		t.Fatalf("ops fragment %d", code)
	}
	if code, body := w.postHX("/mail/check", url.Values{}); code != 200 || !strings.Contains(body, "dry-run") {
		t.Fatalf("check %d %s", code, body)
	}

	// The mail host is no site name; a site can't take it either.
	if res := w.post("/sites", url.Values{"customer_id": {"1"}, "domain": {"mail.ornek.com"}, "runtime": {"static"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("site on the mail host %d", res.StatusCode)
	}

	// 2. DNS: MX/SPF/DKIM/DMARC + A for the host (no AAAA) in the zone.
	waitIdle(t, s)
	z, _ := s.DNS.Store.ZoneByName(ctx, "ornek.com")
	preview, _, _ := s.DNS.Preview(ctx, z)
	for _, want := range []string{"ornek.com. 3600 IN MX 10 mail.ornek.com.", `ornek.com. 3600 IN TXT "v=spf1 mx ~all"`,
		"mail._domainkey.ornek.com. 3600 IN TXT \"v=DKIM1; k=rsa; p=", "_dmarc.ornek.com. 3600 IN TXT", "mail.ornek.com. 3600 IN A 185.48.180.32"} {
		if !strings.Contains(preview, want) {
			t.Fatalf("zone misses %q:\n%s", want, preview)
		}
	}
	if strings.Contains(preview, "mail.ornek.com. 3600 IN AAAA") {
		t.Fatalf("AAAA for the mail host:\n%s", preview)
	}

	// 3. Domain page; mailbox with a generated password shown once.
	d, _ := s.Mail.Store.DomainByName(ctx, "ornek.com")
	dp := fmt.Sprintf("/mail/domains/%d", d.ID)
	if code, body := w.get(dp, false); code != 200 || !strings.Contains(body, "postmaster@ornek.com") || !strings.Contains(body, "zone'u panelin DNS'inde") {
		t.Fatalf("domain page %d", code)
	}
	res = w.postBody(dp+"/mailboxes", url.Values{"local": {"ali"}, "quota_mb": {"1024"}})
	body := bodyOf(res)
	m := passRe.FindStringSubmatch(body)
	if res.StatusCode != 200 || m == nil || len(m[1]) != 20 {
		t.Fatalf("create mailbox %d", res.StatusCode)
	}
	pw := m[1]
	if code, body := w.get(dp, false); code != 200 || strings.Contains(body, pw) || !strings.Contains(body, "ali@ornek.com") {
		t.Fatal("password shown again / mailbox missing")
	}
	res = w.postBody(dp+"/mailboxes/password", url.Values{"address": {"ali@ornek.com"}, "password": {"Elle-Girilen-1"}})
	if b := bodyOf(res); res.StatusCode != 200 || !strings.Contains(b, "Elle-Girilen-1") {
		t.Fatalf("reset %d", res.StatusCode)
	}
	if res := w.post(dp+"/mailboxes/password", url.Values{"address": {"ali@ornek.com"}, "password": {"kisa"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatal("short password accepted")
	}
	if res := w.post(dp+"/mailboxes/quota", url.Values{"address": {"ali@ornek.com"}, "quota_mb": {"0"}}); res.StatusCode != 200 {
		t.Fatalf("quota %d", res.StatusCode)
	}
	if res := w.post(dp+"/aliases", url.Values{"local": {"info"}, "target": {"ali@ornek.com"}}); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("alias %d", res.StatusCode)
	}
	if res := w.post(dp+"/aliases", url.Values{"local": {"ali"}, "target": {"x@gmail.com"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatal("alias on a mailbox")
	}
	if res := w.post(dp+"/delete", url.Values{"confirm": {"ornek.com"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatal("domain with mailboxes deleted")
	}
	if res := w.post(dp+"/mailboxes/delete", url.Values{"address": {"ali@ornek.com"}, "confirm": {"yanlis"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatal("delete without confirmation")
	}
	_, log = mustJob(t, s, w.post(dp+"/mailboxes/delete", url.Values{"address": {"ali@ornek.com"}, "confirm": {"ali@ornek.com"}}))
	if !strings.Contains(log, "hp-mail.sh account-del ali@ornek.com") {
		t.Fatalf("delete log:\n%s", log)
	}
	l, _ := s.Mail.Listing(ctx)
	if l.HasMailbox("ali@ornek.com") || len(l.Aliases) != 0 {
		t.Fatalf("after delete %+v", l)
	}

	// 4. A second domain outside the panel's zones: copy-paste records.
	res = w.post("/mail/domains", url.Values{"name": {"baska.net"}, "customer_id": {"1"}})
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("domain add %d", res.StatusCode)
	}
	if code, body := w.get(res.Header.Get("Location"), false); code != 200 || !strings.Contains(body, "DNS sağlayıcısına") || !strings.Contains(body, "mail._domainkey.baska.net") {
		t.Fatalf("records table %d", code)
	}
	if code, body := w.get("/customers/1", false); code != 200 || !strings.Contains(body, "baska.net") {
		t.Fatalf("customer page misses mail domains (%d)", code)
	}

	// 5. Settings → recreate.
	if res := w.post("/mail/server/settings", url.Values{"memory_mb": {"1024"}, "clamav": {"1"}, "msg_limit_mb": {"25"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatal("ClamAV with 1 GB")
	}
	_, log = mustJob(t, s, w.post("/mail/server/settings", url.Values{"memory_mb": {"3072"}, "clamav": {"1"}, "msg_limit_mb": {"50"}}))
	if !strings.Contains(log, "hp-mail.sh remove") || !strings.Contains(log, "3072 1 50 ornek.com") {
		t.Fatalf("recreate log:\n%s", log)
	}

	// 6. Backup + plan scope + restore.
	_, log = mustJob(t, s, w.post("/mail/backup", url.Values{}))
	if !strings.Contains(log, "hp-mail.sh backup ") {
		t.Fatalf("backup log:\n%s", log)
	}
	bl, _ := s.Backups.Store.Backups(ctx, backups.Filter{Domain: backups.MailDomain})
	if len(bl) != 1 || !bl[0].Local {
		t.Fatalf("%+v", bl)
	}
	if code, body := w.get("/mail", false); code != 200 || !strings.Contains(body, bl[0].Name) {
		t.Fatal("backup not listed")
	}
	if res := w.post(fmt.Sprintf("/mail/backups/%d/restore", bl[0].ID), url.Values{"confirm": {"x"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatal("restore without confirmation")
	}
	_, log = mustJob(t, s, w.post(fmt.Sprintf("/mail/backups/%d/restore", bl[0].ID), url.Values{"confirm": {bl[0].Name}}))
	if !strings.Contains(log, "hp-mail.sh restore "+bl[0].Name) {
		t.Fatalf("restore log:\n%s", log)
	}
	res = w.post("/backups/plans", url.Values{"name": {"posta gece"}, "scope": {"mail"}, "kind": {"daily"}, "time": {"04:00"},
		"destination": {"local"}, "keep_local": {"3"}})
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("mail plan %d", res.StatusCode)
	}
	plans, _ := s.Backups.Store.Plans(ctx)
	if len(plans) != 1 || plans[0].Scope != backups.ScopeMail {
		t.Fatalf("%+v", plans)
	}

	// 7. Log center source; no password anywhere in the activity log.
	if code, body := w.get("/logs/system?source=mail", false); code != 200 || !strings.Contains(body, "Posta sunucusu") {
		t.Fatalf("log source %d", code)
	}
	for _, secret := range []string{pw, "Elle-Girilen-1"} {
		var n int
		s.DB.QueryRow(`SELECT count(*) FROM activity_log WHERE params LIKE ? OR summary LIKE ? OR diff LIKE ? OR error LIKE ?`,
			"%"+secret+"%", "%"+secret+"%", "%"+secret+"%", "%"+secret+"%").Scan(&n)
		if n != 0 {
			t.Fatalf("password %q in the activity log", secret)
		}
		jl, _ := s.Jobs.List(ctx, "", "", "", 0, 500)
		for _, j := range jl {
			if strings.Contains(j.Params, secret) || strings.Contains(jobLog(t, s, j.ID), secret) {
				t.Fatalf("password in job %d", j.ID)
			}
		}
	}
}

// waitIdle waits for queued jobs (dns.apply after mail changes).
func waitIdle(t *testing.T, s *Server) {
	t.Helper()
	jl, _ := s.Jobs.List(context.Background(), "", "", "", 0, 500)
	for _, j := range jl {
		if j.Status == jobs.StatusQueued || j.Status == jobs.StatusRunning {
			waitJob(t, s, j.ID)
		}
	}
}

func bodyOf(res *http.Response) string {
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return string(b)
}
