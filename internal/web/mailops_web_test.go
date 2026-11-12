package web

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zahit5834/hostpanel/internal/rbl"
	"github.com/zahit5834/hostpanel/internal/ssl"
)

// rblRes answers blocklist lookups: the server IP is on SpamCop only.
type rblRes struct{}

func (rblRes) LookupHost(_ context.Context, h string) ([]string, error) {
	if h == "32.180.48.185.bl.spamcop.net" {
		return []string{"127.0.0.2"}, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: h, IsNotFound: true}
}

const testDMARCXML = `<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata><org_name>google.com</org_name><email>noreply-dmarc-support@google.com</email>
    <report_id>9988776655</report_id><date_range><begin>%d</begin><end>%d</end></date_range></report_metadata>
  <policy_published><domain>ornek.com</domain><adkim>r</adkim><aspf>r</aspf><p>quarantine</p><sp>quarantine</sp><pct>100</pct></policy_published>
  <record><row><source_ip>185.48.180.32</source_ip><count>12</count>
    <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
    <identifiers><header_from>ornek.com</header_from></identifiers>
    <auth_results><dkim><domain>ornek.com</domain><result>pass</result></dkim><spf><domain>ornek.com</domain><result>pass</result></spf></auth_results></record>
  <record><row><source_ip>203.0.113.7</source_ip><count>3</count>
    <policy_evaluated><disposition>quarantine</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
    <identifiers><header_from>ornek.com</header_from></identifiers>
    <auth_results><spf><domain>spoof.example</domain><result>softfail</result></spf></auth_results></record>
</feedback>`

func TestMailOpsWildcardRelocateDryRun(t *testing.T) {
	ts, s := newTestServer(t)
	c := client()
	w := webClient{t: t, ts: ts, c: c, csrf: login(t, ts, c)}
	ctx := context.Background()
	s.RBL = &rbl.Service{DB: s.DB, Box: s.SSL.Box, Resolver: rblRes{}, Targets: s.RBLTargets}
	s.Mail.ReportsDir = t.TempDir()

	w.post("/dns/settings", url.Values{"ns1": {"ns1.ornek.com"}, "ns2": {"ns2.ornek.com"},
		"hostmaster": {"hostmaster@ornek.com"}, "ips": {"185.48.180.32"}})
	w.post("/customers", url.Values{"name": {"Acme"}})
	w.post("/dns/zones", url.Values{"name": {"ornek.com"}, "customer_id": {"1"}})
	mustJob(t, s, w.post("/dns/install", url.Values{}))
	waitJob(t, s, jobFromLocation(t, w.post("/databases/docker", url.Values{"back": {"mail"}}).Header.Get("Location")))
	_, log := mustJob(t, s, w.post("/mail/server", url.Values{"hostname": {"mail.ornek.com"}, "domain": {"ornek.com"},
		"customer_id": {"1"}, "le_email": {"admin@ornek.com"}, "memory_mb": {"1024"}}))
	if !strings.Contains(log, "hp-mail.sh ratelimit") && !strings.Contains(log, "hp-mail.sh prepare") {
		t.Fatalf("install log:\n%s", log)
	}
	d, _ := s.Mail.Store.DomainByName(ctx, "ornek.com")
	dp := fmt.Sprintf("/mail/domains/%d", d.ID)
	for _, local := range []string{"ali", "dmarc"} {
		if res := w.postBody(dp+"/mailboxes", url.Values{"local": {local}, "quota_mb": {"0"}}); res.StatusCode != 200 {
			t.Fatalf("mailbox %s %d", local, res.StatusCode)
		}
	}
	mb := func(addr string) (bool, bool) {
		l, err := s.Mail.Listing(ctx)
		if err != nil {
			t.Fatal(err)
		}
		m, ok := l.Mailbox(addr)
		if !ok {
			t.Fatalf("no mailbox %s", addr)
		}
		return m.Suspended, m.SendBlocked
	}

	// --- P4 suspend / P3 send block (+ queue purge) ---
	if res := w.post(dp+"/mailboxes/suspend", url.Values{"address": {"ali@ornek.com"}}); res.StatusCode != 200 {
		t.Fatalf("suspend %d", res.StatusCode)
	}
	if sus, _ := mb("ali@ornek.com"); !sus {
		t.Fatal("not suspended")
	}
	if code, body := w.get(dp, false); code != 200 || !strings.Contains(body, "askıda") {
		t.Fatalf("domain page lacks the suspended badge (%d)", code)
	}
	w.post(dp+"/mailboxes/unsuspend", url.Values{"address": {"ali@ornek.com"}})
	if sus, _ := mb("ali@ornek.com"); sus {
		t.Fatal("still suspended")
	}
	if res := w.post(dp+"/mailboxes/block", url.Values{"address": {"ali@ornek.com"}, "purge": {"1"}}); res.StatusCode != 200 {
		t.Fatalf("block %d", res.StatusCode)
	}
	if _, blk := mb("ali@ornek.com"); !blk {
		t.Fatal("send not blocked")
	}
	if res := w.post(dp+"/mailboxes/block", url.Values{"address": {"yok@ornek.com"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatal("block of a missing mailbox")
	}
	w.post(dp+"/mailboxes/unblock", url.Values{"address": {"ali@ornek.com"}})
	if _, blk := mb("ali@ornek.com"); blk {
		t.Fatal("still blocked")
	}
	// Re-enabling needs a recent login.
	s.DB.Exec(`UPDATE sessions SET elevated_until=0`)
	if res := w.post(dp+"/mailboxes/unsuspend", url.Values{"address": {"ali@ornek.com"}}); res.StatusCode != http.StatusSeeOther ||
		!strings.HasPrefix(res.Header.Get("Location"), "/reauth") {
		t.Fatalf("unsuspend without elevation %d", res.StatusCode)
	}
	s.DB.Exec(`UPDATE sessions SET elevated_until=?`, 1<<40)

	// --- catch-all: only a mailbox of the panel ---
	if res := w.post(dp+"/catchall", url.Values{"target": {"x@gmail.com"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatal("external catch-all accepted")
	}
	if res := w.post(dp+"/catchall", url.Values{"target": {"ali@ornek.com"}}); res.StatusCode != 200 {
		t.Fatalf("catch-all %d", res.StatusCode)
	}
	if l, _ := s.Mail.Listing(ctx); l.CatchAll["ornek.com"] != "ali@ornek.com" {
		t.Fatalf("catch-all %+v", l.CatchAll)
	}

	// --- limits ---
	if res := w.post("/mail/limits", url.Values{"rate_per_hour": {"5"}, "queue_alert": {"50"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatal("rate 5 accepted")
	}
	if res := w.post("/mail/limits", url.Values{"rate_per_hour": {"300"}, "queue_alert": {"20"}}); res.StatusCode != 200 {
		t.Fatalf("limits %d", res.StatusCode)
	}
	if srv, _ := s.Mail.Store.Server(ctx); srv.RatePerHour != 300 || srv.QueueAlert != 20 {
		t.Fatalf("limits not saved %+v", srv)
	}

	// --- P1 Apple profile: no password inside ---
	res, _ := c.Get(ts.URL + dp + "/mobileconfig?address=ali@ornek.com")
	prof := bodyOf(res)
	if res.StatusCode != 200 || res.Header.Get("Content-Type") != "application/x-apple-aspen-config" ||
		!strings.Contains(prof, "<string>mail.ornek.com</string>") || strings.Contains(prof, "<key>IncomingPassword</key>") {
		t.Fatalf("mobileconfig %d %q", res.StatusCode, res.Header.Get("Content-Type"))
	}
	if res, _ := c.Get(ts.URL + dp + "/mobileconfig?address=yok@ornek.com"); res.StatusCode != 404 {
		t.Fatal("profile for a missing mailbox")
	}
	_, log = mustJob(t, s, w.post("/mail/autoconf", url.Values{}))
	if !strings.Contains(log, "hp-mail.sh cert mail.ornek.com admin@ornek.com autoconf") || !s.Mail.AutoconfReady(ctx) {
		t.Fatalf("cert expand log:\n%s", log)
	}

	// --- P2 blocklists, DQS key never shown or logged ---
	if code, body := w.get("/mail/deliverability", false); code != 200 || !strings.Contains(body, "Henüz kontrol edilmedi") {
		t.Fatalf("deliverability %d", code)
	}
	if code, body := w.get("/mail/deliverability/senders", true); code != 200 || strings.Contains(body, "<html") {
		t.Fatalf("senders fragment %d", code)
	}
	body := bodyOf(w.postBody("/mail/rbl/check", url.Values{}))
	if !strings.Contains(body, "listede") || !strings.Contains(body, "185.48.180.32") {
		t.Fatalf("rbl result:\n%s", body)
	}
	var n int
	s.DB.QueryRow(`SELECT count(*) FROM activity_log WHERE action='mail.rbl.listed'`).Scan(&n)
	if n != 1 {
		t.Fatalf("rbl listed activity %d", n)
	}
	w.postBody("/mail/rbl/check", url.Values{}) // no second record for the same listing
	s.DB.QueryRow(`SELECT count(*) FROM activity_log WHERE action='mail.rbl.listed'`).Scan(&n)
	if n != 1 {
		t.Fatalf("rbl listing recorded twice (%d)", n)
	}
	if code, body := w.get("/", false); code != 200 || !strings.Contains(body, "kara liste") {
		t.Fatal("dashboard lacks the blocklist alert")
	}
	if code, body := w.get("/security", false); code != 200 || !strings.Contains(body, "Posta kara listeleri") {
		t.Fatal("audit lacks the blocklist row")
	}
	const dqs = "abcdefghijklmnopqrstuvwxyz"
	if res := w.post("/mail/rbl/key", url.Values{"dqs_key": {"kisa"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatal("short DQS key")
	}
	if body := bodyOf(w.postBody("/mail/rbl/key", url.Values{"dqs_key": {dqs}})); strings.Contains(body, dqs) || !s.RBL.HasKey(ctx) {
		t.Fatal("DQS key echoed / not saved")
	}

	// --- P5 DMARC: rua + policy in the zone, report parsed ---
	if res := w.post("/mail/dmarc/address", url.Values{"address": {"ali@ornek.com"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatal("non-dmarc@ report mailbox accepted")
	}
	if res := w.post("/mail/dmarc/address", url.Values{"address": {"dmarc@ornek.com"}}); res.StatusCode != 200 {
		t.Fatalf("report address %d", res.StatusCode)
	}
	if res := w.post(dp+"/dmarc", url.Values{"policy": {"reject"}}); res.StatusCode != 200 {
		t.Fatalf("policy %d", res.StatusCode)
	}
	waitIdle(t, s)
	z, _ := s.DNS.Store.ZoneByName(ctx, "ornek.com")
	preview, _, _ := s.DNS.Preview(ctx, z)
	for _, want := range []string{`_dmarc.ornek.com. 3600 IN TXT "v=DMARC1; p=reject; rua=mailto:dmarc@ornek.com"`,
		"_autodiscover._tcp.ornek.com. 3600 IN SRV 0 0 443 mail.ornek.com.", "_submissions._tcp.ornek.com. 3600 IN SRV 0 1 465 mail.ornek.com.",
		"autoconfig.ornek.com. 3600 IN A 185.48.180.32"} {
		if !strings.Contains(preview, want) {
			t.Fatalf("zone misses %q:\n%s", want, preview)
		}
	}
	var gz bytes.Buffer
	gw := gzip.NewWriter(&gz)
	fmt.Fprintf(gw, testDMARCXML, 1794355200, 1794441599)
	gw.Close()
	msg := "From: noreply-dmarc-support@google.com\r\nTo: dmarc@ornek.com\r\nSubject: Report domain: ornek.com\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: application/gzip; name=\"r.xml.gz\"\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
		base64.StdEncoding.EncodeToString(gz.Bytes()) + "\r\n"
	os.WriteFile(filepath.Join(s.Mail.ReportsDir, "1794441700.M1P2.mail"), []byte(msg), 0o640)
	broken := strings.Replace(msg, base64.StdEncoding.EncodeToString(gz.Bytes()), base64.StdEncoding.EncodeToString([]byte("bozuk gzip")), 1)
	os.WriteFile(filepath.Join(s.Mail.ReportsDir, "1794441701.M1P3.mail"), []byte(broken), 0o640)
	code, body := w.get("/mail/deliverability/dmarc", true)
	if code != 200 || !strings.Contains(body, "203.0.113.7") || !strings.Contains(body, "google.com") || !strings.Contains(body, "Okunamayan") {
		t.Fatalf("dmarc fragment %d:\n%s", code, body)
	}
	w.get("/mail/deliverability/dmarc", true) // second sync: files parsed once
	s.DB.QueryRow(`SELECT count(*) FROM dmarc_reports`).Scan(&n)
	if n != 1 {
		t.Fatalf("dmarc reports %d", n)
	}

	// --- T4 wildcard site + DNS-01 ---
	mustJob(t, s, w.post("/sites", url.Values{"customer_id": {"1"}, "domain": {"ornek.com"}, "runtime": {"static"}, "www_mode": {"none"},
		"field_index": {"index.html"}, "field_spa": {"hayır"}}))
	st, _ := s.Sites.Store.GetByDomain(ctx, "ornek.com")
	base := fmt.Sprintf("/sites/%d", st.ID)
	settings := url.Values{"www_mode": {"none"}, "field_index": {"index.html"}, "field_spa": {"hayır"}, "max_upload_mb": {"50"}, "wildcard": {"1"}}
	if res := w.post(base+"/settings", settings); res.StatusCode >= 400 {
		t.Fatalf("wildcard settings %d %s", res.StatusCode, bodyOf(res))
	}
	if st, _ = s.Sites.Store.Get(ctx, st.ID); !st.Wildcard {
		t.Fatal("wildcard not saved")
	}
	if conf, _ := s.Sites.RenderNginxFor(st); !strings.Contains(conf, "*.ornek.com;") {
		t.Fatalf("nginx:\n%s", conf)
	}
	waitIdle(t, s)
	if preview, _, _ = s.DNS.Preview(ctx, z); !strings.Contains(preview, "\n*.ornek.com. 3600 IN A 185.48.180.32\n") {
		t.Fatalf("no wildcard record:\n%s", preview)
	}
	if code, body := w.get(base+"/ssl/check", true); code != 200 || !strings.Contains(body, `value="*.ornek.com" checked`) ||
		strings.Contains(body, `value="dns" disabled`) {
		t.Fatalf("ssl check %d:\n%s", code, body)
	}
	if res := w.post(base+"/ssl/letsencrypt", url.Values{"names": {"ornek.com", "*.ornek.com"}, "email": {"admin@ornek.com"}, "method": {"http"}}); res.StatusCode != 400 {
		t.Fatal("wildcard over HTTP-01 accepted")
	}
	_, log = mustJob(t, s, w.post(base+"/ssl/letsencrypt", url.Values{"names": {"ornek.com", "*.ornek.com"}, "email": {"admin@ornek.com"},
		"method": {"dns"}, "staging": {"1"}}))
	if !strings.Contains(log, "hp-ssl.sh issue ornek.com admin@ornek.com dns 1 0 ornek.com *.ornek.com") {
		t.Fatalf("LE log:\n%s", log)
	}
	if cert, err := s.SSL.Store.Active(ctx, st.ID); err != nil || cert.Challenge != "dns-01" || !strings.Contains(strings.Join(cert.Names, " "), "*.ornek.com") {
		t.Fatalf("cert %+v %v", cert, err)
	}
	// A site outside the panel's zones can't serve *.
	mustJob(t, s, w.post("/sites", url.Values{"customer_id": {"1"}, "domain": {"baska.org"}, "runtime": {"static"}, "www_mode": {"none"},
		"field_index": {"index.html"}, "field_spa": {"hayır"}}))
	other, _ := s.Sites.Store.GetByDomain(ctx, "baska.org")
	if res := w.post(fmt.Sprintf("/sites/%d/settings", other.ID), settings); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("wildcard without a zone %d", res.StatusCode)
	}
	if err := s.SSL.DNSReady(ctx, ssl.SiteNames(other)); err == nil {
		t.Fatal("DNS-01 ready outside the zones")
	}

	// --- T2 relocation (MSSQL) ---
	mustJob(t, s, w.post("/databases/server", url.Values{"edition": {"Express"}, "memory_mb": {"2048"}, "accept_eula": {"1"}}))
	if code, body := w.get("/security", false); code != 200 || !strings.Contains(body, "/var/lib/hostpanel-db") {
		t.Fatal("audit lacks the relocation hint")
	}
	if res := w.post("/databases/server/relocate", url.Values{"confirm": {"x"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatal("relocate without confirmation")
	}
	_, log = mustJob(t, s, w.post("/databases/server/relocate", url.Values{"confirm": {relocateConfirm}}))
	for _, want := range []string{"hp-mssql.sh remove-container", "hp-mssql.sh relocate to-new", "hp-mssql.sh create "} {
		if !strings.Contains(log, want) {
			t.Fatalf("relocate log misses %q:\n%s", want, log)
		}
	}

	// --- nothing secret in activity / jobs ---
	for _, secret := range []string{dqs} {
		s.DB.QueryRow(`SELECT count(*) FROM activity_log WHERE params LIKE ? OR summary LIKE ? OR diff LIKE ? OR error LIKE ?`,
			"%"+secret+"%", "%"+secret+"%", "%"+secret+"%", "%"+secret+"%").Scan(&n)
		if n != 0 {
			t.Fatalf("%q in the activity log", secret)
		}
		jl, _ := s.Jobs.List(ctx, "", "", "", 0, 500)
		for _, j := range jl {
			if strings.Contains(j.Params, secret) || strings.Contains(jobLog(t, s, j.ID), secret) {
				t.Fatalf("secret in job %d", j.ID)
			}
		}
	}
}
