package web

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/zahit5834/hostpanel/internal/dns"
	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/store"
)

// TestDNSLifecycleDryRun: settings → install → zone → records → automatic site
// records → delegation/local checks → wizard zone → zone delete.
func TestDNSLifecycleDryRun(t *testing.T) {
	ts, s := newTestServer(t)
	c := client()
	w := webClient{t: t, ts: ts, c: c, csrf: login(t, ts, c)}
	ctx := context.Background()
	dryRan := func(text string) bool {
		list, _ := s.Activity.Query(ctx, logs.Filter{Text: text})
		return len(list) > 0
	}

	code, body := w.get("/dns", false)
	if code != 200 || !strings.Contains(body, "DNS sunucusunu kur") || !strings.Contains(body, "185.48.180.32") {
		t.Fatalf("dns page %d", code)
	}
	if res := w.post("/dns/install", url.Values{}); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("install without settings: %d", res.StatusCode)
	}
	if res := w.post("/dns/settings", url.Values{"ns1": {"ns1.ornek.com"}, "ns2": {"ns1.ornek.com"},
		"hostmaster": {"hostmaster@ornek.com"}, "ips": {"185.48.180.32"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("same ns accepted: %d", res.StatusCode)
	}
	if res := w.post("/dns/settings", url.Values{"ns1": {"ns1.ornek.com"}, "ns2": {"ns2.ornek.com"},
		"hostmaster": {"hostmaster@ornek.com"}, "ips": {"10.0.0.1"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("private IP accepted: %d", res.StatusCode)
	}
	res := w.post("/dns/settings", url.Values{"ns1": {"NS1.ornek.com."}, "ns2": {"ns2.ornek.com"},
		"hostmaster": {"hostmaster@ornek.com"}, "ips": {"185.48.180.32, 2a01:4f8::1"}})
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("settings %d", res.StatusCode)
	}
	if st := s.DNS.Settings(ctx); st.NS1 != "ns1.ornek.com" || len(st.IPs) != 2 {
		t.Fatalf("%+v", st)
	}

	// Zones can be created before BIND exists; nothing is applied yet.
	w.post("/customers", url.Values{"name": {"Acme"}})
	res = w.post("/dns/zones", url.Values{"name": {"Ornek.com"}, "customer_id": {"1"}})
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/dns/zones/1" {
		t.Fatalf("zone create %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	if res := w.post("/dns/zones", url.Values{"name": {"ornek.com"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatal("duplicate zone accepted")
	}
	if res := w.post("/dns/zones", url.Values{"name": {"x.com;id"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatal("bad zone name accepted")
	}

	// Install: BIND + every stored zone + zone list.
	_, log := mustJob(t, s, w.post("/dns/install", url.Values{}))
	if !strings.Contains(log, "hp-dns.sh install") || !strings.Contains(log, "hp-dns.sh write-zone ornek.com") ||
		!strings.Contains(log, "hp-dns.sh sync-config") {
		t.Fatalf("install log:\n%s", log)
	}
	if !s.DNS.Installed(ctx) {
		t.Fatal("not marked installed")
	}

	// Records.
	z, _ := s.DNS.Store.ZoneByName(ctx, "ornek.com")
	zp := fmt.Sprintf("/dns/zones/%d", z.ID)
	for _, bad := range []url.Values{
		{"name": {"@"}, "type": {"CNAME"}, "value": {"x.ornek.com"}},
		{"name": {"www"}, "type": {"A"}, "value": {"999.1.1.1"}},
		{"name": {"x"}, "type": {"TXT"}, "value": {"a\nb"}},
		{"name": {"x"}, "type": {"PTR"}, "value": {"a.ornek.com"}},
	} {
		res := w.postBody(zp+"/records", bad)
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != http.StatusBadRequest || !strings.Contains(string(b), `class="alert err"`) {
			t.Errorf("bad record %v: %d", bad, res.StatusCode)
		}
	}
	_, log = mustJob(t, s, w.post(zp+"/records", url.Values{"name": {"@"}, "type": {"MX"}, "prio": {"10"}, "value": {"mail.ornek.com"}}))
	if !strings.Contains(log, "write-zone ornek.com") || strings.Contains(log, "sync-config") {
		t.Fatalf("record apply log:\n%s", log)
	}
	mustJob(t, s, w.post(zp+"/records", url.Values{"name": {"_dmarc"}, "type": {"TXT"}, "value": {`v=DMARC1; p=none; x="y"`}}))
	mustJob(t, s, w.post(zp+"/records", url.Values{"name": {"blog"}, "type": {"CNAME"}, "value": {"ornek.com"}}))
	if res := w.post(zp+"/records", url.Values{"name": {"blog"}, "type": {"A"}, "value": {"1.2.3.4"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatal("A next to CNAME accepted")
	}

	// A site in the zone gets automatic A/AAAA records; the site job triggers a re-render.
	res = w.post("/sites", url.Values{"customer_id": {"1"}, "domain": {"ornek.com"}, "runtime": {"static"}, "www_mode": {"to_www"},
		"aliases": {"blog.ornek.com"}, "field_index": {"index.html"}, "field_spa": {"hayır"}, "create_zone": {"1"}})
	mustJob(t, s, res)
	apply := latestJob(t, s, "dns.apply")
	if apply.Status != "success" || !strings.Contains(jobLog(t, s, apply.ID), "write-zone ornek.com") {
		t.Fatalf("no re-render after site create: %+v", apply)
	}
	if n, _ := s.DNS.Store.ZoneNames(ctx); len(n) != 1 {
		t.Fatalf("wizard created a second zone for a covered domain: %v", n)
	}
	code, body = w.get(zp, false)
	for _, want := range []string{"IN MX 10 mail.ornek.com.", "ornek.com. 3600 IN NS ns1.ornek.com.", "www.ornek.com. 3600 IN A 185.48.180.32",
		`IN TXT &#34;v=DMARC1; p=none; x=\&#34;y\&#34;&#34;`, "ns1.ornek.com. 3600 IN AAAA 2a01:4f8::1", "otomatik"} {
		if !strings.Contains(body, want) {
			t.Errorf("zone page lacks %q", want)
		}
	}
	if strings.Contains(body, "blog.ornek.com. 3600 IN A") {
		t.Error("auto record overrode the manual CNAME")
	}
	if code != 200 {
		t.Fatal(code)
	}
	preview, _, _ := s.DNS.Preview(ctx, z)
	if err := dns.ValidateZoneFile(preview, "ornek.com"); err != nil {
		t.Fatalf("%v\n%s", err, preview)
	}

	// Edit + delete.
	recs, _ := s.DNS.Store.Records(ctx, z.ID)
	var mx dns.Record
	for _, r := range recs {
		if r.Type == dns.TypeMX {
			mx = r
		}
	}
	mustJob(t, s, w.post(fmt.Sprintf("%s/records/%d", zp, mx.ID), url.Values{"name": {"@"}, "type": {"MX"}, "prio": {"20"}, "value": {"mail.ornek.com"}}))
	if r, _ := s.DNS.Store.Record(ctx, z.ID, mx.ID); r.Prio != 20 {
		t.Fatalf("%+v", r)
	}
	if up, _ := s.Activity.Query(ctx, logs.Filter{Action: "dns.record.update"}); len(up) != 1 || !strings.Contains(up[0].Diff, "20 mail.ornek.com") {
		t.Fatalf("%+v", up)
	}
	mustJob(t, s, w.post(fmt.Sprintf("%s/records/%d/delete", zp, mx.ID), url.Values{}))
	if res := w.post(fmt.Sprintf("%s/records/%d/delete", zp, mx.ID), url.Values{}); res.StatusCode != http.StatusNotFound {
		t.Fatalf("delete twice %d", res.StatusCode)
	}
	if res := w.post("/dns/zones/999/records", url.Values{"type": {"A"}, "value": {"1.2.3.4"}}); res.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown zone %d", res.StatusCode)
	}

	// Checks: delegation (fake resolver says ns1/ns2), local check (dry-run).
	if _, body := w.get(zp+"/delegation", true); !strings.Contains(body, "yönlendirilmiş") || strings.Contains(body, "yönlendirilmemiş") {
		t.Fatalf("delegation: %s", body)
	}
	if _, body := w.get(zp+"/check", true); !strings.Contains(body, "Dry-run") {
		t.Fatalf("check: %s", body)
	}

	// DNSSEC on: zone list regenerated; DS shown on check.
	_, log = mustJob(t, s, w.post(zp+"/settings", url.Values{"customer_id": {"1"}, "default_ttl": {"3600"}, "dnssec": {"1"}, "auto_sites": {"1"}}))
	if !strings.Contains(log, "sync-config") {
		t.Fatalf("dnssec toggle did not resync:\n%s", log)
	}
	if ds, _ := s.Activity.Query(ctx, logs.Filter{Action: "dns.dnssec"}); len(ds) != 1 {
		t.Fatal("dns.dnssec activity missing")
	}
	if _, body := w.get(zp+"/check", true); !strings.Contains(body, "DS kaydı henüz yok") {
		t.Fatalf("check with dnssec: %s", body)
	}

	// Wizard: a domain without zone gets one.
	mustJob(t, s, w.post("/sites", url.Values{"customer_id": {"1"}, "domain": {"yeni.net"}, "runtime": {"static"},
		"field_index": {"index.html"}, "field_spa": {"hayır"}, "create_zone": {"1"}}))
	nz, err := s.DNS.Store.ZoneByName(ctx, "yeni.net")
	if err != nil || nz.CustomerID != 1 {
		t.Fatalf("wizard zone: %+v %v", nz, err)
	}
	if _, body := w.get(fmt.Sprintf("/dns/zones/%d/delegation", nz.ID), true); !strings.Contains(body, "yönlendirilmemiş") {
		t.Fatalf("undelegated zone: %s", body)
	}
	if _, body := w.get("/customers/1", false); !strings.Contains(body, "yeni.net") || !strings.Contains(body, "DNS zone") {
		t.Fatal("customer page lacks zones")
	}
	site, _ := s.Sites.Store.GetByDomain(ctx, "ornek.com")
	if _, body := w.get(fmt.Sprintf("/sites/%d?tab=ssl", site.ID), false); !strings.Contains(body, "panelde yönetiliyor") {
		t.Fatal("SSL tab lacks DNS note")
	}

	// Other pages.
	if _, body := w.get("/server", false); !strings.Contains(body, "BIND (DNS)") {
		t.Fatal("server page lacks named")
	}
	if code, _ := w.get("/logs/system?source=dns", false); code != 200 {
		t.Fatalf("dns log source %d", code)
	}

	// Without CSRF: refused.
	plain := client()
	login(t, ts, plain)
	if r, _ := plain.PostForm(ts.URL+zp+"/records", url.Values{"type": {"A"}, "value": {"1.2.3.4"}}); r.StatusCode != http.StatusForbidden {
		t.Fatalf("no CSRF: %d", r.StatusCode)
	}

	// Zone delete: typed confirmation, then BIND list + archive.
	if res := w.post(zp+"/delete", url.Values{"confirm": {"yanlis.com"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatal("delete without confirmation")
	}
	_, log = mustJob(t, s, w.post(zp+"/delete", url.Values{"confirm": {"ornek.com"}}))
	if !strings.Contains(log, "sync-config") || !strings.Contains(log, "delete-zone ornek.com") {
		t.Fatalf("delete log:\n%s", log)
	}
	if _, err := s.DNS.Store.Zone(ctx, z.ID); err == nil {
		t.Fatal("zone still stored")
	}
	if !dryRan("hp-dns.sh delete-zone ornek.com") {
		t.Fatal("helper not called")
	}
	// Deleting the site re-renders nothing for a missing zone (no error).
	if store.GetSetting(ctx, s.DB, dns.SettingInstalled, "") != "1" {
		t.Fatal("installed flag lost")
	}
}
