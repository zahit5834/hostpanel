package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/zahit5834/hostpanel/internal/dns"
	"github.com/zahit5834/hostpanel/internal/logs"
)

// Settings → panel address (dry-run): name checks, the job, the live
// address, the DNS record and the way back to IP only.
func TestPanelAddressDryRun(t *testing.T) {
	ts, s := newTestServer(t)
	c := client()
	w := webClient{t: t, ts: ts, c: c, csrf: login(t, ts, c)}
	ctx := context.Background()

	w.post("/dns/settings", url.Values{"ns1": {"ns1.ornek.com"}, "ns2": {"ns2.ornek.com"},
		"hostmaster": {"hostmaster@ornek.com"}, "ips": {"185.48.180.32"}})
	w.post("/customers", url.Values{"name": {"Acme"}})
	w.post("/dns/zones", url.Values{"name": {"ornek.com"}, "customer_id": {"1"}})
	mustJob(t, s, w.post("/dns/install", url.Values{}))
	mustJob(t, s, w.post("/sites", url.Values{"customer_id": {"1"}, "domain": {"site.ornek.com"}, "runtime": {"static"},
		"www_mode": {"none"}, "field_index": {"index.html"}, "field_spa": {"hayır"}}))
	mustJob(t, s, w.post("/sites", url.Values{"customer_id": {"1"}, "domain": {"baska.org"}, "runtime": {"static"},
		"www_mode": {"none"}, "field_index": {"index.html"}, "field_spa": {"hayır"}}))

	_, body := w.get("/settings/general", false)
	for _, want := range []string{"Panel adresi", "ornek.com — DNS panelde", "baska.org — DNS başka yerde", "site.ornek.com"} {
		if !strings.Contains(body, want) {
			t.Fatalf("card misses %q", want)
		}
	}
	// Collisions: a site's name, a nameserver, an unknown parent, a bad label.
	for _, v := range []url.Values{
		{"label": {"site"}, "base": {"ornek.com"}},
		{"label": {"ns1"}, "base": {"ornek.com"}},
		{"label": {"panel"}, "base": {"yok.com"}},
		{"label": {"Panel_1"}, "base": {"ornek.com"}},
	} {
		if res := w.post("/settings/panel-address", v); res.StatusCode != http.StatusBadRequest {
			t.Fatalf("%v accepted: %d", v, res.StatusCode)
		}
	}

	_, log := mustJob(t, s, w.post("/settings/panel-address", url.Values{"label": {"panel"}, "base": {"ornek.com"}}))
	if !strings.Contains(log, "hp-update.sh panel-domain set panel.ornek.com -") || !strings.Contains(log, "kaydı ornek.com zone'una") {
		t.Fatalf("set log:\n%s", log)
	}
	a := s.PanelAddr.Addr.Get()
	if a.Domain != "panel.ornek.com" || a.Port != 443 || a.IPPort != 8443 || a.URL() != "https://panel.ornek.com" {
		t.Fatalf("addr %+v", a)
	}
	z, _ := s.DNS.Store.ZoneByName(ctx, "ornek.com")
	in, _ := s.DNS.Input(ctx, z)
	found := false
	for _, r := range dns.AutoRecords(in) {
		if r.Name == "panel" && r.Type == dns.TypeA && r.Value == "185.48.180.32" && r.Source == "panel" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no automatic panel record: %+v", dns.AutoRecords(in))
	}
	// Sites and the mail server can't take the panel's name now.
	if res := w.post("/sites", url.Values{"customer_id": {"1"}, "domain": {"panel.ornek.com"}, "runtime": {"static"},
		"www_mode": {"none"}, "field_index": {"index.html"}, "field_spa": {"hayır"}}); res.StatusCode == http.StatusSeeOther {
		t.Fatal("site may take the panel name")
	}
	if _, body := w.get("/settings/general", false); !strings.Contains(body, `href="https://panel.ornek.com"`) ||
		!strings.Contains(body, "https://185.48.180.32:8443") || !strings.Contains(body, "Alan adını kaldır") {
		t.Fatal("card after the change")
	}
	if e, _ := s.Activity.Query(ctx, logs.Filter{Action: "panel.domain", Limit: 1}); len(e) != 1 || !strings.Contains(e[0].Summary, "https://panel.ornek.com") {
		t.Fatalf("activity %+v", e)
	}
	if res := w.post("/settings/panel-address", url.Values{"label": {"panel"}, "base": {"ornek.com"}}); res.StatusCode != http.StatusBadRequest {
		t.Fatal("same name twice")
	}

	// A name outside the panel's zones: DNS is not touched; public lookup is skipped in dry-run.
	_, log = mustJob(t, s, w.post("/settings/panel-address", url.Values{"label": {"yonetim"}, "base": {"baska.org"}}))
	if !strings.Contains(log, "panelde değil") || s.PanelAddr.Addr.Domain() != "yonetim.baska.org" || s.PanelAddr.Addr.Get().IPPort != 8443 {
		t.Fatalf("second switch %+v\n%s", s.PanelAddr.Addr.Get(), log)
	}
	in, _ = s.DNS.Input(ctx, z)
	for _, r := range dns.AutoRecords(in) {
		if r.Source == "panel" {
			t.Fatalf("old panel record left: %+v", r)
		}
	}

	_, log = mustJob(t, s, w.post("/settings/panel-address", url.Values{"action": {"clear"}}))
	if !strings.Contains(log, "hp-update.sh panel-domain clear") {
		t.Fatalf("clear log:\n%s", log)
	}
	if a := s.PanelAddr.Addr.Get(); a.Domain != "" || a.Port != 8443 || a.FallbackPort() != 8443 {
		t.Fatalf("after clear %+v", a)
	}
}
