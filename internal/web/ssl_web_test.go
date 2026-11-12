package web

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zahit5834/hostpanel/internal/jobs"
	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/ssl"
)

// signCSR plays the commercial CA: root → intermediate → leaf for the CSR.
func signCSR(t *testing.T, csrPEM string) (leaf, chain string, roots *x509.CertPool) {
	t.Helper()
	b, _ := pem.Decode([]byte(csrPEM))
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	mk := func(tpl, parent *x509.Certificate, pub any, k *ecdsa.PrivateKey) *x509.Certificate {
		der, err := x509.CreateCertificate(rand.Reader, tpl, parent, pub, k)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c
	}
	rk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ik, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rt := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Paid Root"}, NotBefore: now.AddDate(-1, 0, 0),
		NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	root := mk(rt, rt, rk.Public(), rk)
	it := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Paid DV CA", Organization: []string{"Paid CA Ltd"}},
		NotBefore: now.AddDate(-1, 0, 0), NotAfter: now.AddDate(5, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	inter := mk(it, root, ik.Public(), rk)
	lt := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: csr.Subject, DNSNames: csr.DNSNames, NotBefore: now.Add(-time.Hour),
		NotAfter: now.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	l := mk(lt, inter, csr.PublicKey, ik)
	roots = x509.NewCertPool()
	roots.AddCert(root)
	return ssl.EncodeCerts([]*x509.Certificate{l}), ssl.EncodeCerts([]*x509.Certificate{inter}), roots
}

func jobLog(t *testing.T, s *Server, id int64) string {
	b, _ := os.ReadFile(s.Jobs.LogPath(id))
	return string(b)
}

// TestSSLLifecycleDryRun: precheck → Let's Encrypt → force HTTPS → CSR →
// purchased certificate (verify + install, replaces LE) → export → maintenance → remove.
func TestSSLLifecycleDryRun(t *testing.T) {
	ts, s := newTestServer(t)
	c := client()
	w := webClient{t: t, ts: ts, c: c, csrf: login(t, ts, c)}
	ctx := context.Background()

	w.post("/customers", url.Values{"name": {"Acme"}})
	res := w.post("/sites", url.Values{"customer_id": {"1"}, "domain": {"ornek.com.tr"}, "www_mode": {"to_apex"},
		"runtime": {"static"}, "field_index": {"index.html"}, "field_spa": {"hayır"}})
	if j := waitJob(t, s, jobFromLocation(t, res.Header.Get("Location"))); j.Status != jobs.StatusSuccess {
		t.Fatalf("create: %s", j.Error)
	}
	site, _ := s.Sites.Store.GetByDomain(ctx, "ornek.com.tr")
	base := "/sites/" + strconv.FormatInt(site.ID, 10)

	if code, body := w.get(base+"?tab=ssl", false); code != 200 || !strings.Contains(body, `hx-get="`+base+`/ssl/check"`) {
		t.Fatalf("ssl tab %d", code)
	}
	code, body := w.get(base+"/ssl/check", true)
	if code != 200 || !strings.Contains(body, "192.0.2.1") || !strings.Contains(body, "bu sunucuyu göstermiyor") ||
		!strings.Contains(body, `value="ornek.com.tr" checked`) || strings.Contains(body, `value="www.ornek.com.tr" checked`) {
		t.Fatalf("precheck %d:\n%s", code, body)
	}

	// Let's Encrypt: a name the site does not serve, a bad e-mail, then success.
	if res := w.post(base+"/ssl/letsencrypt", url.Values{"names": {"ornek.com.tr", "evil.com"}, "email": {"a@ornek.com"}}); res.StatusCode != 400 {
		t.Fatalf("foreign name %d", res.StatusCode)
	}
	if res := w.post(base+"/ssl/letsencrypt", url.Values{"names": {"ornek.com.tr"}, "email": {"nope"}}); res.StatusCode != 400 {
		t.Fatalf("bad email %d", res.StatusCode)
	}
	res = w.post(base+"/ssl/letsencrypt", url.Values{"names": {"ornek.com.tr", "www.ornek.com.tr"}, "email": {"admin@ornek.com"}, "staging": {"1"}})
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("le %d", res.StatusCode)
	}
	leJob := jobFromLocation(t, res.Header.Get("Location"))
	if j := waitJob(t, s, leJob); j.Status != jobs.StatusSuccess {
		t.Fatalf("le job: %s\n%s", j.Error, jobLog(t, s, leJob))
	}
	if l := jobLog(t, s, leJob); !strings.Contains(l, "hp-ssl.sh issue ornek.com.tr admin@ornek.com webroot 1 0 ornek.com.tr www.ornek.com.tr") ||
		!strings.Contains(l, "hp-nginx-site.sh install ornek.com.tr") {
		t.Fatalf("le log:\n%s", l)
	}
	le, err := s.SSL.Store.Active(ctx, site.ID)
	if err != nil || le.Kind != ssl.KindLE || !le.Staging || le.Issuer != "DRY-RUN" || len(le.Names) != 2 {
		t.Fatalf("le cert %+v %v", le, err)
	}
	conf, _ := s.Sites.RenderNginxFor(site)
	if !strings.Contains(conf, "ssl_certificate /etc/letsencrypt/live/ornek.com.tr/fullchain.pem;") || !strings.Contains(conf, "hostpanel-probe") {
		t.Fatalf("nginx after LE:\n%s", conf)
	}

	// Force HTTPS + HSTS now apply.
	res = w.post(base+"/settings", url.Values{"www_mode": {"to_apex"}, "field_index": {"index.html"}, "field_spa": {"hayır"},
		"max_upload_mb": {"50"}, "force_https": {"1"}, "hsts": {"1"}, "gzip": {"1"}})
	if res.StatusCode != 200 {
		t.Fatalf("settings %d", res.StatusCode)
	}
	site, _ = s.Sites.Store.Get(ctx, site.ID)
	conf, _ = s.Sites.RenderNginxFor(site)
	if !strings.Contains(conf, "return 301 https://$host$request_uri;") || !strings.Contains(conf, "Strict-Transport-Security") {
		t.Fatalf("force https:\n%s", conf)
	}
	for _, p := range []string{"/ssl", "/sites", "/", base + "?tab=ssl", base + "?tab=settings", "/settings/general", "/logs/system?source=certbot"} {
		if code, body := w.get(p, false); code != 200 {
			t.Fatalf("%s → %d\n%s", p, code, body)
		}
	}
	if _, body := w.get("/sites", false); !strings.Contains(body, " gün</span>") {
		t.Fatal("ssl column missing on sites list")
	}

	// CSR
	res = w.post("/ssl/csr", url.Values{"site_id": {strconv.FormatInt(site.ID, 10)}, "cn": {"ornek.com.tr"}, "sans": {"www.ornek.com.tr"},
		"c": {"TR"}, "st": {"İstanbul"}, "o": {"Acme Ltd"}, "key_type": {ssl.KeyECP256}})
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("csr %d", res.StatusCode)
	}
	if code, body := w.get(res.Header.Get("Location")+"?download=1", false); code != 200 || !strings.HasPrefix(body, "-----BEGIN CERTIFICATE REQUEST-----") {
		t.Fatalf("csr download %d", code)
	}
	if code, body := w.get(res.Header.Get("Location"), false); code != 200 || strings.Contains(body, "PRIVATE KEY") {
		t.Fatal("csr page leaks the key or fails")
	}
	if res := w.post("/ssl/csr", url.Values{"cn": {"bad domain"}, "key_type": {ssl.KeyECP256}}); res.StatusCode != 400 {
		t.Fatalf("bad csr %d", res.StatusCode)
	}
	csrs, _ := s.SSL.Store.CSRs(ctx)
	leaf, chain, roots := signCSR(t, csrs[0].PEM)
	s.SSL.Roots = roots
	form := url.Values{"site_id": {strconv.FormatInt(site.ID, 10)}, "csr_id": {strconv.FormatInt(csrs[0].ID, 10)}, "cert": {chain + leaf}}

	// Verify: chain in wrong order is fixed; missing chain fails.
	code, _ = w.get("/ssl/install", false)
	if code != 200 {
		t.Fatalf("install page %d", code)
	}
	vreq := func(f url.Values) string {
		f.Set("_csrf", w.csrf)
		req, _ := http.NewRequest("POST", ts.URL+"/ssl/install/verify", strings.NewReader(f.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("HX-Request", "true")
		res, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return string(b)
	}
	if b := vreq(form); !strings.Contains(b, "badge success") || !strings.Contains(b, "sırası düzeltildi") || strings.Contains(b, "<html") {
		t.Fatalf("verify:\n%s", b)
	}
	if b := vreq(url.Values{"site_id": form["site_id"], "csr_id": form["csr_id"], "cert": {leaf}}); !strings.Contains(b, "badge failed") || !strings.Contains(b, "Zincir eksik") {
		t.Fatalf("verify missing chain:\n%s", b)
	}
	if res := w.post("/ssl/install", url.Values{"site_id": form["site_id"], "csr_id": form["csr_id"], "cert": {leaf}}); res.StatusCode != 400 {
		t.Fatalf("install with bad chain %d", res.StatusCode)
	}

	res = w.post("/ssl/install", url.Values{"site_id": form["site_id"], "csr_id": form["csr_id"], "cert": {leaf}, "chain": {chain}})
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("install %d", res.StatusCode)
	}
	instJob := jobFromLocation(t, res.Header.Get("Location"))
	if j := waitJob(t, s, instJob); j.Status != jobs.StatusSuccess {
		t.Fatalf("install job: %s\n%s", j.Error, jobLog(t, s, instJob))
	}
	paid, _ := s.SSL.Store.Active(ctx, site.ID)
	l := jobLog(t, s, instJob)
	if paid.Kind != ssl.KindCustom || !strings.Contains(l, "hp-ssl.sh install-custom ornek.com.tr "+strconv.FormatInt(paid.ID, 10)) ||
		!strings.Contains(l, "hp-ssl.sh delete ornek.com.tr le") || strings.Contains(l, "PRIVATE KEY") {
		t.Fatalf("install log / cert %+v:\n%s", paid, l)
	}
	if old, _ := s.SSL.Store.Get(ctx, le.ID); old.Status != ssl.StatusReplaced {
		t.Fatalf("LE cert status %s", old.Status)
	}
	if csr, _ := s.SSL.Store.GetCSR(ctx, csrs[0].ID); csr.CertID != paid.ID {
		t.Fatal("csr not linked")
	}
	conf, _ = s.Sites.RenderNginxFor(site)
	if !strings.Contains(conf, "/etc/hostpanel/ssl/ornek.com.tr/"+strconv.FormatInt(paid.ID, 10)+"/privkey.pem") {
		t.Fatalf("nginx custom paths:\n%s", conf)
	}

	// Export: zip contains a key that matches the certificate.
	req, _ := http.NewRequest("POST", ts.URL+"/ssl/"+strconv.FormatInt(paid.ID, 10)+"/export", strings.NewReader(url.Values{"_csrf": {w.csrf}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	eres, _ := c.Do(req)
	zb, _ := io.ReadAll(eres.Body)
	eres.Body.Close()
	zr, err := zip.NewReader(bytes.NewReader(zb), int64(len(zb)))
	if err != nil {
		t.Fatalf("export %d: %v", eres.StatusCode, err)
	}
	files := map[string]string{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		files[f.Name] = string(b)
	}
	if !ssl.KeyMatches(files["ornek.com.tr/fullchain.pem"], files["ornek.com.tr/privkey.pem"]) || files["ornek.com.tr/chain.pem"] != chain {
		t.Fatalf("export content: %v", len(files))
	}

	// Maintenance: renewal log is ingested once; expiry warnings once per threshold.
	os.WriteFile(s.SSL.RenewLog, []byte("2026-11-05T03:00:00Z renewed ornek.com.tr\n"), 0o640)
	soon := ssl.Certificate{Domain: "eski.com", Kind: ssl.KindCustom, Status: ssl.StatusActive, NotAfter: time.Now().AddDate(0, 0, 10)}
	s.SSL.Store.Insert(ctx, &soon)
	s.SSL.Maintain(ctx)
	s.SSL.Maintain(ctx)
	count := func(action string) int {
		e, _ := s.Activity.Query(ctx, logs.Filter{Action: action, Limit: 50})
		return len(e)
	}
	if count("ssl.renew") != 1 || count("ssl.expiring") != 1 {
		t.Fatalf("maintenance renew=%d expiring=%d", count("ssl.renew"), count("ssl.expiring"))
	}
	if _, body := w.get("/", false); !strings.Contains(body, "eski.com") {
		t.Fatal("dashboard expiring card missing")
	}

	// Remove: back to HTTP, custom files deleted.
	res = w.post(base+"/ssl/remove", nil)
	rmJob := jobFromLocation(t, res.Header.Get("Location"))
	if j := waitJob(t, s, rmJob); j.Status != jobs.StatusSuccess {
		t.Fatalf("remove: %s", j.Error)
	}
	if _, err := s.SSL.Store.Active(ctx, site.ID); err == nil {
		t.Fatal("still active")
	}
	if l := jobLog(t, s, rmJob); !strings.Contains(l, "hp-ssl.sh delete ornek.com.tr custom "+strconv.FormatInt(paid.ID, 10)) {
		t.Fatalf("remove log:\n%s", l)
	}
	conf, _ = s.Sites.RenderNginxFor(site)
	if strings.Contains(conf, "listen 443") {
		t.Fatalf("nginx still TLS:\n%s", conf)
	}

	// Site deletion also removes certificates.
	res = w.post(base+"/delete", url.Values{"confirm": {"ornek.com.tr"}})
	delJob := jobFromLocation(t, res.Header.Get("Location"))
	waitJob(t, s, delJob)
	if l := jobLog(t, s, delJob); !strings.Contains(l, "hp-ssl.sh delete ornek.com.tr all") {
		t.Fatalf("delete log:\n%s", l)
	}
}
