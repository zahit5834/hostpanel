package ssl

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"
)

// testPKI is a root → intermediate → leaf chain for verification tests.
type testPKI struct {
	Root, Inter, Leaf *x509.Certificate
	RootKey, InterKey crypto.Signer
	LeafKey           crypto.Signer
	Pool              *x509.CertPool
}

func mkCert(t *testing.T, tpl, parent *x509.Certificate, pub any, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

var serial int64

func tpl(cn string, ca bool, nb, na time.Time, names ...string) *x509.Certificate {
	serial++
	c := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn, Organization: []string{"Test"}},
		NotBefore: nb, NotAfter: na, DNSNames: names, BasicConstraintsValid: true, IsCA: ca}
	if ca {
		c.KeyUsage = x509.KeyUsageCertSign
	} else {
		c.KeyUsage = x509.KeyUsageDigitalSignature
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	return c
}

func newPKI(t *testing.T, leafKey crypto.Signer, nb, na time.Time, names ...string) testPKI {
	now := time.Now()
	rk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ik, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rt := tpl("Test Root", true, now.AddDate(-1, 0, 0), now.AddDate(5, 0, 0))
	root := mkCert(t, rt, rt, rk.Public(), rk)
	inter := mkCert(t, tpl("Test Intermediate", true, now.AddDate(-1, 0, 0), now.AddDate(3, 0, 0)), root, ik.Public(), rk)
	leaf := mkCert(t, tpl(names[0], false, nb, na, names...), inter, leafKey.Public(), ik)
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return testPKI{Root: root, Inter: inter, Leaf: leaf, RootKey: rk, InterKey: ik, LeafKey: leafKey, Pool: pool}
}

func pemOf(cs ...*x509.Certificate) string { return EncodeCerts(cs) }

func keyPEM(t *testing.T, k crypto.Signer) string {
	s, err := MarshalKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func levels(r Report) string {
	var b strings.Builder
	for _, c := range r.Checks {
		b.WriteString(c.Level + ": " + c.Text + "\n")
	}
	return b.String()
}

func hasCheck(r Report, level, substr string) bool {
	for _, c := range r.Checks {
		if c.Level == level && strings.Contains(c.Text, substr) {
			return true
		}
	}
	return false
}

func TestCSRAllKeyTypes(t *testing.T) {
	for _, kt := range []string{KeyRSA2048, KeyECP256, KeyRSA4096} {
		if kt == KeyRSA4096 && testing.Short() {
			continue
		}
		in := CSRInput{CommonName: " Ornek.COM ", SANs: []string{"www.ornek.com", "ornek.com", ""}, KeyType: kt,
			Subject: Subject{Country: "tr", State: "İstanbul", Locality: "Kadıköy", Org: "Örnek A.Ş.", Email: "it@ornek.com"}}
		if err := in.Validate(); err != nil {
			t.Fatal(err)
		}
		k, err := GenerateKey(kt)
		if err != nil {
			t.Fatal(err)
		}
		p, err := CreateCSR(k, in)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := pem.Decode([]byte(p))
		csr, err := x509.ParseCertificateRequest(b.Bytes)
		if err != nil || csr.CheckSignature() != nil {
			t.Fatalf("%s: %v", kt, err)
		}
		if csr.Subject.CommonName != "ornek.com" || strings.Join(csr.DNSNames, ",") != "ornek.com,www.ornek.com" ||
			csr.Subject.Country[0] != "TR" || csr.Subject.Organization[0] != "Örnek A.Ş." {
			t.Fatalf("%s: subject %v %v", kt, csr.Subject, csr.DNSNames)
		}
		kp := keyPEM(t, k)
		back, err := ParseKey(kp)
		if err != nil || !samePublicKey(back.Public(), k.Public()) {
			t.Fatalf("key roundtrip %v", err)
		}
	}
	bad := []CSRInput{
		{CommonName: "not a domain", KeyType: KeyRSA2048},
		{CommonName: "ornek.com", KeyType: "dsa"},
		{CommonName: "ornek.com", KeyType: KeyRSA2048, Subject: Subject{Country: "TUR"}},
		{CommonName: "ornek.com", KeyType: KeyRSA2048, Subject: Subject{Org: "x\ny"}},
		{CommonName: "ornek.com", KeyType: KeyRSA2048, Subject: Subject{Org: strings.Repeat("ş", 65)}},
		{CommonName: "ornek.com", KeyType: KeyRSA2048, SANs: []string{"bad_name.com"}},
	}
	for _, in := range bad {
		if err := in.Validate(); err == nil {
			t.Errorf("accepted %+v", in)
		}
	}
	if _, err := ParseKey("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n"); err == nil {
		t.Fatal("encrypted key accepted")
	}
}

func TestVerifyChains(t *testing.T) {
	now := time.Now()
	lk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p := newPKI(t, lk, now.Add(-time.Hour), now.AddDate(1, 0, 0), "ornek.com", "www.ornek.com")
	k := keyPEM(t, lk)
	in := VerifyInput{CertPEM: pemOf(p.Leaf), ChainPEM: pemOf(p.Inter), KeyPEM: k, Primary: "ornek.com",
		Names: []string{"ornek.com", "www.ornek.com", "eski.ornek.com"}}

	r := Verify(in, now, p.Pool)
	if !r.OK || !hasCheck(r, LevelOK, "eşleşiyor") || !hasCheck(r, LevelOK, "Test Intermediate") || !hasCheck(r, LevelWarn, "eski.ornek.com") {
		t.Fatalf("good chain:\n%s", levels(r))
	}
	if certs, _ := ParseCerts(r.FullChain); len(certs) != 2 || !certs[0].Equal(p.Leaf) || !certs[1].Equal(p.Inter) {
		t.Fatal("fullchain order")
	}

	// Reversed order + root included: fixed, root dropped.
	in2 := in
	in2.CertPEM, in2.ChainPEM = pemOf(p.Inter, p.Leaf), pemOf(p.Root)
	r = Verify(in2, now, p.Pool)
	if !r.OK || !hasCheck(r, LevelWarn, "sırası düzeltildi") || !hasCheck(r, LevelWarn, "Kök sertifika") {
		t.Fatalf("reordered:\n%s", levels(r))
	}
	if certs, _ := ParseCerts(r.FullChain); len(certs) != 2 || !certs[0].Equal(p.Leaf) {
		t.Fatal("reordered fullchain")
	}

	// Missing intermediate.
	in3 := in
	in3.ChainPEM = ""
	if r = Verify(in3, now, p.Pool); r.OK || !hasCheck(r, LevelErr, "Zincir eksik") {
		t.Fatalf("missing intermediate:\n%s", levels(r))
	}

	// Wrong key.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	in4 := in
	in4.KeyPEM = keyPEM(t, other)
	if r = Verify(in4, now, p.Pool); r.OK || !hasCheck(r, LevelErr, "eşleşmiyor") {
		t.Fatalf("wrong key:\n%s", levels(r))
	}

	// Domain not covered.
	in5 := in
	in5.Primary = "baska.com"
	if r = Verify(in5, now, p.Pool); r.OK || !hasCheck(r, LevelErr, "kapsamıyor") {
		t.Fatalf("not covered:\n%s", levels(r))
	}

	// Unrelated extra certificate in the bundle.
	ok2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	unrelated := newPKI(t, ok2, now.Add(-time.Hour), now.AddDate(1, 0, 0), "x.com")
	in6 := in
	in6.ChainPEM = pemOf(p.Inter, unrelated.Inter)
	if r = Verify(in6, now, p.Pool); !r.OK || !hasCheck(r, LevelWarn, "ilgisi olmayan 1") {
		t.Fatalf("unrelated:\n%s", levels(r))
	}

	// Expired and not-yet-valid.
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	exp := newPKI(t, ek, now.AddDate(0, 0, -40), now.AddDate(0, 0, -1), "ornek.com")
	r = Verify(VerifyInput{CertPEM: pemOf(exp.Leaf), ChainPEM: pemOf(exp.Inter), KeyPEM: keyPEM(t, ek), Primary: "ornek.com"}, now, exp.Pool)
	if r.OK || !hasCheck(r, LevelErr, "süresi dolmuş") || hasCheck(r, LevelErr, "Zincir") {
		t.Fatalf("expired:\n%s", levels(r))
	}
	fk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fut := newPKI(t, fk, now.Add(24*time.Hour), now.AddDate(1, 0, 0), "ornek.com")
	r = Verify(VerifyInput{CertPEM: pemOf(fut.Leaf), ChainPEM: pemOf(fut.Inter), KeyPEM: keyPEM(t, fk), Primary: "ornek.com"}, now, fut.Pool)
	if r.OK || !hasCheck(r, LevelErr, "henüz geçerli değil") {
		t.Fatalf("future:\n%s", levels(r))
	}

	// A key pasted into the certificate field.
	if r = Verify(VerifyInput{CertPEM: k, KeyPEM: k, Primary: "ornek.com"}, now, p.Pool); r.OK || !hasCheck(r, LevelErr, "private key var") {
		t.Fatalf("key in cert field:\n%s", levels(r))
	}

	// Untrusted root (system pool doesn't know the test CA).
	if r = Verify(in, now, x509.NewCertPool()); r.OK {
		t.Fatal("untrusted root accepted")
	}
}

func TestWildcardCovers(t *testing.T) {
	now := time.Now()
	lk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p := newPKI(t, lk, now.Add(-time.Hour), now.AddDate(1, 0, 0), "*.ornek.com", "ornek.com")
	r := Verify(VerifyInput{CertPEM: pemOf(p.Leaf, p.Inter), KeyPEM: keyPEM(t, lk), Primary: "ornek.com", Names: []string{"www.ornek.com", "a.b.ornek.com"}}, now, p.Pool)
	if !r.OK || !hasCheck(r, LevelWarn, "a.b.ornek.com") || hasCheck(r, LevelWarn, "www.ornek.com,") {
		t.Fatalf("wildcard:\n%s", levels(r))
	}
}

type fakeResolver map[string][]string

func (f fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	ips, ok := f[host]
	if !ok {
		return nil, errors.New("no such host")
	}
	var out []net.IPAddr
	for _, s := range ips {
		out = append(out, net.IPAddr{IP: net.ParseIP(s)})
	}
	return out, nil
}

func TestPrecheck(t *testing.T) {
	// The probe server answers like nginx would: token only for names "served here".
	served := map[string]bool{"ok.test": true, "cdn.test": true, "v6.test": true}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.Host)
		if r.URL.Path == ProbePath && served[host] {
			w.Write([]byte("tok123\n"))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()
	u, _ := url.Parse(ts.URL)
	_, port, _ := net.SplitHostPort(u.Host)
	c := &Checker{
		Resolver: fakeResolver{
			"ok.test": {"127.0.0.1"}, "cdn.test": {"104.16.0.1"}, "elsewhere.test": {"203.0.113.9"},
			"v6.test": {"127.0.0.1", "2001:db8::1"}, "down.test": {"127.0.0.1"},
		},
		Client: &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, u.Host) // every name resolves to the test server
			}}},
		ServerIPs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Token: "tok123", Port: port,
	}
	got := map[string]NameCheck{}
	for _, r := range c.Check(context.Background(), []string{"ok.test", "cdn.test", "elsewhere.test", "v6.test", "down.test", "none.test"}) {
		got[r.Name] = r
	}
	if !got["ok.test"].OK() || len(got["ok.test"].Notes) != 0 {
		t.Errorf("ok: %+v", got["ok.test"])
	}
	if !got["cdn.test"].OK() || len(got["cdn.test"].Notes) == 0 {
		t.Errorf("cdn should pass with a note: %+v", got["cdn.test"])
	}
	if got["elsewhere.test"].OK() || !strings.Contains(strings.Join(got["elsewhere.test"].Problems, " "), "203.0.113.9") {
		t.Errorf("elsewhere: %+v", got["elsewhere.test"])
	}
	if got["v6.test"].OK() || !strings.Contains(strings.Join(got["v6.test"].Problems, " "), "AAAA") {
		t.Errorf("v6: %+v", got["v6.test"])
	}
	if got["down.test"].OK() || !strings.Contains(strings.Join(got["down.test"].Problems, " "), "HTTP") {
		t.Errorf("down: %+v", got["down.test"])
	}
	if got["none.test"].OK() || !strings.Contains(strings.Join(got["none.test"].Problems, " "), "DNS kaydı") {
		t.Errorf("none: %+v", got["none.test"])
	}
}

func TestDaysLeftAndPaths(t *testing.T) {
	c := Certificate{ID: 7, Domain: "ornek.com", Kind: KindCustom, NotAfter: time.Now().Add(36 * time.Hour)}
	if c.DaysLeft() != 1 {
		t.Fatal(c.DaysLeft())
	}
	cert, key := c.Paths()
	if cert != "/etc/hostpanel/ssl/ornek.com/7/fullchain.pem" || key != "/etc/hostpanel/ssl/ornek.com/7/privkey.pem" {
		t.Fatal(cert, key)
	}
	c.Kind = KindLE
	if cert, _ = c.Paths(); cert != "/etc/letsencrypt/live/ornek.com/fullchain.pem" {
		t.Fatal(cert)
	}
	if _, err := ParseIPList("1.2.3.4, ::ffff:5.6.7.8\n2001:db8::1"); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseIPList("1.2.3"); err == nil {
		t.Fatal("bad ip accepted")
	}
}
