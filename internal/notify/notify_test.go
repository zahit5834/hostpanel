package notify

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"hostpanel/internal/crypto"
	"hostpanel/internal/logs"
	"hostpanel/internal/store"
)

const testToken = "123456789:AAbbCCddEEffGGhhIIjjKKllMMnnOOppQQ"

func newSvc(t *testing.T) (*Service, *sql.DB) {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	store.Migrate(context.Background(), db)
	key, _ := crypto.LoadKey(filepath.Join(dir, "k"), true, true)
	box, _ := crypto.New(key)
	return &Service{DB: db, Box: box, Activity: logs.NewActivity(db), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}, db
}

// fakeTelegram records sendMessage calls.
type fakeTelegram struct {
	mu    sync.Mutex
	texts []string
	paths []string
	fail  bool
}

func (f *fakeTelegram) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	f.mu.Lock()
	f.texts = append(f.texts, r.PostFormValue("text"))
	f.paths = append(f.paths, r.URL.Path)
	fail := f.fail
	f.mu.Unlock()
	if fail {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"ok":false,"description":"Bad Request: chat not found"}`))
		return
	}
	w.Write([]byte(`{"ok":true,"result":{}}`))
}

func (f *fakeTelegram) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.texts)
}

func TestSaveValidation(t *testing.T) {
	s, _ := newSvc(t)
	ctx := context.Background()
	bad := []Input{
		{TelegramOn: true, TelegramToken: "nope", TelegramChat: "1"},
		{TelegramOn: true, TelegramToken: testToken},
		{TelegramToken: testToken, TelegramChat: "1; rm"},
		{SMTPOn: true, SMTPHost: "smtp.example.com", SMTPFrom: "a@example.com"},
		{SMTPHost: "smtp example.com"},
		{SMTPHost: "smtp.example.com", SMTPPort: 70000},
		{SMTPFrom: "a@example.com\r\nBcc: x@example.com"},
		{SMTPUser: "u\r\nX"},
	}
	for _, in := range bad {
		if err := s.Save(ctx, in); err == nil {
			t.Errorf("%+v accepted", in)
		}
	}
	in := Input{TelegramOn: true, TelegramToken: testToken, TelegramChat: "-1001234567890",
		SMTPHost: "smtp.example.com", SMTPPort: 465, SMTPPass: "s3cret", SMTPFrom: "Panel <p@example.com>", SMTPTo: "a@example.com",
		Kinds: []string{KindDisk, "bogus"}}
	if err := s.Save(ctx, in); err != nil {
		t.Fatal(err)
	}
	c := s.Load(ctx)
	if c.TelegramToken != testToken || c.SMTPPass != "s3cret" || len(c.Kinds) != 1 || !c.Enabled(KindDisk) || c.Enabled(KindBackup) {
		t.Fatalf("%+v", c)
	}
	// Secrets are sealed in the settings table.
	var raw string
	s.DB.QueryRow(`SELECT value FROM settings WHERE key=?`, setTGToken).Scan(&raw)
	if raw == "" || strings.Contains(raw, "AAbb") {
		t.Fatalf("token stored as %q", raw)
	}
	// Empty secret fields keep the stored values.
	in.TelegramToken, in.SMTPPass = "", ""
	s.Save(ctx, in)
	if c = s.Load(ctx); c.TelegramToken != testToken || c.SMTPPass != "s3cret" {
		t.Fatal("secrets lost on re-save")
	}
}

func TestTelegramSendDedupe(t *testing.T) {
	s, _ := newSvc(t)
	tg := &fakeTelegram{}
	ts := httptest.NewServer(tg)
	defer ts.Close()
	s.TelegramAPI = ts.URL
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	if err := s.Save(ctx, Input{TelegramOn: true, TelegramToken: testToken, TelegramChat: "42",
		Kinds: []string{KindSiteStatus, KindDisk}}); err != nil {
		t.Fatal(err)
	}
	s.Send(ctx, Event{Kind: KindDisk, Key: "disk", Title: "Disk %90"})
	s.Send(ctx, Event{Kind: KindDisk, Key: "disk", Title: "Disk %91"}) // deduped
	s.Send(ctx, Event{Kind: KindBackup, Title: "Yedek başarısız"})     // kind off
	s.Send(ctx, Event{Kind: KindSiteStatus, Key: "down:x", NoDedupe: true, Title: "down"})
	s.Send(ctx, Event{Kind: KindSiteStatus, Key: "down:x", NoDedupe: true, Title: "down again"})
	waitFor(t, func() bool { return tg.count() == 3 })
	time.Sleep(50 * time.Millisecond)
	if n := tg.count(); n != 3 {
		t.Fatalf("sent %d", n)
	}
	if tg.paths[0] != "/bot"+testToken+"/sendMessage" || !strings.Contains(tg.texts[0], "Disk %90") {
		t.Fatalf("%v %v", tg.paths, tg.texts)
	}
	waitFor(t, func() bool {
		got, _ := s.Activity.Query(ctx, logs.Filter{Action: "notify.sent"})
		return len(got) == 3
	})
	assertNoSecret(t, s, testToken)
}

func TestTelegramErrorHidesToken(t *testing.T) {
	s, _ := newSvc(t)
	ctx := context.Background()
	s.Save(ctx, Input{TelegramOn: true, TelegramToken: testToken, TelegramChat: "42"})
	// Unreachable API: the transport error contains the URL (with the token).
	s.TelegramAPI = "http://127.0.0.1:1"
	err := s.Test(ctx)
	if err == nil || strings.Contains(err.Error(), "AAbb") {
		t.Fatalf("%v", err)
	}
	tg := &fakeTelegram{fail: true}
	ts := httptest.NewServer(tg)
	defer ts.Close()
	s.TelegramAPI = ts.URL
	if err := s.Test(ctx); err == nil || !strings.Contains(err.Error(), "chat not found") {
		t.Fatalf("%v", err)
	}
	got, _ := s.Activity.Query(ctx, logs.Filter{Action: "notify.failed"})
	if len(got) != 2 {
		t.Fatalf("%+v", got)
	}
	assertNoSecret(t, s, testToken)
}

func TestNewIP(t *testing.T) {
	s, _ := newSvc(t)
	ctx := context.Background()
	if s.NewIP(ctx, "192.0.2.1") {
		t.Fatal("first login ever is not 'new'")
	}
	if s.NewIP(ctx, "192.0.2.1") || !s.NewIP(ctx, "192.0.2.2") || s.NewIP(ctx, "192.0.2.2") {
		t.Fatal("known/new mismatch")
	}
	for i := 0; i < 30; i++ {
		s.NewIP(ctx, "198.51.100."+string(rune('a'+i)))
	}
	if !s.NewIP(ctx, "192.0.2.1") {
		t.Fatal("list should keep only the last 20 IPs")
	}
}

func TestBuildMail(t *testing.T) {
	c := Config{SMTPFrom: "Panel <p@example.com>", SMTPTo: "a@example.com"}
	m := string(buildMail(c, Event{Title: "Şü\r\nBcc: x@evil", Text: ".hidden\nline"}, time.Unix(0, 0)))
	head, body, _ := strings.Cut(m, "\r\n\r\n")
	if strings.Contains(head, "\r\nBcc:") || !strings.Contains(head, "Subject: =?utf-8?q?") {
		t.Fatalf("%q", head)
	}
	if !strings.Contains(body, "\r\n..hidden\r\nline\r\n") {
		t.Fatalf("%q", body)
	}
}

func TestSMTP(t *testing.T) {
	for _, mode := range []string{"implicit", "starttls", "plain"} {
		t.Run(mode, func(t *testing.T) {
			s, _ := newSvc(t)
			srv := newSMTPServer(t, mode)
			s.RootCAs, s.SMTPAddr = srv.pool, srv.addr
			ctx := context.Background()
			port := 587
			if mode == "implicit" {
				port = 465
			}
			if err := s.Save(ctx, Input{SMTPOn: true, SMTPHost: "smtp.test", SMTPPort: port, SMTPUser: "panel",
				SMTPPass: "pa55word", SMTPFrom: "p@example.com", SMTPTo: "admin@example.com"}); err != nil {
				t.Fatal(err)
			}
			err := s.Test(ctx)
			if mode == "plain" {
				// No STARTTLS offered: refuse instead of sending the password in clear text.
				if err == nil || !strings.Contains(err.Error(), "STARTTLS") || srv.gotAuth() != "" {
					t.Fatalf("%v auth=%q", err, srv.gotAuth())
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if a := srv.gotAuth(); a != "\x00panel\x00pa55word" {
				t.Fatalf("auth %q", a)
			}
			if d := srv.data(); !strings.Contains(d, "To: admin@example.com") || !strings.Contains(d, "Bildirimler çalışıyor.") {
				t.Fatalf("%q", d)
			}
			assertNoSecret(t, s, "pa55word")
		})
	}
}

func assertNoSecret(t *testing.T, s *Service, secret string) {
	t.Helper()
	var n int
	s.DB.QueryRow(`SELECT COUNT(*) FROM activity_log WHERE params LIKE ? OR summary LIKE ? OR error LIKE ?`,
		"%"+secret+"%", "%"+secret+"%", "%"+secret+"%").Scan(&n)
	if n != 0 {
		t.Fatalf("secret in activity log")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timeout")
}

// --- minimal SMTP server ---

type smtpServer struct {
	addr string
	pool *x509.CertPool
	mu   sync.Mutex
	auth string
	msg  string
}

func (s *smtpServer) gotAuth() string { s.mu.Lock(); defer s.mu.Unlock(); return s.auth }
func (s *smtpServer) data() string    { s.mu.Lock(); defer s.mu.Unlock(); return s.msg }

func newSMTPServer(t *testing.T, mode string) *smtpServer {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "smtp.test"}, DNSNames: []string{"smtp.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	tlsConf := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	srv := &smtpServer{addr: ln.Addr().String(), pool: pool}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			if mode == "implicit" {
				conn = tls.Server(conn, tlsConf)
			}
			go srv.serve(conn, mode, tlsConf)
		}
	}()
	return srv
}

func (s *smtpServer) serve(conn net.Conn, mode string, tlsConf *tls.Config) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(conn)
	w := func(l string) { io.WriteString(conn, l+"\r\n") }
	secure := mode == "implicit"
	w("220 smtp.test ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.TrimRight(line, "\r\n")
		switch up := strings.ToUpper(cmd); {
		case strings.HasPrefix(up, "EHLO"):
			if mode == "starttls" && !secure {
				w("250-smtp.test")
				w("250 STARTTLS")
			} else {
				w("250-smtp.test")
				w("250 AUTH PLAIN")
			}
		case up == "STARTTLS":
			w("220 go ahead")
			tc := tls.Server(conn, tlsConf)
			if tc.Handshake() != nil {
				return
			}
			conn, r, secure = tc, bufio.NewReader(tc), true
			w = func(l string) { io.WriteString(conn, l+"\r\n") }
		case strings.HasPrefix(up, "AUTH PLAIN"):
			b, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(cmd[len("AUTH PLAIN"):]))
			s.mu.Lock()
			s.auth = string(b)
			s.mu.Unlock()
			w("235 ok")
		case strings.HasPrefix(up, "MAIL"), strings.HasPrefix(up, "RCPT"):
			w("250 ok")
		case up == "DATA":
			w("354 go")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			s.mu.Lock()
			s.msg = b.String()
			s.mu.Unlock()
			w("250 queued")
		case up == "QUIT":
			w("221 bye")
			return
		default:
			w("250 ok")
		}
	}
}
