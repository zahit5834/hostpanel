package domains

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zahit5834/hostpanel/internal/store"
)

// A real Verisign answer (mehmetzahitakbulut.com, 2026-11-12), trimmed.
const sampleRDAP = `{"objectClassName":"domain","ldhName":"MEHMETZAHITAKBULUT.COM",
"events": [{"eventAction": "registration", "eventDate": "2025-02-06T15:15:08Z"}, {"eventAction": "expiration", "eventDate": "2027-02-06T15:15:08Z"},
 {"eventAction": "last changed", "eventDate": "2026-07-06T16:51:58Z"}, {"eventAction": "last update of RDAP database", "eventDate": "2026-11-12T06:22:33Z"}],
"entities": [{"objectClassName":"entity","handle":"1091","roles": ["registrar"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "IHS Telekom, Inc."]]]}]}`

func TestRegistrable(t *testing.T) {
	for in, want := range map[string]string{
		"www.shop.ornek.com.tr": "ornek.com.tr", "ornek.com.tr": "ornek.com.tr", "com.tr": "", "a.b.example.com": "example.com",
		"Example.COM.": "example.com", "mail.ornek.co.uk": "ornek.co.uk", "localhost": "", "a..com": "", "ornek.tr": "ornek.tr",
	} {
		if got := Registrable(in); got != want {
			t.Errorf("%s: %q want %q", in, got, want)
		}
	}
}

func TestParse(t *testing.T) {
	boot, err := ParseBootstrap(strings.NewReader(`{"services":[[["com","net"],["http://insecure/","https://rdap.verisign.com/com/v1/"]],
		[["org"],["https://rdap.publicinterestregistry.org/rdap"]],[["xyz"],["http://only-http/"]]]}`))
	if err != nil {
		t.Fatal(err)
	}
	if boot["com"] != "https://rdap.verisign.com/com/v1/" || boot["net"] == "" || boot["org"] != "https://rdap.publicinterestregistry.org/rdap/" || boot["xyz"] != "" {
		t.Fatalf("bootstrap %v", boot)
	}
	exp, reg, err := ParseRDAP(strings.NewReader(sampleRDAP))
	if err != nil || reg != "IHS Telekom, Inc." || !exp.Equal(time.Date(2027, 2, 6, 15, 15, 8, 0, time.UTC)) {
		t.Fatalf("rdap %v %q %v", exp, reg, err)
	}
	if _, _, err := ParseRDAP(strings.NewReader(`{"events":[]}`)); err == nil {
		t.Fatal("missing expiry accepted")
	}
}

type notice struct{ title, key string }

func newSvc(t *testing.T, h http.Handler) (*Service, *[]notice, *httptest.Server) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	store.Migrate(context.Background(), db)
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	var mu sync.Mutex
	var got []notice
	s := &Service{DB: db, Client: srv.Client(), Bootstrap: srv.URL + "/dns.json",
		Notify: func(_ context.Context, title, _, key string) {
			mu.Lock()
			got = append(got, notice{title, key})
			mu.Unlock()
		}}
	return s, &got, srv
}

func TestRefresh(t *testing.T) {
	var base string
	exp := time.Now().AddDate(0, 0, 10).UTC().Format(time.RFC3339)
	var calls []string
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.URL.Path)
		switch r.URL.Path {
		case "/dns.json":
			fmt.Fprintf(w, `{"services":[[["com"],["%s/com/"]]]}`, base)
		case "/com/domain/ornek.com":
			fmt.Fprintf(w, `{"events":[{"eventAction":"expiration","eventDate":"%s"}]}`, exp)
		default:
			http.NotFound(w, r)
		}
	})
	s, got, srv := newSvc(t, h)
	base = srv.URL
	ctx := context.Background()
	if err := s.Sync(ctx, []string{"www.ornek.com", "ornek.com", "yok.com", "site.com.tr", "x"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Refresh(ctx, false); err != nil {
		t.Fatal(err)
	}
	m := s.Map(ctx)
	if len(m) != 3 {
		t.Fatalf("entries %v", m)
	}
	if e := m["ornek.com"]; e.ExpiresAt.IsZero() || e.Error != "" || e.Notified != 15 {
		t.Fatalf("ornek.com %+v", e)
	}
	if e := m["yok.com"]; !strings.Contains(e.Error, "bulunamadı") {
		t.Fatalf("yok.com %+v", e)
	}
	if e := m["site.com.tr"]; !strings.Contains(e.Error, "elle") {
		t.Fatalf(".tr %+v", e)
	}
	if len(*got) != 1 || !strings.Contains((*got)[0].title, "ornek.com") {
		t.Fatalf("notifications %v", *got)
	}
	// Not due again within 20 h; no second notification for the same threshold.
	n := len(calls)
	s.Refresh(ctx, false)
	if len(calls) != n || len(*got) != 1 {
		t.Fatalf("re-looked up or re-notified: %v %v", calls[n:], *got)
	}
	// Manual date for .tr: 5 days → the 7-day threshold.
	if err := s.SetManual(ctx, "site.com.tr", time.Now().AddDate(0, 0, 5)); err != nil {
		t.Fatal(err)
	}
	if err := s.SetManual(ctx, "site.com.tr", time.Now().AddDate(30, 0, 0)); err == nil {
		t.Fatal("absurd date accepted")
	}
	s.Refresh(ctx, false)
	if len(*got) != 2 || !strings.Contains((*got)[1].key, ":7") {
		t.Fatalf("manual notification %v", *got)
	}
	if exp := s.Expiring(ctx, 15); len(exp) != 2 {
		t.Fatalf("expiring %v", exp)
	}
	// Forced lookup skips manual entries.
	n = len(calls)
	s.Refresh(ctx, true)
	for _, c := range calls[n:] {
		if strings.Contains(c, "site.com.tr") {
			t.Fatal("manual entry looked up")
		}
	}
	// Removed names leave the table.
	s.Sync(ctx, []string{"ornek.com"})
	if m := s.Map(ctx); len(m) != 1 {
		t.Fatalf("sync kept %v", m)
	}
}
