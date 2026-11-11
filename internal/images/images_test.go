package images

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/zahit5834/hostpanel/internal/notify"
	"github.com/zahit5834/hostpanel/internal/store"
)

var mcrTags = []string{"2017-CU31-ubuntu-18.04", "2022-CU27-ubuntu-22.04", "2022-CU27-GDR2-ubuntu-22.04",
	"2025-CU9-ubuntu-24.04", "2025-CU10-ubuntu-24.04", "2025-CU10-GDR1-ubuntu-22.04", "2025-CU10-GDR1-ubuntu-24.04",
	"2025-CU2-GDR1-ubuntu-24.04", "2025-latest", "2025-RTM-ubuntu-24.04-preview", "2027-CU1-ubuntu-24.04", "2027-CU2-ubuntu-26.04"}

func TestPickMSSQL(t *testing.T) {
	for _, c := range []struct{ cur, latest, major string }{
		{"2025-CU10-ubuntu-24.04", "2025-CU10-GDR1-ubuntu-24.04", "2027-CU1-ubuntu-24.04"},
		{"2025-CU9-ubuntu-24.04", "2025-CU10-GDR1-ubuntu-24.04", "2027-CU1-ubuntu-24.04"},
		{"2025-CU10-GDR1-ubuntu-24.04", "", "2027-CU1-ubuntu-24.04"},
		{"2022-CU20-ubuntu-22.04", "2022-CU27-GDR2-ubuntu-22.04", "2025-CU10-GDR1-ubuntu-22.04"},
		{"2025-latest", "", ""}, // moving tags are never "current"
	} {
		l, m := PickMSSQL(c.cur, mcrTags)
		if l != c.latest || m != c.major {
			t.Errorf("PickMSSQL(%s) = %q, %q; want %q, %q", c.cur, l, m, c.latest, c.major)
		}
	}
	// a GDR of a newer CU beats the plain CU, a newer CU beats an older GDR
	if l, _ := PickMSSQL("2025-CU9-GDR1-ubuntu-24.04", []string{"2025-CU10-ubuntu-24.04", "2025-CU9-GDR2-ubuntu-24.04"}); l != "2025-CU10-ubuntu-24.04" {
		t.Errorf("got %q", l)
	}
}

var hubTags = []string{"edge", "latest", "17.0.0-r1", "17.0.0", "17.0", "17", "16.0.1-r2", "17.0.0-r0", "17.1.0", "17.0.2-r3", "18.0.0-r1", "18.0.0"}

func TestPickMail(t *testing.T) {
	for _, c := range []struct{ cur, latest, major string }{
		{"17.0.0-r1", "17.0.2-r3", "18.0.0-r1"}, // 17.1.0 has no immutable revision tag yet
		{"17.0.0", "17.0.2-r3", "18.0.0-r1"},    // plain tag = r0
		{"17.0.2-r3", "", "18.0.0-r1"},          //
		{"16.0.1-r1", "16.0.1-r2", "18.0.0-r1"}, // newest major wins
		{"18.0.0-r1", "", ""},                   //
		{"latest", "", ""},                      //
	} {
		l, m := PickMail(c.cur, hubTags)
		if l != c.latest || m != c.major {
			t.Errorf("PickMail(%s) = %q, %q; want %q, %q", c.cur, l, m, c.latest, c.major)
		}
	}
}

func TestIsUpdate(t *testing.T) {
	cur := MSSQLRepo + ":2025-CU10-ubuntu-24.04"
	for img, want := range map[string]bool{
		MSSQLRepo + ":2025-CU10-GDR1-ubuntu-24.04": true,
		MSSQLRepo + ":2025-CU11-ubuntu-24.04":      true,
		MSSQLRepo + ":2025-CU9-ubuntu-24.04":       false, // older
		MSSQLRepo + ":2025-CU10-ubuntu-24.04":      false, // same
		MSSQLRepo + ":2027-CU1-ubuntu-24.04":       false, // new major: not one-click
		MSSQLRepo + ":2025-CU11-ubuntu-22.04":      false, // other OS
		"evil/mssql:2025-CU11-ubuntu-24.04":        false,
	} {
		if IsUpdate(MSSQL, cur, img) != want {
			t.Errorf("IsUpdate(%s) = %v", img, !want)
		}
	}
	if !IsUpdate(Mail, MailRepo+":17.0.0-r1", MailRepo+":17.0.1-r1") || IsUpdate(Mail, MailRepo+":17.0.0-r1", MailRepo+":18.0.0-r1") ||
		IsUpdate(Mail, MailRepo+":17.0.0-r1", MailRepo+":17.0.1") {
		t.Error("mail IsUpdate")
	}
}

func openDB(t *testing.T) *sql.DB {
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestCheckNotifiesOnce(t *testing.T) {
	ctx := context.Background()
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		switch r.URL.Path {
		case "/v2/mssql/server/tags/list":
			fmt.Fprint(w, `{"name":"mssql/server","tags":["2025-CU10-ubuntu-24.04","2025-CU10-GDR1-ubuntu-24.04"]}`)
		case "/v2/namespaces/mailserver/repositories/docker-mailserver/tags":
			fmt.Fprint(w, `{"count":2,"results":[{"name":"17.0.0-r1"},{"name":"latest"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	var sent []notify.Event
	mssqlImg := MSSQLRepo + ":2025-CU10-ubuntu-24.04"
	s := &Service{DB: openDB(t), MCR: srv.URL, Hub: srv.URL, Notify: func(_ context.Context, e notify.Event) { sent = append(sent, e) },
		Engines: []Engine{
			{ID: MSSQL, Label: "MSSQL", Current: func(context.Context) string { return mssqlImg }},
			{ID: Mail, Label: "Posta sunucusu", Current: func(context.Context) string { return MailRepo + ":17.0.0-r1" }},
			{ID: "none", Label: "x", Current: func(context.Context) string { return "" }},
		}}
	infos := s.Check(ctx)
	if len(infos) != 2 || !infos[0].Available() || infos[0].Latest != MSSQLRepo+":2025-CU10-GDR1-ubuntu-24.04" || infos[1].Available() {
		t.Fatalf("infos = %+v", infos)
	}
	if len(sent) != 1 || sent[0].Kind != notify.KindUpdate {
		t.Fatalf("sent = %+v", sent)
	}
	s.Check(ctx)
	if len(sent) != 1 {
		t.Fatal("notified twice for the same tag")
	}
	i, ok := s.Info(ctx, MSSQL)
	if !ok || !i.Available() || i.CheckedAt.IsZero() {
		t.Fatalf("cached info = %+v", i)
	}
	// after the update the cached offer is dropped until the next check
	mssqlImg = MSSQLRepo + ":2025-CU10-GDR1-ubuntu-24.04"
	if i, _ := s.Info(ctx, MSSQL); i.Available() {
		t.Fatalf("stale offer after update: %+v", i)
	}
	if _, ok := s.Info(ctx, "none"); ok {
		t.Fatal("not installed engine has info")
	}
	// registry error is recorded, not fatal
	s.MCR = srv.URL + "/missing"
	if infos := s.Check(ctx); infos[0].Err == "" {
		t.Fatal("expected error")
	}
	if hits == 0 {
		t.Fatal("no requests")
	}
}
