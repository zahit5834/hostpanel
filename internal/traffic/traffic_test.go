package traffic

import (
	"compress/gzip"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zahit5834/hostpanel/internal/sites"
	"github.com/zahit5834/hostpanel/internal/store"
)

func TestParseLine(t *testing.T) {
	e, ok := ParseLine(`203.0.113.7 - - [11/Nov/2026:18:00:01 +0300] "GET /urun/5?ref=x HTTP/2.0" 200 5120 "https://google.com/" "Mozilla/5.0 (Windows NT 10.0)"`)
	if !ok || e.IP != "203.0.113.7" || e.Day != "2026-11-11" || e.Path != "/urun/5" || e.Status != 200 || e.Bytes != 5120 || e.Bot {
		t.Fatalf("%+v %v", e, ok)
	}
	e, ok = ParseLine(`2001:db8::1 - - [01/Jan/2027:00:00:00 +0000] "POST /api HTTP/1.1" 502 0 "-" "Googlebot/2.1"`)
	if !ok || e.Day != "2027-01-01" || e.Status != 502 || !e.Bot {
		t.Fatalf("%+v", e)
	}
	// junk request line still counts, without a path
	e, ok = ParseLine(`198.51.100.2 - - [02/Feb/2026:10:00:00 +0300] "\x16\x03\x01" 400 157 "-" "-"`)
	if !ok || e.Path != "" || e.Status != 400 || !e.Bot {
		t.Fatalf("%+v %v", e, ok)
	}
	for _, bad := range []string{"", "x", `1.2.3.4 - - [99/Foo/2026:00:00:00] "GET / HTTP/1.1" 200 1`, `1.2.3.4 - - [11/Nov/2026:00:00:00 +0000] "GET / HTTP/1.1" abc 1 "-" "-"`} {
		if _, ok := ParseLine(bad); ok {
			t.Errorf("parsed %q", bad)
		}
	}
}

func line(ip, day, path string, status int, bytes int, ua string) string {
	t, _ := time.Parse("2006-01-02", day)
	return fmt.Sprintf(`%s - - [%s:12:00:00 +0300] "GET %s HTTP/1.1" %d %d "-" "%s"`+"\n", ip, t.Format("02/Jan/2006"), path, status, bytes, ua)
}

const browser = "Mozilla/5.0"

func writeLog(t *testing.T, path string, gz bool, mtime time.Time, lines ...string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if gz {
		zw := gzip.NewWriter(f)
		zw.Write([]byte(strings.Join(lines, "")))
		zw.Close()
	} else {
		f.WriteString(strings.Join(lines, ""))
	}
	f.Close()
	os.Chtimes(path, mtime, mtime)
}

func TestScanRotated(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "hp-ornek.com.access.log")
	now := time.Date(2026, 11, 11, 15, 0, 0, 0, time.Local)
	writeLog(t, base, false, now,
		line("1.1.1.1", "2026-11-10", "/a", 200, 100, browser), // late lines of the 10th after rotation
		line("1.1.1.1", "2026-11-11", "/a", 200, 100, browser),
		line("127.0.0.1", "2026-11-11", "/", 200, 1, "Go-http-client/1.1"), // health check
	)
	writeLog(t, base+".1", false, now.Add(-15*time.Hour),
		line("1.1.1.1", "2026-11-10", "/a", 200, 100, browser),
		line("2.2.2.2", "2026-11-10", "/b", 200, 300, browser),
		line("2.2.2.2", "2026-11-10", "/app.js", 200, 1000, browser),
		line("3.3.3.3", "2026-11-10", "/a", 404, 10, browser),
		line("4.4.4.4", "2026-11-10", "/a", 500, 10, browser),
		line("5.5.5.5", "2026-11-10", "/a", 200, 50, "bingbot/2.0"),
		line("6.6.6.6", "2026-11-10", "/.well-known/acme-challenge/x", 200, 5, "Let's Encrypt validation server"),
	)
	writeLog(t, base+".2.gz", true, now.Add(-39*time.Hour),
		line("7.7.7.7", "2026-11-09", "/c", 301, 0, browser),
	)
	writeLog(t, base+".3.gz", true, now.Add(-70*time.Hour), // older than wanted: not opened
		line("8.8.8.8", "2026-11-10", "/zzz", 200, 1, browser),
	)
	days, err := Scan(base, map[string]bool{"2026-11-09": true, "2026-11-10": true}, time.Date(2026, 11, 9, 0, 0, 0, 0, time.Local))
	if err != nil {
		t.Fatal(err)
	}
	d := days["2026-11-10"]
	if d.Requests != 7 || d.Bytes != 1570 || d.Visitors != 4 || d.Bots != 1 || d.S2 != 5 || d.S4 != 1 || d.S5 != 1 {
		t.Fatalf("10th: %+v", d)
	}
	if len(d.Top) != 2 || d.Top[0] != (PathCount{"/a", 2}) || d.Top[1] != (PathCount{"/b", 1}) {
		t.Fatalf("top: %+v", d.Top)
	}
	if days["2026-11-09"].Requests != 1 || days["2026-11-09"].S3 != 1 {
		t.Fatalf("9th: %+v", days["2026-11-09"])
	}
	if _, ok := days["2026-11-11"]; ok {
		t.Fatal("unwanted day aggregated")
	}
}

func TestCollectAndToday(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := store.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	db.ExecContext(ctx, `PRAGMA foreign_keys=OFF`) // no sites row needed
	dir := t.TempDir()
	base := filepath.Join(dir, "access.log")
	now := time.Date(2026, 11, 11, 15, 0, 0, 0, time.Local)
	writeLog(t, base, false, now,
		line("1.1.1.1", "2026-11-10", "/x", 200, 10, browser),
		line("1.1.1.1", "2026-11-11", "/x", 200, 10, browser),
		line("2.2.2.2", "2026-11-11", "/y", 200, 10, browser),
	)
	s := &Service{DB: db, LogPath: func(sites.Site) string { return base }, Now: func() time.Time { return now }}
	site := sites.Site{ID: 1, Domain: "ornek.com", CreatedAt: now.AddDate(0, 0, -3)}
	if err := s.Collect(ctx, site); err != nil {
		t.Fatal(err)
	}
	got, err := s.Range(ctx, 1, "2026-11-01")
	if err != nil || len(got) != 3 { // 8th (created), 9th, 10th; today is not stored
		t.Fatalf("range = %+v, %v", got, err)
	}
	if got[2].Day != "2026-11-10" || got[2].Requests != 1 || got[0].Requests != 0 {
		t.Fatalf("rows = %+v", got)
	}
	// a second collect has nothing left to do (the log is not even read)
	os.Remove(base)
	if err := s.Collect(ctx, site); err != nil {
		t.Fatal(err)
	}
	writeLog(t, base, false, now, line("1.1.1.1", "2026-11-11", "/x", 200, 10, browser), line("2.2.2.2", "2026-11-11", "/y", 200, 10, browser))
	today, err := s.Today(site)
	if err != nil || today.Day != "2026-11-11" || today.Requests != 2 || today.Visitors != 2 {
		t.Fatalf("today = %+v, %v", today, err)
	}
	tot, top := Sum(append(got, today))
	if tot.Requests != 3 || tot.VisitorDays != 3 || len(top) != 2 || top[0].Path != "/x" {
		t.Fatalf("sum = %+v %+v", tot, top)
	}
	if n, _ := s.Purge(ctx, "2026-11-10"); n != 2 {
		t.Fatalf("purged %d", n)
	}
}

func TestLimits(t *testing.T) {
	a := newAgg("2026-11-11")
	for i := 0; i < maxPaths+10; i++ {
		a.add(Entry{IP: "1.1.1.1", Day: "2026-11-11", Path: fmt.Sprintf("/p%d", i), Status: 200})
	}
	d := a.day()
	if !d.Capped || d.Requests != maxPaths+10 || len(d.Top) != TopN {
		t.Fatalf("%+v", d)
	}
}
