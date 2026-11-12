package metrics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zahit5834/hostpanel/internal/store"
	"github.com/zahit5834/hostpanel/internal/system"
)

func newSvc(t *testing.T) *Service {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := store.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	return &Service{DB: db}
}

func TestValidHeartbeat(t *testing.T) {
	for _, ok := range []string{"", "https://hc-ping.com/abc-123", "http://kuma.local:3001/api/push/x?status=up&msg=OK"} {
		if err := ValidHeartbeat(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"ftp://x", "https://", "https://u:p@hc-ping.com/x", "https://x/ y", "https://x/#f", "javascript:alert(1)",
		"https://x/" + string(make([]byte, 300))} {
		if ValidHeartbeat(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestSampleAndQuery(t *testing.T) {
	s := newSvc(t)
	ctx := context.Background()
	var busy, total, rx, tx uint64
	s.CPU = func() (system.CPUTimes, bool) { return system.CPUTimes{Busy: busy, Total: total}, true }
	s.Net = func() (uint64, uint64, bool) { return rx, tx, true }
	s.Read = func() system.Snapshot {
		return system.Snapshot{MemTotal: 8 << 30, MemAvail: 6 << 30, SwapTotal: 1 << 30, SwapFree: 1 << 29,
			DiskTotal: 100, DiskFree: 40, Load1: 0.5}
	}
	base := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	// first call primes the counters: no row
	if err := s.sample(ctx, base); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		busy += 25
		total += 100
		rx += 300 * 1000
		tx += 600 * 1000
		if err := s.sample(ctx, base.Add(time.Duration(i)*Interval)); err != nil {
			t.Fatal(err)
		}
	}
	pts, err := s.Query(ctx, base, base.Add(time.Hour), 100)
	if err != nil || len(pts) != 3 {
		t.Fatalf("points %d err %v", len(pts), err)
	}
	p := pts[0]
	if p.CPU != 25 || p.DiskPct != 60 || p.Load1 != 0.5 || p.MemUsed != 2<<30 || p.SwapUsed != 1<<29 {
		t.Fatalf("point %+v", p)
	}
	if p.RXps != 1000 || p.TXps != 2000 { // 300 000 bytes over 300 s
		t.Fatalf("rate %v %v", p.RXps, p.TXps)
	}
	// One bucket for the whole hour: averages, rates over the sampled time.
	one, _ := s.Query(ctx, base, base.Add(time.Hour), 1)
	if len(one) != 1 || one[0].CPU != 25 || one[0].RXps != 1000 {
		t.Fatalf("bucket %+v", one)
	}
	s.Purge(ctx, base.AddDate(0, 0, KeepDays+1))
	if pts, _ := s.Query(ctx, base, base.Add(time.Hour), 10); len(pts) != 0 {
		t.Fatal("purge kept rows")
	}
}

func TestHeartbeat(t *testing.T) {
	s := newSvc(t)
	ctx := context.Background()
	var hits atomic.Int32
	status := atomic.Int32{}
	status.Store(200)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.UserAgent() != "HostPanel-heartbeat" {
			t.Errorf("UA %q", r.UserAgent())
		}
		w.WriteHeader(int(status.Load()))
	}))
	defer srv.Close()
	if err := s.TestPing(ctx); err == nil {
		t.Fatal("ping without URL")
	}
	if err := s.SaveHeartbeat(ctx, srv.URL+"/ping/abc"); err != nil {
		t.Fatal(err)
	}
	if err := s.TestPing(ctx); err != nil || hits.Load() != 1 {
		t.Fatalf("ping: %v hits %d", err, hits.Load())
	}
	status.Store(500)
	if err := s.TestPing(ctx); err == nil || err.Error() != "HTTP 500" {
		t.Fatalf("want HTTP 500, got %v", err)
	}
	if err := s.SaveHeartbeat(ctx, "https://u:p@x/y"); err == nil {
		t.Fatal("credentials accepted")
	}
	// Tick sends the heartbeat even with the history off.
	s.SetEnabledTo(ctx, false)
	status.Store(200)
	s.Tick(ctx)
	if hits.Load() != 3 {
		t.Fatalf("tick did not ping (%d)", hits.Load())
	}
}

func TestRunSleepsWhenOff(t *testing.T) {
	s := newSvc(t)
	ctx, cancel := context.WithCancel(context.Background())
	s.SetEnabledTo(ctx, false)
	var ticks atomic.Int32
	s.AfterTick = func() { ticks.Add(1) }
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop")
	}
	if ticks.Load() != 0 {
		t.Fatal("ticked while off")
	}
}
