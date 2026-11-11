package monitor

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/zahit5834/hostpanel/internal/customers"
	"github.com/zahit5834/hostpanel/internal/exec"
	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/notify"
	"github.com/zahit5834/hostpanel/internal/runtimes"
	"github.com/zahit5834/hostpanel/internal/sites"
	"github.com/zahit5834/hostpanel/internal/store"
)

type noProbe struct{}

func (noProbe) Run(context.Context, exec.Cmd) (exec.Result, error) { return exec.Result{}, nil }

type env struct {
	svc    *Service
	sites  *sites.Store
	act    *logs.Activity
	mu     sync.Mutex
	events []notify.Event
	now    time.Time
}

func (e *env) sent() []notify.Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]notify.Event(nil), e.events...)
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := store.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	reg, err := runtimes.Load("../../deploy/runtimes", noProbe{}, false)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{sites: sites.NewStore(db), act: logs.NewActivity(db), now: time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)}
	e.svc = &Service{Store: NewStore(db), Sites: &sites.Service{Store: e.sites, Runtimes: reg}, Probe: noProbe{},
		Activity: e.act, Notify: func(_ context.Context, ev notify.Event) {
			e.mu.Lock()
			e.events = append(e.events, ev)
			e.mu.Unlock()
		},
		Now: func() time.Time { return e.now }, DiskFunc: func() int { return 10 }}
	return e
}

func (e *env) site(t *testing.T, domain, runtime string, port int) sites.Site {
	t.Helper()
	c := customers.Customer{Name: "Test"}
	if err := customers.New(e.svc.Store.db).Create(context.Background(), &c); err != nil {
		t.Fatal(err)
	}
	s := sites.Site{CustomerID: c.ID, Domain: domain, ShortName: "s" + strconv.Itoa(port), WWWMode: sites.WWWNone,
		RuntimeID: runtime, Port: port, Status: sites.StatusRunning, HealthPath: "/health"}
	if err := e.sites.Insert(context.Background(), &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestTransition(t *testing.T) {
	st, f, ev := Transition(StateUnknown, 0, false)
	if st != StateUnknown || f != 1 || ev != "" {
		t.Fatal(st, f, ev)
	}
	st, f, ev = Transition(st, f, false)
	if st != StateDown || ev != "down" {
		t.Fatal(st, f, ev)
	}
	if st, _, ev = Transition(st, f+1, false); st != StateDown || ev != "" {
		t.Fatal("down must be reported once", ev)
	}
	if st, f, ev = Transition(StateDown, 5, true); st != StateUp || f != 0 || ev != "up" {
		t.Fatal(st, f, ev)
	}
	if _, _, ev = Transition(StateUnknown, 1, true); ev != "" {
		t.Fatal("first success is not an 'up' event")
	}
}

func TestCountRestarts(t *testing.T) {
	now := time.Unix(10_000, 0)
	log := countRestarts(nil, 2, now.Add(-20*time.Minute)) // outside the window
	log = countRestarts(log, 1, now)
	if len(log) != 1 {
		t.Fatal(log)
	}
	if c := (Check{RestartLog: countRestarts(log, 2, now)}); c.RecentRestarts(now) != 3 {
		t.Fatal(c.RestartLog)
	}
}

func TestRunDueDownUpAndRestarts(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	site := e.site(t, "app.example.com", "dotnet", 5001)
	stopped := e.site(t, "stopped.example.com", "node", 5002)
	e.sites.SetStatus(ctx, stopped.ID, sites.StatusStopped)

	var fail bool
	checked := map[int64]int{}
	e.svc.CheckFunc = func(_ context.Context, s sites.Site, c Check) (int, error) {
		checked[s.ID]++
		if c.Path != "/health" {
			t.Errorf("path %q", c.Path)
		}
		if fail {
			return 0, errors.New("bağlantı hatası: refused")
		}
		return 200, nil
	}
	restarts := 0
	e.svc.RestartsFunc = func(context.Context, sites.Site) int { return restarts }

	step := func() time.Time {
		next := e.svc.RunDue(ctx, e.now)
		e.now = e.now.Add(time.Duration(DefaultInterval) * time.Second)
		return next
	}
	if next := step(); !next.Equal(e.now) { // rows created with 300 s interval
		t.Fatalf("next %v want %v", next, e.now)
	}
	if checked[stopped.ID] != 0 || checked[site.ID] != 1 {
		t.Fatal(checked)
	}
	c, _ := e.svc.Store.Get(ctx, site.ID)
	if c.State != StateUp || c.LastCode != 200 || c.Restarts != 0 {
		t.Fatalf("%+v", c)
	}

	fail = true
	step()
	if len(e.sent()) != 0 {
		t.Fatal("one failure must not alert")
	}
	step()
	ev := e.sent()
	if len(ev) != 1 || ev[0].Kind != notify.KindSiteStatus || !ev[0].NoDedupe {
		t.Fatalf("%+v", ev)
	}
	step() // still down: no repeat
	if len(e.sent()) != 1 {
		t.Fatal("down repeated")
	}
	fail = false
	step()
	if ev = e.sent(); len(ev) != 2 || ev[1].Key != "up:app.example.com" {
		t.Fatalf("%+v", ev)
	}
	got, _ := e.act.Query(ctx, logs.Filter{Action: "site.", TargetID: "app.example.com"})
	if len(got) != 2 || got[0].Action != "site.up" || got[1].Action != "site.down" {
		t.Fatalf("%+v", got)
	}

	// Crash loop: 3 restarts within 15 minutes → one alert per hour.
	restarts = 2
	step()
	restarts = 3
	step()
	ev = e.sent()
	if len(ev) != 3 || ev[2].Kind != notify.KindRestarting {
		t.Fatalf("%+v", ev)
	}
	restarts = 6
	step()
	if len(e.sent()) != 3 {
		t.Fatal("restart alert repeated within the hour")
	}

	// Stopping the site forgets its state (no alert when stopped on purpose).
	e.sites.SetStatus(ctx, site.ID, sites.StatusStopped)
	step()
	if c, _ = e.svc.Store.Get(ctx, site.ID); c.State != StateUnknown {
		t.Fatal(c.State)
	}
	// Disabled checks are skipped.
	e.sites.SetStatus(ctx, site.ID, sites.StatusRunning)
	c.Enabled = false
	e.svc.Store.SaveSettings(ctx, c)
	n := checked[site.ID]
	step()
	if checked[site.ID] != n {
		t.Fatal("disabled check ran")
	}
}

func TestDiskAlert(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	pct := 90
	e.svc.DiskFunc = func() int { return pct }
	e.svc.RunDue(ctx, e.now)
	e.svc.RunDue(ctx, e.now.Add(11*time.Minute))
	if ev := e.sent(); len(ev) != 1 || ev[0].Kind != notify.KindDisk || !e.svc.DiskHigh() {
		t.Fatalf("%+v", ev)
	}
	pct = 50
	e.svc.RunDue(ctx, e.now.Add(22*time.Minute))
	got, _ := e.act.Query(ctx, logs.Filter{Action: "disk."})
	if e.svc.DiskHigh() || len(got) != 2 || got[0].Action != "disk.ok" {
		t.Fatalf("%+v", got)
	}
}

func TestHTTPCheckProxy(t *testing.T) {
	e := newEnv(t)
	var code = 200
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
			return
		}
		w.WriteHeader(code)
	}))
	defer ts.Close()
	_, portStr, _ := net.SplitHostPort(ts.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)
	site := e.site(t, "proxy.example.com", "dotnet", port)
	ctx := context.Background()
	c := Check{Path: "/health"}
	if got, err := e.svc.probe(ctx, site, c); err != nil || got != 200 {
		t.Fatal(got, err)
	}
	code = 503
	if _, err := e.svc.probe(ctx, site, c); err == nil {
		t.Fatal("5xx accepted")
	}
	code = 404
	if _, err := e.svc.probe(ctx, site, c); err != nil {
		t.Fatal("404 < 500 must pass with expect=0", err)
	}
	c.Expect = 200
	if _, err := e.svc.probe(ctx, site, c); err == nil {
		t.Fatal("expect 200 got 404 accepted")
	}
	if got, _ := e.svc.probe(ctx, site, Check{Path: "/redirect"}); got != http.StatusFound {
		t.Fatal("redirect followed", got)
	}
	ts.Close()
	if _, err := e.svc.probe(ctx, site, c); err == nil {
		t.Fatal("closed port accepted")
	}
}

func TestRunStops(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.svc.Run(ctx); close(done) }()
	e.svc.Reschedule()
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not stop")
	}
}

func TestUptimeHistory(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	site := e.site(t, "up.example.com", "dotnet", 5011)
	fail := false
	e.svc.CheckFunc = func(context.Context, sites.Site, Check) (int, error) {
		if fail {
			return 0, errors.New("zaman aşımı")
		}
		return 200, nil
	}
	step := func() {
		e.svc.RunDue(ctx, e.now)
		e.now = e.now.Add(time.Duration(DefaultInterval) * time.Second)
	}
	step()
	step()
	fail = true
	firstFail := e.now
	step() // 1st failure: no incident yet
	if inc, _ := e.svc.Store.Incidents(ctx, site.ID, time.Time{}, 10); len(inc) != 0 {
		t.Fatalf("incident after one failure: %+v", inc)
	}
	step() // 2nd failure → down, incident starts at the first failure
	inc, _ := e.svc.Store.Incidents(ctx, site.ID, time.Time{}, 10)
	if len(inc) != 1 || !inc[0].Open() || !inc[0].StartedAt.Equal(firstFail) || inc[0].Reason != "zaman aşımı" {
		t.Fatalf("%+v (first fail %v)", inc, firstFail)
	}
	fail = false
	upAt := e.now
	step()
	inc, _ = e.svc.Store.Incidents(ctx, site.ID, time.Time{}, 10)
	if inc[0].Open() || !inc[0].EndedAt.Equal(upAt) || inc[0].Duration(e.now) != 10*time.Minute {
		t.Fatalf("%+v", inc)
	}
	days, _ := e.svc.Store.UptimeDays(ctx, site.ID, "2000-01-01")
	if len(days) != 1 || days[0].Checks != 5 || days[0].Fails != 2 || days[0].Pct() != 60 {
		t.Fatalf("%+v", days)
	}
	sum, _ := e.svc.Store.UptimeSummary(ctx, "2000-01-01")
	if sum[site.ID].Checks != 5 {
		t.Fatalf("%+v", sum)
	}
	// down, then stopped on purpose: the incident is closed with a note
	fail = true
	step()
	step()
	e.sites.SetStatus(ctx, site.ID, sites.StatusStopped)
	step()
	inc, _ = e.svc.Store.Incidents(ctx, site.ID, time.Time{}, 10)
	if len(inc) != 2 || inc[0].Open() || inc[0].EndNote == "" {
		t.Fatalf("%+v", inc)
	}
	if n, _ := e.svc.Store.PurgeUptime(ctx, e.now.AddDate(0, 0, 1)); n != 3 {
		t.Fatalf("purged %d", n)
	}
}
