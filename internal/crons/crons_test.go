package crons

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"hostpanel/internal/customers"
	"hostpanel/internal/exec"
	"hostpanel/internal/logs"
	"hostpanel/internal/notify"
	"hostpanel/internal/sites"
	"hostpanel/internal/store"
)

// fakeRunner records helper calls; block (if set) holds a run until closed.
type fakeRunner struct {
	mu    sync.Mutex
	calls [][]string
	stdin []string
	exit  int
	out   string
	block chan struct{}
}

func (f *fakeRunner) Run(ctx context.Context, c exec.Cmd) (exec.Result, error) {
	f.mu.Lock()
	f.calls = append(f.calls, c.Args)
	if c.Stdin != nil {
		b := new(strings.Builder)
		buf := make([]byte, 2048)
		n, _ := c.Stdin.Read(buf)
		b.Write(buf[:n])
		f.stdin = append(f.stdin, b.String())
	}
	exit, out, block := f.exit, f.out, f.block
	f.mu.Unlock()
	if block != nil {
		<-block
	}
	if c.Output != nil {
		c.Output.Write([]byte(out))
	}
	if exit != 0 {
		return exec.Result{ExitCode: exit}, &exec.ExitError{Code: exit}
	}
	return exec.Result{}, nil
}

func (f *fakeRunner) n() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

type env struct {
	svc    *Service
	run    *fakeRunner
	sites  *sites.Store
	act    *logs.Activity
	now    time.Time
	mu     sync.Mutex
	events []notify.Event
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
	e := &env{run: &fakeRunner{}, sites: sites.NewStore(db), act: logs.NewActivity(db),
		now: time.Date(2026, 11, 6, 12, 0, 0, 0, time.Local)}
	e.svc = &Service{Store: NewStore(db), Sites: &sites.Service{Store: e.sites}, Runner: e.run, Activity: e.act,
		ScriptsDir: "/opt/hostpanel/scripts", Now: func() time.Time { return e.now },
		Notify: func(_ context.Context, ev notify.Event) { e.mu.Lock(); e.events = append(e.events, ev); e.mu.Unlock() }}
	return e
}

func (e *env) site(t *testing.T, domain string, status string) sites.Site {
	t.Helper()
	ctx := context.Background()
	c := customers.Customer{Name: "Test"}
	if err := customers.New(e.svc.Store.db).Create(ctx, &c); err != nil {
		t.Fatal(err)
	}
	s := sites.Site{CustomerID: c.ID, Domain: domain, ShortName: strings.ReplaceAll(strings.Split(domain, ".")[0], "-", "_"),
		WWWMode: sites.WWWNone, RuntimeID: "node", RuntimeVersion: "24.11.1", Port: 5000 + int(domain[0])*10 + len(domain), Status: status,
		MemoryMaxMB: 512, CPUQuotaPct: 100}
	if err := e.sites.Insert(ctx, &s); err != nil {
		t.Fatal(err)
	}
	e.sites.AddRelease(ctx, &sites.Release{SiteID: s.ID, Name: "20261106-110000", Status: sites.ReleaseActive})
	return s
}

func TestValidate(t *testing.T) {
	ok := Cron{Name: " Laravel ", Schedule: " * *  * * * ", Command: "cd current && php artisan schedule:run >/dev/null 2>&1"}
	if err := Validate(&ok); err != nil || ok.Name != "Laravel" || ok.Schedule != "* * * * *" || ok.TimeoutSec != DefaultTimeout {
		t.Fatalf("%+v %v", ok, err)
	}
	for _, bad := range []Cron{
		{Name: "", Schedule: "* * * * *", Command: "x"},
		{Name: "a", Schedule: "@hourly", Command: "x"},
		{Name: "a", Schedule: "* * * *", Command: "x"},
		{Name: "a", Schedule: "* * * * *", Command: "  "},
		{Name: "a", Schedule: "* * * * *", Command: "echo a\necho b"},
		{Name: "a", Schedule: "* * * * *", Command: "echo\x00"},
		{Name: "a", Schedule: "* * * * *", Command: "echo\ta"},
		{Name: "a", Schedule: "* * * * *", Command: strings.Repeat("x", 1001)},
		{Name: "a", Schedule: "* * * * *", Command: "x", TimeoutSec: 30},
		{Name: "a", Schedule: "* * * * *", Command: "x", TimeoutSec: 3601},
		{Name: strings.Repeat("ş", 61), Schedule: "* * * * *", Command: "x"},
	} {
		if err := Validate(&bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestSchedulerRunsDueAndSkipsMissed(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	site := e.site(t, "ornek.com", sites.StatusRunning)
	c, err := e.svc.Save(ctx, site, Cron{Name: "her 5 dk", Schedule: "*/5 * * * *", Command: "echo 'merhaba $HOME'", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Date(2026, 11, 6, 12, 5, 0, 0, time.Local); !c.NextRunAt.Equal(want) {
		t.Fatalf("next %v", c.NextRunAt)
	}
	// Not due yet.
	if next := e.svc.RunDue(ctx, e.now); !next.Equal(c.NextRunAt) || e.run.n() != 0 {
		t.Fatalf("next %v calls %d", next, e.run.n())
	}
	// Due (timer fired a bit late).
	e.now = c.NextRunAt.Add(2 * time.Second)
	e.run.out = "merhaba\n"
	next := e.svc.RunDue(ctx, e.now)
	e.svc.Wait()
	if !next.Equal(time.Date(2026, 11, 6, 12, 10, 0, 0, time.Local)) || e.run.n() != 1 {
		t.Fatalf("next %v calls %d", next, e.run.n())
	}
	args := e.run.calls[0]
	want := []string{"-n", "/opt/hostpanel/scripts/hp-site-cron.sh", "run", "ornek.com", "site_ornek", "1", "node", "24.11.1", "600", "512", "100"}
	if !slices.Equal(args, want) || e.run.stdin[0] != "echo 'merhaba $HOME'" {
		t.Fatalf("args %v stdin %q", args, e.run.stdin)
	}
	runs, _ := e.svc.Store.Runs(ctx, RunFilter{SiteID: site.ID})
	if len(runs) != 1 || runs[0].Status != StatusOK || runs[0].Output != "merhaba\n" || runs[0].Source != "system" || runs[0].Domain != "ornek.com" {
		t.Fatalf("%+v", runs)
	}
	// Panel was down for an hour: the missed runs are not caught up.
	e.now = e.now.Add(time.Hour)
	next = e.svc.RunDue(ctx, e.now)
	e.svc.Wait()
	if e.run.n() != 1 || !next.After(e.now) {
		t.Fatalf("missed run executed (calls %d, next %v)", e.run.n(), next)
	}
}

func TestIneligibleSitesAndDisabledCrons(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	stopped := e.site(t, "durmus.com", sites.StatusStopped)
	running := e.site(t, "calisan.com", sites.StatusRunning)
	e.svc.Save(ctx, stopped, Cron{Name: "a", Schedule: "* * * * *", Command: "true", Enabled: true})
	e.svc.Save(ctx, running, Cron{Name: "b", Schedule: "* * * * *", Command: "true", Enabled: false})
	e.now = e.now.Add(time.Minute)
	if next := e.svc.RunDue(ctx, e.now); e.run.n() != 0 || next.IsZero() {
		t.Fatalf("calls %d next %v", e.run.n(), next)
	}
	if err := e.svc.RunNow(ctx, ctx, stopped, 1); err == nil {
		t.Fatal("RunNow on a stopped site")
	}
	if !Eligible(sites.Site{Status: sites.StatusMaintenance}, "20261106-110000") || Eligible(sites.Site{Status: sites.StatusRunning}, sites.PlaceholderRelease) {
		t.Fatal("Eligible")
	}
}

func TestOverlapSkippedAndFailureNotifies(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	site := e.site(t, "ornek.com", sites.StatusRunning)
	c, _ := e.svc.Save(ctx, site, Cron{Name: "uzun", Schedule: "* * * * *", Command: "sleep 100", Enabled: true})
	e.run.block = make(chan struct{})
	e.run.exit, e.run.out = 3, "hata satırı\n"
	if err := e.svc.RunNow(ctx, ctx, site, c.ID); err != nil {
		t.Fatal(err)
	}
	for e.run.n() == 0 {
		time.Sleep(time.Millisecond)
	}
	if !e.svc.Running(c.ID) {
		t.Fatal("not running")
	}
	if err := e.svc.RunNow(ctx, ctx, site, c.ID); err == nil {
		t.Fatal("second RunNow accepted while running")
	}
	// The scheduler fires meanwhile → skipped.
	e.now = e.now.Add(time.Minute)
	e.svc.RunDue(ctx, e.now)
	close(e.run.block)
	e.svc.Wait()
	runs, _ := e.svc.Store.Runs(ctx, RunFilter{CronID: c.ID})
	if len(runs) != 2 || runs[0].Status != StatusFailed || runs[0].ExitCode != 3 || runs[1].Status != StatusSkipped {
		t.Fatalf("%+v", runs)
	}
	if len(e.events) != 1 || e.events[0].Kind != notify.KindCron || !strings.Contains(e.events[0].Text, "hata satırı") {
		t.Fatalf("events %+v", e.events)
	}
	failed, _ := e.act.Query(ctx, logs.Filter{Action: "site.cron.failed"})
	if len(failed) != 1 {
		t.Fatalf("activity %+v", failed)
	}
	// Next run succeeds → recovered.
	e.run.block, e.run.exit = nil, 0
	if err := e.svc.RunNow(ctx, ctx, site, c.ID); err != nil {
		t.Fatal(err)
	}
	e.svc.Wait()
	rec, _ := e.act.Query(ctx, logs.Filter{Action: "site.cron.recovered"})
	if len(rec) != 1 {
		t.Fatalf("recovered %+v", rec)
	}
	got, _ := e.svc.Store.Get(ctx, c.ID)
	if got.LastStatus != StatusOK {
		t.Fatalf("%+v", got)
	}
	ok, _ := e.svc.Store.Runs(ctx, RunFilter{Status: StatusFailed})
	if len(ok) != 1 {
		t.Fatalf("failed filter %d", len(ok))
	}
}

func TestTimeoutDetected(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	site := e.site(t, "ornek.com", sites.StatusRunning)
	c, _ := e.svc.Save(ctx, site, Cron{Name: "t", Schedule: "* * * * *", Command: "sleep 9999", Enabled: true, TimeoutSec: 60})
	e.run.exit, e.run.out = 1, "Finished with result: timeout\n"
	e.svc.RunNow(ctx, ctx, site, c.ID)
	e.svc.Wait()
	runs, _ := e.svc.Store.Runs(ctx, RunFilter{CronID: c.ID})
	if len(runs) != 1 || runs[0].Status != StatusTimeout {
		t.Fatalf("%+v", runs)
	}
}

func TestDryRunAndOutputTail(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.svc.DryRun = true
	site := e.site(t, "ornek.com", sites.StatusRunning)
	c, _ := e.svc.Save(ctx, site, Cron{Name: "d", Schedule: "0 3 * * *", Command: "echo x", Enabled: true})
	e.svc.RunNow(ctx, ctx, site, c.ID)
	e.svc.Wait()
	runs, _ := e.svc.Store.Runs(ctx, RunFilter{})
	if e.run.n() != 0 || len(runs) != 1 || !strings.Contains(runs[0].Output, "[DRY-RUN]") || runs[0].Source != "user" {
		t.Fatalf("calls %d %+v", e.run.n(), runs)
	}
	tb := &tailBuffer{max: 10}
	tb.Write([]byte("0123456789"))
	tb.Write([]byte("abc"))
	if s := tb.String(); !strings.HasSuffix(s, "3456789abc") || !strings.Contains(s, "kısaltıldı") {
		t.Fatalf("%q", s)
	}
}

func TestPruneAndDelete(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	site := e.site(t, "ornek.com", sites.StatusRunning)
	c, _ := e.svc.Save(ctx, site, Cron{Name: "p", Schedule: "* * * * *", Command: "true", Enabled: true})
	for i := 0; i < 5; i++ {
		e.svc.Store.AddRun(ctx, &Run{CronID: c.ID, SiteID: site.ID, StartedAt: e.now.Add(time.Duration(i) * time.Minute), Status: StatusOK})
	}
	e.svc.Store.AddRun(ctx, &Run{CronID: c.ID, SiteID: site.ID, StartedAt: e.now.Add(-40 * 24 * time.Hour), Status: StatusOK})
	n, err := e.svc.Store.Prune(ctx, e.now, 3, RunMaxAge)
	if err != nil || n != 4 { // 3 beyond the newest 3 by id + the 40-day-old one
		t.Fatalf("pruned %d %v", n, err)
	}
	other := e.site(t, "baska.com", sites.StatusRunning)
	if err := e.svc.Delete(ctx, other, c.ID); err == nil {
		t.Fatal("deleted another site's cron")
	}
	if err := e.svc.Delete(ctx, site, c.ID); err != nil {
		t.Fatal(err)
	}
	if runs, _ := e.svc.Store.Runs(ctx, RunFilter{}); len(runs) != 0 {
		t.Fatalf("runs left %d", len(runs))
	}
	if _, err := e.svc.Store.Get(ctx, c.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("get after delete: %v", err)
	}
}

func TestSchedulerStops(t *testing.T) {
	e := newEnv(t)
	e.svc.Now = nil
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.svc.Run(ctx); close(done) }()
	e.svc.Reschedule()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("scheduler did not stop")
	}
}
