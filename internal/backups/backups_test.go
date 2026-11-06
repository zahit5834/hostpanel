package backups

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zahit5834/hostpanel/internal/crypto"
	"github.com/zahit5834/hostpanel/internal/jobs"
	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/sites"
	"github.com/zahit5834/hostpanel/internal/store"
)

func TestPrune(t *testing.T) {
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	mk := func(id int64, daysAgo int, local, remote bool) Backup {
		return Backup{ID: id, CreatedAt: now.AddDate(0, 0, -daysAgo), Local: local, Remote: remote, Status: StatusSuccess}
	}
	items := []Backup{mk(1, 10, true, true), mk(2, 8, true, true), mk(3, 6, true, true), mk(4, 4, true, true), mk(5, 2, true, true), mk(6, 0, true, true)}
	sorted := func(v []int64) []int64 { slices.Sort(v); return v }

	l, r := Prune(items, 3, 0, 0, now)
	if !slices.Equal(sorted(l), []int64{1, 2, 3}) || len(r) != 0 {
		t.Errorf("keep 3 local: %v %v", l, r)
	}
	l, r = Prune(items, 10, 4, 0, now)
	if len(l) != 0 || !slices.Equal(sorted(r), []int64{1, 2}) {
		t.Errorf("keep 4 remote: %v %v", l, r)
	}
	l, r = Prune(items, 10, 0, 5, now)
	if len(l) != 0 || !slices.Equal(sorted(r), []int64{1, 2, 3}) {
		t.Errorf("remote older than 5 days: %v %v", l, r)
	}
	_, r = Prune(items, 10, 5, 7, now) // both limits: union
	if !slices.Equal(sorted(r), []int64{1, 2}) {
		t.Errorf("count + age: %v", r)
	}
	// The newest remote copy survives even when everything is "too old".
	old := []Backup{mk(1, 100, false, true), mk(2, 90, false, true)}
	if _, r = Prune(old, 0, 0, 30, now); !slices.Equal(r, []int64{1}) {
		t.Errorf("newest remote copy must stay: %v", r)
	}
	// Local-only copies don't count towards the remote limit.
	mixed := []Backup{mk(1, 3, true, false), mk(2, 2, false, true), mk(3, 1, true, false), mk(4, 0, false, true)}
	if l, r = Prune(mixed, 1, 1, 0, now); !slices.Equal(l, []int64{1}) || !slices.Equal(r, []int64{2}) {
		t.Errorf("mixed: %v %v", l, r)
	}
	if l, _ = Prune(items, 0, 0, 0, now); len(l) != 6 {
		t.Errorf("keepLocal 0 drops every local copy: %v", l)
	}
}

func TestConfigRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	box, _ := crypto.New(key)
	sealed, _ := box.SealString(`Server=127.0.0.1;Password=p"$x`)
	site := sites.Site{Domain: "shop.example.com", ShortName: "shop", Aliases: []string{"old.example.com"}, WWWMode: sites.WWWToApex,
		RuntimeID: "dotnet", RuntimeVersion: "10.0.14", Fields: map[string]string{"dll": "Shop.dll"}, MemoryMaxMB: 512,
		CPUQuotaPct: 100, PersistentDirs: []string{"wwwroot/uploads"}, HealthPath: "/health", MaxUploadMB: 50, HSTS: true}
	cfg := ConfigFor(site, "20261105-120000", map[string]string{"ConnectionStrings__Default": sealed},
		[]ConfigDB{{Name: "shop_db", EnvKey: "ConnectionStrings__Default"}})
	js, _ := jsonMarshal(cfg)
	if strings.Contains(string(js), "Password=") {
		t.Fatal("env value stored in plain text")
	}
	back, err := ParseConfig(js)
	if err != nil {
		t.Fatal(err)
	}
	if plain, err := box.OpenString(back.EnvSealed["ConnectionStrings__Default"]); err != nil || !strings.Contains(plain, `p"$x`) {
		t.Errorf("env round trip: %q %v", plain, err)
	}
	other, _ := crypto.New(append([]byte{1}, key[1:]...))
	if _, err := other.OpenString(back.EnvSealed["ConnectionStrings__Default"]); err == nil {
		t.Error("a different master key opened the env")
	}

	same := back.SettingsFor(site)
	if same.Aliases != "old.example.com" || same.WWWMode != sites.WWWToApex || same.Fields["dll"] != "Shop.dll" || !same.HSTS {
		t.Errorf("same-site settings: %+v", same)
	}
	clone := back.SettingsFor(sites.Site{Domain: "staging.example.com", WWWMode: sites.WWWNone})
	if clone.Aliases != "" || clone.WWWMode != sites.WWWNone || clone.PersistentDirs != "wwwroot/uploads" || clone.HealthPath != "/health" {
		t.Errorf("clone keeps target names: %+v", clone)
	}
	if _, err := ParseConfig([]byte(`{"version":2}`)); err == nil {
		t.Error("unknown version accepted")
	}
}

func TestTokens(t *testing.T) {
	paste := `Paste the following into your remote machine --->
{"access_token":"ya29.a0","token_type":"Bearer","refresh_token":"1//0g","expiry":"2026-11-05T13:00:00+03:00"}
<---End paste`
	tok, err := ExtractToken(paste)
	if err != nil || !strings.HasPrefix(tok, `{"access_token":"ya29.a0"`) || strings.Contains(tok, "\n") {
		t.Errorf("ExtractToken: %q %v", tok, err)
	}
	for _, bad := range []string{"", "no json here", `{"access_token":"x"}`, `{"refresh_token":`} {
		if _, err := ExtractToken(bad); err == nil {
			t.Errorf("ExtractToken(%q) accepted", bad)
		}
	}
	sa := `{
  "type": "service_account", "project_id": "p", "client_email": "bk@p.iam.gserviceaccount.com",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n"
}`
	js, email, err := CheckServiceAccount(sa)
	if err != nil || email != "bk@p.iam.gserviceaccount.com" || strings.Contains(js, "\n  ") {
		t.Errorf("CheckServiceAccount: %v %q", err, email)
	}
	if _, _, err := CheckServiceAccount(`{"type":"authorized_user"}`); err == nil {
		t.Error("non service account accepted")
	}
	if !ValidFolder("HostPanel-Backups/srv1") || ValidFolder("a/../b") || ValidFolder("/abs") || ValidFolder("a b") {
		t.Error("ValidFolder")
	}
}

func TestParseDotenv(t *testing.T) {
	got, err := ParseDotenv("# comment\r\n\nexport A=1\nB = \"two words\"\nC='it''s'\nD=x=y\nE=\"unterminated\n")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"A": "1", "B": "two words", "C": "it''s", "D": "x=y", "E": `"unterminated`}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	for _, bad := range []string{"", "# only comments", "NOEQUALS", "1BAD=x", "BAD KEY=x"} {
		if _, err := ParseDotenv(bad); err == nil {
			t.Errorf("ParseDotenv(%q) accepted", bad)
		}
	}
}

// --- scheduler ---

func testService(t *testing.T) (*Service, *atomic.Int32) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := store.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	act := logs.NewActivity(db)
	jm := jobs.NewManager(db, t.TempDir(), act, jobs.NewBroker(), log)
	s := &Service{Store: NewStore(db), DB: db, Jobs: jm, Activity: act, Log: log}
	s.Register()
	runs := &atomic.Int32{}
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	jm.Register("backup.plan", func(ctx context.Context, l *jobs.Log, p map[string]any) error {
		runs.Add(1)
		select { // stays "running" so a second submit is refused
		case <-release:
		case <-ctx.Done():
		}
		return nil
	})
	jctx, cancel := context.WithCancel(ctx)
	t.Cleanup(func() { cancel(); jm.Wait() })
	if err := jm.Start(jctx, 2); err != nil {
		t.Fatal(err)
	}
	return s, runs
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not reached")
}

func TestRunDue(t *testing.T) {
	s, runs := testService(t)
	ctx := context.Background()
	now := time.Date(2026, 11, 5, 3, 30, 0, 0, time.Local)
	missed := Plan{Name: "gece", Scope: "all", Components: []string{CompFiles}, Schedule: "0 3 * * *", Destination: DestLocal,
		KeepLocal: 3, Enabled: true, NextRunAt: now.Add(-25 * time.Hour)} // panel was down for a day
	later := Plan{Name: "akşam", Scope: "all", Components: []string{CompFiles}, Schedule: "0 22 * * *", Destination: DestLocal,
		KeepLocal: 3, Enabled: true, NextRunAt: time.Date(2026, 11, 5, 22, 0, 0, 0, time.Local)}
	off := Plan{Name: "kapalı", Scope: "all", Components: []string{CompFiles}, Schedule: "* * * * *", Destination: DestLocal,
		KeepLocal: 3, Enabled: false, NextRunAt: now.Add(-time.Hour)}
	for _, p := range []*Plan{&missed, &later, &off} {
		if err := s.Store.SavePlan(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	next := s.RunDue(ctx, now)
	if !next.Equal(later.NextRunAt) {
		t.Errorf("earliest next = %v, want %v", next, later.NextRunAt)
	}
	waitFor(t, func() bool { return runs.Load() == 1 })
	p, _ := s.Store.Plan(ctx, missed.ID)
	if want := time.Date(2026, 11, 6, 3, 0, 0, 0, time.Local); !p.NextRunAt.Equal(want) {
		t.Errorf("missed plan rescheduled to %v, want %v (runs once, not once per missed day)", p.NextRunAt, want)
	}

	// Due again while the first run is still going: not started twice.
	later.Enabled = false
	s.Store.SavePlan(ctx, &later)
	s.RunDue(ctx, p.NextRunAt.Add(time.Minute))
	time.Sleep(50 * time.Millisecond)
	if runs.Load() != 1 {
		t.Errorf("plan started while already running (%d runs)", runs.Load())
	}
	if _, err := s.RunPlanNow(ctx, missed.ID); err == nil {
		t.Error("manual run of a running plan accepted")
	}
}

func TestSchedulerStops(t *testing.T) {
	s, _ := testService(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.RunScheduler(ctx); close(done) }()
	s.Reschedule()
	s.Reschedule() // never blocks
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("scheduler did not stop on cancel")
	}
}

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }
