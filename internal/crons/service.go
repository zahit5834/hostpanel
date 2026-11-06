package crons

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"hostpanel/internal/exec"
	"hostpanel/internal/logs"
	"hostpanel/internal/notify"
	"hostpanel/internal/schedule"
	"hostpanel/internal/sites"
)

// Tunables.
const (
	MaxConcurrent  = 4             // runs at the same time (all sites)
	OutputMax      = 16 << 10      // bytes of output kept per run
	DefaultTimeout = 600           // seconds
	MinTimeout     = 60            //
	MaxTimeout     = 3600          //
	lateTolerance  = time.Minute   // a run later than this (panel was down) is skipped, not caught up
	maxSleep       = 6 * time.Hour // bounds one sleep (clock jumps)
	KeepRuns       = 100           // per cron
	RunMaxAge      = 30 * 24 * time.Hour
)

// Service schedules and runs site crons.
type Service struct {
	Store      *Store
	Sites      *sites.Service
	Runner     exec.Runner // privileged helpers (dry-run in dev)
	Activity   *logs.Activity
	Log        *slog.Logger
	ScriptsDir string
	DryRun     bool
	Notify     func(ctx context.Context, e notify.Event)
	Now        func() time.Time // tests

	once    sync.Once
	wake    chan struct{}
	sem     chan struct{}
	mu      sync.Mutex
	running map[int64]bool
	wg      sync.WaitGroup
}

func (s *Service) init() {
	s.once.Do(func() {
		s.wake = make(chan struct{}, 1)
		s.sem = make(chan struct{}, MaxConcurrent)
		s.running = map[int64]bool{}
	})
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// ValidCommand: one line, no control characters, 1–1000 bytes (shared with
// git build commands; mirrors validate_user_command in lib.sh).
var ValidCommand = sites.ValidCommand

// Validate cleans and checks a cron before it is saved.
func Validate(c *Cron) error {
	c.Name = strings.TrimSpace(c.Name)
	if c.Name == "" || utf8.RuneCountInString(c.Name) > 60 || strings.ContainsFunc(c.Name, func(r rune) bool { return r < 0x20 }) {
		return errors.New("ad 1–60 karakter olmalı")
	}
	c.Schedule = strings.Join(strings.Fields(c.Schedule), " ")
	if _, err := schedule.NextRun(c.Schedule, time.Now()); err != nil {
		return err
	}
	if err := ValidCommand(c.Command); err != nil {
		return err
	}
	if c.TimeoutSec == 0 {
		c.TimeoutSec = DefaultTimeout
	}
	if c.TimeoutSec < MinTimeout || c.TimeoutSec > MaxTimeout {
		return fmt.Errorf("zaman aşımı %d–%d saniye olmalı", MinTimeout, MaxTimeout)
	}
	return nil
}

func cronDiff(old, cur Cron) string {
	var b strings.Builder
	field := func(name, a, c string) {
		if a != c {
			if a != "" {
				fmt.Fprintf(&b, "- %s=%s\n", name, a)
			}
			fmt.Fprintf(&b, "+ %s=%s\n", name, c)
		}
	}
	onoff := map[bool]string{true: "açık", false: "kapalı"}
	field("ad", old.Name, cur.Name)
	field("zamanlama", old.Schedule, cur.Schedule)
	field("komut", old.Command, cur.Command)
	field("etkin", onoff[old.Enabled], onoff[cur.Enabled])
	if old.TimeoutSec != cur.TimeoutSec {
		field("zaman_aşımı", strconv.Itoa(old.TimeoutSec), strconv.Itoa(cur.TimeoutSec))
	}
	return strings.TrimRight(b.String(), "\n")
}

// Save creates (ID == 0) or updates a cron of site and records the change.
func (s *Service) Save(ctx context.Context, site sites.Site, c Cron) (Cron, error) {
	c.SiteID = site.ID
	if err := Validate(&c); err != nil {
		return c, err
	}
	var old Cron
	if c.ID != 0 {
		var err error
		if old, err = s.Store.Get(ctx, c.ID); err != nil || old.SiteID != site.ID {
			return c, errors.New("cron bulunamadı")
		}
	}
	c.NextRunAt = time.Time{}
	if c.Enabled {
		c.NextRunAt, _ = schedule.NextRun(c.Schedule, s.now())
	}
	var err error
	action, summary := "site.cron.update", "Cron güncellendi: "
	if c.ID == 0 {
		action, summary = "site.cron.create", "Cron eklendi: "
		err = s.Store.Insert(ctx, &c)
	} else {
		err = s.Store.Update(ctx, c)
	}
	if err != nil {
		return c, err
	}
	s.Activity.Record(ctx, logs.Entry{Action: action, TargetType: "site", TargetID: site.Domain,
		Summary: summary + c.Name + " (" + site.Domain + ")", Diff: cronDiff(old, c)}, nil)
	s.Reschedule()
	return c, nil
}

// Delete removes a cron of site.
func (s *Service) Delete(ctx context.Context, site sites.Site, id int64) error {
	c, err := s.Store.Get(ctx, id)
	if err != nil || c.SiteID != site.ID {
		return errors.New("cron bulunamadı")
	}
	if err := s.Store.Delete(ctx, id); err != nil {
		return err
	}
	s.Activity.Record(ctx, logs.Entry{Action: "site.cron.delete", TargetType: "site", TargetID: site.Domain,
		Summary: "Cron silindi: " + c.Name + " (" + site.Domain + ")", Diff: cronDiff(c, Cron{})}, nil)
	s.Reschedule()
	return nil
}

// Running reports whether a cron is executing now.
func (s *Service) Running(id int64) bool {
	s.init()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running[id]
}

// RunNow starts a cron immediately (in the background); the run is recorded
// with source "user". ctx only carries the actor; the run itself uses base.
func (s *Service) RunNow(ctx, base context.Context, site sites.Site, id int64) error {
	c, err := s.Store.Get(ctx, id)
	if err != nil || c.SiteID != site.ID {
		return errors.New("cron bulunamadı")
	}
	if !Eligible(site, s.Sites.Store.ActiveRelease(ctx, site.ID)) {
		return errors.New("site çalışmıyor veya henüz deploy edilmedi")
	}
	if s.Running(id) {
		return errors.New("bu cron zaten çalışıyor")
	}
	s.Activity.Record(ctx, logs.Entry{Action: "site.cron.run", TargetType: "site", TargetID: site.Domain,
		Summary: "Cron elle çalıştırıldı: " + c.Name + " (" + site.Domain + ")"}, nil)
	s.start(base, c, site, "user")
	return nil
}

// Eligible: crons run only for running sites (also in maintenance mode) with
// a real release.
func Eligible(site sites.Site, active string) bool {
	return (site.Status == sites.StatusRunning || site.Status == sites.StatusMaintenance) &&
		active != "" && active != sites.PlaceholderRelease
}

// start runs c in its own goroutine unless it is already running (then a
// "skipped" run is recorded).
func (s *Service) start(ctx context.Context, c Cron, site sites.Site, source string) {
	s.init()
	s.mu.Lock()
	if s.running[c.ID] {
		s.mu.Unlock()
		s.Store.AddRun(ctx, &Run{CronID: c.ID, SiteID: c.SiteID, StartedAt: s.now(), Status: StatusSkipped, Source: source,
			Output: "Önceki çalışma hâlâ sürüyor; bu çalışma atlandı."})
		return
	}
	s.running[c.ID] = true
	s.mu.Unlock()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer func() {
			s.mu.Lock()
			delete(s.running, c.ID)
			s.mu.Unlock()
		}()
		select {
		case s.sem <- struct{}{}:
		case <-ctx.Done():
			return
		}
		defer func() { <-s.sem }()
		s.execute(ctx, c, site, source)
	}()
}

// Wait blocks until running crons finish (shutdown, tests).
func (s *Service) Wait() { s.wg.Wait() }

// tailBuffer keeps the last max bytes written.
type tailBuffer struct {
	mu   sync.Mutex
	buf  []byte
	max  int
	lost bool
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if over := len(t.buf) - t.max; over > 0 {
		t.buf = append(t.buf[:0], t.buf[over:]...)
		t.lost = true
	}
	return len(p), nil
}

func (t *tailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := string(bytes.ToValidUTF8(t.buf, nil))
	if t.lost {
		out = "… (çıktının başı kısaltıldı)\n" + out
	}
	return out
}

func (s *Service) execute(ctx context.Context, c Cron, site sites.Site, source string) {
	started := s.now()
	run := Run{CronID: c.ID, SiteID: c.SiteID, StartedAt: started, Source: source, Status: StatusOK}
	out := &tailBuffer{max: OutputMax}
	if s.DryRun {
		fmt.Fprintf(out, "[DRY-RUN] %s olarak çalıştırılırdı (zaman aşımı %d sn):\n%s\n", site.User(), c.TimeoutSec, c.Command)
	} else {
		version := site.RuntimeVersion
		if version == "" {
			version = "-"
		}
		cmd := exec.Helper(s.ScriptsDir, "hp-site-cron.sh", "run", site.Domain, site.User(), strconv.FormatInt(c.ID, 10),
			site.RuntimeID, version, strconv.Itoa(c.TimeoutSec), strconv.Itoa(site.MemoryMaxMB), strconv.Itoa(site.CPUQuotaPct))
		cmd.Stdin = strings.NewReader(c.Command)
		cmd.Output = out
		cmd.Timeout = time.Duration(c.TimeoutSec)*time.Second + time.Minute
		res, err := s.Runner.Run(ctx, cmd)
		run.ExitCode = res.ExitCode
		switch {
		case err == nil:
		case strings.Contains(out.String(), "Finished with result: timeout") || errors.Is(err, context.DeadlineExceeded):
			run.Status = StatusTimeout
		default:
			run.Status = StatusFailed
			if run.ExitCode == 0 {
				run.ExitCode = -1
			}
			var ee *exec.ExitError
			if !errors.As(err, &ee) {
				fmt.Fprintf(out, "\n%v\n", err)
			}
		}
	}
	run.DurationMS = int(s.now().Sub(started).Milliseconds())
	run.Output = out.String()
	rctx := context.WithoutCancel(ctx)
	prev := c.LastStatus
	if err := s.Store.AddRun(rctx, &run); err != nil && s.Log != nil {
		s.Log.Error("cron run not recorded", "cron", c.ID, "err", err)
	}
	failed := run.Failed()
	wasFailed := prev == StatusFailed || prev == StatusTimeout
	switch {
	case failed:
		msg := "Cron başarısız: " + c.Name + " (" + site.Domain + ")"
		if run.Status == StatusTimeout {
			msg = "Cron zaman aşımına uğradı: " + c.Name + " (" + site.Domain + ")"
		}
		s.Activity.Record(rctx, logs.Entry{Action: "site.cron.failed", TargetType: "site", TargetID: site.Domain,
			Status: logs.StatusFailed, Summary: msg, Error: fmt.Sprintf("çıkış kodu %d", run.ExitCode), DurationMS: int64(run.DurationMS)}, nil)
		if s.Notify != nil {
			s.Notify(rctx, notify.Event{Kind: notify.KindCron, Key: "cron:" + strconv.FormatInt(c.ID, 10),
				Title: "⚠️ " + msg, Text: lastLines(run.Output, 10)})
		}
	case wasFailed:
		s.Activity.Record(rctx, logs.Entry{Action: "site.cron.recovered", TargetType: "site", TargetID: site.Domain,
			Summary: "Cron tekrar başarılı: " + c.Name + " (" + site.Domain + ")"}, nil)
	}
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	out := strings.Join(lines, "\n")
	if len(out) > 1500 {
		out = out[len(out)-1500:]
	}
	return out
}

// Reschedule wakes the scheduler after a change.
func (s *Service) Reschedule() {
	s.init()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Run sleeps on a single timer until the earliest due cron, starts it and
// repeats; it returns when ctx is cancelled (after running crons finish).
func (s *Service) Run(ctx context.Context) {
	s.init()
	defer s.wg.Wait()
	for {
		next := s.RunDue(ctx, s.now())
		d := maxSleep
		if !next.IsZero() {
			d = min(max(next.Sub(s.now()), time.Second), maxSleep)
		}
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		case <-s.wake:
			t.Stop()
		}
	}
}

// RunDue starts every enabled cron whose time has come and returns the
// earliest next run. A run missed by more than lateTolerance (panel down) is
// not caught up: like cron, only the next time is computed.
func (s *Service) RunDue(ctx context.Context, now time.Time) time.Time {
	list, err := s.Store.All(ctx)
	if err != nil {
		if ctx.Err() == nil && s.Log != nil {
			s.Log.Error("cron scheduler", "err", err)
		}
		return now.Add(time.Minute)
	}
	siteCache := map[int64]*sites.Site{}
	var earliest time.Time
	for _, c := range list {
		if !c.Enabled {
			continue
		}
		next := c.NextRunAt
		if next.IsZero() || !next.After(now) {
			if !next.IsZero() && now.Sub(next) <= lateTolerance {
				site, ok := siteCache[c.SiteID]
				if !ok {
					if st, err := s.Sites.Store.Get(ctx, c.SiteID); err == nil {
						site = &st
					}
					siteCache[c.SiteID] = site
				}
				if site != nil && Eligible(*site, s.Sites.Store.ActiveRelease(ctx, site.ID)) {
					s.start(ctx, c, *site, "system")
				}
			}
			n, err := schedule.NextRun(c.Schedule, now)
			if err != nil {
				continue
			}
			s.Store.SetNext(ctx, c.ID, n)
			next = n
		}
		if earliest.IsZero() || next.Before(earliest) {
			earliest = next
		}
	}
	return earliest
}

// Maintain prunes old runs (daily maintenance).
func (s *Service) Maintain(ctx context.Context) {
	n, err := s.Store.Prune(ctx, s.now(), KeepRuns, RunMaxAge)
	if err != nil && s.Log != nil {
		s.Log.Warn("cron runs prune", "err", err)
	} else if n > 0 && s.Log != nil {
		s.Log.Info("cron runs pruned", "n", n)
	}
}
