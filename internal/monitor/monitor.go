// Package monitor runs per-site health checks, detects crash loops and
// watches disk usage. One goroutine with one timer; results become activity
// entries and notifications.
package monitor

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	neturl "net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zahit5834/hostpanel/internal/exec"
	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/notify"
	"github.com/zahit5834/hostpanel/internal/runtimes"
	"github.com/zahit5834/hostpanel/internal/sites"
	"github.com/zahit5834/hostpanel/internal/system"
)

// Health states.
const (
	StateUnknown = "unknown"
	StateUp      = "up"
	StateDown    = "down"
)

// Tunables.
const (
	FailThreshold   = 2 // consecutive failures before "down"
	RestartWindow   = 15 * time.Minute
	RestartLimit    = 3 // restarts within RestartWindow = crash loop
	DiskThreshold   = 85
	diskEvery       = 10 * time.Minute
	checkTimeout    = 10 * time.Second
	DefaultInterval = 300
	maxSleep        = 10 * time.Minute
)

// Intervals offered in the UI (seconds).
var Intervals = []int{60, 300, 900}

// Check is a site's health check row.
type Check struct {
	SiteID      int64
	Enabled     bool
	Path        string
	Expect      int // 0 = any status < 500
	Interval    int
	State       string
	Fails       int
	LastChecked time.Time
	LastMS      int
	LastCode    int
	LastError   string
	ChangedAt   time.Time
	Restarts    int
	RestartLog  []int64
}

// Due is the next check time.
func (c Check) Due() time.Time {
	if c.LastChecked.IsZero() {
		return time.Time{}
	}
	return c.LastChecked.Add(time.Duration(c.Interval) * time.Second)
}

// RecentRestarts counts restarts seen within RestartWindow before now.
func (c Check) RecentRestarts(now time.Time) int {
	n, cut := 0, now.Add(-RestartWindow).Unix()
	for _, t := range c.RestartLog {
		if t >= cut {
			n++
		}
	}
	return n
}

// Store accesses health_checks.
type Store struct{ db *sql.DB }

// NewStore wraps db.
func NewStore(db *sql.DB) *Store { return &Store{db: db} }

const cols = `site_id, enabled, path, expect_status, interval_sec, state, fails, last_checked, last_ms, last_code,
	last_error, changed_at, restarts, restart_log`

func scan(sc interface{ Scan(...any) error }) (Check, error) {
	var c Check
	var last, changed int64
	var rl string
	err := sc.Scan(&c.SiteID, &c.Enabled, &c.Path, &c.Expect, &c.Interval, &c.State, &c.Fails, &last, &c.LastMS, &c.LastCode,
		&c.LastError, &changed, &c.Restarts, &rl)
	if last > 0 {
		c.LastChecked = time.Unix(last, 0)
	}
	if changed > 0 {
		c.ChangedAt = time.Unix(changed, 0)
	}
	json.Unmarshal([]byte(rl), &c.RestartLog)
	return c, err
}

// Get returns a site's check.
func (st *Store) Get(ctx context.Context, siteID int64) (Check, error) {
	return scan(st.db.QueryRowContext(ctx, `SELECT `+cols+` FROM health_checks WHERE site_id=?`, siteID))
}

// All returns every check by site id.
func (st *Store) All(ctx context.Context) (map[int64]Check, error) {
	rows, err := st.db.QueryContext(ctx, `SELECT `+cols+` FROM health_checks`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]Check{}
	for rows.Next() {
		c, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out[c.SiteID] = c
	}
	return out, rows.Err()
}

// Ensure creates the default check of a site.
func (st *Store) Ensure(ctx context.Context, site sites.Site) error {
	path := site.HealthPath
	if path == "" {
		path = "/"
	}
	_, err := st.db.ExecContext(ctx, `INSERT OR IGNORE INTO health_checks(site_id, path, interval_sec) VALUES (?,?,?)`,
		site.ID, path, DefaultInterval)
	return err
}

// SaveSettings updates the admin-editable fields.
func (st *Store) SaveSettings(ctx context.Context, c Check) error {
	_, err := st.db.ExecContext(ctx, `UPDATE health_checks SET enabled=?, path=?, expect_status=?, interval_sec=? WHERE site_id=?`,
		c.Enabled, c.Path, c.Expect, c.Interval, c.SiteID)
	return err
}

func (st *Store) saveResult(ctx context.Context, c Check) error {
	rl, _ := json.Marshal(c.RestartLog)
	if c.RestartLog == nil {
		rl = []byte("[]")
	}
	var last, changed int64
	if !c.LastChecked.IsZero() {
		last = c.LastChecked.Unix()
	}
	if !c.ChangedAt.IsZero() {
		changed = c.ChangedAt.Unix()
	}
	_, err := st.db.ExecContext(ctx, `UPDATE health_checks SET state=?, fails=?, last_checked=?, last_ms=?, last_code=?, last_error=?,
		changed_at=?, restarts=?, restart_log=? WHERE site_id=?`,
		c.State, c.Fails, last, c.LastMS, c.LastCode, c.LastError, changed, c.Restarts, string(rl), c.SiteID)
	return err
}

// Transition is the health state machine: FailThreshold consecutive failures
// make a site down, one success brings it back. event is "down", "up" or "".
func Transition(state string, fails int, ok bool) (string, int, string) {
	if ok {
		if state == StateDown {
			return StateUp, 0, "up"
		}
		return StateUp, 0, ""
	}
	fails++
	if fails >= FailThreshold && state != StateDown {
		return StateDown, fails, "down"
	}
	return state, fails, ""
}

// countRestarts appends delta restarts at now and keeps only the window.
func countRestarts(log []int64, delta int, now time.Time) []int64 {
	for i := 0; i < delta && i < 50; i++ {
		log = append(log, now.Unix())
	}
	cut := now.Add(-RestartWindow).Unix()
	out := log[:0]
	for _, t := range log {
		if t >= cut {
			out = append(out, t)
		}
	}
	return out
}

// Service runs the checks.
type Service struct {
	Store    *Store
	Sites    *sites.Service
	Probe    exec.Runner
	Activity *logs.Activity
	Log      *slog.Logger
	Notify   func(ctx context.Context, e notify.Event)
	DryRun   bool

	// Probe hooks (tests): HTTP check, NRestarts and disk usage.
	CheckFunc    func(ctx context.Context, site sites.Site, c Check) (code int, err error)
	RestartsFunc func(ctx context.Context, site sites.Site) int
	DiskFunc     func() int
	Now          func() time.Time

	once       sync.Once
	runMu      sync.Mutex // RunDue and CheckNow update rows one at a time
	wake       chan struct{}
	mu         sync.Mutex
	diskNext   time.Time
	diskHigh   atomic.Bool
	restartMsg map[int64]time.Time
}

func (s *Service) init() {
	s.once.Do(func() {
		s.wake = make(chan struct{}, 1)
		s.restartMsg = map[int64]time.Time{}
	})
}

// Clock is the service's notion of now (tests inject Now).
func (s *Service) Clock() time.Time { return s.now() }

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) send(ctx context.Context, e notify.Event) {
	if s.Notify != nil {
		s.Notify(ctx, e)
	}
}

// Reschedule wakes the loop (settings changed).
func (s *Service) Reschedule() {
	s.init()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Run checks due sites until ctx is cancelled.
func (s *Service) Run(ctx context.Context) {
	s.init()
	for {
		next := s.RunDue(ctx, s.now())
		d := min(max(time.Until(next), time.Second), maxSleep)
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

// RunDue runs every due check (sequentially) and the disk check, and returns
// the earliest next due time.
func (s *Service) RunDue(ctx context.Context, now time.Time) time.Time {
	s.init()
	s.runMu.Lock()
	defer s.runMu.Unlock()
	next := now.Add(maxSleep)
	list, err := s.Sites.Store.List(ctx, 0)
	if err != nil {
		return now.Add(time.Minute)
	}
	checks, _ := s.Store.All(ctx)
	for _, site := range list {
		if ctx.Err() != nil {
			return next
		}
		c, ok := checks[site.ID]
		if !ok {
			if site.Status == sites.StatusProvisioning {
				continue
			}
			s.Store.Ensure(ctx, site)
			if c, err = s.Store.Get(ctx, site.ID); err != nil {
				continue
			}
		}
		if site.Status != sites.StatusRunning || !c.Enabled {
			if c.State != StateUnknown { // stopped on purpose: forget the state, no alert
				if c.State == StateDown {
					s.Store.closeIncident(ctx, site.ID, now, "site durduruldu ya da kontrol kapatıldı")
				}
				c.State, c.Fails = StateUnknown, 0
				s.Store.saveResult(ctx, c)
			}
			continue
		}
		if due := c.Due(); due.IsZero() || !due.After(now) {
			c = s.checkSite(ctx, site, c, now)
		}
		if due := c.Due(); due.Before(next) {
			next = due
		}
	}
	if !now.Before(s.diskNext) {
		s.checkDisk(ctx)
		s.diskNext = now.Add(diskEvery)
	}
	if s.diskNext.Before(next) {
		next = s.diskNext
	}
	return next
}

// CheckNow runs one site's check immediately (the "Şimdi kontrol et" button).
func (s *Service) CheckNow(ctx context.Context, site sites.Site) (Check, error) {
	s.init()
	s.runMu.Lock()
	defer s.runMu.Unlock()
	s.Store.Ensure(ctx, site)
	c, err := s.Store.Get(ctx, site.ID)
	if err != nil {
		return c, err
	}
	if site.Status != sites.StatusRunning {
		return c, errors.New("yalnızca çalışan siteler kontrol edilir")
	}
	return s.checkSite(ctx, site, c, s.now()), nil
}

func (s *Service) checkSite(ctx context.Context, site sites.Site, c Check, now time.Time) Check {
	start := time.Now()
	code, err := s.probe(ctx, site, c)
	c.LastChecked, c.LastMS, c.LastCode = now, int(time.Since(start).Milliseconds()), code
	ok := err == nil
	c.LastError = ""
	if err != nil {
		c.LastError = err.Error()
	}
	prev := c.State
	var ev string
	c.State, c.Fails, ev = Transition(c.State, c.Fails, ok)
	if c.State != prev {
		c.ChangedAt = now
	}
	s.Store.recordUptime(ctx, site.ID, now, ok, c.LastMS)
	switch ev {
	case "down":
		// The site has been failing since the first of the consecutive failures.
		started := now.Add(-time.Duration((c.Fails-1)*c.Interval) * time.Second)
		s.Store.openIncident(ctx, site.ID, started, c.LastError)
		s.Activity.Record(ctx, logs.Entry{Action: "site.down", TargetType: "site", TargetID: site.Domain, Status: logs.StatusFailed,
			Summary: "Site erişilemiyor: " + site.Domain, Error: c.LastError}, nil)
		s.send(ctx, notify.Event{Kind: notify.KindSiteStatus, Key: "down:" + site.Domain, NoDedupe: true,
			Title: "🔴 " + site.Domain + " erişilemiyor", Text: c.LastError})
	case "up":
		s.Store.closeIncident(ctx, site.ID, now, "")
		s.Activity.Record(ctx, logs.Entry{Action: "site.up", TargetType: "site", TargetID: site.Domain,
			Summary: "Site tekrar erişilebilir: " + site.Domain}, nil)
		s.send(ctx, notify.Event{Kind: notify.KindSiteStatus, Key: "up:" + site.Domain, NoDedupe: true,
			Title: "🟢 " + site.Domain + " tekrar erişilebilir"})
	}
	if s.hasUnit(site) {
		s.checkRestarts(ctx, site, &c, now)
	}
	s.Store.saveResult(ctx, c)
	return c
}

func (s *Service) isProxy(site sites.Site) bool {
	p, ok := s.Sites.Runtimes.Get(site.RuntimeID)
	return ok && p.Def().Type == runtimes.TypeProxy
}

// hasUnit: proxy apps and PHP sites run their own unit (restart counting).
func (s *Service) hasUnit(site sites.Site) bool {
	p, ok := s.Sites.Runtimes.Get(site.RuntimeID)
	return ok && p.Def().HasUnit()
}

func (s *Service) checkRestarts(ctx context.Context, site sites.Site, c *Check, now time.Time) {
	n := s.restarts(ctx, site)
	if n < 0 {
		return
	}
	delta := 0
	if c.Restarts >= 0 && n > c.Restarts {
		delta = n - c.Restarts
	}
	c.Restarts = n
	c.RestartLog = countRestarts(c.RestartLog, delta, now)
	if len(c.RestartLog) < RestartLimit {
		return
	}
	s.mu.Lock()
	last := s.restartMsg[site.ID]
	fire := now.Sub(last) >= time.Hour
	if fire {
		s.restartMsg[site.ID] = now
	}
	s.mu.Unlock()
	if !fire {
		return
	}
	msg := fmt.Sprintf("%s son %d dakikada %d kez yeniden başladı", site.Domain, int(RestartWindow.Minutes()), len(c.RestartLog))
	s.Activity.Record(ctx, logs.Entry{Action: "site.restarting", TargetType: "site", TargetID: site.Domain,
		Status: logs.StatusFailed, Summary: msg}, nil)
	s.send(ctx, notify.Event{Kind: notify.KindRestarting, Key: "restart:" + site.Domain, Title: "🔁 " + msg,
		Text: "Site → Loglar → Uygulama (journal) sekmesine bakın."})
}

func (s *Service) restarts(ctx context.Context, site sites.Site) int {
	if s.RestartsFunc != nil {
		return s.RestartsFunc(ctx, site)
	}
	res, err := s.Probe.Run(ctx, exec.Cmd{Name: "systemctl", Args: []string{"show", "-p", "NRestarts", "--value", site.Unit() + ".service"},
		Timeout: 5 * time.Second})
	if err != nil {
		return -1
	}
	n, err := strconv.Atoi(strings.TrimSpace(res.Stdout))
	if err != nil {
		return -1
	}
	return n
}

func (s *Service) checkDisk(ctx context.Context) {
	pct := 0
	if s.DiskFunc != nil {
		pct = s.DiskFunc()
	} else {
		pct = system.Read().DiskUsedPct()
	}
	high := pct >= DiskThreshold
	if high == s.diskHigh.Load() {
		return
	}
	s.diskHigh.Store(high)
	if high {
		msg := fmt.Sprintf("Disk kullanımı %%%d (eşik %%%d)", pct, DiskThreshold)
		s.Activity.Record(ctx, logs.Entry{Action: "disk.high", TargetType: "server", TargetID: "/", Status: logs.StatusFailed, Summary: msg}, nil)
		s.send(ctx, notify.Event{Kind: notify.KindDisk, Key: "disk", Title: "💾 " + msg,
			Text: "Sunucu sayfasındaki disk dağılımına bakın; eski yedekleri temizleyin."})
	} else {
		s.Activity.Record(ctx, logs.Entry{Action: "disk.ok", TargetType: "server", TargetID: "/",
			Summary: fmt.Sprintf("Disk kullanımı eşiğin altına indi (%%%d)", pct)}, nil)
	}
}

// DiskHigh reports the last disk state (dashboard).
func (s *Service) DiskHigh() bool { return s.diskHigh.Load() }

// probe performs the HTTP check: proxy apps directly on their port, static
// sites through nginx (Host header; HTTPS with SNI when HTTPS is forced).
// Redirects are not followed.
func (s *Service) probe(ctx context.Context, site sites.Site, c Check) (int, error) {
	var code int
	var err error
	switch {
	case s.CheckFunc != nil:
		code, err = s.CheckFunc(ctx, site, c)
	case s.DryRun:
		return 200, nil
	default:
		code, err = s.httpCheck(ctx, site, c)
	}
	if err != nil {
		return code, err
	}
	if c.Expect != 0 && code != c.Expect {
		return code, fmt.Errorf("HTTP %d (beklenen %d)", code, c.Expect)
	}
	if c.Expect == 0 && code >= 500 {
		return code, fmt.Errorf("HTTP %d", code)
	}
	return code, nil
}

func (s *Service) httpCheck(ctx context.Context, site sites.Site, c Check) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()
	var url string
	tr := &http.Transport{DisableKeepAlives: true}
	if s.isProxy(site) {
		url = fmt.Sprintf("http://127.0.0.1:%d%s", site.Port, c.Path)
	} else {
		scheme, port := "http", "80"
		if site.ForceHTTPS {
			scheme, port = "https", "443"
			tr.TLSClientConfig = &tls.Config{ServerName: site.Domain, MinVersion: tls.VersionTLS12}
		}
		url = scheme + "://" + site.Domain + c.Path
		d := net.Dialer{}
		tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, "127.0.0.1:"+port)
		}
	}
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "HostPanel-HealthCheck")
	res, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return 0, fmt.Errorf("zaman aşımı (%s)", checkTimeout)
		}
		var ue *neturl.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return 0, fmt.Errorf("bağlantı hatası: %v", err)
	}
	res.Body.Close()
	return res.StatusCode, nil
}

// ValidPath reuses the deploy health path rule.
func ValidPath(p string) bool { return sites.ValidHealthPath(p) }
