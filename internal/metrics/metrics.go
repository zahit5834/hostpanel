// Package metrics keeps a 30-day history of server metrics (Faz 12, S6) and
// sends the optional external heartbeat (I2).
//
// Both need a periodic wake-up, the panel's one deliberate exception to "no
// idle timers": one goroutine, one timer every Interval, and only while the
// history is enabled or a heartbeat URL is set. Each tick is a handful of
// /proc reads, one INSERT and (with a URL) one small HTTP request.
package metrics

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/zahit5834/hostpanel/internal/store"
	"github.com/zahit5834/hostpanel/internal/system"
)

const (
	// Interval between samples (and heartbeats).
	Interval = 5 * time.Minute
	// KeepDays is how long samples are kept.
	KeepDays = 30

	SetEnabled   = "metrics_enabled" // "1" (default) | "0"
	SetHeartbeat = "heartbeat_url"   // "" = off
	heartbeatTO  = 10 * time.Second
	maxURLLen    = 300
)

// Service samples the server and pings the heartbeat URL.
type Service struct {
	DB  *sql.DB
	Log *slog.Logger
	// Client is used for the heartbeat (tests replace it).
	Client *http.Client
	// Read and Net are replaceable in tests.
	Read func() system.Snapshot
	Net  func() (rx, tx uint64, ok bool)
	CPU  func() (system.CPUTimes, bool)
	// AfterTick runs after each tick (main: hand the garbage back to the OS).
	AfterTick func()

	wake chan struct{}

	mu       sync.Mutex
	prevCPU  system.CPUTimes
	prevRX   uint64
	prevTX   uint64
	havePrev bool
	lastPing time.Time
	pingErr  string
}

// Enabled reports whether the metric history is on (default on).
func (s *Service) Enabled(ctx context.Context) bool {
	return store.GetSetting(ctx, s.DB, SetEnabled, "1") == "1"
}

// HeartbeatURL is the configured heartbeat target ("" = off).
func (s *Service) HeartbeatURL(ctx context.Context) string {
	return store.GetSetting(ctx, s.DB, SetHeartbeat, "")
}

// ValidHeartbeat checks a heartbeat URL: http(s), a host, no credentials,
// printable and short ("" switches the heartbeat off).
func ValidHeartbeat(raw string) error {
	if raw == "" {
		return nil
	}
	if len(raw) > maxURLLen {
		return fmt.Errorf("adres en fazla %d karakter olabilir", maxURLLen)
	}
	for _, r := range raw {
		if r <= ' ' || r > '~' {
			return errors.New("adreste boşluk ya da yazdırılamayan karakter olamaz")
		}
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.Fragment != "" {
		return errors.New("geçersiz adres (https://… ya da http://…, kullanıcı adı/şifre içermeden)")
	}
	return nil
}

// SetEnabledTo switches the metric history and wakes the loop.
func (s *Service) SetEnabledTo(ctx context.Context, enabled bool) error {
	v := "0"
	if enabled {
		v = "1"
	}
	if err := store.SetSetting(ctx, s.DB, SetEnabled, v); err != nil {
		return err
	}
	s.Reschedule()
	return nil
}

// SaveHeartbeat stores the heartbeat URL ("" = off) and wakes the loop.
func (s *Service) SaveHeartbeat(ctx context.Context, heartbeat string) error {
	heartbeat = strings.TrimSpace(heartbeat)
	if err := ValidHeartbeat(heartbeat); err != nil {
		return err
	}
	if err := store.SetSetting(ctx, s.DB, SetHeartbeat, heartbeat); err != nil {
		return err
	}
	s.Reschedule()
	return nil
}

// Reschedule wakes the loop after a settings change.
func (s *Service) Reschedule() {
	if s.wake != nil {
		select {
		case s.wake <- struct{}{}:
		default:
		}
	}
}

// Init must be called before Run and Reschedule are used concurrently.
func (s *Service) Init() {
	if s.wake == nil {
		s.wake = make(chan struct{}, 1)
	}
}

// Run is the single sampling loop. It sleeps without a timer while both
// features are off.
func (s *Service) Run(ctx context.Context) {
	s.Init()
	for {
		active := s.Enabled(ctx) || s.HeartbeatURL(ctx) != ""
		if !active {
			s.mu.Lock()
			s.havePrev = false // the next sample after a pause has no interval
			s.mu.Unlock()
			select {
			case <-ctx.Done():
				return
			case <-s.wake:
				continue
			}
		}
		// Align to the interval so samples land on :00, :05, …
		now := time.Now()
		next := now.Truncate(Interval).Add(Interval)
		if !s.started() {
			next = now.Add(5 * time.Second) // first sample soon after start: counters for the interval
		}
		t := time.NewTimer(time.Until(next))
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-s.wake:
			t.Stop()
			continue
		case <-t.C:
		}
		s.Tick(ctx)
	}
}

func (s *Service) started() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.havePrev
}

// Tick takes one sample (when enabled) and sends the heartbeat (when set).
func (s *Service) Tick(ctx context.Context) {
	if s.Enabled(ctx) {
		if err := s.sample(ctx, time.Now()); err != nil && s.Log != nil {
			s.Log.Warn("metrics sample", "err", err)
		}
	} else {
		s.counters() // keep the deltas meaningful when it is switched on again
	}
	if u := s.HeartbeatURL(ctx); u != "" {
		s.ping(ctx, u)
	}
}

func (s *Service) read() system.Snapshot {
	if s.Read != nil {
		return s.Read()
	}
	return system.Read()
}

// counters reads the cumulative counters and returns the deltas since the
// previous call (ok=false on the first call).
func (s *Service) counters() (cpuPct float64, rx, tx uint64, ok bool) {
	readCPU, readNet := s.CPU, s.Net
	if readCPU == nil {
		readCPU = system.ReadCPU
	}
	if readNet == nil {
		readNet = system.ReadNet
	}
	c, cok := readCPU()
	r, t, nok := readNet()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.havePrev {
		if cok && c.Total > s.prevCPU.Total && c.Busy >= s.prevCPU.Busy {
			cpuPct = float64(c.Busy-s.prevCPU.Busy) * 100 / float64(c.Total-s.prevCPU.Total)
		}
		if nok && r >= s.prevRX && t >= s.prevTX {
			rx, tx = r-s.prevRX, t-s.prevTX
		}
		ok = true
	}
	s.prevCPU, s.prevRX, s.prevTX, s.havePrev = c, r, t, true
	return cpuPct, rx, tx, ok
}

func (s *Service) sample(ctx context.Context, now time.Time) error {
	cpu, rx, tx, ok := s.counters()
	if !ok {
		return nil // first reading only primes the counters
	}
	snap := s.read()
	var diskPct int64
	if snap.DiskTotal > 0 {
		diskPct = int64((snap.DiskTotal - snap.DiskFree) * 1000 / snap.DiskTotal)
	}
	_, err := s.DB.ExecContext(ctx, `INSERT OR REPLACE INTO metrics(ts, cpu, mem_used, mem_total, swap_used, disk_pct, load1, rx, tx)
		VALUES(?,?,?,?,?,?,?,?,?)`, now.Unix(), int64(cpu*10+0.5), int64(snap.MemTotal-snap.MemAvail), int64(snap.MemTotal),
		int64(snap.SwapTotal-snap.SwapFree), diskPct, int64(snap.Load1*100+0.5), int64(rx), int64(tx))
	return err
}

func (s *Service) ping(ctx context.Context, u string) {
	c := s.Client
	if c == nil {
		c = &http.Client{Timeout: heartbeatTO}
	}
	ctx, cancel := context.WithTimeout(ctx, heartbeatTO)
	defer cancel()
	errText := ""
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err == nil {
		req.Header.Set("User-Agent", "HostPanel-heartbeat")
		var res *http.Response
		if res, err = c.Do(req); err == nil {
			res.Body.Close()
			if res.StatusCode >= 300 {
				errText = fmt.Sprintf("HTTP %d", res.StatusCode)
			}
		}
	}
	if err != nil {
		errText = "bağlantı hatası" // the URL itself is not logged (it is the check's secret)
		var ue *url.Error
		if errors.As(err, &ue) && ue.Timeout() {
			errText = "zaman aşımı"
		}
	}
	s.mu.Lock()
	if errText == "" {
		s.lastPing, s.pingErr = time.Now(), ""
	} else {
		s.pingErr = errText
	}
	s.mu.Unlock()
	if errText != "" && s.Log != nil {
		s.Log.Warn("heartbeat failed", "err", errText)
	}
}

// PingState is the last heartbeat result (for the settings page).
func (s *Service) PingState() (last time.Time, errText string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastPing, s.pingErr
}

// TestPing sends one heartbeat now (settings page button).
func (s *Service) TestPing(ctx context.Context) error {
	u := s.HeartbeatURL(ctx)
	if u == "" {
		return errors.New("adres girilmemiş")
	}
	s.ping(ctx, u)
	if _, e := s.PingState(); e != "" {
		return errors.New(e)
	}
	return nil
}

// Point is one (possibly averaged) chart point.
type Point struct {
	TS       time.Time
	CPU      float64 // %
	MemUsed  float64 // bytes
	MemTotal float64
	SwapUsed float64
	DiskPct  float64
	Load1    float64
	RXps     float64 // bytes per second
	TXps     float64
}

// Query returns the samples in [from, to], averaged into at most n buckets.
func (s *Service) Query(ctx context.Context, from, to time.Time, n int) ([]Point, error) {
	if n < 1 {
		n = 1
	}
	span := to.Unix() - from.Unix()
	step := span / int64(n)
	if step < int64(Interval/time.Second) {
		step = int64(Interval / time.Second)
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT MIN(ts), AVG(cpu), AVG(mem_used), MAX(mem_total), AVG(swap_used), AVG(disk_pct),
		AVG(load1), SUM(rx), SUM(tx), COUNT(*) FROM metrics WHERE ts >= ? AND ts <= ? GROUP BY (ts - ?) / ? ORDER BY 1`,
		from.Unix(), to.Unix(), from.Unix(), step)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Point
	for rows.Next() {
		var ts, mt, n int64
		var cpu, mu, su, dp, ld float64
		var rx, tx int64
		if err := rows.Scan(&ts, &cpu, &mu, &mt, &su, &dp, &ld, &rx, &tx, &n); err != nil {
			return nil, err
		}
		secs := float64(n) * Interval.Seconds()
		out = append(out, Point{TS: time.Unix(ts, 0), CPU: cpu / 10, MemUsed: mu, MemTotal: float64(mt), SwapUsed: su,
			DiskPct: dp / 10, Load1: ld / 100, RXps: float64(rx) / secs, TXps: float64(tx) / secs})
	}
	return out, rows.Err()
}

// Purge drops samples older than KeepDays.
func (s *Service) Purge(ctx context.Context, now time.Time) {
	s.DB.ExecContext(ctx, `DELETE FROM metrics WHERE ts < ?`, now.AddDate(0, 0, -KeepDays).Unix())
}
