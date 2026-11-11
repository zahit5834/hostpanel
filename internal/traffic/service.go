package traffic

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"

	"github.com/zahit5834/hostpanel/internal/sites"
)

// Service stores and reads daily traffic statistics.
type Service struct {
	DB    *sql.DB
	Sites *sites.Service
	Log   *slog.Logger
	// LogPath returns a site's access log (sites.NginxLogPath by default;
	// tests point it elsewhere).
	LogPath func(sites.Site) string
	// Now is the clock (tests).
	Now func() time.Time

	mu sync.Mutex // one scan at a time: bounds memory on busy servers
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) logPath(site sites.Site) string {
	if s.LogPath != nil {
		return s.LogPath(site)
	}
	return sites.NginxLogPath(site, "access")
}

func startOfDay(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, t.Location())
}

// Collect stores the complete days (yesterday back to MaxBackfill days, not
// before the site existed) that are missing for site. Days without log
// lines are stored as zero so they are not scanned again.
func (s *Service) Collect(ctx context.Context, site sites.Site) error {
	now := s.now()
	today := startOfDay(now)
	first := today.AddDate(0, 0, -MaxBackfill)
	if c := startOfDay(site.CreatedAt.In(now.Location())); !site.CreatedAt.IsZero() && c.After(first) {
		first = c
	}
	have := map[string]bool{}
	rows, err := s.DB.QueryContext(ctx, `SELECT day FROM traffic_daily WHERE site_id=? AND day>=?`, site.ID, DayKey(first))
	if err != nil {
		return err
	}
	for rows.Next() {
		var d string
		if rows.Scan(&d) == nil {
			have[d] = true
		}
	}
	rows.Close()
	want := map[string]bool{}
	for d := first; d.Before(today); d = d.AddDate(0, 0, 1) {
		if k := DayKey(d); !have[k] {
			want[k] = true
		}
	}
	if len(want) == 0 {
		return nil
	}
	s.mu.Lock()
	days, scanErr := Scan(s.logPath(site), want, first)
	s.mu.Unlock()
	for k := range want {
		if err := s.save(ctx, site.ID, days[k], k); err != nil {
			return err
		}
	}
	return scanErr
}

func (s *Service) save(ctx context.Context, siteID int64, d Day, key string) error {
	top, _ := json.Marshal(d.Top)
	if d.Top == nil {
		top = []byte("[]")
	}
	_, err := s.DB.ExecContext(ctx, `INSERT INTO traffic_daily(site_id, day, requests, bytes, visitors, bots, s2xx, s3xx, s4xx, s5xx, top_paths, capped)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(site_id, day) DO UPDATE SET requests=excluded.requests, bytes=excluded.bytes, visitors=excluded.visitors,
			bots=excluded.bots, s2xx=excluded.s2xx, s3xx=excluded.s3xx, s4xx=excluded.s4xx, s5xx=excluded.s5xx,
			top_paths=excluded.top_paths, capped=excluded.capped`,
		siteID, key, d.Requests, d.Bytes, d.Visitors, d.Bots, d.S2, d.S3, d.S4, d.S5, string(top), d.Capped)
	return err
}

// CollectAll runs Collect for every site (daily maintenance) and gives the
// scan buffers back to the OS afterwards.
func (s *Service) CollectAll(ctx context.Context) {
	list, err := s.Sites.Store.List(ctx, 0)
	if err != nil {
		return
	}
	for _, site := range list {
		if ctx.Err() != nil {
			return
		}
		if err := s.Collect(ctx, site); err != nil && s.Log != nil {
			s.Log.Warn("traffic collect", "site", site.Domain, "err", err)
		}
	}
	debug.FreeOSMemory()
}

// Today scans today's lines (live; not stored).
func (s *Service) Today(site sites.Site) (Day, error) {
	now := s.now()
	key := DayKey(now)
	s.mu.Lock()
	days, err := Scan(s.logPath(site), map[string]bool{key: true}, startOfDay(now))
	s.mu.Unlock()
	d, ok := days[key]
	if !ok {
		d = Day{Day: key}
	}
	return d, err
}

// Range returns the stored days of site from (inclusive), oldest first.
func (s *Service) Range(ctx context.Context, siteID int64, from string) ([]Day, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT day, requests, bytes, visitors, bots, s2xx, s3xx, s4xx, s5xx, top_paths, capped
		FROM traffic_daily WHERE site_id=? AND day>=? ORDER BY day`, siteID, from)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Day
	for rows.Next() {
		var d Day
		var top string
		if err := rows.Scan(&d.Day, &d.Requests, &d.Bytes, &d.Visitors, &d.Bots, &d.S2, &d.S3, &d.S4, &d.S5, &top, &d.Capped); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(top), &d.Top)
		out = append(out, d)
	}
	return out, rows.Err()
}

// Totals sums days.
type Totals struct {
	Requests, Bytes, Bots, S4, S5 int64
	VisitorDays                   int64 // sum of daily visitors (a visitor on two days counts twice)
	Days                          int
}

// Sum adds up days; Top merges the daily top lists (approximate: a page
// outside a day's top list is not counted for that day).
func Sum(days []Day) (Totals, []PathCount) {
	var t Totals
	m := map[string]int64{}
	for _, d := range days {
		t.Requests += d.Requests
		t.Bytes += d.Bytes
		t.Bots += d.Bots
		t.S4 += d.S4
		t.S5 += d.S5
		t.VisitorDays += d.Visitors
		t.Days++
		for _, p := range d.Top {
			m[p.Path] += p.Count
		}
	}
	return t, topPaths(m, TopN)
}

// Summary returns the stored totals per site since from (overview page).
func (s *Service) Summary(ctx context.Context, from string) (map[int64]Totals, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT site_id, SUM(requests), SUM(bytes), SUM(bots), SUM(s4xx), SUM(s5xx), SUM(visitors), COUNT(*)
		FROM traffic_daily WHERE day>=? GROUP BY site_id`, from)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]Totals{}
	for rows.Next() {
		var id int64
		var t Totals
		if err := rows.Scan(&id, &t.Requests, &t.Bytes, &t.Bots, &t.S4, &t.S5, &t.VisitorDays, &t.Days); err != nil {
			return nil, err
		}
		out[id] = t
	}
	return out, rows.Err()
}

// Purge deletes days before the given day key.
func (s *Service) Purge(ctx context.Context, before string) (int64, error) {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM traffic_daily WHERE day<?`, before)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
