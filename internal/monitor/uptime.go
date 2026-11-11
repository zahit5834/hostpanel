package monitor

import (
	"context"
	"time"
)

// UptimeDay is one day of health check results.
type UptimeDay struct {
	Day    string // YYYY-MM-DD, server local time
	Checks int64
	Fails  int64
	MSSum  int64
	MSMax  int64
}

// Pct is the share of successful checks (100 when nothing was checked).
func (u UptimeDay) Pct() float64 {
	if u.Checks == 0 {
		return 100
	}
	return float64(u.Checks-u.Fails) * 100 / float64(u.Checks)
}

// AvgMS is the mean response time of the successful checks.
func (u UptimeDay) AvgMS() int64 {
	if ok := u.Checks - u.Fails; ok > 0 {
		return u.MSSum / ok
	}
	return 0
}

// Incident is a down period.
type Incident struct {
	ID        int64
	SiteID    int64
	StartedAt time.Time
	EndedAt   time.Time // zero while still down
	Reason    string
	EndNote   string
}

// Open reports whether the site is still down.
func (i Incident) Open() bool { return i.EndedAt.IsZero() }

// Duration is the length of the incident (until now while open).
func (i Incident) Duration(now time.Time) time.Duration {
	end := i.EndedAt
	if end.IsZero() {
		end = now
	}
	if end.Before(i.StartedAt) {
		return 0
	}
	return end.Sub(i.StartedAt)
}

const dayLayout = "2006-01-02"

func (st *Store) recordUptime(ctx context.Context, siteID int64, now time.Time, ok bool, ms int) error {
	fail, msOK := 0, 0
	if ok {
		msOK = ms
	} else {
		fail = 1
	}
	_, err := st.db.ExecContext(ctx, `INSERT INTO uptime_daily(site_id, day, checks, fails, ms_sum, ms_max) VALUES (?,?,1,?,?,?)
		ON CONFLICT(site_id, day) DO UPDATE SET checks=checks+1, fails=fails+excluded.fails,
			ms_sum=ms_sum+excluded.ms_sum, ms_max=max(ms_max, excluded.ms_max)`,
		siteID, now.Format(dayLayout), fail, msOK, msOK)
	return err
}

func (st *Store) openIncident(ctx context.Context, siteID int64, started time.Time, reason string) error {
	if len(reason) > 500 {
		reason = reason[:500]
	}
	_, err := st.db.ExecContext(ctx, `INSERT INTO uptime_incidents(site_id, started_at, reason) VALUES (?,?,?)`,
		siteID, started.Unix(), reason)
	return err
}

func (st *Store) closeIncident(ctx context.Context, siteID int64, now time.Time, note string) error {
	_, err := st.db.ExecContext(ctx, `UPDATE uptime_incidents SET ended_at=?, end_note=? WHERE site_id=? AND ended_at=0`,
		now.Unix(), note, siteID)
	return err
}

// UptimeDays returns site's days from (inclusive), oldest first.
func (st *Store) UptimeDays(ctx context.Context, siteID int64, from string) ([]UptimeDay, error) {
	rows, err := st.db.QueryContext(ctx, `SELECT day, checks, fails, ms_sum, ms_max FROM uptime_daily
		WHERE site_id=? AND day>=? ORDER BY day`, siteID, from)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UptimeDay
	for rows.Next() {
		var u UptimeDay
		if err := rows.Scan(&u.Day, &u.Checks, &u.Fails, &u.MSSum, &u.MSMax); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// UptimeSummary sums every site's days from (inclusive).
func (st *Store) UptimeSummary(ctx context.Context, from string) (map[int64]UptimeDay, error) {
	rows, err := st.db.QueryContext(ctx, `SELECT site_id, SUM(checks), SUM(fails), SUM(ms_sum), MAX(ms_max) FROM uptime_daily
		WHERE day>=? GROUP BY site_id`, from)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]UptimeDay{}
	for rows.Next() {
		var id int64
		var u UptimeDay
		if err := rows.Scan(&id, &u.Checks, &u.Fails, &u.MSSum, &u.MSMax); err != nil {
			return nil, err
		}
		out[id] = u
	}
	return out, rows.Err()
}

// Incidents returns site's down periods that started at or after since or
// are still open, newest first.
func (st *Store) Incidents(ctx context.Context, siteID int64, since time.Time, limit int) ([]Incident, error) {
	rows, err := st.db.QueryContext(ctx, `SELECT id, site_id, started_at, ended_at, reason, end_note FROM uptime_incidents
		WHERE site_id=? AND (started_at>=? OR ended_at=0) ORDER BY started_at DESC LIMIT ?`, siteID, since.Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Incident
	for rows.Next() {
		var i Incident
		var s, e int64
		if err := rows.Scan(&i.ID, &i.SiteID, &s, &e, &i.Reason, &i.EndNote); err != nil {
			return nil, err
		}
		i.StartedAt = time.Unix(s, 0)
		if e > 0 {
			i.EndedAt = time.Unix(e, 0)
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// PurgeUptime deletes history before the given day.
func (st *Store) PurgeUptime(ctx context.Context, before time.Time) (int64, error) {
	r1, err := st.db.ExecContext(ctx, `DELETE FROM uptime_daily WHERE day<?`, before.Format(dayLayout))
	if err != nil {
		return 0, err
	}
	r2, err := st.db.ExecContext(ctx, `DELETE FROM uptime_incidents WHERE ended_at>0 AND ended_at<?`, before.Unix())
	if err != nil {
		return 0, err
	}
	a, _ := r1.RowsAffected()
	b, _ := r2.RowsAffected()
	return a + b, nil
}
