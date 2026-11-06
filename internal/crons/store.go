// Package crons runs per-site scheduled commands as the site user. One
// goroutine with one timer sleeps until the earliest due cron; each run goes
// through the root helper hp-site-cron.sh (sandboxed transient unit) and its
// result lands in cron_runs (Log Merkezi → Cron çalışmaları).
package crons

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

// Run statuses.
const (
	StatusOK      = "ok"
	StatusFailed  = "failed"
	StatusTimeout = "timeout"
	StatusSkipped = "skipped"
)

// Cron is one scheduled command of a site.
type Cron struct {
	ID         int64
	SiteID     int64
	Name       string
	Schedule   string
	Command    string
	Enabled    bool
	TimeoutSec int
	NextRunAt  time.Time
	LastRunAt  time.Time
	LastStatus string
	LastExit   int
	LastMS     int
	CreatedAt  time.Time
}

// Run is one execution.
type Run struct {
	ID         int64
	CronID     int64
	SiteID     int64
	StartedAt  time.Time
	DurationMS int
	ExitCode   int
	Status     string
	Output     string
	Source     string // system | user

	// Joined for lists.
	CronName string
	Domain   string
}

// Failed is a template helper.
func (r Run) Failed() bool { return r.Status == StatusFailed || r.Status == StatusTimeout }

// Store accesses site_crons and cron_runs.
type Store struct{ db *sql.DB }

// NewStore wraps db.
func NewStore(db *sql.DB) *Store { return &Store{db: db} }

const cronCols = `id, site_id, name, schedule, command, enabled, timeout_sec, next_run_at, last_run_at, last_status, last_exit, last_ms, created_at`

func unix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func fromUnix(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.Unix(v, 0)
}

func scanCron(sc interface{ Scan(...any) error }) (Cron, error) {
	var c Cron
	var next, last, created int64
	err := sc.Scan(&c.ID, &c.SiteID, &c.Name, &c.Schedule, &c.Command, &c.Enabled, &c.TimeoutSec, &next, &last,
		&c.LastStatus, &c.LastExit, &c.LastMS, &created)
	c.NextRunAt, c.LastRunAt, c.CreatedAt = fromUnix(next), fromUnix(last), fromUnix(created)
	return c, err
}

func (st *Store) query(ctx context.Context, where string, args ...any) ([]Cron, error) {
	rows, err := st.db.QueryContext(ctx, `SELECT `+cronCols+` FROM site_crons `+where+` ORDER BY site_id, id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Cron
	for rows.Next() {
		c, err := scanCron(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// All returns every cron.
func (st *Store) All(ctx context.Context) ([]Cron, error) { return st.query(ctx, "") }

// BySite returns a site's crons.
func (st *Store) BySite(ctx context.Context, siteID int64) ([]Cron, error) {
	return st.query(ctx, "WHERE site_id=?", siteID)
}

// Get returns one cron.
func (st *Store) Get(ctx context.Context, id int64) (Cron, error) {
	return scanCron(st.db.QueryRowContext(ctx, `SELECT `+cronCols+` FROM site_crons WHERE id=?`, id))
}

// Insert stores a new cron.
func (st *Store) Insert(ctx context.Context, c *Cron) error {
	res, err := st.db.ExecContext(ctx, `INSERT INTO site_crons(site_id, name, schedule, command, enabled, timeout_sec, next_run_at, created_at)
		VALUES (?,?,?,?,?,?,?,?)`, c.SiteID, c.Name, c.Schedule, c.Command, c.Enabled, c.TimeoutSec, unix(c.NextRunAt), time.Now().Unix())
	if err != nil {
		return err
	}
	c.ID, _ = res.LastInsertId()
	return nil
}

// Update saves the editable fields.
func (st *Store) Update(ctx context.Context, c Cron) error {
	_, err := st.db.ExecContext(ctx, `UPDATE site_crons SET name=?, schedule=?, command=?, enabled=?, timeout_sec=?, next_run_at=? WHERE id=?`,
		c.Name, c.Schedule, c.Command, c.Enabled, c.TimeoutSec, unix(c.NextRunAt), c.ID)
	return err
}

// Delete removes a cron (its runs cascade).
func (st *Store) Delete(ctx context.Context, id int64) error {
	_, err := st.db.ExecContext(ctx, `DELETE FROM site_crons WHERE id=?`, id)
	return err
}

// SetNext stores the next run time.
func (st *Store) SetNext(ctx context.Context, id int64, next time.Time) error {
	_, err := st.db.ExecContext(ctx, `UPDATE site_crons SET next_run_at=? WHERE id=?`, unix(next), id)
	return err
}

// AddRun records a finished (or skipped) run and updates the cron's last_* fields.
func (st *Store) AddRun(ctx context.Context, r *Run) error {
	res, err := st.db.ExecContext(ctx, `INSERT INTO cron_runs(cron_id, site_id, started_at, duration_ms, exit_code, status, output, source)
		VALUES (?,?,?,?,?,?,?,?)`, r.CronID, r.SiteID, r.StartedAt.Unix(), r.DurationMS, r.ExitCode, r.Status, r.Output, r.Source)
	if err != nil {
		return err
	}
	r.ID, _ = res.LastInsertId()
	if r.Status == StatusSkipped {
		return nil
	}
	_, err = st.db.ExecContext(ctx, `UPDATE site_crons SET last_run_at=?, last_status=?, last_exit=?, last_ms=? WHERE id=?`,
		r.StartedAt.Unix(), r.Status, r.ExitCode, r.DurationMS, r.CronID)
	return err
}

// RunFilter narrows run lists.
type RunFilter struct {
	SiteID int64
	CronID int64
	Status string // "" | ok | failed (failed + timeout) | skipped
	Since  time.Time
	Until  time.Time
	Limit  int
}

// Runs lists runs newest first. Output is included (≤16 KB each), so Limit
// stays small.
func (st *Store) Runs(ctx context.Context, f RunFilter) ([]Run, error) {
	var where []string
	var args []any
	if f.SiteID > 0 {
		where, args = append(where, "r.site_id=?"), append(args, f.SiteID)
	}
	if f.CronID > 0 {
		where, args = append(where, "r.cron_id=?"), append(args, f.CronID)
	}
	switch f.Status {
	case StatusOK, StatusSkipped:
		where, args = append(where, "r.status=?"), append(args, f.Status)
	case StatusFailed:
		where = append(where, "r.status IN ('failed','timeout')")
	}
	if !f.Since.IsZero() {
		where, args = append(where, "r.started_at>=?"), append(args, f.Since.Unix())
	}
	if !f.Until.IsZero() {
		where, args = append(where, "r.started_at<?"), append(args, f.Until.Unix())
	}
	q := `SELECT r.id, r.cron_id, r.site_id, r.started_at, r.duration_ms, r.exit_code, r.status, r.output, r.source, c.name, s.domain
		FROM cron_runs r JOIN site_crons c ON c.id=r.cron_id JOIN sites s ON s.id=r.site_id`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	q += " ORDER BY r.id DESC LIMIT ?"
	args = append(args, f.Limit)
	rows, err := st.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Run
	for rows.Next() {
		var r Run
		var started int64
		if err := rows.Scan(&r.ID, &r.CronID, &r.SiteID, &started, &r.DurationMS, &r.ExitCode, &r.Status, &r.Output, &r.Source,
			&r.CronName, &r.Domain); err != nil {
			return nil, err
		}
		r.StartedAt = time.Unix(started, 0)
		out = append(out, r)
	}
	return out, rows.Err()
}

// Prune keeps the newest keep runs per cron and nothing older than maxAge.
func (st *Store) Prune(ctx context.Context, now time.Time, keep int, maxAge time.Duration) (int64, error) {
	res, err := st.db.ExecContext(ctx, `DELETE FROM cron_runs WHERE started_at < ? OR id IN (
		SELECT id FROM (SELECT id, ROW_NUMBER() OVER (PARTITION BY cron_id ORDER BY id DESC) AS rn FROM cron_runs) WHERE rn > ?)`,
		now.Add(-maxAge).Unix(), keep)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
