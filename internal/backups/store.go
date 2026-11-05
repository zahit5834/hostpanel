// Package backups takes site backups (files, MSSQL databases, settings, SSL),
// keeps them locally and/or on Google Drive via rclone, applies retention,
// runs schedules and restores (also into another site).
package backups

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

// Components a backup can contain.
const (
	CompFiles  = "files"
	CompDB     = "db"
	CompConfig = "config"
	CompSSL    = "ssl"
)

// AllComponents in display order.
var AllComponents = []string{CompFiles, CompDB, CompConfig, CompSSL}

// Destinations.
const (
	DestLocal  = "local"
	DestRemote = "remote"
	DestBoth   = "both"
)

// Kinds.
const (
	KindManual     = "manual"
	KindScheduled  = "scheduled"
	KindPreRestore = "pre-restore"
	KindImported   = "imported"
)

// Statuses.
const (
	StatusRunning = "running"
	StatusSuccess = "success"
	StatusFailed  = "failed"
)

// Plan is a scheduled backup.
type Plan struct {
	ID             int64
	Name           string
	Scope          string // all | sites
	SiteIDs        []int64
	Components     []string
	Schedule       string
	Destination    string
	KeepLocal      int
	KeepRemote     int
	KeepRemoteDays int
	Enabled        bool
	LastRunAt      time.Time
	NextRunAt      time.Time
	CreatedAt      time.Time
}

// Backup is one backup of one site.
type Backup struct {
	ID         int64
	PlanID     int64
	PlanName   string
	SiteID     int64
	Domain     string
	Name       string
	Kind       string
	Components []string
	Status     string
	SizeBytes  int64
	Local      bool
	Remote     bool
	RemoteSrv  string
	JobID      int64
	Error      string
	CreatedAt  time.Time
	FinishedAt time.Time
}

// Has reports whether the backup includes component c.
func (b Backup) Has(c string) bool {
	for _, x := range b.Components {
		if x == c {
			return true
		}
	}
	return false
}

// Store accesses backup_plans and backups.
type Store struct{ db *sql.DB }

// NewStore wraps db.
func NewStore(db *sql.DB) *Store { return &Store{db: db} }

func toJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func unixOrZero(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(n, 0)
}

func timeUnix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// --- plans ---

const planCols = `id, name, scope, site_ids, components, schedule, destination, keep_local, keep_remote,
	keep_remote_days, enabled, last_run_at, next_run_at, created_at`

func scanPlan(sc interface{ Scan(...any) error }) (Plan, error) {
	var p Plan
	var sites, comps string
	var last, next, created int64
	err := sc.Scan(&p.ID, &p.Name, &p.Scope, &sites, &comps, &p.Schedule, &p.Destination, &p.KeepLocal, &p.KeepRemote,
		&p.KeepRemoteDays, &p.Enabled, &last, &next, &created)
	json.Unmarshal([]byte(sites), &p.SiteIDs)
	json.Unmarshal([]byte(comps), &p.Components)
	p.LastRunAt, p.NextRunAt, p.CreatedAt = unixOrZero(last), unixOrZero(next), time.Unix(created, 0)
	return p, err
}

// Plan returns one plan.
func (st *Store) Plan(ctx context.Context, id int64) (Plan, error) {
	return scanPlan(st.db.QueryRowContext(ctx, `SELECT `+planCols+` FROM backup_plans WHERE id=?`, id))
}

// Plans lists all plans.
func (st *Store) Plans(ctx context.Context) ([]Plan, error) {
	rows, err := st.db.QueryContext(ctx, `SELECT `+planCols+` FROM backup_plans ORDER BY name, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Plan
	for rows.Next() {
		p, err := scanPlan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// SavePlan inserts (ID 0) or updates p.
func (st *Store) SavePlan(ctx context.Context, p *Plan) error {
	now := time.Now().Unix()
	if p.SiteIDs == nil {
		p.SiteIDs = []int64{}
	}
	if p.ID == 0 {
		res, err := st.db.ExecContext(ctx, `INSERT INTO backup_plans(name, scope, site_ids, components, schedule, destination,
			keep_local, keep_remote, keep_remote_days, enabled, next_run_at, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			p.Name, p.Scope, toJSON(p.SiteIDs), toJSON(p.Components), p.Schedule, p.Destination, p.KeepLocal, p.KeepRemote,
			p.KeepRemoteDays, p.Enabled, timeUnix(p.NextRunAt), now, now)
		if err != nil {
			return err
		}
		p.ID, _ = res.LastInsertId()
		return nil
	}
	_, err := st.db.ExecContext(ctx, `UPDATE backup_plans SET name=?, scope=?, site_ids=?, components=?, schedule=?, destination=?,
		keep_local=?, keep_remote=?, keep_remote_days=?, enabled=?, next_run_at=?, updated_at=? WHERE id=?`,
		p.Name, p.Scope, toJSON(p.SiteIDs), toJSON(p.Components), p.Schedule, p.Destination, p.KeepLocal, p.KeepRemote,
		p.KeepRemoteDays, p.Enabled, timeUnix(p.NextRunAt), now, p.ID)
	return err
}

// SetPlanRun records a run and the next scheduled time.
func (st *Store) SetPlanRun(ctx context.Context, id int64, last, next time.Time) error {
	_, err := st.db.ExecContext(ctx, `UPDATE backup_plans SET last_run_at=?, next_run_at=? WHERE id=?`, timeUnix(last), timeUnix(next), id)
	return err
}

// SetPlanNext stores the next run time.
func (st *Store) SetPlanNext(ctx context.Context, id int64, next time.Time) error {
	_, err := st.db.ExecContext(ctx, `UPDATE backup_plans SET next_run_at=? WHERE id=?`, timeUnix(next), id)
	return err
}

// DeletePlan removes a plan (its backups stay, plan_id becomes NULL).
func (st *Store) DeletePlan(ctx context.Context, id int64) error {
	_, err := st.db.ExecContext(ctx, `DELETE FROM backup_plans WHERE id=?`, id)
	return err
}

// --- backups ---

const backupCols = `b.id, COALESCE(b.plan_id, 0), COALESCE(p.name, ''), COALESCE(b.site_id, 0), b.domain, b.name, b.kind,
	b.components, b.status, b.size_bytes, b.local, b.remote, b.remote_server, COALESCE(b.job_id, 0), b.error, b.created_at, b.finished_at`

const backupFrom = ` FROM backups b LEFT JOIN backup_plans p ON p.id = b.plan_id`

func scanBackup(sc interface{ Scan(...any) error }) (Backup, error) {
	var b Backup
	var comps string
	var created, finished int64
	err := sc.Scan(&b.ID, &b.PlanID, &b.PlanName, &b.SiteID, &b.Domain, &b.Name, &b.Kind, &comps, &b.Status, &b.SizeBytes,
		&b.Local, &b.Remote, &b.RemoteSrv, &b.JobID, &b.Error, &created, &finished)
	json.Unmarshal([]byte(comps), &b.Components)
	b.CreatedAt, b.FinishedAt = time.Unix(created, 0), unixOrZero(finished)
	return b, err
}

// Backup returns one backup.
func (st *Store) Backup(ctx context.Context, id int64) (Backup, error) {
	return scanBackup(st.db.QueryRowContext(ctx, `SELECT `+backupCols+backupFrom+` WHERE b.id=?`, id))
}

// Filter narrows Backups.
type Filter struct {
	SiteID int64
	Domain string
	PlanID int64
	Limit  int
}

// Backups lists backups, newest first.
func (st *Store) Backups(ctx context.Context, f Filter) ([]Backup, error) {
	q := `SELECT ` + backupCols + backupFrom + ` WHERE 1=1`
	var args []any
	if f.SiteID > 0 {
		q += ` AND b.site_id=?`
		args = append(args, f.SiteID)
	}
	if f.Domain != "" {
		q += ` AND b.domain=?`
		args = append(args, f.Domain)
	}
	if f.PlanID > 0 {
		q += ` AND b.plan_id=?`
		args = append(args, f.PlanID)
	}
	if f.Limit <= 0 {
		f.Limit = 500
	}
	q += ` ORDER BY b.id DESC LIMIT ?`
	args = append(args, f.Limit)
	rows, err := st.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Backup
	for rows.Next() {
		b, err := scanBackup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// Insert stores a new backup row.
func (st *Store) Insert(ctx context.Context, b *Backup) error {
	if b.CreatedAt.IsZero() {
		b.CreatedAt = time.Now()
	}
	var plan, site any
	if b.PlanID > 0 {
		plan = b.PlanID
	}
	if b.SiteID > 0 {
		site = b.SiteID
	}
	if b.Components == nil {
		b.Components = []string{}
	}
	res, err := st.db.ExecContext(ctx, `INSERT INTO backups(plan_id, site_id, domain, name, kind, components, status, size_bytes,
		local, remote, remote_server, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`, plan, site, b.Domain, b.Name, b.Kind, toJSON(b.Components),
		b.Status, b.SizeBytes, b.Local, b.Remote, b.RemoteSrv, b.CreatedAt.Unix())
	if err != nil {
		return err
	}
	b.ID, _ = res.LastInsertId()
	return nil
}

// SetJob links the job that runs the backup.
func (st *Store) SetJob(ctx context.Context, id, jobID int64) error {
	_, err := st.db.ExecContext(ctx, `UPDATE backups SET job_id=? WHERE id=?`, jobID, id)
	return err
}

// Finish records the result.
func (st *Store) Finish(ctx context.Context, id int64, status string, size int64, local bool, errMsg string) error {
	_, err := st.db.ExecContext(ctx, `UPDATE backups SET status=?, size_bytes=?, local=?, error=?, finished_at=? WHERE id=?`,
		status, size, local, errMsg, time.Now().Unix(), id)
	return err
}

// SetLocation updates where copies exist; a backup with no copy left is deleted.
func (st *Store) SetLocation(ctx context.Context, id int64, local, remote bool) error {
	if !local && !remote {
		_, err := st.db.ExecContext(ctx, `DELETE FROM backups WHERE id=?`, id)
		return err
	}
	_, err := st.db.ExecContext(ctx, `UPDATE backups SET local=?, remote=? WHERE id=?`, local, remote, id)
	return err
}

// SetUploaded marks the remote copy and where it went.
func (st *Store) SetUploaded(ctx context.Context, id int64, server string) error {
	_, err := st.db.ExecContext(ctx, `UPDATE backups SET remote=1, remote_server=? WHERE id=?`, server, id)
	return err
}

// SetComponents updates the component list (learnt from the manifest after a scan).
func (st *Store) SetComponents(ctx context.Context, id int64, comps []string) error {
	_, err := st.db.ExecContext(ctx, `UPDATE backups SET components=? WHERE id=?`, toJSON(comps), id)
	return err
}

// Delete removes a backup row.
func (st *Store) Delete(ctx context.Context, id int64) error {
	_, err := st.db.ExecContext(ctx, `DELETE FROM backups WHERE id=?`, id)
	return err
}

// Exists reports a known backup by domain + name.
func (st *Store) Exists(ctx context.Context, domain, name string) bool {
	var n int
	st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM backups WHERE domain=? AND name=?`, domain, name).Scan(&n)
	return n > 0
}

// LocalSize sums the size of local copies.
func (st *Store) LocalSize(ctx context.Context) int64 {
	var n int64
	st.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(size_bytes), 0) FROM backups WHERE local=1`).Scan(&n)
	return n
}
