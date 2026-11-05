package logs

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"
)

// Activity statuses.
const (
	StatusSuccess = "success"
	StatusFailed  = "failed"
	StatusRunning = "running"
)

// Sources distinguish admin actions from automatic ones.
const (
	SourceUser   = "user"
	SourceSystem = "system"
)

// Entry is one row of the activity log.
type Entry struct {
	ID         int64
	TS         time.Time
	Source     string
	IP         string
	Action     string
	TargetType string
	TargetID   string
	Status     string
	DurationMS int64
	Summary    string
	Params     string
	Diff       string
	Error      string
	JobID      int64
}

// Failed is a template helper.
func (e Entry) Failed() bool { return e.Status == StatusFailed }

type actorKey struct{}

// Actor identifies who triggered an action.
type Actor struct {
	Source string
	IP     string
}

// WithActor attaches the actor to ctx; web handlers use it so every log call
// made while serving a request is attributed to the admin and their IP.
func WithActor(ctx context.Context, a Actor) context.Context {
	return context.WithValue(ctx, actorKey{}, a)
}

// ActorFrom returns the actor in ctx, defaulting to "system".
func ActorFrom(ctx context.Context) Actor {
	if a, ok := ctx.Value(actorKey{}).(Actor); ok {
		return a
	}
	return Actor{Source: SourceSystem}
}

// Activity writes and queries the activity log.
type Activity struct {
	db *sql.DB
}

// NewActivity wraps db.
func NewActivity(db *sql.DB) *Activity { return &Activity{db: db} }

// Record inserts an entry. params are masked before being stored.
func (a *Activity) Record(ctx context.Context, e Entry, params map[string]any) (int64, error) {
	act := ActorFrom(ctx)
	if e.Source == "" {
		e.Source = act.Source
	}
	if e.IP == "" {
		e.IP = act.IP
	}
	if e.TS.IsZero() {
		e.TS = time.Now()
	}
	if e.Status == "" {
		e.Status = StatusSuccess
	}
	if params != nil && e.Params == "" {
		b, _ := json.Marshal(MaskMap(params))
		e.Params = string(b)
	}
	var jobID any
	if e.JobID > 0 {
		jobID = e.JobID
	}
	res, err := a.db.ExecContext(ctx, `INSERT INTO activity_log
		(ts, source, ip, action, target_type, target_id, status, duration_ms, summary, params, diff, error, job_id)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		e.TS.UnixMilli(), e.Source, e.IP, e.Action, e.TargetType, e.TargetID, e.Status,
		e.DurationMS, e.Summary, e.Params, e.Diff, e.Error, jobID)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// Op is an in-progress activity created by Begin.
type Op struct {
	a     *Activity
	id    int64
	start time.Time
}

// Begin records a "running" entry and returns an Op to finish later.
func (a *Activity) Begin(ctx context.Context, e Entry, params map[string]any) *Op {
	e.Status = StatusRunning
	id, _ := a.Record(ctx, e, params)
	return &Op{a: a, id: id, start: time.Now()}
}

// ID is the activity row id.
func (o *Op) ID() int64 { return o.id }

// Finish marks the op success or failed (if err != nil) and stores its duration.
// It uses a fresh context so a canceled request still gets its result logged.
func (o *Op) Finish(err error) {
	if o.id == 0 {
		return
	}
	status, msg := StatusSuccess, ""
	if err != nil {
		status, msg = StatusFailed, err.Error()
	}
	o.a.db.ExecContext(context.Background(),
		`UPDATE activity_log SET status=?, duration_ms=?, error=? WHERE id=?`,
		status, time.Since(o.start).Milliseconds(), msg, o.id)
}

// SetJob links the op to a background job.
func (o *Op) SetJob(jobID int64) {
	o.a.db.ExecContext(context.Background(), `UPDATE activity_log SET job_id=? WHERE id=?`, jobID, o.id)
}

// FailRunning marks entries left "running" (e.g. by a restart) as failed.
func (a *Activity) FailRunning(ctx context.Context, reason string) {
	a.db.ExecContext(ctx, `UPDATE activity_log SET status=?, error=? WHERE status=?`,
		StatusFailed, reason, StatusRunning)
}

// Filter narrows a Query. Empty fields are ignored.
type Filter struct {
	Action     string // prefix match: "site." matches site.create
	Status     string
	Source     string
	TargetType string
	TargetID   string
	Text       string
	From, To   time.Time
	BeforeID   int64 // keyset pagination
	Limit      int
}

const entryCols = `id, ts, source, ip, action, target_type, target_id, status, duration_ms, summary, params, diff, error, COALESCE(job_id,0)`

func scanEntry(sc interface{ Scan(...any) error }) (Entry, error) {
	var e Entry
	var ts int64
	err := sc.Scan(&e.ID, &ts, &e.Source, &e.IP, &e.Action, &e.TargetType, &e.TargetID, &e.Status,
		&e.DurationMS, &e.Summary, &e.Params, &e.Diff, &e.Error, &e.JobID)
	e.TS = time.UnixMilli(ts)
	return e, err
}

// Query returns newest-first entries matching f.
func (a *Activity) Query(ctx context.Context, f Filter) ([]Entry, error) {
	var where []string
	var args []any
	add := func(cond string, v any) { where = append(where, cond); args = append(args, v) }
	if f.Action != "" {
		add("action LIKE ? ESCAPE '\\'", escapeLike(f.Action)+"%")
	}
	if f.Status != "" {
		add("status = ?", f.Status)
	}
	if f.Source != "" {
		add("source = ?", f.Source)
	}
	if f.TargetType != "" {
		add("target_type = ?", f.TargetType)
	}
	if f.TargetID != "" {
		add("target_id = ?", f.TargetID)
	}
	if f.Text != "" {
		where = append(where, "(summary LIKE ? ESCAPE '\\' OR target_id LIKE ? ESCAPE '\\' OR error LIKE ? ESCAPE '\\')")
		p := "%" + escapeLike(f.Text) + "%"
		args = append(args, p, p, p)
	}
	if !f.From.IsZero() {
		add("ts >= ?", f.From.UnixMilli())
	}
	if !f.To.IsZero() {
		add("ts < ?", f.To.UnixMilli())
	}
	if f.BeforeID > 0 {
		add("id < ?", f.BeforeID)
	}
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 50
	}
	q := `SELECT ` + entryCols + ` FROM activity_log`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY id DESC LIMIT ?"
	args = append(args, f.Limit)
	rows, err := a.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		e, err := scanEntry(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Get returns one entry.
func (a *Activity) Get(ctx context.Context, id int64) (Entry, error) {
	return scanEntry(a.db.QueryRowContext(ctx, `SELECT `+entryCols+` FROM activity_log WHERE id=?`, id))
}

// Purge deletes entries older than before and returns the number removed.
func (a *Activity) Purge(ctx context.Context, before time.Time) (int64, error) {
	res, err := a.db.ExecContext(ctx, `DELETE FROM activity_log WHERE ts < ?`, before.UnixMilli())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}
