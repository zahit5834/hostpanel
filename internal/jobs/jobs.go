// Package jobs runs long operations in the background with a persistent
// job table, per-job log files and live SSE streaming.
package jobs

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zahit5834/hostpanel/internal/logs"
)

// Job statuses.
const (
	StatusQueued   = "queued"
	StatusRunning  = "running"
	StatusSuccess  = "success"
	StatusFailed   = "failed"
	StatusCanceled = "canceled"
)

// Handler does the work of a job kind. It must honour ctx cancellation.
//
// Rule: params are stored masked, so handlers must never receive secrets via
// params; they load secrets themselves (e.g. by site id). That keeps the job
// table and logs secret-free and makes "retry" safe.
type Handler func(ctx context.Context, l *Log, params map[string]any) error

// Spec describes a job to submit.
type Spec struct {
	Kind       string
	TargetType string
	TargetID   string
	Summary    string // activity log summary
	Params     map[string]any
	Retryable  bool
}

// Job is a row of the jobs table.
type Job struct {
	ID         int64
	Kind       string
	TargetType string
	TargetID   string
	Status     string
	Progress   int
	Params     string
	Error      string
	Retryable  bool
	ActivityID int64
	CreatedAt  time.Time
	StartedAt  time.Time
	FinishedAt time.Time
}

// Done reports whether the job reached a final state.
func (j Job) Done() bool {
	return j.Status == StatusSuccess || j.Status == StatusFailed || j.Status == StatusCanceled
}

// Duration is the run time so far (or total if finished).
func (j Job) Duration() time.Duration {
	if j.StartedAt.IsZero() {
		return 0
	}
	end := j.FinishedAt
	if end.IsZero() {
		end = time.Now()
	}
	return end.Sub(j.StartedAt).Round(time.Second)
}

type task struct {
	id     int64
	spec   Spec
	op     *logs.Op
	ctx    context.Context
	cancel context.CancelFunc
}

// Manager owns the queue and workers.
type Manager struct {
	db       *sql.DB
	dir      string
	activity *logs.Activity
	broker   *Broker
	log      *slog.Logger

	mu       sync.Mutex
	handlers map[string]Handler
	running  map[int64]*task
	queue    chan *task
	baseCtx  context.Context
	wg       sync.WaitGroup

	// AfterJob runs when a job has finished (memory release, see system.IdleGC).
	AfterJob func()
}

// NewManager creates a manager writing job logs to dir.
func NewManager(db *sql.DB, dir string, activity *logs.Activity, broker *Broker, log *slog.Logger) *Manager {
	return &Manager{
		db: db, dir: dir, activity: activity, broker: broker, log: log,
		handlers: make(map[string]Handler),
		running:  make(map[int64]*task),
		queue:    make(chan *task, 64),
	}
}

// Broker exposes the live event broker.
func (m *Manager) Broker() *Broker { return m.broker }

// Register binds a handler to a job kind. Call before Start.
func (m *Manager) Register(kind string, h Handler) { m.handlers[kind] = h }

// Start recovers interrupted jobs and launches n workers. They stop when ctx is canceled;
// call Wait afterwards to block until running jobs have returned.
func (m *Manager) Start(ctx context.Context, n int) error {
	if err := os.MkdirAll(m.dir, 0o750); err != nil {
		return err
	}
	now := time.Now().Unix()
	// Jobs left queued/running by a crash or restart can't resume: mark them failed.
	if _, err := m.db.ExecContext(ctx, `UPDATE jobs SET status=?, error=?, finished_at=?
		WHERE status IN (?, ?)`, StatusFailed, "panel yeniden başlatıldığı için yarıda kaldı", now,
		StatusQueued, StatusRunning); err != nil {
		return err
	}
	m.activity.FailRunning(ctx, "panel yeniden başlatıldı")
	m.mu.Lock()
	m.baseCtx = ctx
	m.mu.Unlock()
	for i := 0; i < n; i++ {
		m.wg.Add(1)
		go m.worker(ctx)
	}
	return nil
}

// Wait blocks until all workers exit.
func (m *Manager) Wait() { m.wg.Wait() }

// Submit queues a job and returns its id.
func (m *Manager) Submit(ctx context.Context, s Spec) (int64, error) {
	if _, ok := m.handlers[s.Kind]; !ok {
		return 0, fmt.Errorf("unknown job kind %q", s.Kind)
	}
	m.mu.Lock()
	base := m.baseCtx
	m.mu.Unlock()
	if base == nil {
		return 0, errors.New("job manager not started")
	}
	params, _ := json.Marshal(logs.MaskMap(s.Params))
	res, err := m.db.ExecContext(ctx, `INSERT INTO jobs(kind, target_type, target_id, status, params, retryable, created_at)
		VALUES (?,?,?,?,?,?,?)`, s.Kind, s.TargetType, s.TargetID, StatusQueued, string(params), s.Retryable, time.Now().Unix())
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	op := m.activity.Begin(ctx, logs.Entry{
		Action: s.Kind, TargetType: s.TargetType, TargetID: s.TargetID, Summary: s.Summary, JobID: id,
	}, s.Params)
	m.db.ExecContext(ctx, `UPDATE jobs SET activity_id=? WHERE id=?`, op.ID(), id)

	tctx, cancel := context.WithCancel(base)
	t := &task{id: id, spec: s, op: op, ctx: tctx, cancel: cancel}
	m.mu.Lock()
	m.running[id] = t
	m.mu.Unlock()
	select {
	case m.queue <- t:
		return id, nil
	default:
		m.finish(t, StatusFailed, errors.New("iş kuyruğu dolu"))
		return 0, errors.New("job queue full")
	}
}

// Retry resubmits a failed retryable job with its stored params.
func (m *Manager) Retry(ctx context.Context, id int64) (int64, error) {
	j, err := m.Get(ctx, id)
	if err != nil {
		return 0, err
	}
	if !j.Retryable || (j.Status != StatusFailed && j.Status != StatusCanceled) {
		return 0, errors.New("bu iş yeniden denenemez")
	}
	var params map[string]any
	json.Unmarshal([]byte(j.Params), &params)
	return m.Submit(ctx, Spec{Kind: j.Kind, TargetType: j.TargetType, TargetID: j.TargetID,
		Summary: "yeniden deneme #" + strconv.FormatInt(id, 10), Params: params, Retryable: true})
}

// Cancel stops a queued or running job.
func (m *Manager) Cancel(id int64) bool {
	m.mu.Lock()
	t, ok := m.running[id]
	m.mu.Unlock()
	if ok {
		t.cancel()
	}
	return ok
}

// IsActive reports whether the job is queued or running in this process.
func (m *Manager) IsActive(id int64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.running[id]
	return ok
}

func (m *Manager) worker(ctx context.Context) {
	defer m.wg.Done()
	for {
		select {
		case <-ctx.Done():
			// Drain queued tasks so they are marked, not silently lost.
			for {
				select {
				case t := <-m.queue:
					m.finish(t, StatusCanceled, ctx.Err())
				default:
					return
				}
			}
		case t := <-m.queue:
			m.run(t)
		}
	}
}

func (m *Manager) run(t *task) {
	if m.AfterJob != nil {
		defer m.AfterJob()
	}
	if t.ctx.Err() != nil { // canceled while queued
		m.finish(t, StatusCanceled, t.ctx.Err())
		return
	}
	l, err := m.openLog(t.id)
	if err != nil {
		m.finish(t, StatusFailed, err)
		return
	}
	defer l.close()
	m.db.Exec(`UPDATE jobs SET status=?, started_at=? WHERE id=?`, StatusRunning, time.Now().Unix(), t.id)
	m.broker.Publish(t.id, Event{Type: EventStatus, Data: StatusRunning})
	l.Printf("İş başladı: %s", t.spec.Kind)

	err = func() (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("panic: %v", r)
				m.log.Error("job panic", "job", t.id, "panic", r)
			}
		}()
		return m.handlers[t.spec.Kind](t.ctx, l, t.spec.Params)
	}()

	switch {
	case err == nil:
		l.Printf("İş başarıyla tamamlandı")
		m.finish(t, StatusSuccess, nil)
	case t.ctx.Err() != nil:
		l.Printf("İş iptal edildi")
		m.finish(t, StatusCanceled, err)
	default:
		l.Printf("HATA: %v", err)
		m.finish(t, StatusFailed, err)
	}
}

func (m *Manager) finish(t *task, status string, err error) {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	progress := "progress"
	if status == StatusSuccess {
		progress = "100"
	}
	m.db.Exec(`UPDATE jobs SET status=?, error=?, finished_at=?, progress=`+progress+` WHERE id=?`,
		status, msg, time.Now().Unix(), t.id)
	if status == StatusCanceled && err != nil {
		err = errors.New("iptal edildi")
	}
	t.op.Finish(err)
	t.cancel()
	m.mu.Lock()
	delete(m.running, t.id)
	m.mu.Unlock()
	m.broker.Publish(t.id, Event{Type: EventStatus, Data: status})
	m.broker.CloseTopic(t.id)
}

// LogPath is the output file of job id.
func (m *Manager) LogPath(id int64) string {
	return filepath.Join(m.dir, strconv.FormatInt(id, 10)+".log")
}

// Get loads one job.
func (m *Manager) Get(ctx context.Context, id int64) (Job, error) {
	return scanJob(m.db.QueryRowContext(ctx, `SELECT `+jobCols+` FROM jobs WHERE id=?`, id))
}

// List returns newest jobs, optionally filtered by status, kind prefix or target.
func (m *Manager) List(ctx context.Context, status, kind, targetID string, beforeID int64, limit int) ([]Job, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	q := `SELECT ` + jobCols + ` FROM jobs WHERE 1=1`
	var args []any
	if status != "" {
		q += ` AND status=?`
		args = append(args, status)
	}
	if kind != "" {
		q += ` AND kind LIKE ?`
		args = append(args, strings.ReplaceAll(kind, "%", "")+"%")
	}
	if targetID != "" {
		q += ` AND target_id=?`
		args = append(args, targetID)
	}
	if beforeID > 0 {
		q += ` AND id<?`
		args = append(args, beforeID)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := m.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Job
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// Purge removes finished jobs (and their log files) created before t.
func (m *Manager) Purge(ctx context.Context, before time.Time) (int, error) {
	rows, err := m.db.QueryContext(ctx, `SELECT id FROM jobs WHERE created_at < ? AND status IN (?,?,?)`,
		before.Unix(), StatusSuccess, StatusFailed, StatusCanceled)
	if err != nil {
		return 0, err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		rows.Scan(&id)
		ids = append(ids, id)
	}
	rows.Close()
	for _, id := range ids {
		os.Remove(m.LogPath(id))
		m.db.ExecContext(ctx, `DELETE FROM jobs WHERE id=?`, id)
	}
	return len(ids), nil
}

const jobCols = `id, kind, target_type, target_id, status, progress, params, error, retryable,
	COALESCE(activity_id,0), created_at, COALESCE(started_at,0), COALESCE(finished_at,0)`

func scanJob(sc interface{ Scan(...any) error }) (Job, error) {
	var j Job
	var c, s, f int64
	err := sc.Scan(&j.ID, &j.Kind, &j.TargetType, &j.TargetID, &j.Status, &j.Progress, &j.Params,
		&j.Error, &j.Retryable, &j.ActivityID, &c, &s, &f)
	j.CreatedAt = time.Unix(c, 0)
	if s > 0 {
		j.StartedAt = time.Unix(s, 0)
	}
	if f > 0 {
		j.FinishedAt = time.Unix(f, 0)
	}
	return j, err
}

// Log is a job's output: it appends timestamped lines to the job file and
// publishes each line to live subscribers. It implements io.Writer so it can
// be used directly as exec.Cmd.Output.
type Log struct {
	m       *Manager
	id      int64
	f       *os.File
	mu      sync.Mutex
	seq     int64
	partial []byte
}

func (m *Manager) openLog(id int64) (*Log, error) {
	f, err := os.OpenFile(m.LogPath(id), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return nil, err
	}
	return &Log{m: m, id: id, f: f}, nil
}

// ID is the job id.
func (l *Log) ID() int64 { return l.id }

// Printf writes one line.
func (l *Log) Printf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.line(fmt.Sprintf(format, args...))
}

// Write splits p into lines; an unterminated tail waits for the next Write or close.
func (l *Log) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	data := append(l.partial, p...)
	for {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			break
		}
		l.line(strings.TrimRight(string(data[:i]), "\r"))
		data = data[i+1:]
	}
	if len(data) > logs.MaxLineBytes { // never buffer unbounded output
		l.line(string(data))
		data = nil
	}
	l.partial = append([]byte(nil), data...)
	return len(p), nil
}

// Progress records 0..100 completion.
func (l *Log) Progress(p int) {
	p = max(0, min(100, p))
	l.m.db.Exec(`UPDATE jobs SET progress=? WHERE id=?`, p, l.id)
	l.m.broker.Publish(l.id, Event{Type: EventProgress, Data: strconv.Itoa(p)})
}

// line must be called with l.mu held. The file write happens before the
// publish so SSE replay (file first, then events with Seq > lines read) never
// misses or duplicates a line.
func (l *Log) line(s string) {
	if len(s) > logs.MaxLineBytes {
		s = s[:logs.MaxLineBytes]
	}
	s = time.Now().Format("15:04:05") + " " + s
	l.f.WriteString(s + "\n")
	l.seq++
	l.m.broker.Publish(l.id, Event{Seq: l.seq, Type: EventLine, Data: s})
}

func (l *Log) close() {
	l.mu.Lock()
	if len(l.partial) > 0 {
		l.line(string(l.partial))
		l.partial = nil
	}
	l.mu.Unlock()
	l.f.Close()
}

// ReplayFile streams the existing lines of a job log to fn and returns how many
// lines were sent. Lines are read one at a time to keep memory flat.
func ReplayFile(path string, fn func(line string) error) (int64, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 16*1024)
	var n int64
	for {
		line, err := r.ReadString('\n')
		if err == io.EOF {
			return n, nil // a partial last line is still being written; skip it
		}
		if err != nil {
			return n, err
		}
		n++
		if err := fn(strings.TrimSuffix(line, "\n")); err != nil {
			return n, err
		}
	}
}
