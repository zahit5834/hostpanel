package jobs

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/store"
)

func newManager(t *testing.T) (*Manager, context.CancelFunc) {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := store.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	m := NewManager(db, filepath.Join(dir, "jobs"), logs.NewActivity(db), NewBroker(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.Register("test.ok", func(ctx context.Context, l *Log, p map[string]any) error {
		l.Printf("hello %v", p["n"])
		io.WriteString(l, "partial ")
		io.WriteString(l, "line\nsecond\n")
		l.Progress(50)
		return nil
	})
	m.Register("test.fail", func(ctx context.Context, l *Log, p map[string]any) error { return errors.New("boom") })
	m.Register("test.block", func(ctx context.Context, l *Log, p map[string]any) error {
		<-ctx.Done()
		return ctx.Err()
	})
	m.Register("test.panic", func(ctx context.Context, l *Log, p map[string]any) error { panic("oops") })
	ctx, cancel := context.WithCancel(context.Background())
	if err := m.Start(ctx, 1); err != nil {
		t.Fatal(err)
	}
	return m, cancel
}

func waitDone(t *testing.T, m *Manager, id int64) Job {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		j, err := m.Get(context.Background(), id)
		if err == nil && j.Done() && !m.IsActive(id) {
			return j
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("job %d not done", id)
	return Job{}
}

func TestJobLifecycle(t *testing.T) {
	before := runtime.NumGoroutine()
	m, cancel := newManager(t)
	ctx := context.Background()

	id, err := m.Submit(ctx, Spec{Kind: "test.ok", Params: map[string]any{"n": 1, "password": "x"}})
	if err != nil {
		t.Fatal(err)
	}
	j := waitDone(t, m, id)
	if j.Status != StatusSuccess || j.Progress != 100 {
		t.Fatalf("%+v", j)
	}
	var lines []string
	n, _ := ReplayFile(m.LogPath(id), func(s string) error { lines = append(lines, s[9:]); return nil })
	if n != 5 || lines[1] != "hello 1" || lines[2] != "partial line" || lines[3] != "second" {
		t.Fatalf("%q", lines)
	}
	if j.Params != `{"n":1,"password":"***"}` {
		t.Fatalf("params %s", j.Params)
	}

	id, _ = m.Submit(ctx, Spec{Kind: "test.fail", Retryable: true})
	if j := waitDone(t, m, id); j.Status != StatusFailed || j.Error != "boom" {
		t.Fatalf("%+v", j)
	}
	if _, err := m.Retry(ctx, id); err != nil {
		t.Fatalf("retry: %v", err)
	}

	id, _ = m.Submit(ctx, Spec{Kind: "test.panic"})
	if j := waitDone(t, m, id); j.Status != StatusFailed {
		t.Fatalf("%+v", j)
	}

	// Live subscription + cancel.
	id, _ = m.Submit(ctx, Spec{Kind: "test.block"})
	ch, unsub := m.Broker().Subscribe(id)
	defer unsub()
	time.Sleep(50 * time.Millisecond)
	m.Cancel(id)
	if j := waitDone(t, m, id); j.Status != StatusCanceled {
		t.Fatalf("%+v", j)
	}
	gotStatus := false
	for ev := range ch { // must be closed by CloseTopic
		if ev.Type == EventStatus && ev.Data == StatusCanceled {
			gotStatus = true
		}
	}
	if !gotStatus {
		t.Fatal("no canceled status event")
	}

	// Activity log rows are linked and finished.
	ents, _ := logs.NewActivity(m.db).Query(ctx, logs.Filter{})
	for _, e := range ents {
		if e.Status == logs.StatusRunning || e.JobID == 0 {
			t.Fatalf("activity %+v", e)
		}
	}

	cancel()
	m.Wait()
	time.Sleep(50 * time.Millisecond)
	if after := runtime.NumGoroutine(); after > before+2 { // db pool may keep a goroutine
		t.Fatalf("goroutine leak: before=%d after=%d", before, after)
	}
}

func TestBrokerDropsSlowSubscriber(t *testing.T) {
	b := NewBroker()
	ch, unsub := b.Subscribe(1)
	for i := 0; i < subBuffer+10; i++ {
		b.Publish(1, Event{Type: EventLine})
	}
	if b.Subscribers(1) != 0 {
		t.Fatal("slow subscriber not dropped")
	}
	n := 0
	for range ch {
		n++
	}
	if n != subBuffer {
		t.Fatalf("n=%d", n)
	}
	unsub() // must not panic after close
}
