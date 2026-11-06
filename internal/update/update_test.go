package update

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/zahit5834/hostpanel/internal/exec"
	"github.com/zahit5834/hostpanel/internal/logs"
	"github.com/zahit5834/hostpanel/internal/notify"
	"github.com/zahit5834/hostpanel/internal/store"
)

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"v0.2.0", "v0.1.9", true},
		{"v1.0.0", "v0.99.99", true},
		{"v0.1.10", "v0.1.9", true},
		{"v0.1.1", "v0.1.1", false},
		{"v0.1.0", "v0.1.1", false},
		{"v0.2.0", "dev", false},
		{"v0.2.0", "34f07b6-dirty", false},
		{"0.2.0", "v0.1.0", false},
	} {
		if got := Newer(c.a, c.b); got != c.want {
			t.Errorf("Newer(%s, %s) = %v", c.a, c.b, got)
		}
	}
}

type recRunner struct {
	mu   sync.Mutex
	cmds []string
}

func (r *recRunner) Run(_ context.Context, c exec.Cmd) (exec.Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cmds = append(r.cmds, c.Name+" "+strings.Join(c.Args, " "))
	return exec.Result{}, nil
}

func newService(t *testing.T, version string, handler http.HandlerFunc) (*Service, *recRunner, *[]notify.Event) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := store.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	run := &recRunner{}
	var sent []notify.Event
	dir := t.TempDir()
	s := &Service{DB: db, Runner: run, ScriptsDir: "/opt/hostpanel/scripts", Activity: logs.NewActivity(db),
		Version: version, Repo: "zahit5834/hostpanel", API: ts.URL, StatusPath: filepath.Join(dir, "status.json"),
		LogPath: filepath.Join(dir, "update.log"), Notify: func(_ context.Context, e notify.Event) { sent = append(sent, e) }}
	return s, run, &sent
}

func release(tag string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/zahit5834/hostpanel/releases/latest" || !strings.HasPrefix(r.Header.Get("User-Agent"), "hostpanel/") {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(`{"tag_name":"` + tag + `","name":"HostPanel ` + tag + `","body":"- düzeltmeler <b>x</b>","html_url":"https://github.com/zahit5834/hostpanel/releases/tag/` + tag + `","published_at":"2026-11-06T10:00:00Z"}`))
	}
}

func TestCheckAndStart(t *testing.T) {
	ctx := context.Background()
	s, run, sent := newService(t, "v0.1.0", release("v0.2.0"))
	rel, err := s.Check(ctx)
	if err != nil || rel.Tag != "v0.2.0" || !strings.Contains(rel.Notes, "düzeltmeler") {
		t.Fatalf("%+v %v", rel, err)
	}
	s.Check(ctx)
	if len(*sent) != 1 || (*sent)[0].Kind != notify.KindUpdate {
		t.Fatalf("one notification per tag, got %+v", *sent)
	}
	in := s.Info(ctx, false)
	if !in.Available || !in.CanUpdate || in.Latest.Tag != "v0.2.0" || in.CheckedAt.IsZero() {
		t.Fatalf("%+v", in)
	}
	if err := s.Start(ctx, "v0.3.0"); err == nil {
		t.Fatal("unknown tag accepted")
	}
	if err := s.Start(ctx, "v0.2.0; rm -rf /"); err == nil {
		t.Fatal("bad tag accepted")
	}
	if err := s.Start(ctx, "v0.2.0"); err != nil {
		t.Fatal(err)
	}
	if len(run.cmds) != 1 || run.cmds[0] != "sudo -n /opt/hostpanel/scripts/hp-update.sh start v0.2.0" {
		t.Fatalf("%v", run.cmds)
	}

	// While running, no second start.
	os.WriteFile(s.StatusPath, []byte(`{"id":"1","from":"v0.1.0","to":"v0.2.0","state":"running","step":"download"}`), 0o644)
	if err := s.Start(ctx, "v0.2.0"); err == nil {
		t.Fatal("second update started while running")
	}
}

func TestInfoReasons(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newService(t, "34f07b6-dirty", release("v0.2.0"))
	s.Check(ctx)
	if in := s.Info(ctx, false); in.CanUpdate || !strings.Contains(in.Reason, "geliştirme") {
		t.Fatalf("dev build: %+v", in)
	}
	s, _, _ = newService(t, "v0.2.0", release("v0.2.0"))
	s.Check(ctx)
	if in := s.Info(ctx, false); in.CanUpdate || in.Available {
		t.Fatalf("up to date: %+v", in)
	}
	s, _, _ = newService(t, "v0.2.0", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	if _, err := s.Check(ctx); err == nil || !strings.Contains(err.Error(), "yayınlanmış sürüm yok") {
		t.Fatal(err)
	}
	if in := s.Info(ctx, false); in.CheckErr == "" {
		t.Fatal("check error not cached")
	}
	s, _, _ = newService(t, "v0.2.0", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"tag_name":"latest"}`)) })
	if _, err := s.Check(ctx); err == nil {
		t.Fatal("odd tag accepted")
	}
}

func TestRecordFinishedOnce(t *testing.T) {
	ctx := context.Background()
	s, _, sent := newService(t, "v0.1.0", release("v0.2.0"))
	s.RecordFinished(ctx) // no status file: nothing
	os.WriteFile(s.LogPath, []byte("=== güncelleme v0.2.0 → v0.2.1\nhealth check başarısız\n"), 0o640)
	os.WriteFile(s.StatusPath, []byte(`{"id":"20261106T100000Z","from":"v0.2.0","to":"v0.2.1","state":"rolled_back","step":"health","reason":"yeni sürüm health check'i geçemedi"}`), 0o644)
	s.RecordFinished(ctx)
	s.RecordFinished(ctx)
	list, _ := s.Activity.Query(ctx, logs.Filter{Action: "panel.update"})
	if len(list) != 1 || list[0].Status != "failed" || !strings.Contains(list[0].Summary, "geri alındı") ||
		!strings.Contains(list[0].Params, "health check başarısız") || list[0].Source != logs.SourceSystem {
		t.Fatalf("%+v", list)
	}
	if len(*sent) != 1 {
		t.Fatalf("notifications %+v", *sent)
	}
}
