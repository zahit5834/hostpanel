package logs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hostpanel/internal/store"
)

func TestMaskMap(t *testing.T) {
	m := MaskMap(map[string]any{
		"domain":   "a.com",
		"password": "x",
		"env":      map[string]string{"ConnectionStrings__Default": "Server=..;Password=p", "PORT": "5000"},
		"apiKey":   "k",
	})
	if m["password"] != Masked || m["apiKey"] != Masked || m["domain"] != "a.com" {
		t.Fatalf("%v", m)
	}
	env := m["env"].(map[string]any)
	if env["ConnectionStrings__Default"] != Masked || env["PORT"] != "5000" {
		t.Fatalf("%v", env)
	}
}

func TestMaskArgs(t *testing.T) {
	got := MaskArgs([]string{"create", "--password", "hunter22", "--name", "db1", "SA_PASSWORD=zz", "-token=abc", "literal-s3cret"}, []string{"s3cret"})
	want := "create --password *** --name db1 SA_PASSWORD=*** -token=*** literal-***"
	if strings.Join(got, " ") != want {
		t.Fatalf("got %q", strings.Join(got, " "))
	}
}

func TestTailLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big.log")
	f, _ := os.Create(path)
	const total = 200000 // ~ 4 MB
	for i := 0; i < total; i++ {
		fmt.Fprintf(f, "line %06d some padding text\n", i)
	}
	f.Close()
	got, err := TailLines(path, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0] != "line 199997 some padding text" || got[2] != "line 199999 some padding text" {
		t.Fatalf("%q", got)
	}
	// More lines than file has.
	small := filepath.Join(t.TempDir(), "s.log")
	os.WriteFile(small, []byte("a\nb"), 0o600)
	got, _ = TailLines(small, 10)
	if strings.Join(got, ",") != "a,b" {
		t.Fatalf("%q", got)
	}
	// Line spanning chunk boundary and overlong line truncation.
	long := filepath.Join(t.TempDir(), "l.log")
	os.WriteFile(long, []byte("x\n"+strings.Repeat("y", 100000)+"\nz\n"), 0o600)
	got, _ = TailLines(long, 3)
	if len(got) != 3 || got[0] != "x" || len(got[1]) != MaxLineBytes || got[2] != "z" {
		t.Fatalf("len=%d first=%q", len(got), got[0])
	}
}

func TestActivityRecordQuery(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := store.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	a := NewActivity(db)
	uctx := WithActor(ctx, Actor{Source: SourceUser, IP: "1.2.3.4"})
	a.Record(uctx, Entry{Action: "login.success", Summary: "ok"}, map[string]any{"password": "p"})
	op := a.Begin(ctx, Entry{Action: "backup.run", TargetType: "site", TargetID: "a.com"}, nil)
	op.Finish(fmt.Errorf("disk full"))

	all, _ := a.Query(ctx, Filter{})
	if len(all) != 2 {
		t.Fatalf("n=%d", len(all))
	}
	if all[0].Status != StatusFailed || all[0].Source != SourceSystem || all[0].Error != "disk full" {
		t.Fatalf("%+v", all[0])
	}
	if all[1].IP != "1.2.3.4" || strings.Contains(all[1].Params, `"p"`) {
		t.Fatalf("%+v", all[1])
	}
	f, _ := a.Query(ctx, Filter{Action: "login."})
	if len(f) != 1 {
		t.Fatalf("prefix filter n=%d", len(f))
	}
	f, _ = a.Query(ctx, Filter{Text: "a.com"})
	if len(f) != 1 {
		t.Fatalf("text filter n=%d", len(f))
	}
}

func TestLineDiff(t *testing.T) {
	d := LineDiff("a\nb\nc", "a\nx\nc\nd")
	want := "  a\n- b\n+ x\n  c\n+ d"
	if d != want {
		t.Fatalf("got\n%s", d)
	}
	if LineDiff("same", "same") != "" {
		t.Fatal("equal inputs should give empty diff")
	}
}
