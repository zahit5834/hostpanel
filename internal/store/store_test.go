package store

import (
	"context"
	"path/filepath"
	"testing"
)

func TestMigrateIdempotent(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if err := Migrate(ctx, db); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
	var mode string
	db.QueryRow(`PRAGMA journal_mode`).Scan(&mode)
	if mode != "wal" {
		t.Fatalf("journal_mode=%s", mode)
	}
	if err := SetSetting(ctx, db, "a", "1"); err != nil {
		t.Fatal(err)
	}
	SetSetting(ctx, db, "a", "2")
	if v := GetSetting(ctx, db, "a", ""); v != "2" {
		t.Fatalf("setting=%q", v)
	}
	if v := GetSetting(ctx, db, "missing", "def"); v != "def" {
		t.Fatalf("default=%q", v)
	}
}
