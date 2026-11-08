package pgsql

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidName(t *testing.T) {
	for _, ok := range []string{"otopanom", "c_acme", "shop_example_com", "a1"} {
		if !ValidName(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", "a", "1db", "Db", "a-b", "postgres", "template0", "template1", "public",
		"pg_x", "hpiso_a", "hprs_1", strings.Repeat("a", 64), "a;b", "a b"} {
		if ValidName(bad) {
			t.Errorf("%q should be invalid", bad)
		}
	}
}

func TestDBBase(t *testing.T) {
	for in, want := range map[string]string{"shop_example_com": "shop_example_com", "pg_site": "db_pg_site"} {
		if got := DBBase(in); got != want || !ValidName(got) {
			t.Errorf("DBBase(%q) = %q, want %q", in, got, want)
		}
	}
	if got := DBBase(strings.Repeat("x", 80)); !ValidName(got) {
		t.Errorf("long base %q invalid", got)
	}
}

func TestConnStrings(t *testing.T) {
	c := ConnInfo{Host: "127.0.0.1", Port: 5432, Database: "otopanom", User: "c_oto", Password: "Abc123"}
	if got := c.Npgsql(); got != "Host=127.0.0.1;Port=5432;Database=otopanom;Username=c_oto;Password=Abc123" {
		t.Errorf("npgsql %q", got)
	}
	if got := c.URL(); got != "postgresql://c_oto:Abc123@127.0.0.1:5432/otopanom" {
		t.Errorf("url %q", got)
	}
	if c.ForRuntime("dotnet") != c.Npgsql() || c.ForRuntime("node") != c.URL() || c.ForRuntime("php") != c.URL() {
		t.Error("ForRuntime picks the wrong format")
	}
	if DefaultEnvKey("dotnet") != "ConnectionStrings__DefaultConnection" || DefaultEnvKey("node") != "DATABASE_URL" {
		t.Error("default env keys")
	}
}

func TestParseSizes(t *testing.T) {
	got := ParseSizes("otopanom=8192\nbad line\nx=abc\nc_db=12\n")
	if len(got) != 2 || got["otopanom"] != 8192 || got["c_db"] != 12 {
		t.Fatalf("%v", got)
	}
}

func TestSaveUpload(t *testing.T) {
	s := &Service{UploadDir: t.TempDir()}
	if _, _, err := s.SaveUpload(strings.NewReader("-- PostgreSQL database dump\n\\! id\n"), 1<<20); err == nil {
		t.Fatal("plain SQL accepted")
	}
	if _, _, err := s.SaveUpload(strings.NewReader("PG"), 1<<20); err == nil {
		t.Fatal("short file accepted")
	}
	data := append([]byte("PGDMP"), bytes.Repeat([]byte{1}, 100)...)
	name, n, err := s.SaveUpload(bytes.NewReader(data), 1<<20)
	if err != nil || n != int64(len(data)) || !ImportRe.MatchString(name) {
		t.Fatalf("%q %d %v", name, n, err)
	}
	if b, _ := os.ReadFile(filepath.Join(s.UploadDir, name)); !bytes.Equal(b, data) {
		t.Fatal("content differs")
	}
	if _, _, err := s.SaveUpload(bytes.NewReader(data), 10); err == nil {
		t.Fatal("over limit accepted")
	}
	if entries, _ := os.ReadDir(s.UploadDir); len(entries) != 1 {
		t.Fatalf("leftover uploads: %d", len(entries))
	}
	s.DiscardUpload(name)
	s.DiscardUpload("../x")
	if entries, _ := os.ReadDir(s.UploadDir); len(entries) != 0 {
		t.Fatal("discard failed")
	}
}
