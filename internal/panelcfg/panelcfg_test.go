package panelcfg

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zahit5834/hostpanel/internal/store"
)

func openDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	return db
}

func count(t *testing.T, db *sql.DB, q string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

func TestExportImportRoundTrip(t *testing.T) {
	ctx := context.Background()
	src := t.TempDir()
	db := openDB(t, filepath.Join(src, "hostpanel.db"))
	defer db.Close()
	now := time.Now().Unix()
	for _, q := range []string{
		`INSERT INTO settings(key, value) VALUES('acme_email','a@ornek.com'),('server_id','abc'),('server_ips','1.2.3.4'),('update_recorded_id','x'),('notify_kinds','["site.status"]')`,
		`INSERT INTO customers(id, name, created_at, updated_at) VALUES(1, 'Acme', 0, 0)`,
		`INSERT INTO dns_zones(id, name, customer_id, dnssec, created_at, updated_at) VALUES(1, 'ornek.com', 1, 1, 0, 0)`,
		`INSERT INTO dns_records(zone_id, name, type, value, created_at) VALUES(1, '@', 'MX', 'mail.ornek.com', 0)`,
		`INSERT INTO settings(key, value) VALUES('dns_ns1','ns1.ornek.com'),('dns_installed','1'),('dns_ips','1.2.3.4')`,
		`INSERT INTO sites(id, customer_id, domain, short_name, runtime_id, status, created_at, updated_at) VALUES(1, 1, 'ornek.com', 'ornek', 'static', 'running', 0, 0)`,
		`INSERT INTO backup_plans(name, scope, site_ids, components, schedule, destination, enabled, last_run_at, next_run_at, created_at, updated_at)
		 VALUES('Hepsi','all','[]','["files"]','0 3 * * *','both',1,5,6,0,0),('Tek','sites','[1]','["files"]','0 4 * * *','local',1,5,6,0,0)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	db.Exec(`INSERT INTO activity_log(ts, source, action, status, summary) VALUES(?, 'user', 'x', 'success', 'y')`, now)
	mustExec(t, db, `INSERT INTO pg_servers(image, memory_mb, status, created_at, updated_at) VALUES('postgres:18.6-trixie', 2048, 'running', ?, ?)`, now, now)
	mustExec(t, db, `INSERT INTO pg_roles(customer_id, name, password_sealed, created_at, updated_at) VALUES(1, 'c_x', 'sealed', ?, ?)`, now, now)
	mustExec(t, db, `INSERT INTO pg_databases(customer_id, role_id, name, status, created_at) VALUES(1, 1, 'x_db', 'ready', ?)`, now)
	rt := filepath.Join(src, "runtimes")
	os.MkdirAll(rt, 0o755)
	os.WriteFile(filepath.Join(rt, "static.yaml"), []byte("id: static # old shipped\n"), 0o644)
	os.WriteFile(filepath.Join(rt, "custom.yaml"), []byte("id: custom\n"), 0o644)
	key := make([]byte, 32)
	rand.Read(key)

	if _, err := Export(ctx, db, ExportOptions{DataDir: src, MasterKey: key, RuntimesDir: rt}, "kısa", &bytes.Buffer{}); err == nil {
		t.Fatal("short passphrase accepted")
	}
	var buf bytes.Buffer
	man, err := Export(ctx, db, ExportOptions{DataDir: src, MasterKey: key, RuntimesDir: rt, Version: "v0.1.0", Server: "srv1"}, "doğru-at-pil-zımba", &buf)
	if err != nil {
		t.Fatal(err)
	}
	if man.Customers != 1 || man.Plans != 2 || len(man.Runtimes) != 2 {
		t.Fatalf("%+v", man)
	}
	if left, _ := filepath.Glob(filepath.Join(src, "export-*")); len(left) != 0 {
		t.Fatalf("temporary copies left: %v", left)
	}
	if bytes.Contains(buf.Bytes(), key) || bytes.Contains(buf.Bytes(), []byte("a@ornek.com")) {
		t.Fatal("export is not encrypted")
	}
	// Live DB untouched.
	if count(t, db, `SELECT COUNT(*) FROM sites`) != 1 || count(t, db, `SELECT COUNT(*) FROM activity_log`) == 0 {
		t.Fatal("export modified the live database")
	}

	if _, err := Open(bytes.NewReader(buf.Bytes()), "yanlış-parola-123"); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	bad := bytes.Clone(buf.Bytes())
	bad[len(bad)-5] ^= 1
	if _, err := Open(bytes.NewReader(bad), "doğru-at-pil-zımba"); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("tampered: %v", err)
	}
	if _, err := Open(strings.NewReader("not a config"), "x"); err == nil {
		t.Fatal("garbage accepted")
	}
	a, err := Open(bytes.NewReader(buf.Bytes()), "doğru-at-pil-zımba")
	if err != nil {
		t.Fatal(err)
	}

	// Target: fresh install with a shipped static.yaml.
	dst := t.TempDir()
	drt := filepath.Join(dst, "runtimes")
	os.MkdirAll(drt, 0o755)
	os.WriteFile(filepath.Join(drt, "static.yaml"), []byte("id: static # new shipped\n"), 0o644)
	opt := ImportOptions{DBPath: filepath.Join(dst, "hostpanel.db"), MasterKeyPath: filepath.Join(dst, "master.key"), RuntimesDir: drt, UID: -1, GID: -1}
	if err := Import(ctx, a, opt); err != nil {
		t.Fatal(err)
	}
	if k, _ := os.ReadFile(opt.MasterKeyPath); !bytes.Equal(k, key) {
		t.Fatal("master key not restored")
	}
	if fi, _ := os.Stat(opt.MasterKeyPath); fi.Mode().Perm() != 0o600 {
		t.Fatalf("master.key mode %o", fi.Mode().Perm())
	}
	if b, _ := os.ReadFile(filepath.Join(drt, "static.yaml")); !strings.Contains(string(b), "new shipped") {
		t.Fatal("shipped runtime overwritten by the import")
	}
	if b, _ := os.ReadFile(filepath.Join(drt, "custom.yaml")); string(b) != "id: custom\n" {
		t.Fatal("custom runtime missing")
	}
	ndb := openDB(t, opt.DBPath)
	for q, want := range map[string]int{
		`SELECT COUNT(*) FROM customers`:                                                        1,
		`SELECT COUNT(*) FROM sites`:                                                            0,
		`SELECT COUNT(*) FROM activity_log`:                                                     0,
		`SELECT COUNT(*) FROM settings WHERE key='acme_email'`:                                  1,
		`SELECT COUNT(*) FROM settings WHERE key IN ('server_id','server_ips')`:                 0,
		`SELECT COUNT(*) FROM settings WHERE key LIKE 'update%'`:                                0,
		`SELECT COUNT(*) FROM dns_zones WHERE name='ornek.com' AND customer_id=1 AND dnssec=1`:  1,
		`SELECT COUNT(*) FROM pg_servers`:                                                       0,
		`SELECT COUNT(*) FROM pg_roles`:                                                         0,
		`SELECT COUNT(*) FROM pg_databases`:                                                     0,
		`SELECT COUNT(*) FROM dns_records`:                                                      1,
		`SELECT COUNT(*) FROM settings WHERE key='dns_ns1'`:                                     1,
		`SELECT COUNT(*) FROM settings WHERE key IN ('dns_installed','dns_ips')`:                0,
		`SELECT COUNT(*) FROM backup_plans WHERE next_run_at=0`:                                 2,
		`SELECT COUNT(*) FROM backup_plans WHERE scope='sites' AND enabled=0 AND site_ids='[]'`: 1,
		`SELECT COUNT(*) FROM backup_plans WHERE scope='all' AND enabled=1`:                     1,
	} {
		if got := count(t, ndb, q); got != want {
			t.Errorf("%s = %d, want %d", q, got, want)
		}
	}
	ndb.Close()

	// A second import onto a panel with customers needs --force.
	if err := Import(ctx, a, opt); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("import onto used panel: %v", err)
	}
	opt.Force = true
	if err := Import(ctx, a, opt); err != nil {
		t.Fatal(err)
	}
}

func TestOpenRejectsNewerSchema(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db := openDB(t, filepath.Join(dir, "hostpanel.db"))
	defer db.Close()
	var buf bytes.Buffer
	key := make([]byte, 32)
	if _, err := Export(ctx, db, ExportOptions{DataDir: dir, MasterKey: key}, "uzun-bir-parola-1", &buf); err != nil {
		t.Fatal(err)
	}
	a, err := Open(bytes.NewReader(buf.Bytes()), "uzun-bir-parola-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Manifest.Migrations) != len(store.MigrationNames()) {
		t.Fatalf("%v", a.Manifest.Migrations)
	}
	future := a.Manifest
	future.Migrations = append(slices.Clone(future.Migrations), "999_future.sql")
	if err := future.check(); err == nil || !strings.Contains(err.Error(), "daha yeni") {
		t.Fatalf("newer schema: %v", err)
	}
	future.Format = 2
	if err := future.check(); err == nil {
		t.Fatal("format 2 accepted")
	}
}

func mustExec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}
