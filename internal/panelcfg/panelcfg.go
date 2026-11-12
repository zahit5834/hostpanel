// Package panelcfg exports the panel's own configuration to a passphrase-
// encrypted file and imports it on another server.
//
// The export holds what the panel itself owns: admin account + 2FA, settings,
// notification channels, IP allowlist, customers, backup plans (with the Drive
// crypt keys) and custom runtime definitions — plus master.key, without which
// the sealed values are useless. Sites, databases, certificates and history
// are server-specific and are left out: sites move with their backups (Drive
// scan + restore). Secrets that only root holds (the Drive token in
// rclone.conf, git deploy keys) are not exported — the panel cannot read them,
// by design — and are entered/generated again on the new server.
//
// File format: "HPCFG1\n" | salt (16) | nonce (12) | AES-256-GCM(tar.gz),
// key = argon2id(passphrase, salt, t=4, m=19 MiB, p=1), AAD = magic.
package panelcfg

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/zahit5834/hostpanel/internal/store"
)

// Magic starts every export file.
const Magic = "HPCFG1\n"

// Format is the archive layout version.
const Format = 1

// MinPassphrase is the shortest passphrase accepted for an export.
const MinPassphrase = 12

const (
	maxFile   = 64 << 20 // encrypted file / plaintext limit
	saltLen   = 16
	argonTime = 4
	argonMem  = 19 * 1024 // KiB, same budget as login hashing
)

// Manifest describes an export.
type Manifest struct {
	Format     int       `json:"format"`
	Version    string    `json:"version"`
	Server     string    `json:"server"`
	Created    time.Time `json:"created"`
	Migrations []string  `json:"migrations"`
	Customers  int       `json:"customers"`
	Plans      int       `json:"plans"`
	Zones      int       `json:"zones"`
	Runtimes   []string  `json:"runtimes"`
}

// ErrDecrypt means wrong passphrase or a damaged file.
var ErrDecrypt = errors.New("dosya açılamadı: parola yanlış ya da dosya bozuk")

var runtimeName = regexp.MustCompile(`^[a-z0-9_-]{1,40}\.yaml$`)

// Server-specific settings dropped from an export.
var droppedSettings = []string{"server_id", "server_ips", "backup_rclone_installed", "dns_installed", "dns_ips"}

// scrub turns a copy of the live database into an export: everything tied to
// this server goes, history goes, plans lose their (now meaningless) site ids.
var scrub = []string{
	`DELETE FROM cron_runs`, `DELETE FROM site_crons`, `DELETE FROM site_git`, `DELETE FROM health_checks`,
	`DELETE FROM backups`, `DELETE FROM pg_databases`, `DELETE FROM pg_roles`, `DELETE FROM pg_servers`,
	`DELETE FROM mail_domains`, `DELETE FROM mail_servers`,
	`DELETE FROM traffic_daily`, `DELETE FROM uptime_daily`, `DELETE FROM uptime_incidents`,
	`DELETE FROM metrics`, `DELETE FROM domain_expiry`, `DELETE FROM backup_verifications`,
	`DELETE FROM databases`, `DELETE FROM db_logins`, `DELETE FROM db_servers`,
	`DELETE FROM csrs`, `DELETE FROM certificates`, `DELETE FROM releases`, `DELETE FROM site_env`, `DELETE FROM sites`,
	`DELETE FROM sessions`, `DELETE FROM login_attempts`, `DELETE FROM activity_log`, `DELETE FROM jobs`,
	`UPDATE backup_plans SET last_run_at=0, next_run_at=0`,
	`UPDATE backup_plans SET site_ids='[]', enabled=0 WHERE scope='sites'`,
	`UPDATE backup_plans SET enabled=0 WHERE scope='mail'`, // the mail server is installed again from the panel
	`DELETE FROM settings WHERE key LIKE 'update\_%' ESCAPE '\'`,
	`DELETE FROM settings WHERE key LIKE 'image\_%' ESCAPE '\'`,
	// Faz 11: state of this server (boot ids, audit/integrity results, watches).
	`DELETE FROM settings WHERE key LIKE 'security\_%' ESCAPE '\'`,
	`DELETE FROM settings WHERE key IN ('last_boot_id','reboot_planned_boot_id','oom_checked_at','ssh_watch_since','transfer_exported_at',
		'infra_state','runtime_patch_notified','backup_verify_at','heartbeat_url')`,
}

// ExportOptions are the panel paths and identity for Export.
type ExportOptions struct {
	DataDir     string // where the temporary DB copy is made
	MasterKey   []byte
	RuntimesDir string
	Version     string
	Server      string
}

// Export writes an encrypted configuration archive of db to w.
func Export(ctx context.Context, db *sql.DB, opt ExportOptions, passphrase string, w io.Writer) (Manifest, error) {
	if len([]rune(passphrase)) < MinPassphrase {
		return Manifest{}, fmt.Errorf("parola en az %d karakter olmalı", MinPassphrase)
	}
	dbBytes, man, err := scrubbedCopy(ctx, db, opt.DataDir)
	if err != nil {
		return Manifest{}, err
	}
	man.Format, man.Version, man.Server, man.Created = Format, opt.Version, opt.Server, time.Now().UTC()
	man.Migrations = store.MigrationNames()

	var plain bytes.Buffer
	gz := gzip.NewWriter(&plain)
	tw := tar.NewWriter(gz)
	add := func(name string, mode int64, b []byte) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(b)), ModTime: man.Created, Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		_, err := tw.Write(b)
		return err
	}
	if entries, err := os.ReadDir(opt.RuntimesDir); err == nil {
		for _, e := range entries {
			if !e.Type().IsRegular() || !runtimeName.MatchString(e.Name()) {
				continue
			}
			b, err := os.ReadFile(filepath.Join(opt.RuntimesDir, e.Name()))
			if err != nil || len(b) > 1<<20 {
				continue
			}
			if err := add("runtimes/"+e.Name(), 0o644, b); err != nil {
				return Manifest{}, err
			}
			man.Runtimes = append(man.Runtimes, e.Name())
		}
	}
	mb, _ := json.MarshalIndent(man, "", "  ")
	for _, f := range []struct {
		name string
		mode int64
		b    []byte
	}{{"manifest.json", 0o644, mb}, {"hostpanel.db", 0o600, dbBytes}, {"master.key", 0o600, opt.MasterKey}} {
		if err := add(f.name, f.mode, f.b); err != nil {
			return Manifest{}, err
		}
	}
	if err := tw.Close(); err != nil {
		return Manifest{}, err
	}
	if err := gz.Close(); err != nil {
		return Manifest{}, err
	}
	if plain.Len() > maxFile {
		return Manifest{}, errors.New("yapılandırma 64 MB'tan büyük")
	}
	salt := make([]byte, saltLen)
	rand.Read(salt)
	aead, err := newAEAD(passphrase, salt)
	if err != nil {
		return Manifest{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	rand.Read(nonce)
	out := aead.Seal(nil, nonce, plain.Bytes(), []byte(Magic))
	for _, b := range [][]byte{[]byte(Magic), salt, nonce, out} {
		if _, err := w.Write(b); err != nil {
			return Manifest{}, err
		}
	}
	return man, nil
}

func newAEAD(passphrase string, salt []byte) (cipher.AEAD, error) {
	key := argon2.IDKey([]byte(passphrase), salt, argonTime, argonMem, 1, 32)
	// argon2 just allocated ~19 MiB; give it back (idle RSS budget).
	defer debug.FreeOSMemory()
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// scrubbedCopy makes a consistent copy with VACUUM INTO, strips it and returns its bytes.
func scrubbedCopy(ctx context.Context, db *sql.DB, dir string) ([]byte, Manifest, error) {
	var man Manifest
	rnd := make([]byte, 6)
	rand.Read(rnd)
	path := filepath.Join(dir, "export-"+hex.EncodeToString(rnd)+".db")
	defer func() {
		for _, suf := range []string{"", "-wal", "-shm"} {
			os.Remove(path + suf)
		}
	}()
	if _, err := db.ExecContext(ctx, `VACUUM INTO ?`, path); err != nil {
		return nil, man, fmt.Errorf("veritabanı kopyalanamadı: %w", err)
	}
	cp, err := store.Open(path)
	if err != nil {
		return nil, man, err
	}
	err = func() error {
		defer cp.Close()
		for _, q := range scrub {
			if _, err := cp.ExecContext(ctx, q); err != nil {
				return fmt.Errorf("%s: %w", q, err)
			}
		}
		for _, k := range droppedSettings {
			if _, err := cp.ExecContext(ctx, `DELETE FROM settings WHERE key=?`, k); err != nil {
				return err
			}
		}
		cp.QueryRowContext(ctx, `SELECT COUNT(*) FROM customers`).Scan(&man.Customers)
		cp.QueryRowContext(ctx, `SELECT COUNT(*) FROM backup_plans`).Scan(&man.Plans)
		cp.QueryRowContext(ctx, `SELECT COUNT(*) FROM dns_zones`).Scan(&man.Zones)
		if _, err := cp.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
			return err
		}
		if _, err := cp.ExecContext(ctx, `PRAGMA journal_mode=DELETE`); err != nil {
			return err
		}
		_, err := cp.ExecContext(ctx, `VACUUM`)
		return err
	}()
	if err != nil {
		return nil, man, err
	}
	b, err := os.ReadFile(path)
	return b, man, err
}

// Archive is a decrypted export.
type Archive struct {
	Manifest  Manifest
	DB        []byte
	MasterKey []byte
	Runtimes  map[string][]byte
}

// Open decrypts and validates an export.
func Open(r io.Reader, passphrase string) (*Archive, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxFile+1024))
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(raw, []byte(Magic)) {
		return nil, errors.New("bu bir HostPanel yapılandırma dosyası değil")
	}
	raw = raw[len(Magic):]
	if len(raw) < saltLen+12+16 {
		return nil, ErrDecrypt
	}
	aead, err := newAEAD(passphrase, raw[:saltLen])
	if err != nil {
		return nil, err
	}
	ns := aead.NonceSize()
	plain, err := aead.Open(nil, raw[saltLen:saltLen+ns], raw[saltLen+ns:], []byte(Magic))
	if err != nil {
		return nil, ErrDecrypt
	}
	gz, err := gzip.NewReader(bytes.NewReader(plain))
	if err != nil {
		return nil, err
	}
	a := &Archive{Runtimes: map[string][]byte{}}
	tr := tar.NewReader(io.LimitReader(gz, maxFile))
	var manifest []byte
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("arşiv okunamadı: %w", err)
		}
		if h.Typeflag != tar.TypeReg || h.Size > maxFile {
			return nil, fmt.Errorf("beklenmeyen arşiv girişi: %q", h.Name)
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		switch name := h.Name; {
		case name == "manifest.json":
			manifest = b
		case name == "hostpanel.db":
			a.DB = b
		case name == "master.key":
			a.MasterKey = b
		case strings.HasPrefix(name, "runtimes/") && runtimeName.MatchString(strings.TrimPrefix(name, "runtimes/")):
			a.Runtimes[strings.TrimPrefix(name, "runtimes/")] = b
		default:
			return nil, fmt.Errorf("beklenmeyen arşiv girişi: %q", name)
		}
	}
	if err := json.Unmarshal(manifest, &a.Manifest); err != nil {
		return nil, errors.New("manifest.json okunamadı")
	}
	if err := a.Manifest.check(); err != nil {
		return nil, err
	}
	if len(a.MasterKey) != 32 {
		return nil, errors.New("master.key eksik ya da hatalı")
	}
	if !bytes.HasPrefix(a.DB, []byte("SQLite format 3\x00")) {
		return nil, errors.New("veritabanı eksik ya da hatalı")
	}
	return a, nil
}

// check rejects other formats and exports from a newer schema.
func (m Manifest) check() error {
	if m.Format != Format {
		return fmt.Errorf("desteklenmeyen dosya biçimi %d", m.Format)
	}
	known := store.MigrationNames()
	for _, name := range m.Migrations {
		if !slices.Contains(known, name) {
			return fmt.Errorf("dosya daha yeni bir panel sürümünden (%s, migration %s); önce paneli güncelleyin", m.Version, name)
		}
	}
	return nil
}

// ImportOptions are the target paths for Import.
type ImportOptions struct {
	DBPath        string
	MasterKeyPath string
	RuntimesDir   string
	Force         bool // replace a panel that already has customers or sites
	UID, GID      int  // owner of the DB and master.key (-1 = leave)
}

// InUse reports whether the database at path already holds customers or sites.
func InUse(ctx context.Context, path string) (bool, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	db, err := store.Open(path)
	if err != nil {
		return false, err
	}
	defer db.Close()
	var n int
	for _, t := range []string{"customers", "sites"} {
		var c int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+t).Scan(&c); err == nil {
			n += c
		}
	}
	return n > 0, nil
}

// Import writes the archive's database, master key and missing runtime files.
// The panel must be stopped. The database is migrated to this binary's schema.
func Import(ctx context.Context, a *Archive, opt ImportOptions) error {
	if used, err := InUse(ctx, opt.DBPath); err != nil {
		return err
	} else if used && !opt.Force {
		return errors.New("bu panelde zaten müşteri/site var; üzerine yazmak için --force")
	}
	if err := writeFile(opt.MasterKeyPath, a.MasterKey, 0o600, opt.UID, opt.GID); err != nil {
		return fmt.Errorf("master.key yazılamadı: %w", err)
	}
	for _, suf := range []string{"-wal", "-shm"} {
		os.Remove(opt.DBPath + suf)
	}
	if err := writeFile(opt.DBPath, a.DB, 0o600, opt.UID, opt.GID); err != nil {
		return fmt.Errorf("veritabanı yazılamadı: %w", err)
	}
	db, err := store.Open(opt.DBPath)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := store.Migrate(ctx, db); err != nil {
		return err
	}
	for name, b := range a.Runtimes {
		p := filepath.Join(opt.RuntimesDir, name)
		if _, err := os.Lstat(p); err == nil {
			continue // shipped (or already present) definitions win
		}
		if err := writeFile(p, b, 0o644, -1, -1); err != nil {
			return fmt.Errorf("runtime %s yazılamadı: %w", name, err)
		}
	}
	if opt.UID >= 0 {
		for _, suf := range []string{"-wal", "-shm"} {
			os.Chown(opt.DBPath+suf, opt.UID, opt.GID)
		}
	}
	return nil
}

// writeFile writes atomically (temp file + rename) with the given mode/owner.
func writeFile(path string, b []byte, mode os.FileMode, uid, gid int) error {
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s symlink olamaz", path)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".hp-import-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if uid >= 0 {
		if err := tmp.Chown(uid, gid); err != nil {
			tmp.Close()
			return err
		}
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
