package databases

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"sync"
)

// BackupDir is where the server writes backups (inside the container; the
// host path is /var/lib/hostpanel/mssql/backup).
const BackupDir = "/var/opt/mssql/backup"

var backupPathRe = regexp.MustCompile(`^/var/opt/mssql/backup/[A-Za-z0-9][A-Za-z0-9._-]{0,200}\.bak$`)

// ValidBackupPath restricts BACKUP targets to the backup directory.
func ValidBackupPath(p string) bool { return backupPathRe.MatchString(p) }

// FakeServer is an in-memory SQL Server for dry-run mode and tests. It
// enforces the same visibility rules the real server is configured for:
// a login sees and accesses only the databases it owns.
type FakeServer struct {
	mu     sync.Mutex
	sa     string
	logins map[string]*fakeLogin
	dbs    map[string]string // name → owner
}

type fakeLogin struct {
	pw      string
	enabled bool
}

// NewFakeServer starts empty with the given sa password.
func NewFakeServer(sa string) *FakeServer {
	return &FakeServer{sa: sa, logins: map[string]*fakeLogin{}, dbs: map[string]string{}}
}

// Admin returns a provider acting as sa with password pw (Ping fails on a
// wrong password). Statements are echoed to w as "[DRY-RUN SQL] …" without
// passwords. A server whose sa password was never set adopts pw, so a
// restarted dev panel keeps working with the stored password.
func (f *FakeServer) Admin(w io.Writer, pw string) DatabaseProvider {
	return &fakeConn{f: f, w: w, user: "sa", pw: pw}
}

// Session connects as login with password (fails like a real login would).
func (f *FakeServer) Session(login, pw, db string) (LoginSession, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	l, ok := f.logins[login]
	if !ok || l.pw != pw || !l.enabled {
		return nil, fmt.Errorf("login failed for user '%s'", login)
	}
	if db != "" && db != "master" && f.dbs[db] != login {
		return nil, fmt.Errorf("cannot open database %q requested by the login", db)
	}
	return &fakeConn{f: f, user: login}, nil
}

// SetSA replaces the sa password (tests: simulate a fresh container).
func (f *FakeServer) SetSA(pw string) {
	f.mu.Lock()
	f.sa = pw
	f.mu.Unlock()
}

// CheckSA reports whether pw is the current sa password.
func (f *FakeServer) CheckSA(pw string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sa == pw
}

// Databases lists database → owner (tests).
func (f *FakeServer) Databases() map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]string, len(f.dbs))
	for k, v := range f.dbs {
		out[k] = v
	}
	return out
}

// Login reports a login's state (tests).
func (f *FakeServer) Login(name string) (pw string, enabled, ok bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	l, ok := f.logins[name]
	if !ok {
		return "", false, false
	}
	return l.pw, l.enabled, true
}

type fakeConn struct {
	f    *FakeServer
	w    io.Writer
	user string
	pw   string
}

func (c *fakeConn) echo(format string, a ...any) {
	if c.w != nil {
		fmt.Fprintf(c.w, "[DRY-RUN SQL] "+format+"\n", a...)
	}
}

func (c *fakeConn) lock() func() {
	c.f.mu.Lock()
	return c.f.mu.Unlock
}

func (c *fakeConn) Ping(context.Context) error {
	defer c.lock()()
	if c.user != "sa" {
		return nil
	}
	if c.f.sa == "" {
		c.f.sa = c.pw
	}
	if c.f.sa != c.pw {
		return errors.New("login failed for user 'sa'")
	}
	return nil
}

// login returns the named login, creating it if the in-memory state was lost
// (dev panel restart); the isolation test always creates its logins first.
func (c *fakeConn) login(name string) *fakeLogin {
	l, ok := c.f.logins[name]
	if !ok {
		l = &fakeLogin{enabled: true}
		c.f.logins[name] = l
	}
	return l
}

func (c *fakeConn) ChangeSA(_ context.Context, pw string) error {
	if err := checkPassword(pw); err != nil {
		return err
	}
	defer c.lock()()
	c.echo("ALTER LOGIN [sa] WITH PASSWORD = '***'")
	c.f.sa = pw
	return nil
}

func (c *fakeConn) SetMaxMemory(_ context.Context, mb int) error {
	c.echo("EXEC sp_configure 'max server memory (MB)', %d; RECONFIGURE", mb)
	return nil
}

func (c *fakeConn) CreateLogin(_ context.Context, name, pw string) error {
	if err := checkName(name); err != nil {
		return err
	}
	if err := checkPassword(pw); err != nil {
		return err
	}
	defer c.lock()()
	c.echo("CREATE LOGIN [%s] WITH PASSWORD = '***', CHECK_POLICY = ON; DENY VIEW ANY DATABASE TO [%s]", name, name)
	if l, ok := c.f.logins[name]; ok {
		l.pw = pw
		return nil
	}
	c.f.logins[name] = &fakeLogin{pw: pw, enabled: true}
	return nil
}

func (c *fakeConn) SetPassword(_ context.Context, name, pw string) error {
	if err := checkPassword(pw); err != nil {
		return err
	}
	defer c.lock()()
	c.echo("ALTER LOGIN [%s] WITH PASSWORD = '***' UNLOCK", name)
	c.login(name).pw = pw
	return nil
}

func (c *fakeConn) SetLoginEnabled(_ context.Context, name string, enabled bool) error {
	defer c.lock()()
	verb := "DISABLE"
	if enabled {
		verb = "ENABLE"
	}
	c.echo("ALTER LOGIN [%s] %s", name, verb)
	c.login(name).enabled = enabled
	return nil
}

func (c *fakeConn) DropLogin(_ context.Context, name string) error {
	defer c.lock()()
	c.echo("DROP LOGIN [%s]", name)
	for db, owner := range c.f.dbs {
		if owner == name {
			return fmt.Errorf("login %s veritabanı sahibi: %s", name, db)
		}
	}
	delete(c.f.logins, name)
	return nil
}

func (c *fakeConn) CreateDatabase(_ context.Context, db, owner string) error {
	if err := checkName(db, owner); err != nil {
		return err
	}
	defer c.lock()()
	c.echo("CREATE DATABASE [%s]; ALTER AUTHORIZATION ON DATABASE::[%s] TO [%s]; SET RECOVERY SIMPLE", db, db, owner)
	c.login(owner)
	if cur, ok := c.f.dbs[db]; ok && cur != owner {
		return errors.New("bu adda başka bir sahibe ait veritabanı var")
	}
	c.f.dbs[db] = owner
	return nil
}

func (c *fakeConn) Drop(_ context.Context, db, backupPath string) error {
	if backupPath != "" && !ValidBackupPath(backupPath) {
		return fmt.Errorf("geçersiz yedek yolu: %s", backupPath)
	}
	defer c.lock()()
	if backupPath != "" {
		c.echo("BACKUP DATABASE [%s] TO DISK = '%s' WITH COPY_ONLY", db, backupPath)
	}
	c.echo("DROP DATABASE [%s]", db)
	delete(c.f.dbs, db)
	return nil
}

func (c *fakeConn) Backup(_ context.Context, db, path string) error {
	c.echo("BACKUP DATABASE [%s] TO DISK = '%s' WITH COPY_ONLY", db, path)
	return nil
}

func (c *fakeConn) Restore(context.Context, string, string) error { return ErrNotImplemented }

func (c *fakeConn) GetSize(context.Context) (map[string]int64, error) {
	defer c.lock()()
	out := map[string]int64{}
	for db := range c.f.dbs {
		out[db] = 16 << 20 // empty MSSQL database: 8 MB data + 8 MB log
	}
	return out, nil
}

// --- LoginSession ---

func (c *fakeConn) VisibleDatabases(context.Context) ([]string, error) {
	defer c.lock()()
	out := []string{"master", "tempdb"}
	for db, owner := range c.f.dbs {
		if owner == c.user {
			out = append(out, db)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (c *fakeConn) TryAccess(_ context.Context, db string) error {
	defer c.lock()()
	if c.f.dbs[db] != c.user {
		return fmt.Errorf("the server principal %q is not able to access the database %q under the current security context", c.user, db)
	}
	return nil
}

func (c *fakeConn) WriteProbe(ctx context.Context, db string) error { return c.TryAccess(ctx, db) }

func (c *fakeConn) IsSysadmin(context.Context) (bool, error) { return c.user == "sa", nil }
