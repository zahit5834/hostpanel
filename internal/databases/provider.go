package databases

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strconv"
)

// ErrNotImplemented marks provider operations that arrive in a later phase.
var ErrNotImplemented = errors.New("bu işlem henüz desteklenmiyor")

// DatabaseProvider is a database engine as seen by the panel (MSSQL now;
// PostgreSQL/MySQL could implement the same interface). All names have been
// checked with ValidName by the caller and are validated again here.
type DatabaseProvider interface {
	Ping(ctx context.Context) error
	ChangeSA(ctx context.Context, newPassword string) error
	SetMaxMemory(ctx context.Context, mb int) error

	// CreateLogin creates an isolated login: it can only see and use the
	// databases it owns.
	CreateLogin(ctx context.Context, name, password string) error
	SetPassword(ctx context.Context, name, password string) error
	SetLoginEnabled(ctx context.Context, name string, enabled bool) error
	DropLogin(ctx context.Context, name string) error

	// CreateDatabase creates name and makes owner its owner (dbo).
	CreateDatabase(ctx context.Context, name, owner string) error
	// Drop removes name; if backupPath is not empty a COPY_ONLY full backup is
	// written there first (path inside the server, e.g. /var/opt/mssql/backup/…).
	Drop(ctx context.Context, name, backupPath string) error
	Backup(ctx context.Context, name, path string) error
	// VerifyBackup runs RESTORE VERIFYONLY on the .bak at path (inside the server).
	VerifyBackup(ctx context.Context, path string) error
	// Restore restores the .bak at path (inside the server) as name, replacing
	// an existing database, and makes owner its owner.
	Restore(ctx context.Context, name, path, owner string) error
	GetSize(ctx context.Context) (map[string]int64, error)
}

// LoginSession is a connection as a customer login, used by the isolation test.
type LoginSession interface {
	// VisibleDatabases lists sys.databases as the login sees it.
	VisibleDatabases(ctx context.Context) ([]string, error)
	// TryAccess reads db's catalog; it must fail for databases the login doesn't own.
	TryAccess(ctx context.Context, db string) error
	// WriteProbe creates, fills, reads and drops a table in db.
	WriteProbe(ctx context.Context, db string) error
	// IsSysadmin reports IS_SRVROLEMEMBER('sysadmin').
	IsSysadmin(ctx context.Context) (bool, error)
}

// ConnInfo is everything needed to build connection strings.
type ConnInfo struct {
	Host     string
	Port     int
	Database string
	User     string
	Password string
}

// ADONET is the .NET (Microsoft.Data.SqlClient) connection string. The
// container uses a self-signed certificate, hence TrustServerCertificate.
// Passwords are [A-Za-z0-9], so no quoting is needed.
func (c ConnInfo) ADONET() string {
	return "Server=" + c.Host + "," + strconv.Itoa(c.Port) + ";Database=" + c.Database + ";User Id=" + c.User +
		";Password=" + c.Password + ";Encrypt=True;TrustServerCertificate=True;"
}

// URL is the URI form understood by the Node.js "mssql" package (tedious).
func (c ConnInfo) URL() string {
	u := url.URL{Scheme: "mssql", User: url.UserPassword(c.User, c.Password),
		Host: net.JoinHostPort(c.Host, strconv.Itoa(c.Port)), Path: "/" + c.Database,
		RawQuery: "encrypt=true&trustServerCertificate=true"}
	return u.String()
}

// ForRuntime picks the format a runtime's apps usually read.
func (c ConnInfo) ForRuntime(runtimeID string) string {
	if runtimeID == "dotnet" {
		return c.ADONET()
	}
	return c.URL()
}

// DefaultEnvKey is the conventional env variable for the runtime.
func DefaultEnvKey(runtimeID string) string {
	if runtimeID == "dotnet" {
		// Configuration["ConnectionStrings:DefaultConnection"] in ASP.NET Core.
		return "ConnectionStrings__DefaultConnection"
	}
	return "DATABASE_URL"
}
