// Package pgsql manages the PostgreSQL container, per-customer login roles
// and their databases. The panel never connects to PostgreSQL itself: every
// operation is a whitelisted hp-pg.sh subcommand that builds its SQL from
// validated names (psql variables) and gets passwords on stdin.
package pgsql

import (
	"errors"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/zahit5834/hostpanel/internal/databases"
)

var nameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{1,62}$`)

var reserved = map[string]bool{"postgres": true, "template0": true, "template1": true, "public": true}

// ValidName mirrors hp-pg.sh validate_pg_name: no system names, no pg_ prefix,
// no prefixes of the isolation test (hpiso_) or restore temp DBs (hprs_).
func ValidName(s string) bool {
	return nameRe.MatchString(s) && !reserved[s] &&
		!strings.HasPrefix(s, "pg_") && !strings.HasPrefix(s, "hpiso_") && !strings.HasPrefix(s, "hprs_")
}

// ErrName is the user-facing error for invalid names.
var ErrName = errors.New("ad küçük harfle başlamalı; yalnızca küçük harf, rakam ve _ içerebilir (2–63 karakter); sistem adları (postgres, pg_…) kullanılamaz")

// DBBase suggests a database name (same rules as MSSQL).
func DBBase(s string) string {
	out := databases.DBBase(s)
	if !ValidName(out) {
		out = "db_" + out
	}
	if len(out) > 63 {
		out = strings.TrimRight(out[:63], "_")
	}
	return out
}

// ConnInfo is everything needed to build connection strings.
type ConnInfo struct {
	Host     string
	Port     int
	Database string
	User     string
	Password string
}

// Npgsql is the .NET (Npgsql) connection string. Passwords are [A-Za-z0-9],
// so no quoting is needed.
func (c ConnInfo) Npgsql() string {
	return "Host=" + c.Host + ";Port=" + strconv.Itoa(c.Port) + ";Database=" + c.Database +
		";Username=" + c.User + ";Password=" + c.Password
}

// URL is the libpq URI (Node pg / Prisma / PHP parse_url, …).
func (c ConnInfo) URL() string {
	u := url.URL{Scheme: "postgresql", User: url.UserPassword(c.User, c.Password),
		Host: net.JoinHostPort(c.Host, strconv.Itoa(c.Port)), Path: "/" + c.Database}
	return u.String()
}

// ForRuntime picks the format a runtime's apps usually read.
func (c ConnInfo) ForRuntime(runtimeID string) string {
	if runtimeID == "dotnet" {
		return c.Npgsql()
	}
	return c.URL()
}

// DefaultEnvKey is the conventional env variable for the runtime.
func DefaultEnvKey(runtimeID string) string { return databases.DefaultEnvKey(runtimeID) }
